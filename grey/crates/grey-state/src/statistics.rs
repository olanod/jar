//! Validator activity statistics sub-transition (Section 13, eq 13.3-13.5).
//!
//! Updates per-validator performance records based on block activity,
//! and computes per-core (π_C) and per-service (π_S) statistics.

use grey_types::Timeslot;
use grey_types::config::Config;
use grey_types::constants::ERASURE_PIECE_SIZE;
use grey_types::header::Extrinsic;
use grey_types::state::{CoreStatistics, ServiceStatistics, ValidatorRecord, ValidatorStatistics};
use grey_types::work::WorkReport;
use std::collections::BTreeMap;

/// Apply the statistics sub-transition.
///
/// Updates the validator statistics based on the block's author and extrinsic content.
/// On epoch boundaries, rotates current stats to last and resets current.
/// Computes per-core statistics (π_C) from incoming and available work reports.
/// Computes per-service statistics (π_S) from incoming reports and preimage data.
#[allow(clippy::too_many_arguments)]
pub fn update_statistics(
    config: &Config,
    stats: &mut ValidatorStatistics,
    prior_timeslot: Timeslot,
    new_timeslot: Timeslot,
    author_index: u16,
    extrinsic: &Extrinsic,
    incoming_reports: &[&WorkReport],
    available_reports: &[WorkReport],
    accumulation_stats: &std::collections::BTreeMap<grey_types::ServiceId, (javm::Gas, u32)>,
) {
    let old_epoch = config.epoch_of(prior_timeslot);
    let new_epoch = config.epoch_of(new_timeslot);

    let num_validators = stats.current.len();

    // Epoch transition: rotate statistics (eq 13.4)
    if new_epoch > old_epoch {
        stats.last = stats.current.clone();
        stats.current = vec![ValidatorRecord::default(); num_validators];
    }

    let author = author_index as usize;
    if author < stats.current.len() {
        // Block author: increment blocks_produced (eq 13.5)
        stats.current[author].blocks_produced += 1;

        // Tickets introduced
        stats.current[author].tickets_introduced += extrinsic.tickets.len() as u32;

        // Preimages introduced
        stats.current[author].preimages_introduced += extrinsic.preimages.len() as u32;

        // Preimage total bytes
        let preimage_bytes: u64 = extrinsic
            .preimages
            .iter()
            .map(|(_, data)| data.len() as u64)
            .sum();
        stats.current[author].preimage_bytes += preimage_bytes;
    }

    // Assurances: each validator that submitted an assurance
    for assurance in &extrinsic.assurances {
        let idx = assurance.validator_index as usize;
        if idx < stats.current.len() {
            stats.current[idx].assurances_made += 1;
        }
    }

    // Guarantees: G = set of Ed25519 keys from guarantee credentials (eq 13.5)
    // π_V'[v]_g ≡ a[v]_g + (κ'_v ∈ G) — boolean membership, not count
    {
        let mut reporters = std::collections::HashSet::new();
        for guarantee in &extrinsic.guarantees {
            for (validator_idx, _sig) in &guarantee.credentials {
                reporters.insert(*validator_idx as usize);
            }
        }
        for idx in reporters {
            if idx < stats.current.len() {
                stats.current[idx].reports_guaranteed += 1;
            }
        }
    }

    // Compute per-core statistics π_C (eq 13.3)
    compute_core_statistics(
        config,
        stats,
        &extrinsic.assurances,
        incoming_reports,
        available_reports,
    );

    // Compute per-service statistics π_S (eq 13.3)
    compute_service_statistics(stats, extrinsic, incoming_reports, accumulation_stats);
}

/// Compute per-core statistics π_C (eq 13.3).
///
/// For each core c:
///   R(c) = sum over (d in r.results, r in I, r.core_index == c) of refine-load fields
///   L(c) = sum over (r in I, r.core_index == c) of r.package_spec.bundle_length
///   D(c) = sum over (r in R, r.core_index == c) of (bundle_length + W_G * ceil(exports_count * 65/64))
///   p    = count of assurances with bit c set
fn compute_core_statistics(
    config: &Config,
    stats: &mut ValidatorStatistics,
    assurances: &grey_types::header::AssurancesExtrinsic,
    incoming_reports: &[&WorkReport],
    available_reports: &[WorkReport],
) {
    let num_cores = config.core_count as usize;
    let segment_size = config.erasure_pieces_per_segment as u64 * ERASURE_PIECE_SIZE as u64;

    let mut core_stats = vec![CoreStatistics::default(); num_cores];

    // R(c): sum refine-load fields from incoming reports' digests
    for report in incoming_reports {
        let c = report.core_index as usize;
        if c >= num_cores {
            continue;
        }
        for digest in &report.results {
            core_stats[c].add_digest(digest);
        }
        // L(c): bundle size from incoming reports
        core_stats[c].bundle_size += report.package_spec.bundle_length as u64;
    }

    // D(c): DA load from available reports (newly available via assurances)
    for report in available_reports {
        let c = report.core_index as usize;
        if c >= num_cores {
            continue;
        }
        let bundle_len = report.package_spec.bundle_length as u64;
        let exports = report.package_spec.exports_count as u64;
        // D(c) = bundle_length + W_G * ceil(exports_count * 65 / 64)
        let segments_bytes = segment_size * (exports * 65).div_ceil(64);
        core_stats[c].da_load += bundle_len + segments_bytes;
    }

    // p: popularity = count of assurance bitfield bits set per core
    let popularity = crate::count_assurance_bits(assurances, num_cores);
    for (core, stat) in core_stats.iter_mut().enumerate() {
        stat.popularity += popularity[core] as u64;
    }

    stats.core_stats = core_stats;
}

/// Compute per-service statistics π_S (GP eq 2087-2142).
///
/// For each service s in the union of {services from incoming digests} ∪ {services from preimages} ∪ {services from accumulation}:
///   R(s) = (count, gas_used, imports, extrinsic_count, extrinsic_size, exports) summed from incoming digests
///   p = (count, size) from preimage extrinsic entries
///   a = accumulation results: (gas_used, item_count) per service from the accumulation pipeline
fn compute_service_statistics(
    stats: &mut ValidatorStatistics,
    extrinsic: &Extrinsic,
    incoming_reports: &[&WorkReport],
    accumulation_stats: &std::collections::BTreeMap<grey_types::ServiceId, (javm::Gas, u32)>,
) {
    let mut svc_stats: BTreeMap<grey_types::ServiceId, ServiceStatistics> = BTreeMap::new();

    // s^R: services from incoming work digests (GP eq 2121-2142: R(s))
    for report in incoming_reports {
        for digest in &report.results {
            let entry = svc_stats.entry(digest.service_id).or_default();
            entry.add_digest(digest);
        }
    }

    // s^P: services from preimage extrinsic
    for (service_id, data) in &extrinsic.preimages {
        let entry = svc_stats.entry(*service_id).or_default();
        entry.provided_count += 1;
        entry.provided_size += data.len() as u64;
    }

    // K(S): services from accumulation statistics (GP eq 2113: a ≔ U(S[s], (0,0)))
    // S[s] = (G(s), N(s)) — gas and work item count
    for (service_id, (gas, item_count)) in accumulation_stats {
        let entry = svc_stats.entry(*service_id).or_default();
        entry.accumulate_gas_used += *gas;
        entry.accumulate_count += *item_count as u64;
    }

    stats.service_stats = svc_stats;
}

#[cfg(test)]
mod tests {
    use super::*;
    use grey_types::config::Config;
    use grey_types::header::Extrinsic;
    use grey_types::state::ValidatorStatistics;
    use std::collections::BTreeMap;

    fn make_stats(n: usize) -> ValidatorStatistics {
        ValidatorStatistics {
            current: vec![ValidatorRecord::default(); n],
            last: vec![ValidatorRecord::default(); n],
            core_stats: vec![],
            service_stats: BTreeMap::new(),
        }
    }

    #[test]
    fn test_empty_block_increments_blocks_produced() {
        let config = Config::tiny();
        let mut stats = make_stats(config.validators_count as usize);
        let extrinsic = Extrinsic::default();

        update_statistics(
            &config,
            &mut stats,
            0,
            1,
            0,
            &extrinsic,
            &[],
            &[],
            &BTreeMap::new(),
        );

        assert_eq!(stats.current[0].blocks_produced, 1);
        // Other validators untouched
        assert_eq!(stats.current[1].blocks_produced, 0);
    }

    #[test]
    fn test_epoch_rotation() {
        let config = Config::tiny(); // E=12
        let mut stats = make_stats(config.validators_count as usize);
        let extrinsic = Extrinsic::default();

        // Block in epoch 0
        update_statistics(
            &config,
            &mut stats,
            0,
            1,
            0,
            &extrinsic,
            &[],
            &[],
            &BTreeMap::new(),
        );
        assert_eq!(stats.current[0].blocks_produced, 1);

        // Block crossing into epoch 1 (timeslot 12): should rotate
        update_statistics(
            &config,
            &mut stats,
            11,
            12,
            0,
            &extrinsic,
            &[],
            &[],
            &BTreeMap::new(),
        );
        // After rotation: last should have the old current (1 block), current reset + new block
        assert_eq!(stats.last[0].blocks_produced, 1);
        assert_eq!(stats.current[0].blocks_produced, 1); // new block in new epoch
    }

    #[test]
    fn test_no_rotation_same_epoch() {
        let config = Config::tiny();
        let mut stats = make_stats(config.validators_count as usize);
        let extrinsic = Extrinsic::default();

        update_statistics(
            &config,
            &mut stats,
            1,
            2,
            0,
            &extrinsic,
            &[],
            &[],
            &BTreeMap::new(),
        );
        update_statistics(
            &config,
            &mut stats,
            2,
            3,
            0,
            &extrinsic,
            &[],
            &[],
            &BTreeMap::new(),
        );

        assert_eq!(stats.current[0].blocks_produced, 2);
        assert_eq!(stats.last[0].blocks_produced, 0); // no rotation
    }

    #[test]
    fn test_ticket_and_preimage_counts() {
        let config = Config::tiny();
        let mut stats = make_stats(config.validators_count as usize);
        let extrinsic = Extrinsic {
            tickets: vec![
                grey_types::header::TicketProof {
                    attempt: 0,
                    proof: vec![],
                },
                grey_types::header::TicketProof {
                    attempt: 1,
                    proof: vec![],
                },
            ],
            preimages: vec![(42, vec![0xAA, 0xBB, 0xCC])],
            ..Extrinsic::default()
        };

        update_statistics(
            &config,
            &mut stats,
            0,
            1,
            2,
            &extrinsic,
            &[],
            &[],
            &BTreeMap::new(),
        );

        assert_eq!(stats.current[2].tickets_introduced, 2);
        assert_eq!(stats.current[2].preimages_introduced, 1);
        assert_eq!(stats.current[2].preimage_bytes, 3);
    }

    #[test]
    fn test_author_out_of_range_no_panic() {
        let config = Config::tiny();
        let mut stats = make_stats(config.validators_count as usize);
        let extrinsic = Extrinsic::default();

        // Author index beyond validator count — should not panic
        update_statistics(
            &config,
            &mut stats,
            0,
            1,
            999,
            &extrinsic,
            &[],
            &[],
            &BTreeMap::new(),
        );
        // All validators should be untouched
        for v in &stats.current {
            assert_eq!(v.blocks_produced, 0);
        }
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use grey_types::config::Config;
    use grey_types::header::Extrinsic;
    use grey_types::state::{ValidatorRecord, ValidatorStatistics};
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    fn make_stats(n: usize) -> ValidatorStatistics {
        ValidatorStatistics {
            current: vec![ValidatorRecord::default(); n],
            last: vec![ValidatorRecord::default(); n],
            core_stats: vec![],
            service_stats: BTreeMap::new(),
        }
    }

    proptest! {
        /// Only the author's blocks_produced is incremented; others unchanged.
        #[test]
        fn only_author_blocks_produced_incremented(
            author_index in 0u16..6,
        ) {
            let config = Config::tiny(); // V=6
            let n = config.validators_count as usize;
            let mut stats = make_stats(n);
            let extrinsic = Extrinsic::default();

            update_statistics(
                &config, &mut stats, 0, 1, author_index, &extrinsic,
                &[], &[], &BTreeMap::new(),
            );

            for (i, v) in stats.current.iter().enumerate() {
                if i == author_index as usize {
                    prop_assert_eq!(v.blocks_produced, 1);
                } else {
                    prop_assert_eq!(v.blocks_produced, 0);
                }
            }
        }

        /// Author index out of range never panics and leaves stats untouched.
        #[test]
        fn out_of_range_author_no_panic(
            author_index in 6u16..1000,
            prior_slot in 0u32..100,
        ) {
            let config = Config::tiny(); // V=6
            let n = config.validators_count as usize;
            let mut stats = make_stats(n);
            let extrinsic = Extrinsic::default();

            update_statistics(
                &config, &mut stats, prior_slot, prior_slot + 1,
                author_index, &extrinsic, &[], &[], &BTreeMap::new(),
            );

            for v in &stats.current {
                prop_assert_eq!(v.blocks_produced, 0);
            }
        }

        /// Epoch rotation: when new_epoch > old_epoch, last gets old current
        /// and current resets (then author block added).
        #[test]
        fn epoch_rotation_preserves_previous(
            old_epoch in 0u32..100,
            author_index in 0u16..6,
        ) {
            let config = Config::tiny(); // E=12
            let n = config.validators_count as usize;
            let mut stats = make_stats(n);
            let extrinsic = Extrinsic::default();

            // First: produce a block in old_epoch
            let prior_slot = old_epoch * config.epoch_length;
            let slot1 = prior_slot + 1;
            update_statistics(
                &config, &mut stats, prior_slot, slot1,
                author_index, &extrinsic, &[], &[], &BTreeMap::new(),
            );
            let saved_blocks = stats.current[author_index as usize].blocks_produced;
            prop_assert_eq!(saved_blocks, 1);

            // Second: cross epoch boundary
            let new_epoch_slot = (old_epoch + 1) * config.epoch_length;
            update_statistics(
                &config, &mut stats, slot1, new_epoch_slot,
                author_index, &extrinsic, &[], &[], &BTreeMap::new(),
            );

            // last should have the pre-rotation value
            prop_assert_eq!(stats.last[author_index as usize].blocks_produced, 1);
            // current should be reset + the new block
            prop_assert_eq!(stats.current[author_index as usize].blocks_produced, 1);
        }

        /// Same-epoch updates accumulate without rotation.
        #[test]
        fn same_epoch_accumulates(
            num_blocks in 1u32..10,
            author_index in 0u16..6,
        ) {
            let config = Config::tiny(); // E=12
            let n = config.validators_count as usize;
            let mut stats = make_stats(n);
            let extrinsic = Extrinsic::default();

            for i in 0..num_blocks {
                update_statistics(
                    &config, &mut stats, i, i + 1,
                    author_index, &extrinsic, &[], &[], &BTreeMap::new(),
                );
            }

            prop_assert_eq!(
                stats.current[author_index as usize].blocks_produced,
                num_blocks
            );
            // No rotation happened, so last should be untouched
            prop_assert_eq!(stats.last[author_index as usize].blocks_produced, 0);
        }

        /// Ticket and preimage counts match extrinsic content.
        #[test]
        fn ticket_preimage_counts_match(
            num_tickets in 0usize..5,
            num_preimages in 0usize..5,
            preimage_size in 0usize..100,
            author_index in 0u16..6,
        ) {
            let config = Config::tiny();
            let n = config.validators_count as usize;
            let mut stats = make_stats(n);

            let extrinsic = Extrinsic {
                tickets: (0..num_tickets)
                    .map(|i| grey_types::header::TicketProof {
                        attempt: i as u8,
                        proof: vec![],
                    })
                    .collect(),
                preimages: (0..num_preimages)
                    .map(|i| (i as u32, vec![0u8; preimage_size]))
                    .collect(),
                ..Extrinsic::default()
            };

            update_statistics(
                &config, &mut stats, 0, 1, author_index, &extrinsic,
                &[], &[], &BTreeMap::new(),
            );

            let record = &stats.current[author_index as usize];
            prop_assert_eq!(record.tickets_introduced, num_tickets as u32);
            prop_assert_eq!(record.preimages_introduced, num_preimages as u32);
            prop_assert_eq!(record.preimage_bytes, (num_preimages * preimage_size) as u64);
        }
    }
}
