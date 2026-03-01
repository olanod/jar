//! Block state transition implementation (eq 4.1, 4.5-4.20).

use crate::TransitionError;
use grey_types::constants::*;
use grey_types::header::Block;
use grey_types::state::{PendingReport, RecentBlockInfo, State, ValidatorRecord};
use grey_types::Hash;

// Derived constants
const TOTAL_VALIDATORS_USIZE: usize = TOTAL_VALIDATORS as usize;
const _TOTAL_CORES_USIZE: usize = TOTAL_CORES as usize;
const REPORT_TIMEOUT: u32 = AVAILABILITY_TIMEOUT;
const MINIMUM_GUARANTORS: usize = 2; // Minimum credential count for guarantees
const AUTH_POOL_SIZE: usize = MAX_AUTH_POOL_ITEMS;

/// Apply a block to produce the posterior state.
///
/// The transition follows the dependency graph in eq 4.5-4.20:
/// 1. Timekeeping: τ' = HT
/// 2. Judgments: ψ' from ED
/// 3. Recent history: β' from prior state
/// 4. Safrole: γ', κ', λ', ι', η' from consensus
/// 5. Reporting/assurance: ρ' from EA, EG
/// 6. Accumulation: δ', χ', ι', ϕ' from R (available reports)
/// 7. Statistics: π' from block activity
/// 8. Authorization: α' from ϕ'
pub fn apply(state: &State, block: &Block) -> Result<State, TransitionError> {
    let header = &block.header;
    let extrinsic = &block.extrinsic;

    // Basic validation
    validate_header(state, header)?;

    // Clone state for mutation
    let mut new_state = state.clone();

    // Step 1: Timekeeping (eq 6.1)
    new_state.timeslot = header.timeslot;

    // Step 2: Process judgments/disputes (Section 10)
    apply_judgments(&mut new_state, &extrinsic.disputes);

    // Step 3: Clear disputed pending reports (eq 10.15)
    clear_disputed_reports(&mut new_state, &extrinsic.disputes);

    // Step 4: Process availability assurances (Section 11.2)
    let available_reports = process_assurances(&mut new_state, &extrinsic.assurances, header.timeslot);

    // Step 5: Process work report guarantees (Section 11.4)
    process_guarantees(&mut new_state, &extrinsic.guarantees, header.timeslot)?;

    // Step 6: Update recent block history (Section 7)
    update_recent_history(&mut new_state, header, &extrinsic.guarantees);

    // Step 7: Update validator statistics (Section 13)
    update_statistics(&mut new_state, state.timeslot, header, extrinsic, &available_reports);

    // Step 8: Process preimages (Section 12.4)
    process_preimages(&mut new_state, &extrinsic.preimages, header.timeslot);

    // Step 9: Authorization pool rotation (Section 8)
    rotate_auth_pool(&mut new_state, &extrinsic.guarantees);

    Ok(new_state)
}

/// Validate block header against current state.
fn validate_header(
    state: &State,
    header: &grey_types::header::Header,
) -> Result<(), TransitionError> {
    // Timeslot must advance (eq 6.1: τ' > τ)
    if header.timeslot <= state.timeslot {
        return Err(TransitionError::InvalidTimeslot {
            block_slot: header.timeslot,
            prior_slot: state.timeslot,
        });
    }

    // Author index must be valid
    if header.author_index as usize >= state.current_validators.len() {
        return Err(TransitionError::InvalidAuthorIndex(header.author_index));
    }

    Ok(())
}

/// Process disputes extrinsic to update judgments (Section 10, eq 10.16-10.19).
fn apply_judgments(
    state: &mut State,
    disputes: &grey_types::header::DisputesExtrinsic,
) {
    let supermajority = (TOTAL_VALIDATORS * 2 / 3) + 1;
    let one_third = TOTAL_VALIDATORS / 3;

    // Process verdicts (eq 10.12-10.19)
    for verdict in &disputes.verdicts {
        let positive_count: usize = verdict
            .judgments
            .iter()
            .filter(|j| j.is_valid)
            .count();

        if positive_count >= supermajority as usize {
            // Good: supermajority says valid
            state.judgments.good.insert(verdict.report_hash);
        } else if positive_count == 0 {
            // Bad: all say invalid
            state.judgments.bad.insert(verdict.report_hash);
        } else if positive_count <= one_third as usize {
            // Wonky: about one-third say valid
            state.judgments.wonky.insert(verdict.report_hash);
        }
    }

    // Process culprits — add offending validator keys (eq 10.19)
    for culprit in &disputes.culprits {
        state.judgments.offenders.insert(culprit.validator_key);
    }

    // Process faults — add offending validator keys (eq 10.19)
    for fault in &disputes.faults {
        state.judgments.offenders.insert(fault.validator_key);
    }
}

/// Clear pending reports that have been judged non-good (eq 10.15).
fn clear_disputed_reports(
    state: &mut State,
    disputes: &grey_types::header::DisputesExtrinsic,
) {
    let supermajority = (TOTAL_VALIDATORS * 2 / 3) + 1;

    for verdict in &disputes.verdicts {
        let positive_count: usize = verdict
            .judgments
            .iter()
            .filter(|j| j.is_valid)
            .count();

        // If not supermajority good, clear from pending
        if positive_count < supermajority as usize {
            for slot in state.pending_reports.iter_mut() {
                if let Some(_pending) = slot {
                    if grey_crypto::blake2b_256(&[]) == verdict.report_hash {
                        // Simplified: in practice, hash the serialized report
                        *slot = None;
                    }
                }
            }
        }
    }
}

/// Process availability assurances (Section 11.2, eq 11.10-11.17).
///
/// Returns the list of work reports that became available.
fn process_assurances(
    state: &mut State,
    assurances: &grey_types::header::AssurancesExtrinsic,
    current_timeslot: grey_types::Timeslot,
) -> Vec<grey_types::work::WorkReport> {
    let threshold = (TOTAL_VALIDATORS * 2 / 3) + 1;
    let mut available = Vec::new();

    // Count assurances per core (eq 11.16)
    let num_cores = state.pending_reports.len();
    let mut assurance_counts = vec![0u32; num_cores];

    for assurance in assurances {
        for (core, &assured) in assurance.bitfield.iter().enumerate() {
            if assured && core < num_cores {
                assurance_counts[core] += 1;
            }
        }
    }

    // Determine which reports become available
    for (core, count) in assurance_counts.iter().enumerate() {
        if *count >= threshold as u32 {
            if let Some(pending) = &state.pending_reports[core] {
                available.push(pending.report.clone());
            }
        }
    }

    // Clear available and timed-out reports from pending (eq 11.17)
    for (core, slot) in state.pending_reports.iter_mut().enumerate() {
        if let Some(pending) = slot {
            let is_available = assurance_counts.get(core).copied().unwrap_or(0) >= threshold as u32;
            let is_timed_out = current_timeslot >= pending.timeslot + REPORT_TIMEOUT;

            if is_available || is_timed_out {
                *slot = None;
            }
        }
    }

    available
}

/// Process work report guarantees (Section 11.4, eq 11.23-11.42).
fn process_guarantees(
    state: &mut State,
    guarantees: &grey_types::header::GuaranteesExtrinsic,
    current_timeslot: grey_types::Timeslot,
) -> Result<(), TransitionError> {
    for guarantee in guarantees {
        let report = &guarantee.report;

        // Validate: core index must be valid
        if report.core_index as usize >= state.pending_reports.len() {
            return Err(TransitionError::InvalidExtrinsic(
                format!("invalid core index: {}", report.core_index),
            ));
        }

        // Validate: core slot must be empty
        let core = report.core_index as usize;
        if state.pending_reports[core].is_some() {
            return Err(TransitionError::InvalidExtrinsic(
                format!("core {} already has pending report", core),
            ));
        }

        // Validate: minimum number of guarantors (eq 11.24-11.26)
        if guarantee.credentials.len() < MINIMUM_GUARANTORS {
            return Err(TransitionError::InvalidExtrinsic(
                format!(
                    "insufficient guarantors: {} < {}",
                    guarantee.credentials.len(),
                    MINIMUM_GUARANTORS
                ),
            ));
        }

        // Place report in pending slot
        state.pending_reports[core] = Some(PendingReport {
            report: report.clone(),
            timeslot: current_timeslot,
        });
    }

    Ok(())
}

/// Update recent block history (Section 7, eq 7.5-7.8).
fn update_recent_history(
    state: &mut State,
    _header: &grey_types::header::Header,
    guarantees: &grey_types::header::GuaranteesExtrinsic,
) {
    // Build reported packages map from guarantees (eq 7.8 `p`)
    let mut reported_packages = std::collections::BTreeMap::new();
    for guarantee in guarantees {
        let report = &guarantee.report;
        // Map: work-package hash → authorizer hash
        reported_packages.insert(report.availability.package_hash, report.authorizer_hash);
    }

    // Compute header hash
    let header_hash = grey_crypto::blake2b_256(&[]); // Simplified: should hash serialized header

    // Append new block info (eq 7.8)
    let info = RecentBlockInfo {
        header_hash,
        state_root: Hash::ZERO, // Will be corrected in next block (eq 7.5)
        accumulation_root: Hash::ZERO, // Simplified: compute from β'B
        reported_packages,
    };

    state.recent_blocks.headers.push(info);

    // Keep only the last H entries
    while state.recent_blocks.headers.len() > RECENT_HISTORY_SIZE {
        state.recent_blocks.headers.remove(0);
    }
}

/// Update validator activity statistics (Section 13, eq 13.3-13.5).
fn update_statistics(
    state: &mut State,
    prior_timeslot: u32,
    header: &grey_types::header::Header,
    extrinsic: &grey_types::header::Extrinsic,
    _available_reports: &[grey_types::work::WorkReport],
) {
    let old_epoch = prior_timeslot / EPOCH_LENGTH as u32;
    let new_epoch = header.timeslot / EPOCH_LENGTH as u32;

    // Epoch transition: rotate statistics (eq 13.4)
    if new_epoch > old_epoch {
        state.statistics.last = state.statistics.current.clone();
        state.statistics.current = vec![ValidatorRecord::default(); TOTAL_VALIDATORS_USIZE];
    }

    // Ensure current has enough entries
    while state.statistics.current.len() < TOTAL_VALIDATORS_USIZE {
        state.statistics.current.push(ValidatorRecord::default());
    }

    let author = header.author_index as usize;
    if author < state.statistics.current.len() {
        // Block author: increment blocks_produced (eq 13.5)
        state.statistics.current[author].blocks_produced += 1;

        // Tickets introduced
        state.statistics.current[author].tickets_introduced +=
            extrinsic.tickets.len() as u32;

        // Preimages introduced
        state.statistics.current[author].preimages_introduced +=
            extrinsic.preimages.len() as u32;

        // Preimage total bytes
        let preimage_bytes: u64 = extrinsic
            .preimages
            .iter()
            .map(|(_, data)| data.len() as u64)
            .sum();
        state.statistics.current[author].preimage_bytes += preimage_bytes;
    }

    // Assurances: each validator that submitted an assurance
    for assurance in &extrinsic.assurances {
        let idx = assurance.validator_index as usize;
        if idx < state.statistics.current.len() {
            state.statistics.current[idx].assurances_made += 1;
        }
    }

    // Guarantees: each validator that guaranteed a report
    for guarantee in &extrinsic.guarantees {
        for (validator_idx, _sig) in &guarantee.credentials {
            let idx = *validator_idx as usize;
            if idx < state.statistics.current.len() {
                state.statistics.current[idx].reports_guaranteed += 1;
            }
        }
    }
}

/// Process preimage submissions (Section 12.4, eq 12.35-12.38).
fn process_preimages(
    state: &mut State,
    preimages: &grey_types::header::PreimagesExtrinsic,
    current_timeslot: grey_types::Timeslot,
) {
    for (service_id, data) in preimages {
        if let Some(account) = state.services.get_mut(service_id) {
            let hash = grey_crypto::blake2b_256(data);
            // Store the preimage if not already present
            account.preimage_lookup.entry(hash).or_insert_with(|| data.clone());
            // Update preimage info with current timeslot
            account
                .preimage_info
                .entry((hash, data.len() as u32))
                .or_default()
                .push(current_timeslot);
            account.preimage_count += 1;
            account.last_activity = current_timeslot;
        }
    }
}

/// Rotate authorization pool from queue (Section 8, eq 8.2-8.3).
fn rotate_auth_pool(
    state: &mut State,
    guarantees: &grey_types::header::GuaranteesExtrinsic,
) {
    let timeslot = state.timeslot;

    for core in 0..state.auth_pool.len() {
        // Check if a guarantee was submitted for this core
        let has_guarantee = guarantees.iter().any(|g| g.report.core_index as usize == core);

        if has_guarantee {
            // Remove used authorizer from pool (simplified: remove first)
            if !state.auth_pool[core].is_empty() {
                state.auth_pool[core].remove(0);
            }
        }

        // Rotate in new authorizer from queue
        if core < state.auth_queue.len() {
            let queue = &state.auth_queue[core];
            let queue_idx = timeslot as usize % queue.len().max(1);
            if queue_idx < queue.len() {
                let new_auth = queue[queue_idx];
                // Add to pool if not already full
                if state.auth_pool[core].len() < AUTH_POOL_SIZE {
                    state.auth_pool[core].push(new_auth);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grey_types::header::*;
    use grey_types::state::*;
    use grey_types::validator::ValidatorKey;
    use grey_types::*;
    use std::collections::BTreeMap;

    fn make_default_state() -> State {
        let validators: Vec<ValidatorKey> = (0..TOTAL_VALIDATORS)
            .map(|_| ValidatorKey::default())
            .collect();

        State {
            auth_pool: vec![vec![]; TOTAL_CORES as usize],
            recent_blocks: RecentBlocks {
                headers: vec![],
                accumulation_log: vec![],
            },
            accumulation_outputs: vec![],
            safrole: SafroleState {
                pending_keys: vec![],
                ring_root: BandersnatchRingRoot::default(),
                seal_key_series: SealKeySeries::Fallback(vec![]),
                ticket_accumulator: vec![],
            },
            services: BTreeMap::new(),
            entropy: [Hash::ZERO; 4],
            pending_validators: validators.clone(),
            current_validators: validators.clone(),
            previous_validators: validators,
            pending_reports: vec![None; TOTAL_CORES as usize],
            timeslot: 0,
            auth_queue: vec![vec![]; TOTAL_CORES as usize],
            privileged_services: PrivilegedServices::default(),
            judgments: Judgments::default(),
            statistics: ValidatorStatistics {
                current: vec![ValidatorRecord::default(); TOTAL_VALIDATORS_USIZE],
                last: vec![],
                core_stats: vec![],
                service_stats: BTreeMap::new(),
            },
            accumulation_queue: vec![],
            accumulation_history: vec![],
        }
    }

    fn make_empty_block(timeslot: Timeslot) -> Block {
        Block {
            header: Header {
                parent_hash: Hash::ZERO,
                state_root: Hash::ZERO,
                extrinsic_hash: Hash::ZERO,
                timeslot,
                epoch_marker: None,
                winning_tickets_marker: None,
                offenders_marker: vec![],
                author_index: 0,
                vrf_signature: BandersnatchSignature::default(),
                seal: BandersnatchSignature::default(),
            },
            extrinsic: Extrinsic {
                tickets: vec![],
                disputes: DisputesExtrinsic::default(),
                preimages: vec![],
                assurances: vec![],
                guarantees: vec![],
            },
        }
    }

    #[test]
    fn test_apply_block_advances_timeslot() {
        let state = make_default_state();
        let block = make_empty_block(1);
        let new_state = apply(&state, &block).unwrap();
        assert_eq!(new_state.timeslot, 1);
    }

    #[test]
    fn test_timeslot_must_advance() {
        let state = make_default_state();
        let block = make_empty_block(0); // same timeslot
        assert!(apply(&state, &block).is_err());
    }

    #[test]
    fn test_invalid_author_index() {
        let state = make_default_state();
        let mut block = make_empty_block(1);
        block.header.author_index = TOTAL_VALIDATORS as u16; // out of range
        assert!(apply(&state, &block).is_err());
    }

    #[test]
    fn test_judgments_good_verdict() {
        let state = make_default_state();
        let hash = Hash([1u8; 32]);

        // Create a verdict with supermajority positive judgments
        let supermajority = (TOTAL_VALIDATORS * 2 / 3) + 1;
        let judgments: Vec<Judgment> = (0..supermajority)
            .map(|i| Judgment {
                is_valid: true,
                validator_index: i as u16,
                signature: Ed25519Signature::default(),
            })
            .collect();

        let mut block = make_empty_block(1);
        block.extrinsic.disputes.verdicts.push(Verdict {
            report_hash: hash,
            age: 0,
            judgments,
        });

        let new_state = apply(&state, &block).unwrap();
        assert!(new_state.judgments.good.contains(&hash));
    }

    #[test]
    fn test_judgments_bad_verdict() {
        let state = make_default_state();
        let hash = Hash([2u8; 32]);

        // All judgments say invalid
        let mut block = make_empty_block(1);
        block.extrinsic.disputes.verdicts.push(Verdict {
            report_hash: hash,
            age: 0,
            judgments: vec![], // 0 positive = bad
        });

        let new_state = apply(&state, &block).unwrap();
        assert!(new_state.judgments.bad.contains(&hash));
    }

    #[test]
    fn test_statistics_block_produced() {
        let state = make_default_state();
        let mut block = make_empty_block(1);
        block.header.author_index = 5;

        let new_state = apply(&state, &block).unwrap();
        assert_eq!(new_state.statistics.current[5].blocks_produced, 1);
    }

    #[test]
    fn test_statistics_epoch_rotation() {
        let mut state = make_default_state();
        state.statistics.current[0].blocks_produced = 10;

        // Block in a new epoch
        let block = make_empty_block(EPOCH_LENGTH as u32 + 1);

        let new_state = apply(&state, &block).unwrap();
        // Old stats should be in `last`
        assert_eq!(new_state.statistics.last[0].blocks_produced, 10);
        // Current should be reset (except for this block's author)
        assert_eq!(new_state.statistics.current[0].blocks_produced, 1);
    }

    #[test]
    fn test_recent_history_updated() {
        let state = make_default_state();
        let block = make_empty_block(1);

        let new_state = apply(&state, &block).unwrap();
        assert_eq!(new_state.recent_blocks.headers.len(), 1);
    }

    #[test]
    fn test_recent_history_capped() {
        let mut state = make_default_state();
        // Fill with H entries
        for i in 0..RECENT_HISTORY_SIZE {
            state.recent_blocks.headers.push(RecentBlockInfo {
                header_hash: Hash([i as u8; 32]),
                state_root: Hash::ZERO,
                accumulation_root: Hash::ZERO,
                reported_packages: BTreeMap::new(),
            });
        }
        state.timeslot = RECENT_HISTORY_SIZE as u32;

        let block = make_empty_block(RECENT_HISTORY_SIZE as u32 + 1);
        let new_state = apply(&state, &block).unwrap();
        assert_eq!(new_state.recent_blocks.headers.len(), RECENT_HISTORY_SIZE);
    }

    #[test]
    fn test_preimage_processing() {
        let mut state = make_default_state();
        let service_id: ServiceId = 1;
        state.services.insert(
            service_id,
            ServiceAccount {
                code_hash: Hash::ZERO,
                balance: 1000,
                min_accumulate_gas: 0,
                min_on_transfer_gas: 0,
                storage: BTreeMap::new(),
                preimage_lookup: BTreeMap::new(),
                preimage_info: BTreeMap::new(),
                free_storage_offset: 0,
                total_footprint: 0,
                accumulation_counter: 0,
                last_accumulation: 0,
                last_activity: 0,
                preimage_count: 0,
            },
        );

        let mut block = make_empty_block(1);
        let preimage_data = b"hello world".to_vec();
        block.extrinsic.preimages.push((service_id, preimage_data.clone()));

        let new_state = apply(&state, &block).unwrap();
        let account = new_state.services.get(&service_id).unwrap();
        assert_eq!(account.preimage_count, 1);
        let hash = grey_crypto::blake2b_256(&preimage_data);
        assert!(account.preimage_lookup.contains_key(&hash));
    }
}
