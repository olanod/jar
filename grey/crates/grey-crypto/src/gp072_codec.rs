//! Graypaper (gp072) wire-format encoders for the WorkReport family.
//!
//! grey's primary codec (`scale`) implements the jar1 wire format: fixed-width
//! `u32` count/length prefixes. The graypaper 0.7.2 codec (GP Appendix C) uses
//! a variable-length natural encoding (`encodeNat`, GP C.1) for counts,
//! lengths, and several numeric fields, and omits jar1-only fields. This module
//! provides just enough of the GP encoder to compute the GP `report_hash` that
//! gp072 guarantee signatures are taken over. Field layouts mirror
//! `spec/Jar/Codec.lean` (encodeWorkReport / encodeWorkDigest / encodeAvailSpec
//! / encodeRefinementContext / encodeWorkResult).

use grey_types::work::{AvailabilitySpec, RefinementContext, WorkDigest, WorkReport, WorkResult};

/// Variable-length natural encoding, GP eq (C.1). Encodes `x` into 1–9 bytes.
pub fn encode_nat(x: u64, buf: &mut Vec<u8>) {
    if x == 0 {
        buf.push(0);
        return;
    }
    let l = length_class(x);
    if l < 8 {
        // header = 2^8 − 2^(8−l) + ⌊x / 2^(8l)⌋
        let header = 256u64 - (256u64 >> l) + (x >> (8 * l as u32));
        buf.push(header as u8);
        encode_fixed(l, x % (1u64 << (8 * l as u32)), buf);
    } else {
        buf.push(0xFF);
        encode_fixed(8, x, buf);
    }
}

/// The GP length class of `x`: the number of little-endian bytes that follow
/// the header byte in `encode_nat` (0..=8).
fn length_class(x: u64) -> u8 {
    // Smallest l in 0..=7 with x < 2^(7·(l+1)); else 8.
    for l in 0u8..8 {
        if x < (1u64 << (7 * (l as u32 + 1))) {
            return l;
        }
    }
    8
}

/// `l` little-endian bytes of `x`.
fn encode_fixed(l: u8, x: u64, buf: &mut Vec<u8>) {
    for i in 0..l {
        buf.push((x >> (8 * i as u32)) as u8);
    }
}

/// Count-prefixed array: `encode_nat(len)` followed by each element.
fn encode_count_prefixed<T>(
    items: &[T],
    buf: &mut Vec<u8>,
    mut each: impl FnMut(&T, &mut Vec<u8>),
) {
    encode_nat(items.len() as u64, buf);
    for it in items {
        each(it, buf);
    }
}

/// Length-prefixed byte string, GP eq (C.4): `encode_nat(len) ⌢ data`.
fn encode_length_prefixed(data: &[u8], buf: &mut Vec<u8>) {
    encode_nat(data.len() as u64, buf);
    buf.extend_from_slice(data);
}

/// Encode a WorkResult, GP §C.4. `Ok` carries a length-prefixed blob; the error
/// variants are a single discriminant byte.
pub fn encode_work_result(r: &WorkResult, buf: &mut Vec<u8>) {
    match r {
        WorkResult::Ok(data) => {
            buf.push(0);
            encode_length_prefixed(data, buf);
        }
        WorkResult::OutOfGas => buf.push(1),
        WorkResult::Panic => buf.push(2),
        WorkResult::BadExports => buf.push(3),
        WorkResult::BadCode => buf.push(4),
        WorkResult::CodeOversize => buf.push(5),
    }
}

/// Encode an AvailabilitySpec, GP §C.4. Note: the GP wire format does NOT carry
/// grey's jar1-only `erasure_shards` field.
pub fn encode_avail_spec(a: &AvailabilitySpec, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&a.package_hash.0);
    encode_fixed(4, a.bundle_length as u64, buf);
    buf.extend_from_slice(&a.erasure_root.0);
    buf.extend_from_slice(&a.exports_root.0);
    encode_fixed(2, a.exports_count as u64, buf);
}

/// Encode a RefinementContext, GP §C.4.
pub fn encode_refinement_context(c: &RefinementContext, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&c.anchor.0);
    buf.extend_from_slice(&c.state_root.0);
    buf.extend_from_slice(&c.beefy_root.0);
    buf.extend_from_slice(&c.lookup_anchor.0);
    encode_fixed(4, c.lookup_anchor_timeslot as u64, buf);
    encode_count_prefixed(&c.prerequisites, buf, |h, b| b.extend_from_slice(&h.0));
}

/// Encode a WorkDigest, GP §C.4.
pub fn encode_work_digest(d: &WorkDigest, buf: &mut Vec<u8>) {
    encode_fixed(4, d.service_id as u64, buf);
    buf.extend_from_slice(&d.code_hash.0);
    buf.extend_from_slice(&d.payload_hash.0);
    encode_fixed(8, d.accumulate_gas, buf);
    encode_work_result(&d.result, buf);
    encode_nat(d.gas_used, buf);
    encode_nat(d.imports_count as u64, buf);
    encode_nat(d.extrinsics_count as u64, buf);
    encode_nat(d.extrinsics_size as u64, buf);
    encode_nat(d.exports_count as u64, buf);
}

/// Encode a WorkReport in the GP wire format, GP §C.4.
pub fn encode_work_report(wr: &WorkReport) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_avail_spec(&wr.package_spec, &mut buf);
    encode_refinement_context(&wr.context, &mut buf);
    encode_nat(wr.core_index as u64, &mut buf);
    buf.extend_from_slice(&wr.authorizer_hash.0);
    encode_nat(wr.auth_gas_used, &mut buf);
    encode_length_prefixed(&wr.auth_output, &mut buf);
    encode_count_prefixed(
        &wr.segment_root_lookup.iter().collect::<Vec<_>>(),
        &mut buf,
        |(k, v), b| {
            b.extend_from_slice(&k.0);
            b.extend_from_slice(&v.0);
        },
    );
    encode_count_prefixed(&wr.results, &mut buf, encode_work_digest);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_nat_small_values() {
        let mut b = Vec::new();
        encode_nat(0, &mut b);
        assert_eq!(b, vec![0]);
        b.clear();
        encode_nat(42, &mut b);
        assert_eq!(b, vec![42]);
        b.clear();
        encode_nat(127, &mut b);
        assert_eq!(b, vec![127]);
        // 128 needs the 1-byte class: header = 256 − 128 + 0 = 128, then [128].
        b.clear();
        encode_nat(128, &mut b);
        assert_eq!(b, vec![0x80, 0x80]);
        // 200: header = 128 + 0, then [200].
        b.clear();
        encode_nat(200, &mut b);
        assert_eq!(b, vec![0x80, 200]);
    }
}
