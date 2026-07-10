//! Graypaper (gp072) wire-format codec (GP Appendix C).
//!
//! grey's primary codec (`scale`) implements the jar1 wire format: fixed-width
//! `u32` count/length prefixes. The graypaper 0.7.2 codec uses a variable-length
//! natural encoding (`encodeNat`, GP C.1) for counts, lengths, and several
//! numeric fields, raw `ceil(C/8)` assurance bitfields, no-count-prefix verdict
//! judgments, and it omits jar1-only fields. This module provides encode+decode
//! for the types covered by `spec/tests/vectors/codec/`, mirroring
//! `spec/Jar/Codec.lean`; it computes the GP `report_hash` gp072 guarantee
//! signatures are taken over, and round-trips the shared codec vectors.
//!
//! Some layouts are param-dependent (assurance bitfield = `ceil(core_count/8)`,
//! verdict judgment count = validator supermajority), so those functions take a
//! [`Config`].

use grey_types::config::Config;
use grey_types::header::{
    Assurance, Culprit, DisputesExtrinsic, Fault, Guarantee, Judgment, TicketProof, Verdict,
};
use grey_types::work::{
    AvailabilitySpec, ImportSegment, RefinementContext, WorkDigest, WorkItem, WorkPackage,
    WorkReport, WorkResult,
};
use grey_types::{Ed25519PublicKey, Ed25519Signature, Hash};

/// Fixed length of a Bandersnatch ring-VRF ticket proof (bytes).
const RING_VRF_PROOF_LEN: usize = 784;

/// A GP-codec decode failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Ran out of bytes.
    Eof,
    /// A discriminant byte was outside the valid range.
    BadDiscriminant(u8),
    /// Trailing bytes remained after decoding a top-level value.
    Trailing(usize),
}

/// Cursor over a GP-encoded byte slice.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.pos + n > self.data.len() {
            return Err(DecodeError::Eof);
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    /// `l` little-endian bytes as a u64.
    pub fn fixed(&mut self, l: usize) -> Result<u64, DecodeError> {
        let bytes = self.take(l)?;
        let mut v = 0u64;
        for (i, &b) in bytes.iter().enumerate() {
            v |= (b as u64) << (8 * i);
        }
        Ok(v)
    }

    /// Variable-length natural, inverse of [`encode_nat`] (GP C.1).
    pub fn nat(&mut self) -> Result<u64, DecodeError> {
        let header = self.u8()?;
        // Length class l = number of leading 1 bits in the header.
        let l = header.leading_ones() as usize;
        if l == 0 {
            return Ok(header as u64);
        }
        if l >= 8 {
            // 0xFF prefix + 8 LE bytes.
            return self.fixed(8);
        }
        // header low bits carry the top of x; l following bytes carry the rest.
        let low = self.fixed(l)?;
        let top = (header as u64) & ((1u64 << (8 - l)) - 1);
        Ok(low | (top << (8 * l)))
    }

    pub fn hash(&mut self) -> Result<Hash, DecodeError> {
        Ok(Hash(self.array32()?))
    }

    fn array32(&mut self) -> Result<[u8; 32], DecodeError> {
        let mut a = [0u8; 32];
        a.copy_from_slice(self.take(32)?);
        Ok(a)
    }

    fn ed25519_sig(&mut self) -> Result<Ed25519Signature, DecodeError> {
        let mut a = [0u8; 64];
        a.copy_from_slice(self.take(64)?);
        Ok(Ed25519Signature(a))
    }

    fn ed25519_key(&mut self) -> Result<Ed25519PublicKey, DecodeError> {
        Ok(Ed25519PublicKey(self.array32()?))
    }

    fn bool(&mut self) -> Result<bool, DecodeError> {
        Ok(self.u8()? != 0)
    }

    /// Raw fixed-length byte blob (no prefix).
    fn raw(&mut self, n: usize) -> Result<Vec<u8>, DecodeError> {
        Ok(self.take(n)?.to_vec())
    }

    /// A fixed-count array (no count prefix), `n` elements.
    fn fixed_array<T>(
        &mut self,
        n: usize,
        mut each: impl FnMut(&mut Self) -> Result<T, DecodeError>,
    ) -> Result<Vec<T>, DecodeError> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(each(self)?);
        }
        Ok(out)
    }

    /// A varnat-length-prefixed byte blob.
    pub fn length_prefixed(&mut self) -> Result<Vec<u8>, DecodeError> {
        let n = self.nat()? as usize;
        Ok(self.take(n)?.to_vec())
    }

    /// A varnat-count-prefixed array, decoding each element with `each`.
    pub fn count_prefixed<T>(
        &mut self,
        mut each: impl FnMut(&mut Self) -> Result<T, DecodeError>,
    ) -> Result<Vec<T>, DecodeError> {
        let n = self.nat()? as usize;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(each(self)?);
        }
        Ok(out)
    }

    fn finish(self) -> Result<(), DecodeError> {
        if self.pos == self.data.len() {
            Ok(())
        } else {
            Err(DecodeError::Trailing(self.data.len() - self.pos))
        }
    }
}

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

/// Encode an ImportSegment: `tree_root(32) ⌢ index(fixed2)`.
fn encode_import_segment(seg: &ImportSegment, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&seg.hash.0);
    encode_fixed(2, seg.index as u64, buf);
}

/// Encode a WorkItem, GP §C.4 (canonical JAM layout): service_id, code_hash,
/// refine gas, accumulate gas, export_count (fixed2), payload
/// (length-prefixed), imports (count-prefixed tree_root+index_f2), extrinsics
/// (count-prefixed hash+len_f4).
pub fn encode_work_item(item: &WorkItem, buf: &mut Vec<u8>) {
    encode_fixed(4, item.service_id as u64, buf);
    buf.extend_from_slice(&item.code_hash.0);
    encode_fixed(8, item.gas_limit, buf);
    encode_fixed(8, item.accumulate_gas_limit, buf);
    encode_fixed(2, item.exports_count as u64, buf);
    encode_length_prefixed(&item.payload, buf);
    encode_count_prefixed(&item.imports, buf, encode_import_segment);
    encode_count_prefixed(&item.extrinsics, buf, |(h, n), b| {
        b.extend_from_slice(&h.0);
        encode_fixed(4, *n as u64, b);
    });
}

/// Encode a WorkPackage, GP §C.4 (canonical JAM layout): auth_code_host,
/// auth_code_hash, context, authorization, authorizer_config, items.
pub fn encode_work_package(wp: &WorkPackage) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_fixed(4, wp.auth_code_host as u64, &mut buf);
    buf.extend_from_slice(&wp.auth_code_hash.0);
    encode_refinement_context(&wp.context, &mut buf);
    encode_length_prefixed(&wp.authorization, &mut buf);
    encode_length_prefixed(&wp.authorizer_config, &mut buf);
    encode_count_prefixed(&wp.items, &mut buf, encode_work_item);
    buf
}

// --- Decoders (inverses of the encoders above) ------------------------------

pub fn decode_work_result(r: &mut Reader) -> Result<WorkResult, DecodeError> {
    match r.u8()? {
        0 => Ok(WorkResult::Ok(r.length_prefixed()?)),
        1 => Ok(WorkResult::OutOfGas),
        2 => Ok(WorkResult::Panic),
        3 => Ok(WorkResult::BadExports),
        4 => Ok(WorkResult::BadCode),
        5 => Ok(WorkResult::CodeOversize),
        d => Err(DecodeError::BadDiscriminant(d)),
    }
}

pub fn decode_avail_spec(r: &mut Reader) -> Result<AvailabilitySpec, DecodeError> {
    Ok(AvailabilitySpec {
        package_hash: r.hash()?,
        bundle_length: r.fixed(4)? as u32,
        erasure_root: r.hash()?,
        exports_root: r.hash()?,
        exports_count: r.fixed(2)? as u16,
        // Not on the GP wire; a round-trip re-encode never emits it.
        erasure_shards: 0,
    })
}

pub fn decode_refinement_context(r: &mut Reader) -> Result<RefinementContext, DecodeError> {
    Ok(RefinementContext {
        anchor: r.hash()?,
        state_root: r.hash()?,
        beefy_root: r.hash()?,
        lookup_anchor: r.hash()?,
        lookup_anchor_timeslot: r.fixed(4)? as u32,
        prerequisites: r.count_prefixed(|r| r.hash())?,
    })
}

pub fn decode_work_digest(r: &mut Reader) -> Result<WorkDigest, DecodeError> {
    Ok(WorkDigest {
        service_id: r.fixed(4)? as u32,
        code_hash: r.hash()?,
        payload_hash: r.hash()?,
        accumulate_gas: r.fixed(8)?,
        result: decode_work_result(r)?,
        gas_used: r.nat()?,
        imports_count: r.nat()? as u16,
        extrinsics_count: r.nat()? as u16,
        extrinsics_size: r.nat()? as u32,
        exports_count: r.nat()? as u16,
    })
}

pub fn decode_work_report(r: &mut Reader) -> Result<WorkReport, DecodeError> {
    Ok(WorkReport {
        package_spec: decode_avail_spec(r)?,
        context: decode_refinement_context(r)?,
        core_index: r.nat()? as u16,
        authorizer_hash: r.hash()?,
        auth_gas_used: r.nat()?,
        auth_output: r.length_prefixed()?,
        segment_root_lookup: r
            .count_prefixed(|r| Ok((r.hash()?, r.hash()?)))?
            .into_iter()
            .collect(),
        results: r.count_prefixed(decode_work_digest)?,
    })
}

fn decode_import_segment(r: &mut Reader) -> Result<ImportSegment, DecodeError> {
    Ok(ImportSegment {
        hash: r.hash()?,
        index: r.fixed(2)? as u16,
    })
}

pub fn decode_work_item(r: &mut Reader) -> Result<WorkItem, DecodeError> {
    Ok(WorkItem {
        service_id: r.fixed(4)? as u32,
        code_hash: r.hash()?,
        gas_limit: r.fixed(8)?,
        accumulate_gas_limit: r.fixed(8)?,
        exports_count: r.fixed(2)? as u16,
        payload: r.length_prefixed()?,
        imports: r.count_prefixed(decode_import_segment)?,
        extrinsics: r.count_prefixed(|r| Ok((r.hash()?, r.fixed(4)? as u32)))?,
    })
}

pub fn decode_work_package(r: &mut Reader) -> Result<WorkPackage, DecodeError> {
    let auth_code_host = r.fixed(4)? as u32;
    let auth_code_hash = r.hash()?;
    let context = decode_refinement_context(r)?;
    let authorization = r.length_prefixed()?;
    let authorizer_config = r.length_prefixed()?;
    let items = r.count_prefixed(decode_work_item)?;
    Ok(WorkPackage {
        auth_code_host,
        auth_code_hash,
        context,
        authorization,
        authorizer_config,
        items,
    })
}

// --- Extrinsic sub-types (GP §C.4) ------------------------------------------

/// TicketProof: `attempt(u8) ⌢ proof(784 raw)`.
pub fn encode_ticket_proof(t: &TicketProof, buf: &mut Vec<u8>) {
    buf.push(t.attempt);
    buf.extend_from_slice(&t.proof);
}

pub fn decode_ticket_proof(r: &mut Reader) -> Result<TicketProof, DecodeError> {
    Ok(TicketProof {
        attempt: r.u8()?,
        proof: r.raw(RING_VRF_PROOF_LEN)?,
    })
}

/// PreimagesExtrinsic: count-prefixed `(service_id(fixed4), length-prefixed blob)`.
pub fn encode_preimages(ps: &[(u32, Vec<u8>)], buf: &mut Vec<u8>) {
    encode_count_prefixed(ps, buf, |(sid, blob), b| {
        encode_fixed(4, *sid as u64, b);
        encode_length_prefixed(blob, b);
    });
}

pub fn decode_preimages(r: &mut Reader) -> Result<Vec<(u32, Vec<u8>)>, DecodeError> {
    r.count_prefixed(|r| Ok((r.fixed(4)? as u32, r.length_prefixed()?)))
}

/// Guarantee: `WorkReport ⌢ timeslot(fixed4) ⌢ count-prefixed (validator_index(fixed2), sig(64))`.
pub fn encode_guarantee(g: &Guarantee, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&encode_work_report(&g.report));
    encode_fixed(4, g.timeslot as u64, buf);
    encode_count_prefixed(&g.credentials, buf, |(vi, sig), b| {
        encode_fixed(2, *vi as u64, b);
        b.extend_from_slice(&sig.0);
    });
}

pub fn decode_guarantee(r: &mut Reader) -> Result<Guarantee, DecodeError> {
    Ok(Guarantee {
        report: decode_work_report(r)?,
        timeslot: r.fixed(4)? as u32,
        credentials: r.count_prefixed(|r| Ok((r.fixed(2)? as u16, r.ed25519_sig()?)))?,
    })
}

/// Assurance: `anchor(32) ⌢ bitfield(ceil(C/8) raw) ⌢ validator_index(fixed2) ⌢ sig(64)`.
pub fn encode_assurance(a: &Assurance, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&a.anchor.0);
    buf.extend_from_slice(&a.bitfield);
    encode_fixed(2, a.validator_index as u64, buf);
    buf.extend_from_slice(&a.signature.0);
}

pub fn decode_assurance(r: &mut Reader, cfg: &Config) -> Result<Assurance, DecodeError> {
    Ok(Assurance {
        anchor: r.hash()?,
        bitfield: r.raw(cfg.avail_bitfield_bytes())?,
        validator_index: r.fixed(2)? as u16,
        signature: r.ed25519_sig()?,
    })
}

/// Judgment: `is_valid(u8) ⌢ validator_index(fixed2) ⌢ sig(64)`.
fn encode_judgment(j: &Judgment, buf: &mut Vec<u8>) {
    buf.push(j.is_valid as u8);
    encode_fixed(2, j.validator_index as u64, buf);
    buf.extend_from_slice(&j.signature.0);
}

fn decode_judgment(r: &mut Reader) -> Result<Judgment, DecodeError> {
    Ok(Judgment {
        is_valid: r.bool()?,
        validator_index: r.fixed(2)? as u16,
        signature: r.ed25519_sig()?,
    })
}

/// Verdict: `report_hash(32) ⌢ age(fixed4) ⌢ judgments(fixed-count array)`. The
/// judgment count is not on the wire — it is the validator supermajority.
fn encode_verdict(v: &Verdict, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&v.report_hash.0);
    encode_fixed(4, v.age as u64, buf);
    for j in &v.judgments {
        encode_judgment(j, buf);
    }
}

fn decode_verdict(r: &mut Reader, cfg: &Config) -> Result<Verdict, DecodeError> {
    Ok(Verdict {
        report_hash: r.hash()?,
        age: r.fixed(4)? as u32,
        judgments: r.fixed_array(cfg.super_majority() as usize, decode_judgment)?,
    })
}

/// Culprit: `report_hash(32) ⌢ validator_key(32) ⌢ sig(64)`.
fn encode_culprit(c: &Culprit, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&c.report_hash.0);
    buf.extend_from_slice(&c.validator_key.0);
    buf.extend_from_slice(&c.signature.0);
}

fn decode_culprit(r: &mut Reader) -> Result<Culprit, DecodeError> {
    Ok(Culprit {
        report_hash: r.hash()?,
        validator_key: r.ed25519_key()?,
        signature: r.ed25519_sig()?,
    })
}

/// Fault: `report_hash(32) ⌢ is_valid(u8) ⌢ validator_key(32) ⌢ sig(64)`.
fn encode_fault(f: &Fault, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&f.report_hash.0);
    buf.push(f.is_valid as u8);
    buf.extend_from_slice(&f.validator_key.0);
    buf.extend_from_slice(&f.signature.0);
}

fn decode_fault(r: &mut Reader) -> Result<Fault, DecodeError> {
    Ok(Fault {
        report_hash: r.hash()?,
        is_valid: r.bool()?,
        validator_key: r.ed25519_key()?,
        signature: r.ed25519_sig()?,
    })
}

/// DisputesExtrinsic: count-prefixed verdicts ⌢ culprits ⌢ faults.
pub fn encode_disputes(d: &DisputesExtrinsic, buf: &mut Vec<u8>) {
    encode_count_prefixed(&d.verdicts, buf, encode_verdict);
    encode_count_prefixed(&d.culprits, buf, encode_culprit);
    encode_count_prefixed(&d.faults, buf, encode_fault);
}

pub fn decode_disputes(r: &mut Reader, cfg: &Config) -> Result<DisputesExtrinsic, DecodeError> {
    Ok(DisputesExtrinsic {
        verdicts: r.count_prefixed(|r| decode_verdict(r, cfg))?,
        culprits: r.count_prefixed(decode_culprit)?,
        faults: r.count_prefixed(decode_fault)?,
    })
}

/// TicketsExtrinsic: count-prefixed array of TicketProof.
pub fn encode_tickets(tickets: &[TicketProof], buf: &mut Vec<u8>) {
    encode_count_prefixed(tickets, buf, encode_ticket_proof);
}

pub fn decode_tickets(r: &mut Reader) -> Result<Vec<TicketProof>, DecodeError> {
    r.count_prefixed(decode_ticket_proof)
}

/// GuaranteesExtrinsic: count-prefixed array of Guarantee.
pub fn encode_guarantees(gs: &[Guarantee], buf: &mut Vec<u8>) {
    encode_count_prefixed(gs, buf, encode_guarantee);
}

pub fn decode_guarantees(r: &mut Reader) -> Result<Vec<Guarantee>, DecodeError> {
    r.count_prefixed(decode_guarantee)
}

/// AssurancesExtrinsic: count-prefixed array of Assurance.
pub fn encode_assurances(a: &[Assurance], buf: &mut Vec<u8>) {
    encode_count_prefixed(a, buf, encode_assurance);
}

pub fn decode_assurances(r: &mut Reader, cfg: &Config) -> Result<Vec<Assurance>, DecodeError> {
    r.count_prefixed(|r| decode_assurance(r, cfg))
}

/// Decode a full byte slice with `decode`, requiring all bytes to be consumed.
pub fn decode_all<T>(
    data: &[u8],
    decode: impl FnOnce(&mut Reader) -> Result<T, DecodeError>,
) -> Result<T, DecodeError> {
    let mut r = Reader::new(data);
    let v = decode(&mut r)?;
    r.finish()?;
    Ok(v)
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

    #[test]
    fn nat_roundtrips() {
        for x in [
            0u64,
            1,
            42,
            127,
            128,
            200,
            255,
            256,
            16383,
            16384,
            1 << 20,
            1 << 35,
            u32::MAX as u64,
            u64::MAX,
        ] {
            let mut b = Vec::new();
            encode_nat(x, &mut b);
            let mut r = Reader::new(&b);
            assert_eq!(r.nat().unwrap(), x, "nat roundtrip failed for {x}");
        }
    }
}
