//! gp072 codec conformance: round-trip the shared `.bin` vectors.
//!
//! For each type/variant, decode the reference `.bin` with the GP codec and
//! re-encode it; the bytes must match exactly. This validates both the decoder
//! (it accepts the reference wire format) and the encoder (it reproduces it)
//! against `spec/tests/vectors/codec/`.

use grey_crypto::gp072_codec as gp;

const DIR: &str = "../../../spec/tests/vectors/codec";

/// Decode `bin` with `decode`, re-encode with `encode`, assert byte-equality.
fn roundtrip<T>(
    stem: &str,
    variant: &str,
    decode: impl Fn(&mut gp::Reader) -> Result<T, gp::DecodeError>,
    encode: impl Fn(&T) -> Vec<u8>,
) {
    let path = format!("{DIR}/{stem}.{variant}.bin");
    let bin = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let value =
        gp::decode_all(&bin, decode).unwrap_or_else(|e| panic!("{path}: decode failed: {e:?}"));
    let reencoded = encode(&value);
    assert_eq!(
        reencoded, bin,
        "{path}: re-encode does not match the reference bytes"
    );
}

/// Run a round-trip for both gp072 variants.
fn roundtrip_both<T>(
    stem: &str,
    decode: impl Fn(&mut gp::Reader) -> Result<T, gp::DecodeError> + Copy,
    encode: impl Fn(&T) -> Vec<u8> + Copy,
) {
    roundtrip(stem, "gp072_tiny", decode, encode);
    roundtrip(stem, "gp072_full", decode, encode);
}

#[test]
fn work_report_roundtrip() {
    roundtrip_both(
        "work_report",
        gp::decode_work_report,
        gp::encode_work_report,
    );
}

#[test]
fn work_item_roundtrip() {
    roundtrip_both("work_item", gp::decode_work_item, |it| {
        let mut b = Vec::new();
        gp::encode_work_item(it, &mut b);
        b
    });
}

#[test]
fn work_package_roundtrip() {
    roundtrip_both(
        "work_package",
        gp::decode_work_package,
        gp::encode_work_package,
    );
}

#[test]
fn refine_context_roundtrip() {
    roundtrip_both("refine_context", gp::decode_refinement_context, |c| {
        let mut b = Vec::new();
        gp::encode_refinement_context(c, &mut b);
        b
    });
}

#[test]
fn work_result_roundtrip() {
    // The `work_result_N` vectors encode a WorkDigest (JAM "work result"); the
    // N indexes the digest's result variant (0 = ok, 1 = an error).
    for stem in ["work_result_0", "work_result_1"] {
        roundtrip_both(stem, gp::decode_work_digest, |d| {
            let mut b = Vec::new();
            gp::encode_work_digest(d, &mut b);
            b
        });
    }
}
