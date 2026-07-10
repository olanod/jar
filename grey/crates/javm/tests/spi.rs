//! SPI parser conformance against a real GP service preimage.
//!
//! The `gp072_*` accumulate vectors store service code as a standard-program
//! blob (metadata prefix + GP memory layout). This test pulls the real
//! `test-service` preimage out of a shared vector and asserts the parser
//! recovers exactly the fields an independent byte-level decode found.

use javm::spi::parse_standard_program;

/// Extract the first service preimage blob from a gp072 accumulate input.
fn service_preimage() -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../spec/tests/vectors/accumulate/",
        "accumulate_ready_queued_reports-1.input.gp072_tiny.json"
    );
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let json: serde_json::Value = serde_json::from_str(&text).expect("parse vector json");
    let hex = json["pre_state"]["accounts"][0]["data"]["preimage_blobs"][0]["blob"]
        .as_str()
        .expect("preimage blob hex");
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn parses_real_service_preimage() {
    let blob = service_preimage();
    let prog = parse_standard_program(&blob).expect("standard program parses");

    // Values independently decoded from the raw bytes:
    // E₃|o|=7360, E₃|w|=20, E₂z=2, E₃s=8192; code: jump_len=182, code_len=24792.
    assert_eq!(prog.ro_data.len(), 7360, "read-only data size");
    assert_eq!(prog.rw_data.len(), 20, "read-write data size");
    assert_eq!(prog.heap_pages, 2, "heap pages");
    assert_eq!(prog.stack_size, 8192, "stack size");
    assert_eq!(prog.code.jump_table.len(), 182, "jump table entries");
    assert_eq!(prog.code.code.len(), 24792, "code length");
    assert_eq!(
        prog.code.bitmask.len(),
        24792,
        "bitmask covers every code byte"
    );

    // The layout must fit the 32-bit address space with default (empty) args.
    let layout = prog.layout(&[]).expect("layout fits");
    assert_eq!(layout.ro.base, 1 << 16);
    assert!(layout.rw.base > layout.ro.base);
    assert_eq!(layout.registers[0], javm::PVM_HALT_ADDR);
}
