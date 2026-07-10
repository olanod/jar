//! Differential fuzz target: interpreter vs recompiler.
//!
//! Wraps random bytes into a valid PVM blob, runs on both the interpreter
//! and recompiler backends via the kernel, and asserts that both produce
//! identical results (full register file at halt, gas consumed, and error
//! kind including page-fault addresses).
//!
//! The memory image deliberately contains a read-only page and unmapped
//! gaps so permission and fault-address semantics are exercised, and the
//! input selects the ISA mode (Jar vs Conformance) so the opcode-3 split is
//! covered too. This catches semantic differences between the two PVM
//! backends that targeted unit tests might miss.

#![no_main]

use javm::cap::Access;
use javm::program::{build_blob, CapEntryType, CapManifestEntry};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    // Input layout:
    //   byte 0: heap pages (1-4)
    //   byte 1: flags — bit 0: ISA mode (0 = Jar, 1 = Conformance)
    //                   bit 1: gap-bearing layout (unmapped pages between caps)
    //   rest:   interleaved (bitmask, code) byte pairs — the fuzzer controls
    //           instruction boundaries independently of opcode values (a
    //           parity-derived bitmask would make every even opcode, i.e.
    //           most loads/stores/jumps, unreachable as an instruction start).
    let heap_pages = (data[0] as u32 % 4) + 1;
    let isa_mode = if data[1] & 1 == 0 {
        javm::IsaMode::Jar
    } else {
        javm::IsaMode::Conformance
    };
    let gapped = data[1] & 2 != 0;
    let code: Vec<u8> = data[2..].to_vec();
    if code.is_empty() {
        return;
    }
    // Derive a SELF-CONSISTENT bitmask by walking the code as an instruction
    // stream: each opcode gets its canonical operand length, so the bitmask
    // marks exactly the instruction starts and skip() is unambiguous. A
    // parity- or byte-derived bitmask instead produces malformed streams
    // (multi-operand opcodes marked 1 byte, operand bytes marked as starts)
    // whose decode divergence is a separate, pre-existing concern — this
    // fuzzer targets the *semantic* parity of well-formed programs (control
    // flow, memory permissions, gas), where consensus bugs live.
    let bitmask = well_formed_bitmask(&code);
    let code = &code[..];

    let blob = build_fuzz_blob(code, &bitmask, heap_pages, gapped);

    let gas = 50_000u64; // Small gas limit for fast iteration

    let interp_result = run_backend(&blob, gas, javm::PvmBackend::ForceInterpreter, isa_mode);
    let recomp_result = run_backend(&blob, gas, javm::PvmBackend::ForceRecompiler, isa_mode);

    match (&interp_result, &recomp_result) {
        (Ok((iv, ig)), Ok((rv, rg))) => {
            assert_eq!(iv, rv, "register file mismatch: interp={iv:?} recomp={rv:?}");
            assert_eq!(ig, rg, "gas mismatch: interp={ig} recomp={rg}");
        }
        // Both erroring (panic/oog/pagefault) is fine — just check they agree
        (Err(ie), Err(re)) => {
            assert_eq!(ie, re, "error mismatch: interp={ie:?} recomp={re:?}");
        }
        _ => {
            panic!("backend disagree: interp={interp_result:?} recomp={recomp_result:?}");
        }
    }
});

/// Canonical operand-byte count for an opcode category. The exact value need
/// not match the true variable-length encoding — both backends compute skip
/// from the same bitmask, so any self-consistent choice yields identical
/// decoding. Sensible widths keep operands (immediates/offsets) meaningful.
fn operand_len(category: javm::instruction::InstructionCategory) -> usize {
    use javm::instruction::InstructionCategory::*;
    match category {
        NoArgs => 0,
        OneImm => 4,
        OneOffset => 4,
        OneRegExtImm => 9,
        TwoImm => 8,
        OneRegOneImm => 5,
        OneRegTwoImm => 9,
        OneRegImmOffset => 6,
        TwoReg => 1,
        TwoRegOneImm => 5,
        TwoRegOneOffset => 5,
        TwoRegTwoImm => 6,
        ThreeReg => 2,
    }
}

/// Walk `code` as an instruction stream and return a bitmask that marks each
/// instruction start (opcode byte) and leaves operand bytes unmarked. Invalid
/// opcode bytes are treated as single-byte instructions so both backends reach
/// the same panic position.
fn well_formed_bitmask(code: &[u8]) -> Vec<u8> {
    let mut bitmask = vec![0u8; code.len()];
    let mut pc = 0;
    while pc < code.len() {
        bitmask[pc] = 1;
        let step = match javm::instruction::Opcode::from_byte(code[pc]) {
            Some(op) => 1 + operand_len(op.category()),
            None => 1,
        };
        pc += step;
    }
    bitmask
}

/// Build a JAR blob whose memory image exercises the permission model:
///
/// ```text
/// page 0:            stack (RW)
/// page 1 or 2:       ro data (RO)          — page 2 leaves a gap when `gapped`
/// next or +1:        rw data (RW)          — +1 leaves another gap when `gapped`
/// following pages:   heap (RW, zero-filled)
/// ```
fn build_fuzz_blob(code: &[u8], bitmask: &[u8], heap_pages: u32, gapped: bool) -> Vec<u8> {
    // Code sub-blob: jump_len(4) + entry_size(1) + code_len(4) + code + packed bitmask.
    let mut code_data = Vec::new();
    code_data.extend_from_slice(&0u32.to_le_bytes()); // empty jump table
    code_data.push(1u8);
    code_data.extend_from_slice(&(code.len() as u32).to_le_bytes());
    code_data.extend_from_slice(code);
    let mut packed = vec![0u8; code.len().div_ceil(8)];
    for (i, &b) in bitmask.iter().enumerate() {
        if b != 0 {
            packed[i / 8] |= 1 << (i % 8);
        }
    }
    code_data.extend_from_slice(&packed);

    let step = if gapped { 2 } else { 1 };
    let ro_page = step; // page 1, or 2 with a gap at 1
    let rw_page = ro_page + step;
    let heap_page = rw_page + step;
    let total_pages = heap_page + heap_pages;

    // Derive RO/RW init contents from the code so the fuzzer controls what
    // guest reads observe.
    let ro_init: Vec<u8> = code.iter().rev().cloned().take(64).collect();
    let rw_init: Vec<u8> = code.iter().cloned().take(64).collect();

    let mut data_section = code_data.clone();
    let mut caps = vec![
        CapManifestEntry {
            cap_index: 64,
            cap_type: CapEntryType::Code,
            base_page: 0,
            page_count: 0,
            init_access: Access::RO,
            data_offset: 0,
            data_len: code_data.len() as u32,
        },
        CapManifestEntry {
            cap_index: 65, // stack
            cap_type: CapEntryType::Data,
            base_page: 0,
            page_count: 1,
            init_access: Access::RW,
            data_offset: 0,
            data_len: 0,
        },
    ];
    let ro_offset = data_section.len() as u32;
    data_section.extend_from_slice(&ro_init);
    caps.push(CapManifestEntry {
        cap_index: 66, // ro data
        cap_type: CapEntryType::Data,
        base_page: ro_page,
        page_count: 1,
        init_access: Access::RO,
        data_offset: ro_offset,
        data_len: ro_init.len() as u32,
    });
    let rw_offset = data_section.len() as u32;
    data_section.extend_from_slice(&rw_init);
    caps.push(CapManifestEntry {
        cap_index: 67, // rw data
        cap_type: CapEntryType::Data,
        base_page: rw_page,
        page_count: 1,
        init_access: Access::RW,
        data_offset: rw_offset,
        data_len: rw_init.len() as u32,
    });
    caps.push(CapManifestEntry {
        cap_index: 68, // heap
        cap_type: CapEntryType::Data,
        base_page: heap_page,
        page_count: heap_pages,
        init_access: Access::RW,
        data_offset: 0,
        data_len: 0,
    });

    build_blob(total_pages, 64, 4096, &caps, &data_section)
}

#[derive(Debug, PartialEq, Eq)]
enum PvmError {
    Panic,
    OutOfGas,
    PageFault(u32),
    InitFailed,
}

fn run_backend(
    blob: &[u8],
    gas: u64,
    backend: javm::PvmBackend,
    isa_mode: javm::IsaMode,
) -> Result<([u64; 13], u64), PvmError> {
    let mut kernel = match javm::kernel::InvocationKernel::new_with_backend_and_mode(
        blob, &[], gas, backend, isa_mode,
    ) {
        Ok(k) => k,
        Err(_) => return Err(PvmError::InitFailed),
    };

    loop {
        match kernel.run() {
            javm::kernel::KernelResult::Halt => {
                // GP halt convention: output lives in registers/memory, so
                // compare the full register file at halt.
                let vm = kernel.vm_arena.vm(kernel.active_vm);
                let regs: [u64; 13] = core::array::from_fn(|i| vm.reg(i));
                return Ok((regs, gas - kernel.active_gas()));
            }
            javm::kernel::KernelResult::Panic => return Err(PvmError::Panic),
            javm::kernel::KernelResult::OutOfGas => return Err(PvmError::OutOfGas),
            javm::kernel::KernelResult::PageFault(a) => {
                return Err(PvmError::PageFault(a));
            }
            javm::kernel::KernelResult::ProtocolCall { slot } => {
                // Service protocol calls so both backends' continuations match
                // real-host behavior. The recompiler inlines the GAS host call
                // (slot 1): φ[7] = remaining gas, φ[8] unchanged, continue —
                // so it never returns ProtocolCall{1}. To keep the interpreter
                // (which does return it) in lockstep, resume with the same
                // register effect. Other protocol caps are not inlined by
                // either backend, so a fixed deterministic resume keeps them
                // identical.
                if slot == 1 {
                    let (gas, phi8) = (kernel.active_gas(), kernel.active_reg(8));
                    kernel.resume_protocol_call(gas, phi8);
                } else {
                    kernel.resume_protocol_call(0, 0);
                }
            }
        }
    }
}
