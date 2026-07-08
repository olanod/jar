//! Bootstrap no-op JAM service for spec accumulate test vectors.
//!
//! Identical behavior to `spec-minimal` but produces a distinct blob hash
//! (via a distinguishing .rodata byte) so that test vectors can use two
//! different service code hashes.
//!
//! - **Refine**: returns immediately (identity)
//! - **Accumulate**: returns immediately (no host calls, no state changes)

#![cfg_attr(target_env = "javm", no_std)]
#![cfg_attr(target_env = "javm", no_main)]

#[cfg(target_env = "javm")]
mod service {
    use core::arch::global_asm;

    // Two GP entry points, selected by the transpiler's jump prologue:
    // `_start` (IC 0 = refine) and `accumulate` (IC 5). Both are no-ops that
    // REPLY immediately. A distinguishing constant in `_start` makes the blob
    // hash differ from `minimal`.
    global_asm!(
        ".global _start",
        ".type _start, @function",
        "_start:",
        "li t0, 0x42", // distinguish from minimal blob
        "li t0, 0",    // ecalli(0) = REPLY (IPC slot 0)
        "ecall",
        "unimp", // trap if resumed
        ".global accumulate",
        ".type accumulate, @function",
        "accumulate:",
        "li t0, 0", // ecalli(0) = REPLY (IPC slot 0)
        "ecall",
        "unimp", // trap if resumed
    );

    #[panic_handler]
    fn panic(_: &core::panic::PanicInfo) -> ! {
        loop {}
    }
}

#[cfg(not(target_env = "javm"))]
fn main() {}
