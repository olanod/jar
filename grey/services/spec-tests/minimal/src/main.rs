//! Minimal no-op JAM service for spec accumulate test vectors.
//!
//! - **Refine**: returns immediately (identity)
//! - **Accumulate**: returns immediately (no host calls, no state changes)

#![cfg_attr(target_env = "javm", no_std)]
#![cfg_attr(target_env = "javm", no_main)]

#[cfg(target_env = "javm")]
mod service {
    use core::arch::global_asm;

    // Two GP entry points, selected by the transpiler's jump prologue:
    // `_start` (IC 0 = refine) and `accumulate` (IC 5). Both halt immediately
    // by returning to the halt address the kernel installed in ra (ω_0 =
    // 2^32 − 2^16); a0/a1 (ω_7/ω_8) still hold the args window, so refine
    // echoes its input as output.
    global_asm!(
        ".global _start",
        ".type _start, @function",
        "_start:",
        "ret", // djump to the halt address = halt (∎)
        ".global accumulate",
        ".type accumulate, @function",
        "accumulate:",
        "ret", // djump to the halt address = halt (∎)
    );

    #[panic_handler]
    fn panic(_: &core::panic::PanicInfo) -> ! {
        loop {}
    }
}

#[cfg(not(target_env = "javm"))]
fn main() {}
