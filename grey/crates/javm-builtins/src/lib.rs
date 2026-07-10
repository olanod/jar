//! Shared builtins for freestanding RISC-V service crates.
//!
//! Provides compiler builtins (memset, memcpy, memcmp), a panic handler,
//! and an entry point macro for JAVM/PolkaVM targets.
//!
//! All symbols are gated behind `cfg(target_os = "none")` — on host this
//! crate is empty. Services force-link it via `use javm_builtins as _;`.

#![no_std]

// -- Compiler builtins (freestanding targets only) ----------------------------

#[cfg(target_os = "none")]
mod builtins {
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn memset(dst: *mut u8, val: i32, n: usize) -> *mut u8 {
        let mut i = 0;
        while i < n {
            unsafe { *dst.add(i) = val as u8 };
            i += 1;
        }
        dst
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
        let mut i = 0;
        while i < n {
            unsafe { *dst.add(i) = *src.add(i) };
            i += 1;
        }
        dst
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
        let mut i = 0;
        while i < n {
            let a = unsafe { *s1.add(i) };
            let b = unsafe { *s2.add(i) };
            if a != b {
                return a as i32 - b as i32;
            }
            i += 1;
        }
        0
    }
}

// -- Panic handler (freestanding targets only) --------------------------------

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe {
        core::arch::asm!("li a0, 0xDEAD", "unimp", options(noreturn));
    }
}

// -- Entry point macro --------------------------------------------------------

/// Output window of a JAVM entry function: address + length of the output
/// bytes, left in ω_7/ω_8 (a0/a1) at halt per the GP invocation ABI.
///
/// Returned as a two-register aggregate (a0 = ptr, a1 = len under lp64e).
#[repr(C)]
pub struct EntryOutput {
    pub ptr: u64,
    pub len: u64,
}

/// Generate a `_start` entry point for JAVM and PolkaVM targets.
///
/// On JAVM: `_start` stashes the halt address the kernel installed in `ra`
/// (ω_0 = 2^32 − 2^16), calls the named function, and returns to it — a
/// dynamic jump to the halt address is the GP halt (∎). The entry function
/// takes `(input_ptr, input_len)` (a0/a1 = ω_7/ω_8) and returns
/// [`EntryOutput`], leaving the output window in a0/a1 for the host to read
/// as `μ[ω_7..+ω_8]`.
/// On PolkaVM: `_start` is `unimp` (polkavm uses exported functions directly).
/// On host: expands to nothing.
///
/// Usage: `javm_builtins::javm_entry!(my_bench_fn);`
#[macro_export]
macro_rules! javm_entry {
    ($fn_name:ident) => {
        #[cfg(target_env = "javm")]
        core::arch::global_asm!(
            ".global _start",
            "_start:",
            // GP register ABI: a0=φ[7]=args address, a1=φ[8]=args length —
            // passed straight through to the entry function.
            "mv s0, ra", // stash the halt address (call clobbers ra)
            concat!("call ", stringify!($fn_name)),
            "jr s0", // djump to the halt address = halt (∎)
        );
        #[cfg(target_env = "polkavm")]
        core::arch::global_asm!(".global _start", "_start:", "unimp",);
    };
}
