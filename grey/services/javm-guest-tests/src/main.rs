#![cfg_attr(target_env = "javm", no_std)]
#![cfg_attr(target_env = "javm", no_main)]

#[cfg(target_env = "javm")]
javm_builtins::javm_entry!(javm_main);

#[cfg(target_env = "javm")]
#[no_mangle]
extern "C" fn javm_main(input_ptr: *const u8, input_len: usize) -> u64 {
    // GP register ABI: a0 = φ[7] = args address, a1 = φ[8] = args length.
    let input = unsafe { core::slice::from_raw_parts(input_ptr, input_len) };
    let output_len = javm_guest_tests::dispatch(input);
    let output_ptr = javm_guest_tests::output_buffer() as u64;
    (output_ptr << 32) | (output_len as u64)
}

#[cfg(not(target_env = "javm"))]
fn main() {}
