/// Dump native code for both grey and polkavm fib programs for disassembly comparison.
use grey_bench::*;

fn main() {
    // Grey recompiler
    let blob = grey_fib_blob(FIB_N);
    let pvm = grey_pvm::recompiler::initialize_program_recompiled(&blob, &[], 100_000_000).unwrap();
    let code = pvm.native_code_bytes();
    std::fs::write("/tmp/grey_fib.bin", code).unwrap();
    eprintln!("grey: {} bytes -> /tmp/grey_fib.bin", code.len());

    // PolkaVM compiler
    let pvm_blob = polkavm_fib_blob(FIB_N);
    let mut config = polkavm::Config::new();
    config.set_backend(Some(polkavm::BackendKind::Compiler));
    config.set_allow_experimental(true);
    config.set_sandboxing_enabled(false);
    config.set_sandbox(Some(polkavm::SandboxKind::Generic));
    let engine = polkavm::Engine::new(&config).unwrap();
    let mut mc = polkavm::ModuleConfig::new();
    mc.set_gas_metering(Some(polkavm::GasMeteringKind::Sync));
    let module = polkavm::Module::new(&engine, &mc, pvm_blob.into()).unwrap();
    if let Some(blob) = module.machine_code() {
        std::fs::write("/tmp/polkavm_fib.bin", blob).unwrap();
        eprintln!("polkavm: {} bytes -> /tmp/polkavm_fib.bin", blob.len());
    } else {
        eprintln!("polkavm: no machine code available (interpreter only?)");
    }
}
