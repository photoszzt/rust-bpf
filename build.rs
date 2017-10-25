extern crate bindgen;

fn main() {
    build_ebpf_perf_bindings();
}

fn build_ebpf_perf_bindings() {
    // Get kernel header location from STD_KERNEL_PATH variable supplied by Makefile
    let std_kernel_path = match std::env::var("STD_KERNEL_PATH") {
        Ok(string) => string,
        Err(error) => {
            panic!(
                "Missing environment variable STD_KERNEL_PATH, run from Makefile: {:?}",
                error
            );
        }
    };

    // Tell clang where to find kernel headers by passing -I <include dir> switch
    let mut clang_arg: String = "-I".to_owned();
    clang_arg.push_str(&std_kernel_path);
    clang_arg.push_str(&"/include");

    let bindings = bindgen::Builder::default()
        .header("/usr/include/linux/perf_event.h")
        .clang_arg(clang_arg)
        .generate()
        .expect("Unable to generate perf_event.h bindings");

    bindings
        .write_to_file("./src/perf_event_bindings.rs")
        .expect("Couldn't write kernel bindings!");
}
