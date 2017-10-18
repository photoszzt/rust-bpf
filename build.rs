extern crate bindgen;

fn main() {
    build_ebpf_perf_bindings();
    build_bcc_bindings();
}

fn build_ebpf_perf_bindings() {
    // Get kernel header location from STD_KERNEL_PATH variable supplied by Makefile
    let std_kernel_path = match std::env::var("STD_KERNEL_PATH") {
        Ok(string) => string,
        Err(error) => {
            panic!("Missing environment variable STD_KERNEL_PATH, run from Makefile: {:?}", error);
        }
    };

    // Tell clang where to find kernel headers by passing -I <include dir> switch
    let mut clang_arg: String = "-I".to_owned();
    clang_arg.push_str(&std_kernel_path);
    clang_arg.push_str(&"/include");

    // Generate bindings for headers listed in kernel-wrapper.h
    let bindings = bindgen::Builder::default()
        .header("bpf.h")
        .clang_arg(clang_arg.clone())
        .generate()
        .expect("Unable to generate bpf.h bindings");

    bindings
        .write_to_file("./src/bpf_bindings.rs")
        .expect("Couldn't write kernel bindings!");

    let bindings = bindgen::Builder::default()
        .header("/usr/include/linux/perf_event.h")
        .clang_arg(clang_arg)
        .generate()
        .expect("Unable to generate perf_event.h bindings");

    bindings
        .write_to_file("./src/perf_event_bindings.rs")
        .expect("Couldn't write kernel bindings!");
}

fn build_bcc_bindings() {
    let mut clang_arg: String = "-I".to_owned();
    clang_arg.push_str(&"/usr/include/bcc/compat/");

    let bindings = bindgen::Builder::default()
        .header("bcc.h")
        .clang_arg(clang_arg)
        .generate()
        .expect("Unable to generate bcc bindings");

    bindings
        .write_to_file("./src/bcc_bindings.rs")
        .expect("Couldn't write bcc bindings!");
}
