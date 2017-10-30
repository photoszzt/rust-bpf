extern crate bindgen;

use std::process;

fn main() {
    build_ebpf_perf_bindings();
}

const WHITELIST_TYPES: &'static [&'static str] = &[
    "perf_type_id",
    "perf_event_attr",
    "perf_event_sample_format",
    "perf_event_mmap_page",
    "perf_sw_ids",
];

const WHITELIST_VARS: &'static [&'static str] = &[
    "PERF_FLAG_FD_CLOEXEC",
];

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

    let mut bindings = bindgen::Builder::default()
        .header("/usr/include/linux/perf_event.h")
        .clang_arg(clang_arg);

    for ty in WHITELIST_TYPES {
        bindings = bindings.whitelist_type(ty);
    }

    for var in WHITELIST_VARS {
        bindings = bindings.whitelist_var(var);
    }

    bindings = bindings
        .derive_debug(true)
        .impl_debug(true)
        .derive_default(true)
        .derive_partialeq(true)
        .impl_partialeq(true)
        .derive_eq(true)
        .derive_partialord(true)
        .derive_ord(true)
        .derive_hash(true)
        .rustfmt_bindings(false);

    let builder = bindings
        .generate()
        .expect("Unable to generate perf_event.h bindings");

    builder
        .write_to_file("./src/perf_event_bindings.rs")
        .expect("Couldn't write kernel bindings!");
    let have_working_rustfmt = process::Command::new("rustup")
        .args(&["run", "nightly", "rustfmt", "--version"])
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .status()
        .ok()
        .map_or(false, |status| status.success());

    if have_working_rustfmt {
        let output = process::Command::new("rustup")
            .args(&[
                  "run",
                  "nightly",
                  "rustfmt",
                  "--config-path",
                  concat!(env!("CARGO_MANIFEST_DIR"), "/rustfmt.toml"),
                  concat!(env!("CARGO_MANIFEST_DIR"), "/src/perf_event_bindings.rs"),
            ])
            .output()
            .expect("fail to execute `rustup run nightly rustfmt`");;
        println!("status: {}", output.status);
        println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        println!("stderr: {}", String::from_utf8_lossy(&output.stderr));
        assert!(output.status.success());
    } else {
        println!("
        The latest `rustfmt` is required to format the generated bindings. Install
            `rustfmt` with:
            $ rustup update nightly
            $ rustup run nightly cargo install -f rustfmt-nightly
            ");
    }
}
