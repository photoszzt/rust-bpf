extern crate bindgen;

use std::process;

fn main() {
    build_perf_event_bindings();
    build_bpf_bindings();
}

const PERF_WHITELIST_TYPES: &'static [&'static str] = &[
    "perf_type_id",
    "perf_event_attr",
    "perf_event_sample_format",
    "perf_event_mmap_page",
    "perf_sw_ids",
];

const PERF_WHITELIST_VARS: &'static [&'static str] = &["PERF_FLAG_FD_CLOEXEC"];

const BPF_WHITELIST_TYPES: &'static [&'static str] = &[
    "bpf_.*",
];

const BPF_WHITELIST_VARS: &'static [&'static str] = &[
    "LOG_BUF_SIZE",
    "BPF_.*",
    "MAX_BPF_REG",
    "MAX_BPF_ATTACH_TYPE",
    "__BPF_FUNC_MAPPER",
    "__BPF_ENUM_FN",
];

fn build_perf_event_bindings() {
    let mut bindings = bindgen::Builder::default().header("/usr/include/linux/perf_event.h");

    for ty in PERF_WHITELIST_TYPES {
        bindings = bindings.whitelist_type(ty);
    }

    for var in PERF_WHITELIST_VARS {
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
        .expect("Couldn't write perf_event bindings!");
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
                concat!(env!("CARGO_MANIFEST_DIR"), "/src/rustfmt.toml"),
                concat!(env!("CARGO_MANIFEST_DIR"), "/src/perf_event_bindings.rs"),
            ])
            .output()
            .expect("fail to execute `rustup run nightly rustfmt`");
        println!("status: {}", output.status);
        println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        println!("stderr: {}", String::from_utf8_lossy(&output.stderr));
        assert!(output.status.success());
    } else {
        println!(
            "
        The latest `rustfmt` is required to format the generated bindings. Install
            `rustfmt` with:
            $ rustup update nightly
            $ rustup run nightly cargo install -f rustfmt-nightly
            "
        );
    }
}

fn build_bpf_bindings() {
    let mut bindings = bindgen::Builder::default().header("src/bpf_elf/bpf.h");

    for ty in BPF_WHITELIST_TYPES {
        bindings = bindings.whitelist_type(ty);
    }

    for var in BPF_WHITELIST_VARS {
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
        .write_to_file("./src/bpf_elf/bpf_bindings.rs")
        .expect("Couldn't write bpf bindings!");
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
                concat!(env!("CARGO_MANIFEST_DIR"), "/src/rustfmt.toml"),
                concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_elf/bpf_bindings.rs"),
            ])
            .output()
            .expect("fail to execute `rustup run nightly rustfmt`");
        println!("status: {}", output.status);
        println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        println!("stderr: {}", String::from_utf8_lossy(&output.stderr));
        assert!(output.status.success());
    } else {
        println!(
            "
        The latest `rustfmt` is required to format the generated bindings. Install
            `rustfmt` with:
            $ rustup update nightly
            $ rustup run nightly cargo install -f rustfmt-nightly
            "
        );
    }
}
