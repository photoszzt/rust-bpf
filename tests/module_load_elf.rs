#[macro_use]
extern crate lazy_static;
extern crate rust_bpf;

use rust_bpf::bpf_elf;
use rust_bpf::bpffs;
use std::process;

lazy_static! {
    static ref KERNEL_VERSION_46: u32 = 
    bpf_elf::kernel_version::kernel_version_from_release_string("4.6.0").unwrap();
    static ref KERNEL_VERSION_47: u32 = 
    bpf_elf::kernel_version::kernel_version_from_release_string("4.7.0").unwrap();
    static ref KERNEL_VERSION_48: u32 = 
    bpf_elf::kernel_version::kernel_version_from_release_string("4.8.0").unwrap();
    static ref KERNEL_VERSION_410: u32 = 
    bpf_elf::kernel_version::kernel_version_from_release_string("4.10.0").unwrap();
    static ref KERNEL_VERSION: u32 =
    bpf_elf::kernel_version::current_kernel_version().unwrap();
}

fn check_maps(b: &Module) {
    let mut expectedMaps = vec![
		"dummy_hash",
		"dummy_array",
		"dummy_prog_array",
		"dummy_perf",
		"dummy_array_custom",
    ];

    if KERNEL_VERSION >= KERNEL_VERSION_46 {
        expectedMaps.push("dummy_percpu_hash");
		expectedMaps.push("dummy_percpu_array");
		expectedMaps.push("dummy_stack_trace");
    } else {
        println!("kernel doesn't support percpu maps and stacktrace maps. Skipping...");
    }

    if KERNEL_VERSION >= KERNEL_VERSION_48 {
        expectedMaps.push("dummpy_cgroup_array");
    } else {
        println!("kernel doesn't support cgroup array maps. Skipping...");
    }
}

#[test]
fn test_module_load_elf() {
    let output = process::Command::new("./build")
    .output()
    .expect("fail to execute `./build`");
    println!("status: {}", output.status);
    println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    println!("stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(output.status.success());

    let dummy_elf = if KERNEL_VERSION > KERNEL_VERSION_410 {
        "./dummy-410.o"
    } else if kernel_version > KERNEL_VERSION_48 {
        "./dummy-48.o"
    } else if kernel_version > KERNEL_VERSION_46 {
        "./dummy-46.o"
    } else {
        "./dummy.o"
    };

    let mut sec_params = HashMap::new();
    let pin_path = Path::new("gobpf-test").join("testgroup1").to_string_lossy();
    sec_params.insert("maps/dummy_array_custom", bpf_elf::elf::SectionParams{
        pin_path.clone(),
        ..Default::default()
    })
    let mut close_options = HashMap::new();
    close_options.insert("maps/dummy_array_custom", bpf_elf::module::CloseOptions{
        unpin: true,
        pin_path,
    }); 
    let mut res = bpffs::fs::mounted();
    assert!(res.is_ok(), "Fail to mount bpf fs: {:?}", res); 
    let b = bpf_elf::module::new_module(dummy_elf);
    res = b.load();
    assert!(res.is_ok(), "Fail to load module: {:?}", res);
	checkMaps(b);
	checkProbes(b);
	checkCgroupProgs(b);
	checkSocketFilters(b);
	checkTracepointProgs(b);
}