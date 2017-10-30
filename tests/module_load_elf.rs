#[macro_use]
extern crate lazy_static;
extern crate rust_bpf;

use rust_bpf::bpf_elf;
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
    let kernel_version_res = bpf_elf::kernel_version::current_kernel_version()
    assert!(kernel_version_res.is_ok(), "Fail to get current kernel version: {}",
    kernel_version_res);
    let kernel_version = kernel_version_res.unwrap();

    let dummy_elf = if kernel_version > KERNEL_VERSION_410 {
        "./dummy-410.o"
    } else if kernel_version > KERNEL_VERSION_48 {
        "./dummy-48.o"
    } else if kernel_version > KERNEL_VERSION_46 {
        "./dummy-46.o"
    } else {
        "./dummy.o"
    };

    let sec_params = HashMap::new();
    let pin_path = Path::new("gobpf-test").join("testgroup1").to_string_lossy();
    sec_params.insert("maps/dummy_array_custom", bpf_elf::elf::SectionParams{
        pin_path.clone(),
        ..Default::default()
    })
}