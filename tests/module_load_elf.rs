#[macro_use]
extern crate lazy_static;
extern crate nix;
extern crate rust_bpf;
extern crate xmas_elf;

use nix::errno::Errno;
use nix::Error::Sys;
use rust_bpf::bpf_elf;
use rust_bpf::bpf_elf::elf::{EbpfMap, SectionParams};
use rust_bpf::bpf_elf::module::{CgroupProgram, CloseOptions, Kprobe, Module, SocketFilter,
                                TracepointProgram};
use rust_bpf::bpffs;
use std::collections::HashMap;
use std::path::Path;

lazy_static! {
    static ref KERNEL_VERSION_46: u32 =
        bpf_elf::kernel_version::kernel_version_from_release_string("4.6.0").unwrap();
    static ref KERNEL_VERSION_47: u32 =
        bpf_elf::kernel_version::kernel_version_from_release_string("4.7.0").unwrap();
    static ref KERNEL_VERSION_48: u32 =
        bpf_elf::kernel_version::kernel_version_from_release_string("4.8.0").unwrap();
    static ref KERNEL_VERSION_410: u32 =
        bpf_elf::kernel_version::kernel_version_from_release_string("4.10.0").unwrap();
    static ref KERNEL_VERSION: u32 = bpf_elf::kernel_version::current_kernel_version().unwrap();
}

fn contains_map(maps: &HashMap<String, EbpfMap>, name: &str) -> bool {
    for k in maps.keys() {
        if k == name {
            return true;
        }
    }
    false
}

fn contains_probe(probes: &HashMap<String, Kprobe>, name: &str) -> bool {
    for k in probes.keys() {
        if k == name {
            return true;
        }
    }
    false
}

fn contains_cgroupprog(cgroupprogs: &HashMap<String, CgroupProgram>, name: &str) -> bool {
    for k in cgroupprogs.keys() {
        if k == name {
            return true;
        }
    }
    false
}

fn contains_tracepointprog(
    tracepointprogs: &HashMap<String, TracepointProgram>,
    name: &str,
) -> bool {
    for k in tracepointprogs.keys() {
        if k == name {
            return true;
        }
    }
    false
}

fn contains_socketfilter(socketfilters: &HashMap<String, SocketFilter>, name: &str) -> bool {
    for k in socketfilters.keys() {
        if k == name {
            return true;
        }
    }
    false
}

fn check_maps(b: &Module) {
    let mut expected_maps = vec![
        "dummy_hash",
        "dummy_array",
        "dummy_prog_array",
        "dummy_perf",
        "dummy_array_custom",
    ];

    if *KERNEL_VERSION >= *KERNEL_VERSION_46 {
        expected_maps.push("dummy_percpu_hash");
        expected_maps.push("dummy_percpu_array");
        expected_maps.push("dummy_stack_trace");
    } else {
        println!("kernel doesn't support percpu maps and stacktrace maps. Skipping...");
    }

    if *KERNEL_VERSION >= *KERNEL_VERSION_48 {
        expected_maps.push("dummy_cgroup_array");
    } else {
        println!("kernel doesn't support cgroup array maps. Skipping...");
    }
    assert_eq!(
        b.maps.len(),
        expected_maps.len(),
        "unexpected number of maps. Got {}, expected {}",
        b.maps.len(),
        expected_maps.len()
    );
    for em in &expected_maps {
        assert!(contains_map(&b.maps, em), "map {} not found", em);
    }
}

fn check_probes(b: &Module) {
    let expected_probes = vec!["kprobe/dummy", "kretprobe/dummy"];
    assert_eq!(
        b.probes.len(),
        expected_probes.len(),
        "unexpected number of probes. Got {}, expected {}",
        b.probes.len(),
        expected_probes.len()
    );
    for ek in &expected_probes {
        assert!(contains_probe(&b.probes, ek), "probe {} not found", ek);
    }
}

fn check_cgroupprogs(b: &Module) {
    if *KERNEL_VERSION < *KERNEL_VERSION_410 {
        println!("kernel doesn't support cgroup-bpf. Skipping...");
        return;
    }
    let expected_cgroupprogs = vec!["cgroup/skb", "cgroup/sock"];
    assert_eq!(
        b.cgroup_programs.len(),
        expected_cgroupprogs.len(),
        "unexpected number of cgroup programs. Got {}, expected {}",
        b.cgroup_programs.len(),
        expected_cgroupprogs.len()
    );
    for e in &expected_cgroupprogs {
        assert!(
            contains_cgroupprog(&b.cgroup_programs, e),
            "cgroup program {} not found",
            e
        );
    }
}

fn check_tracepointprogs(b: &Module) {
    if *KERNEL_VERSION < *KERNEL_VERSION_47 {
        println!("kernel doesn't support bpf programs for tracepoints. Skipping...");
        return;
    }
    let expected_tracepoint = "tracepoint/raw_syscalls/sys_enter";
    assert_eq!(
        b.tracepoint_programs.len(),
        1,
        "unexpected number of tracepoint programs. Got {}, expected 1",
        b.tracepoint_programs.len()
    );
    assert!(
        contains_tracepointprog(&b.tracepoint_programs, expected_tracepoint),
        "tracepoint program {} not found",
        expected_tracepoint
    );
}

fn check_socketfilters(b: &Module) {
    let expected_socketfilter = "socket/dummy";
    assert_eq!(
        b.socket_filters.len(),
        1,
        "unexpected number of socket filters. Got {}, expected 1",
        b.socket_filters.len()
    );
    assert!(
        contains_socketfilter(&b.socket_filters, expected_socketfilter),
        "socket filter {} not found",
        expected_socketfilter
    );
}

fn check_pin_config(expected_path: &str) {
    let res = nix::sys::stat::stat(expected_path);
    match res {
        Ok(r) => if r.st_mode & nix::sys::stat::SFlag::S_IFMT.bits()
            != nix::sys::stat::SFlag::S_IFREG.bits()
        {
            panic!("pinned object {} not found", expected_path);
        },
        Err(e) => match e {
            Sys(Errno::ENOENT) => {
                panic!("pinned object {} not found", expected_path);
            }
            _ => (),
        },
    }
}

fn check_pin_config_cleanup(expected_path: &str) {
    let res = nix::sys::stat::stat(expected_path);
    match res {
        Ok(_) => (),
        Err(e) => match e {
            Sys(Errno::ENOENT) => (),
            _ => panic!("pinned object {} is not cleaned up", expected_path),
        },
    }
}

#[test]
fn test_module_load_elf() {
    let dummy_elf = if *KERNEL_VERSION > *KERNEL_VERSION_410 {
        "dummy-410.o"
    } else if *KERNEL_VERSION > *KERNEL_VERSION_48 {
        "dummy-48.o"
    } else if *KERNEL_VERSION > *KERNEL_VERSION_46 {
        "dummy-46.o"
    } else {
        "dummy.o"
    };

    let mut sec_params = HashMap::new();
    let pin_path = Path::new("gobpf-test").join("testgroup1");
    let pin_path_lossy = pin_path.to_string_lossy();
    sec_params.insert(
        "maps/dummy_array_custom".to_string(),
        SectionParams::new(pin_path_lossy.to_string()),
    );
    let mut close_options = HashMap::new();
    close_options.insert(
        "maps/dummy_array_custom".to_string(),
        CloseOptions::new(true, pin_path_lossy.to_string()),
    );
    let mut res = bpffs::mounted();
    assert!(res.is_ok(), "Fail to mount bpf fs: {:?}", res);
    let test_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests");
    let path = Path::new(test_dir).join(dummy_elf).canonicalize().unwrap();
    let buf = Module::read_from_file(path).unwrap();
    let mut b = Module::new(&buf).unwrap();
    res = b.load(&sec_params);
    assert!(res.is_ok(), "Fail to load module: {:?}", res);
    check_maps(&b);
    check_probes(&b);
    check_cgroupprogs(&b);
    check_socketfilters(&b);
    check_tracepointprogs(&b);
    let expected_pin_path = "/sys/fs/bpf/gobpf-test/testgroup1";
    check_pin_config(expected_pin_path);
    res = b.close_ext(Some(&close_options));
    assert!(res.is_ok(), "Fail to close: {:?}", res);
    check_pin_config_cleanup(expected_pin_path);
}
