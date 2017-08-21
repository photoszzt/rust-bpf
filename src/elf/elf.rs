extern crate syscall;
extern crate libc;
extern crate elf;
extern crate byteorder;
// use syscall::nr::BPF;

use bpf_bindings;
use std::io::Error;
use std::default::Default;
use std::path::PathBuf;
use bpffs;
use byteorder::{LittleEndian, ReadBytesExt};


const USE_CURRENT_KERNEL_VERSION : u64 = 0xFFFFFFFE;

pub struct Module {
    file_name: String,
    file: elf::File,
}

#[no_mangle]
pub unsafe extern fn ptr_to_u64(
    mut ptr : *mut ::std::os::raw::c_void
    ) -> usize {
    ptr as (usize)
}

// pub unsafe fn bpf_apply_relocation(fd: i32,
//                                    insn: &mut bpf_bindings::bpf_insn) {
//     insn.imm = fd;
//     insn.src_reg = bpf_bindings::BPF_PSEUDO_MAP_FD;
// }

// pub unsafe fn bpf_create_map(map_type: bpf_bindings::bpf_map_type,
//                              key_size: u32,
//                              value_size: u32,
//                              max_entries: u32) {
//     let mut attr = bpf_bindings::bpf_attr {
//         __bindgen_anon_1: Default::default(),
//         __bindgen_anon_2: Default::default(),
//         __bindgen_anon_3: Default::default(),
//         __bindgen_anon_4: Default::default(),
//         __bindgen_anon_5: Default::default(),
//         bindgen_union_field: Default::default(),
//     };
//     *attr.__bindgen_anon_1.as_mut() = bpf_bindings::bpf_attr__bindgen_ty_1 {
//         map_type: map_type as u32,
//         key_size,
//         value_size,
//         max_entries,
//         map_flags: 0,
//     };
//     let ret = syscall(BPF as i64,
//                       bpf_bindings::bpf_cmd::BPF_MAP_CREATE,
//                       &attr as *const _ as usize,
//                       ::std::mem::size_of::<bpf_bindings::bpf_attr>());
//     if let Some(raw_os_err) = Error::last_os_error().raw_os_error() {
//         if raw_os_err == libc::EPERM {
//             // When EPERM is returned, two reasons are possible:
//             // 1. user has no permissions for bpf()
//             // 2. user has insufficent rlimit for locked memory
//             // Unfortunately, there is no api to inspect the current usage of locked
//             // mem for the user, so an accurate calculation of how much memory to lock
//             // for this new program is difficult to calculate. As a hack, bump the limit
//             // to unlimited. If program load fails again, return the error.
//             let mut rl = libc::rlimit {
//                 rlim_cur: 0,
//                 rlim_max: 0,
//             };
//             if libc::getrlimit(libc::RLIMIT_MEMLOCK, &rl as *mut _) == 0 {
//                 rl.rlim_max = RLIM_INFINITY;
//                 rl.rlim_cur = rl.rlim_max;
//                 if libc::setrlimit(libc::RLIMIT_MEMLOCK, &rl as *mut _) {
//
//                 }
//             }
//         }
//     }
// }

#[no_mangle]
pub unsafe fn elf_read_license(module: &Module) -> Result<String, Error> {
    match module.file.get_section("license") {
        Some(s) => {
            String::from_utf8(s.data)
        }
        None => {
            Err(format!("Failed to look up license section")),
        }
    }
}

pub unsafe fn elf_read_version(module: &Module) -> Result<u32, Error> {
    match module.file.get_section("version") {
        Some(s) => {
            if s.data.length() != 4 {
                return Err("version is not a __u32")
            }
            let mut buf = &s.data;
            buf.read_u32::<LittleEndian>()
        }
        None => {
            Err(format!("Failed to look up version section")),
        }
    }
}

pub unsafe fn prepare_bpffs(namespace: &str, name: &str) {
    mount()
}

#[no_mangle]
pub unsafe fn load(module: &mut Module) {
    let file = if module.file_name != "" {
        let path = PathBuf::from(module.file_name);
        match elf::File::open_path(&path) {
            Ok(f) => f,
            Err(e) => panic!("Error: {:?}", e),
        }
    } else {
        module.file
    };
}
