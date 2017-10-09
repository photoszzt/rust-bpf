extern crate syscall;
extern crate libc;
extern crate elf;
extern crate byteorder;

use bpf_bindings::*;
use bpf::*;
use kernel_version::*;
use std::io::Error;
use std::default::Default;
use std::path::PathBuf;
use std::io::Cursor;
use bpffs;
use self::byteorder::LittleEndian;
use self::byteorder::ReadBytesExt;


const USE_CURRENT_KERNEL_VERSION : u64 = 0xFFFFFFFE;

pub struct Module {
    file_name: String,
    file: elf::File,
}

pub fn bpf_create_map(map_type: bpf_map_type,
                      key_size: u32,
                      value_size: u32,
                      max_entries: u32) -> i32 {
    let attr = bpf_attr::bpf_attr_map_create(map_type as u32,
                                             key_size,
                                             value_size,
                                             max_entries,
                                             0);
    let ret = unsafe {
        syscall!(BPF, bpf_cmd::BPF_MAP_CREATE,
                 &attr as *const _ as usize,
                 ::std::mem::size_of::<bpf_attr>())
    };
    if let Some(raw_os_err) = Error::last_os_error().raw_os_error() {
        if raw_os_err == libc::EPERM {
            // When EPERM is returned, two reasons are possible:
            // 1. user has no permissions for bpf()
            // 2. user has insufficent rlimit for locked memory
            // Unfortunately, there is no api to inspect the current usage of locked
            // mem for the user, so an accurate calculation of how much memory to lock
            // for this new program is difficult to calculate. As a hack, bump the limit
            // to unlimited. If program load fails again, return the error.
            let mut rl = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            unsafe {
                if libc::getrlimit(libc::RLIMIT_MEMLOCK, &rl as *const _ as *mut _) == 0 {
                    rl.rlim_max = libc::RLIM_INFINITY;
                    rl.rlim_cur = rl.rlim_max;
                    if libc::setrlimit(libc::RLIMIT_MEMLOCK, &rl as *const _ as *mut _) != 0 {
                        let ret = syscall!(BPF, bpf_cmd::BPF_MAP_CREATE,
                                           &attr as *const _ as usize, ::std::mem::size_of::<bpf_attr>());
                    } else {
                        println!("setrlimit() failed with errno={}", Error::last_os_error()
                                 .raw_os_error().unwrap());
                        return -1;
                    }
                }
            }
        }
    }
    return ret as i32;
}

#[no_mangle]
pub unsafe fn elf_read_license(module: &Module) -> Result<String, String> {
    match module.file.get_section("license") {
        Some(ref s) => match ::std::str::from_utf8(&s.data) {
            Ok(res) => Ok(res.to_string()),
            Err(e) => Err(format!("Fail to convert result to String: {}", e))
        },
        None => Err("Failed to look up license section".to_string()),
    }
}

pub unsafe fn elf_read_version(module: &Module) -> Result<u32, String> {
    match module.file.get_section("version") {
        Some(s) => {
            if s.data.len() != 4 {
                return Err("version is not a __u32".to_string())
            }
            let mut buf = Cursor::new(&s.data);
            match buf.read_u32::<LittleEndian>() {
                Ok(res) => Ok(res),
                Err(_) => Err("Fail to read version".to_string())
            }
        }
        None => Err("Failed to look up version section".to_string()),
    }
}

pub unsafe fn prepare_bpffs(namespace: &str, name: &str) {
}

pub fn elf_read_maps(module: &Module) -> Result<HashMap<String>, String> {
    for sec in &module.file.sections {
        if sec.shdr.name.starts_with("maps/") {
            continue;
        }
        let data = &module.file.data;
        if data.len() != ::std::mem::size_of::<bpf_map_def>() {
            return Err(format!("only one map with size {} bytes allowed per section (check bpf_map_def)",
                               ::std::mem::size_of::<bpf_map_def>()));
        }

    }
}

#[no_mangle]
pub unsafe fn load(module: &mut Module) -> Result<(), String>{
    if module.file_name != "" {
        let path = PathBuf::from(&module.file_name);
        module.file = match elf::File::open_path(&path) {
            Ok(f) => f,
            Err(e) => panic!("Fail to open file: {}", &module.file_name),
        };
    }

    let license = elf_read_license(module)?;

    let version = elf_read_version(module)?;

    if version == USE_CURRENT_KERNEL_VERSION {
        let version = current_kernel_version()?;
    }


}
