extern crate syscall;
extern crate libc;
extern crate elf;
extern crate byteorder;

use bpf_bindings::*;
use elf_bindings::*;
use bpf::*;
use kernel_version::*;
use std::io::Error;
use std::io::ErrorKind;
use std::default::Default;
use std::path::PathBuf;
use std::io::Cursor;
use bpffs::{BPFFS_PATH, mounted};
use pinning::BPFDIRGLOBALS;
use self::byteorder::LittleEndian;
use self::byteorder::ReadBytesExt;

const USE_CURRENT_KERNEL_VERSION : u64 = 0xFFFFFFFE;

pub struct Module {
    file_name: String,
    file: elf::File,
}

pub enum pin {
    PIN_NONE = 0,
    PIN_OBJECT_NS,
    PIN_GLOBAL_NS,
    PIN_CUSTOM_NS,
}

pub struct SectionParams {
    perf_ring_buffer_page_count: i32,
    skip_perf_map_initialization: bool,
    pin_path: String,
}

fn bpf_create_map(map_type: bpf_map_type,
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

fn bpf_load_map(map_def: bpf_map_def, path: PathBuf) -> bpf_map {
    
}

pub unsafe fn prepare_bpffs(namespace: &str, name: &str) {
}

fn stringify(error: Error) -> String {
    format!("{}", error)
}

fn create_pin_path(path: PathBuf) -> Result<(), String> {
    mounted()?;
    let parent = match path.parent() {
        Some(d) => d,
        None => return Err(format!("Fail to get parent directory of {}", path)),
    };
    fs::create_dir_all(parent).map_err(stringify)
}

fn get_map_path(map_def: &bpf_map_def, map_name: String, pin_path: String) -> Result<PathBuf, String> {
    match map_def.pinning {
        PIN_OBJECT_NS => Err("Not implemented yet"),
        PIN_GLOBAL_NS => {
            let namespace = map_def.namespace.iter().cloned().collect::<String>();
            if namespace == "" {
                return Err(format!("map {} has empty namespace", map_name));
            }
            Ok([BPFFS_PATH, namespace, BPFDIRGLOBALS, map_name].iter().collect())
        }
        PIN_CUSTOM_NS => {
            if pin_path == "" {
                return Err(format!("no pin path given for map {} with PIN_CUSTOM_NS", mapName))
            }
            Ok([BPFFS_PATH, pin_path].iter().collect())
        }
        default => {
            // map is not pinned
            Ok(PathBuf::from(""))
        }
    }
}

fn validate_map_path(path: PathBuf) -> Result<PathBuf> {
    if !path.starts_with(BPFFS_PATH) {
        Error::new(ErrorKind::Other, "path doesn't start with bpffs path")
    } else {
        path.canonicalize()
    }
}

fn create_map_path(map_def: &bpf_map_def, map_name: String, params: SectionParams) -> Result<PathBuf, String> {
    map_path = get_map_path(map_def, map_name, params.pin_path)?;
    
    if let Err(e) = validate_map_path(map_path) {
        return Err(format!("invalid path {:?}", map_path))
    }
    create_pin_path(map_path)?;
    return Ok(map_path);
}

impl Module {
    fn elf_read_license(&self) -> Result<String, String> {
        match self.file.get_section("license") {
            Some(ref s) => match ::std::str::from_utf8(&s.data) {
                Ok(res) => Ok(res.to_string()),
                Err(e) => Err(format!("Fail to convert result to String: {}", e))
            },
            None => Err("Failed to look up license section".to_string()),
        }
    }

    fn elf_read_version(&self) -> Result<u32, String> {
        match self.file.get_section("version") {
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

    fn elf_read_maps(&self, params: &HashMap<String, SectionParams>) -> Result<HashMap<String>, String> {
        for sec in &self.file.sections {
            if sec.shdr.name.starts_with("maps/") {
                continue;
            }
            let data = &self.file.data;
            if data.len() != ::std::mem::size_of::<bpf_map_def>() {
                return Err(format!("only one map with size {} bytes allowed per section (check bpf_map_def)",
                                   ::std::mem::size_of::<bpf_map_def>()));
            }

            let name = sec.shdr.name.trim_left_matches("maps/");
            let map_def = &*(&sec.data[0] as *const u8 as *const bpf_map_def);
            let map_path = create_map_path(map_def, name, params[sec.shdr.name])?;
             
        }
    }

    pub unsafe fn load(&mut self, params: &HashMap<String, SectionParams>) -> Result<(), String>{
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
}
