extern crate libc;
extern crate nix;
extern crate elf;

use bpf_bindings::*;
use bcc_elf::elf_bindings::*;
use bpf::*;
use elf::types::*;
use bcc_elf::kernel_version::*;
use std::io::Error;
use std::io::ErrorKind;
use std::default::Default;
use std::path::PathBuf;
use std::io::Cursor;
use bpffs::fs::{BPFFS_PATH, mounted};
use bcc_elf::pinning::BPFDIRGLOBALS;
use byteorder::{LittleEndian, BigEndian, ReadBytesExt};
use bcc_elf::module::*;
use std::collections::HashMap;

const USE_CURRENT_KERNEL_VERSION : u64 = 0xFFFFFFFE;

#[derive(Debug, Copy, Clone)]
pub enum pin {
    PIN_NONE = 0,
    PIN_OBJECT_NS,
    PIN_GLOBAL_NS,
    PIN_CUSTOM_NS,
}

#[derive(Debug, Default, Clone)]
pub struct SectionParams {
    perf_ring_buffer_page_count: i32,
    skip_perf_map_initialization: bool,
    pin_path: String,
}

// represents a ebpf map.
#[derive(Default, Clone, Debug)]
pub struct EbpfMap {
    name: String,
    m: bpf_map_def,
}

impl Default for bpf_map_def {
    fn default() -> bpf_map_def {
        bpf_map_def {
            type_: 0,
            key_size: 0,
            value_size: 0,
            max_entries: 0,
            map_flags: 0,
            pinning: 0,
            namespace: [0; 256],
        }
    }
}

fn bpf_create_map(map_type: u32,
                  key_size: u32,
                  value_size: u32,
                  max_entries: u32) -> i32 {
    let attr = bpf_attr::bpf_attr_map_create(map_type,
                                             key_size,
                                             value_size,
                                             max_entries,
                                             0);
    let mut ret = unsafe {
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
                    if libc::setrlimit(libc::RLIMIT_MEMLOCK, &rl as *const _ as *mut _) == 0 {
                        ret = syscall!(BPF, bpf_cmd::BPF_MAP_CREATE,
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

fn bpf_prog_load(prog_type: bpf_prog_type,
                 insns: *const bpf_insn,
                 prog_len: u32,
                 license: *const u8,
                 kern_version: u32,
                 log_buf: *const u8,
                 log_size: u32) -> i32 {
    let insns_cnt = prog_len / (::std::mem::size_of::<bpf_insn>() as u32);
    let attr = bpf_attr::bpf_attr_prog_load(
        prog_type as u32,
        insns_cnt as u32,
        insns as *const _ as u64,
        license as u64,
        1,
        log_size as u32,
        log_buf as u64,
        kern_version,
    );

    let mut ret = unsafe {
        syscall!(BPF, bpf_cmd::BPF_PROG_LOAD,
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
                    if libc::setrlimit(libc::RLIMIT_MEMLOCK, &rl as *const _ as *mut _) == 0 {
                        ret = syscall!(BPF, bpf_cmd::BPF_PROG_LOAD,
                                       &attr as *const _ as usize,
                                       ::std::mem::size_of::<bpf_attr>());
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

fn bpf_load_map(map_def: &bpf_map_def, path: &PathBuf) -> Result<bpf_map, String> {
    let map_dev_ = map_def.clone();
    let mut map = bpf_map {
        fd: 1,
        def: map_dev_,
    };
    let mut do_pin = false;
    match map_def.pinning {
        1 => return Err("Not support object pinning".to_string()),
        2|3 => {
            if nix::sys::stat::stat().map_err(stringify).is_ok() {
                let fd = bpf_obj_get(path.to_str().unwrap_or("").as_bytes() as *const libc::c_char);
                if fd < 0 {
                    return Err("Fail to get pinned obj fd");
                }
                map.fd = fd as i32;
                return Ok(map);
            }
            do_pin = true;
        }
    }

    map.fd = bpf_create_map(map_def.type_, map_def.key_size, map_def.value_size, map_def.max_entries);

    if map.fd < 0 {
        return Err("Fail to create map".to_string());
    }

    if do_pin {
        let fd = bpf_obj_pin(map.fd as u32, path.to_str().unwrap_or("").as_bytes() as *const libc::c_char);
        if fd < 0 {
            return Err("Fail to pin object".to_string());
        }
    }

    Ok(map)
}

pub unsafe fn prepare_bpffs(namespace: &str, name: &str) {
}

fn stringify(error: Error) -> String {
    format!("{}", error)
}

fn stringify(nix::error: Error) -> String {
    format!("{}", error)
}

fn create_pin_path(path: PathBuf) -> Result<(), String> {
    mounted()?;
    let parent = match path.parent() {
        Some(d) => d,
        None => return Err(format!("Fail to get parent directory of {:?}", path)),
    };
    ::std::fs::create_dir_all(parent).map_err(stringify)
}

fn get_map_path(map_def: &bpf_map_def, map_name: String, pin_path: String) -> Result<PathBuf, String> {
    match map_def.pinning {
        PIN_OBJECT_NS => Err("Not implemented yet".to_string()),
        PIN_GLOBAL_NS => {
            let namespace = str::from_utf8(&map_def.namespace).map_err(stringify)?;
            if namespace == "" {
                return Err(format!("map {} has empty namespace", map_name));
            }
            Ok([BPFFS_PATH, &namespace, BPFDIRGLOBALS, map_name].iter().collect())
        }
        PIN_CUSTOM_NS => {
            if pin_path == "" {
                return Err(format!("no pin path given for map {} with PIN_CUSTOM_NS", map_name))
            }
            Ok([BPFFS_PATH, pin_path].iter().collect())
        }
        default => {
            // map is not pinned
            Ok(PathBuf::from(""))
        }
    }
}

fn validate_map_path(path: PathBuf) -> ::std::io::Result<PathBuf> {
    if !path.starts_with(BPFFS_PATH) {
        Err(Error::new(ErrorKind::Other, "path doesn't start with bpffs path"))
    } else {
        path.canonicalize()
    }
}

fn create_map_path(map_def: &bpf_map_def, map_name: String, params: SectionParams) -> Result<PathBuf, String> {
    let map_path = get_map_path(map_def, map_name, params.pin_path)?;

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

    fn elf_read_maps(&self, params: &HashMap<String, SectionParams>) -> Result<HashMap<String, EbpfMap>, String> {
        let mut maps = HashMap::new();
        for sec in &self.file.sections {
            if sec.shdr.name.starts_with("maps/") {
                continue;
            }
            let data = &sec.data;
            if data.len() != ::std::mem::size_of::<bpf_map_def>() {
                return Err(format!("only one map with size {} bytes allowed per section (check bpf_map_def)",
                                   ::std::mem::size_of::<bpf_map_def>()));
            }

            let name = sec.shdr.name.trim_left_matches("maps/");
            let map_def = &*(&sec.data[0] as *const u8 as *const bpf_map_def);
            let map_path = create_map_path(map_def, name, params[sec.shdr.name])?;
            let map = bpf_load_map(map_def, &map_path)?;
            let oldMap = maps.get(name);
            if oldMap.is_some() {
                return Err("Duplicate map: {} and {}", oldMap.unwrap().name, name);
            }
            maps[name] = EbpfMap {
                name: name,
                m: map,
            };
        }
        Ok(maps)
    }

    fn relocate(&self, data: &Vec<u8>, rdata: &Vec<u8>) -> Result<(), String>{
        let symtab_sec = match self.file.get_section(".symtab") {
            Some(s) => s,
            None => return Err("Fail to get symbol table".to_string()),
        };
        let symbols = self.file.get_symbols(&symtab_sec).map_err(stringify)?;
        loop {
            let (symbol, offset) = match self.file.ehdr.class {
                ELFCLASS64 => {
                    let mut buf = Cursor::new(data);
                    match self.file.ehdr.data {
                        ELFDATA2LSB => {
                            let off = buf.read_u64::<LittleEndian>().map_err(stringify)?;
                            let info = buf.read_u64::<LittleEndian>().map_err(stringify)?;
                            let sym_no = info >> 32;
                            Ok((symbols[sym_no-1], off))
                        },
                        ELFDATA2MSB => {
                            let off = buf.read_u64::<BigEndian>().map_err(stringify)?;
                            let info = buf.read_u64::<BigEndian>().map_err(stringify)?;
                            let sym_no = info >> 32;
                            Ok((symbols[sym_no-1], off))
                        },
                        _ => Err("invalid endian".to_string()),
                    }
                }
                ELFCLASS32 => {
                    let mut buf = Cursor::new(data);
                    match self.file.ehdr.data {
                        ELFDATA2LSB => {
                            let off = buf.read_u32::<LittleEndian>().map_err(stringify)?;
                            let info = buf.read_u32::<LittleEndian>().map_err(stringify)?;
                            let sym_no = info >> 8;
                            Ok((symbols[sym_no-1], off as u64))
                        },
                        ELFDATA2MSB => {
                            let off = buf.read_u32::<BigEndian>().map_err(stringify)?;
                            let info = buf.read_u32::<BigEndian>().map_err(stringify)?;
                            let sym_no = info >> 8;
                            Ok((symbols[sym_no-1], off as u64))
                        },
                        _ => Err("invalid endian".to_string())
                    }
                }
                _ => Err("elf file class".to_string()),
            }?;
            let mut rinsn = &*(&rdata[offset] as *const u8 as *const bpf_insn);
            if rinsn.code != (BPF_LD | BPF_IMM | BPF_DW) {
                let symbol_sec = self.file.sections[symbol.shndx];
                return Err(format!("invalid relocation: symbol name={}\nsymbol section: Name={}, Type={}, Flags={}",
                                   symbol.name, symbol_sec.name, symbol_sec.shdr.shtype, symbol_sec.shdr.flags));
            }

            let symbol_sec = self.file.sections[symbol.shndx];
            if !symbol_sec.name.starts_with("maps/") {
                return Err(format!("map location not supported: map {} is in section {} instead of \"maps/{}\"",
                                   symbol.name, symbol_sec.name, symbol.name));
            }
            let name = symbol_sec.shdr.name.trim_left_matches("maps/");
            let m = match self.maps[name] {
                Some(res) => res,
                None => return Err(format!("relocation error, symbol {} not found in section {}",
                                           symbol.name, symbol_sec.shdr.name))
            };
            rinsn.src_reg = BPF_PSEUDO_MAP_FD;
            rinsn.imm = m.m.fd;
        }
    }

    pub unsafe fn load(&mut self, params: &HashMap<String, SectionParams>) -> Result<(), String>{
        if self.file_name != "" {
            let path = PathBuf::from(&self.file_name);
            self.file = match elf::File::open_path(&path) {
                Ok(f) => f,
                Err(e) => panic!("Fail to open file: {}", &self.file_name),
            };
        }

        let license = self.elf_read_license()?;

        let version = self.elf_read_version()?;

        if version == USE_CURRENT_KERNEL_VERSION {
            let version = current_kernel_version()?;
        }
        self.maps = self.elf_read_maps(params)?;

        let processed = vec![false; self.file.sections.len()];
        for (idx, sec) in self.file.sections.iter().enumerate() {
            if processed[idx] {
                continue
            }

            let data = sec.data;
            if data.is_empty() {
                continue;
            }

            if sec.shdr.shtype == SHT_REL {
                let rsec = self.file.sections[sec.shdr.info];
                processed[idx] = true;
                processed[sec.shdr.info as i32] = true;
                let sec_name = rsec.shdr.name;
                let is_kprobe = sec_name.starts_with("kprobe/");
                let is_kretprobe = sec_name.starts_with("kretprobe/");
                let is_cgroup_skb = sec_name.starts_with("cgroup/skb");
                let is_cgroup_sock = sec_name.starts_with("cgroup/sock");
                let is_socket_filter = sec_name.starts_with("socket");
                let is_tracepoint = sec_name.starts_with("tracepoint/");

                let progType = {
                    if is_kprobe || is_kretprobe {
                        bpf_prog_type::BPF_PROG_TYPE_KPROBE
                    } else if is_cgroup_skb {
                        bpf_prog_type::BPF_PROG_TYPE_CGROUP_SKB
                    } else if is_cgroup_sock {
                        bpf_prog_type::BPF_PROG_TYPE_CGROUP_SOCK
                    } else if is_socket_filter {
                        bpf_prog_type::BPF_PROG_TYPE_SOCKET_FILTER
                    } else if is_tracepoint {
                        bpf_prog_type::BPF_PROG_TYPE_TRACEPOINT
                    } else {
                        panic!("Invalid prog type");
                    }
                };

                if is_kprobe || is_kretprobe || is_cgroup_sock || is_cgroup_skb || is_socket_filter || is_tracepoint {
                    let rdata = rsec.data();
                    if rdata.len() == 0 {
                        continue
                    }

                    self.relocate(data, rdata)?;

                    let insns = &rdata[0] as *const u8 as *const bpf_insn;
                    let prog_fd = bpf_prog_load(progType, insns, rsec.shdr.size,
                                                license.as_ptr() as *const u8,
                                                version, self.log.as_ptr() as *const u8, self.log.len());
                    if prog_fd < 0 {
                        return Err(format!("error while loading {}: \n{}",
                                           sec_name, String::from_utf8(self.log).unwrap()));
                    }
                    if is_kprobe || is_kretprobe {
                        self.probes[&sec_name] = Kprobe {
                            name: sec_name,
                            insns: insns as usize,
                            fd: prog_fd as i32,
                            efd: -1
                        };
                    } else if is_cgroup_sock || is_cgroup_skb {
                        self.cgroup_programs[&sec_name] = CgroupProgram {
                            name: sec_name,
                            insns: insns as usize,
                            fd: prog_fd as i32,
                        }
                    } else if is_socket_filter {
                        self.socket_filters[&sec_name] = SocketFilter {
                            name: sec_name,
                            insns: insns as usize,
                            fd: prog_fd as i32,
                        }
                    } else if is_tracepoint {
                        self.tracepoint_programs[&sec_name] = TracepointProgram {
                            name: sec_name,
                            insns: insns as usize,
                            fd: prog_fd as i32,
                            efd: -1,
                        }
                    }
                }
            }
        }

        for (idx, sec) in self.file.sections.iter().enumerate() {
            if processed[idx] {
                continue
            }

            let sec_name = sec.shdr.name;
            let is_kprobe = sec_name.starts_with("kprobe/");
            let is_kretprobe = sec_name.starts_with("kretprobe/");
            let is_cgroup_skb = sec_name.starts_with("cgroup/skb");
            let is_cgroup_sock = sec_name.starts_with("cgroup/sock");
            let is_socket_filter = sec_name.starts_with("socket");
            let is_tracepoint = sec_name.starts_with("tracepoint/");

            let progType = {
                if is_kprobe || is_kretprobe {
                    bpf_prog_type::BPF_PROG_TYPE_KPROBE
                } else if is_cgroup_skb {
                    bpf_prog_type::BPF_PROG_TYPE_CGROUP_SKB
                } else if is_cgroup_sock {
                    bpf_prog_type::BPF_PROG_TYPE_CGROUP_SOCK
                } else if is_socket_filter {
                    bpf_prog_type::BPF_PROG_TYPE_SOCKET_FILTER
                } else if is_tracepoint {
                    bpf_prog_type::BPF_PROG_TYPE_TRACEPOINT
                } else {
                    panic!("Invalid prog type");
                }
            };

            if is_kprobe || is_kretprobe || is_cgroup_sock || is_cgroup_skb || is_socket_filter || is_tracepoint {
                let data = sec.data;
                if data.len() == 0 {
                    continue
                }

                let insns = &data[0] as *const u8 as *const bpf_insn;
                let prog_fd = bpf_prog_load(progType, insns, sec.shdr.size as u32,
                                            license.as_ptr() as *const u8,
                                            version, self.log.as_ptr() as *const u8, self.log.len());
                if prog_fd < 0 {
                    return Err("error while loading {}: \n{}", sec_name, String::from_utf8(self.log).unwrap());
                }
                if is_kprobe || is_kretprobe {
                    self.probes[&sec_name] = Kprobe {
                        name: sec_name,
                        insns: insns as usize,
                        fd: prog_fd as i32,
                        efd: -1
                    };
                } else if is_cgroup_sock || is_cgroup_skb {
                    self.cgroup_programs[&sec_name] = CgroupProgram {
                        name: sec_name,
                        insns: insns as usize,
                        fd: prog_fd as i32,
                    }
                } else if is_socket_filter {
                    self.socket_filters[&sec_name] = SocketFilter {
                        name: sec_name,
                        insns: insns as usize,
                        fd: prog_fd as i32,
                    }
                } else if is_tracepoint {
                    self.tracepoint_programs[&sec_name] = TracepointProgram {
                        name: sec_name,
                        insns: insns as usize,
                        fd: prog_fd as i32,
                        efd: -1,
                    }
                }
            }
        }
    }

    fn initialize_perf_maps(&self, params: &HashMap<String, SectionParams>) {
    }
}
