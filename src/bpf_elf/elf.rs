extern crate bcc_sys;
extern crate xmas_elf;
extern crate libc;
extern crate nix;

use bcc_sys::bccapi::*;
use bpf::bpf_map_def;
use elf::types::*;
use bpf_elf::kernel_version::*;
use std::io::Error;
use std::io::ErrorKind;
use std::default::Default;
use std::path::PathBuf;
use std::io::Cursor;
use bpffs::fs::{mounted, BPFFS_PATH};
use cpuonline;
use bpf_elf::pinning::BPFDIRGLOBALS;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use bpf_elf::module::*;
use std::collections::HashMap;
use std::path::Path;
use perf_event_bindings::*;
use bpf_elf::perf_event::PERF_EVENT_IOC_ENABLE;
use bpf::bpf_attr_ext;

const USE_CURRENT_KERNEL_VERSION: u32 = 0xFFFE;


#[repr(C)]
#[derive(Default, Copy)]
pub struct bpf_map {
    pub fd: ::std::os::raw::c_int,
    pub def: bpf_map_def,
}
#[test]
fn bindgen_test_layout_bpf_map() {
    assert_eq!(
        ::std::mem::size_of::<bpf_map>(),
        284usize,
        concat!("Size of: ", stringify!(bpf_map))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_map>(),
        4usize,
        concat!("Alignment of ", stringify!(bpf_map))
    );
    assert_eq!(
        unsafe { &(*(0 as *const bpf_map)).fd as *const _ as usize },
        0usize,
        concat!(
            "Alignment of field: ",
            stringify!(bpf_map),
            "::",
            stringify!(fd)
        )
    );
    assert_eq!(
        unsafe { &(*(0 as *const bpf_map)).def as *const _ as usize },
        4usize,
        concat!(
            "Alignment of field: ",
            stringify!(bpf_map),
            "::",
            stringify!(def)
        )
    );
}
impl Clone for bpf_map {
    fn clone(&self) -> Self {
        *self
    }
}

pub const PIN_NONE: ::std::os::raw::c_uint = 0;
pub const PIN_OBJECT_NS: ::std::os::raw::c_uint = 1;
pub const PIN_GLOBAL_NS: ::std::os::raw::c_uint = 2;
pub const PIN_CUSTOM_NS: ::std::os::raw::c_uint = 3;

#[derive(Debug, Default, Clone)]
pub struct SectionParams {
    perf_ring_buffer_page_count: i32,
    skip_perf_map_initialization: bool,
    pin_path: String,
}

impl SectionParams {
    pub fn new(pin_path: String) -> SectionParams {
        SectionParams {
            pin_path,
            ..Default::default()
        }
    }
}

// represents a ebpf map.
#[derive(Clone)]
pub struct EbpfMap {
    pub name: String,
    pub m: bpf_map,
    pub page_count: u32,
    pub headers: Vec<*mut perf_event_mmap_page>,
    pub pmu_fds: Vec<i32>,
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

fn bpf_create_map(map_type: u32, key_size: u32, value_size: u32, max_entries: u32) -> i32 {
    let attr = bpf_attr::bpf_attr_map_create(map_type, key_size, value_size, max_entries, 0);
    let mut ret = unsafe {
        syscall!(
            BPF,
            bpf_cmd_BPF_MAP_CREATE,
            &attr as *const _ as usize,
            ::std::mem::size_of::<bpf_attr>()
        )
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
                        ret = syscall!(
                            BPF,
                            bpf_cmd_BPF_MAP_CREATE,
                            &attr as *const _ as usize,
                            ::std::mem::size_of::<bpf_attr>()
                        );
                    } else {
                        println!(
                            "setrlimit() failed with errno={}",
                            Error::last_os_error().raw_os_error().unwrap()
                        );
                        return -1;
                    }
                }
            }
        }
    }
    return ret as i32;
}

fn bpf_prog_load(
    prog_type: bpf_prog_type,
    insns: *const bpf_insn,
    prog_len: u32,
    license: *const u8,
    kern_version: u32,
    log_buf: *const u8,
    log_size: u32,
) -> i32 {
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
        syscall!(
            BPF,
            bpf_cmd_BPF_PROG_LOAD,
            &attr as *const _ as usize,
            ::std::mem::size_of::<bpf_attr>()
        )
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
                        ret = syscall!(
                            BPF,
                            bpf_cmd_BPF_PROG_LOAD,
                            &attr as *const _ as usize,
                            ::std::mem::size_of::<bpf_attr>()
                        );
                    } else {
                        println!(
                            "setrlimit() failed with errno={}",
                            Error::last_os_error().raw_os_error().unwrap()
                        );
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
    if map_def.pinning == PIN_OBJECT_NS {
        return Err("Not support object pinning".to_string());
    } else if map_def.pinning == PIN_GLOBAL_NS || map_def.pinning == PIN_CUSTOM_NS {
        if nix::sys::stat::stat(path)
            .map_err(|e| format!("Stat fail: {}", e))
            .is_ok()
        {
            let fd = unsafe {
                bpf_obj_get(path.to_str().unwrap_or("").as_bytes().as_ptr() as *const i8)
            };
            if fd < 0 {
                return Err("Fail to get pinned obj fd".to_string());
            }
            map.fd = fd as i32;
            return Ok(map);
        } else {
            map.fd = bpf_create_map(
                map_def.type_,
                map_def.key_size,
                map_def.value_size,
                map_def.max_entries,
            );

            if map.fd < 0 {
                return Err("Fail to create map".to_string());
            }

            let fd = unsafe {
                bpf_obj_pin(
                    map.fd,
                    path.to_str().unwrap_or("").as_bytes().as_ptr() as *const i8,
                )
            };
            if fd < 0 {
                return Err("Fail to pin object".to_string());
            }
            Ok(map)
        }
    } else {
        return Err("Can't recognize pinning config".to_string());
    }
}

fn stringify_stdio(error: Error) -> String {
    format!("{}", error)
}

fn create_pin_path(path: &Path) -> Result<(), String> {
    mounted()?;
    let parent = match path.parent() {
        Some(d) => d,
        None => return Err(format!("Fail to get parent directory of {:?}", path)),
    };
    ::std::fs::create_dir_all(parent).map_err(|e| format!("Fail to create all dir: {}", e))
}

impl bpf_map_def {
    pub fn get_map_path(&self, map_name: &str, pin_path: &str) -> Result<PathBuf, String> {
        match self.pinning {
            PIN_OBJECT_NS => Err("Not implemented yet".to_string()),
            PIN_GLOBAL_NS => {
                let namespace = unsafe {
                    match ::std::ffi::CStr::from_ptr(self.namespace.as_ptr()).to_str() {
                        Ok(res) => res,
                        Err(e) => {
                            return Err(format!(
                                "Fail to convert namespace to valid utf8 str: {}",
                                e
                            ))
                        }
                    }
                };
                if namespace == "" {
                    return Err(format!("map {} has empty namespace", map_name));
                }
                Ok(
                    [BPFFS_PATH, namespace, BPFDIRGLOBALS, map_name]
                        .iter()
                        .collect(),
                )
            }
            PIN_CUSTOM_NS => {
                if pin_path == "" {
                    return Err(format!(
                        "no pin path given for map {} with PIN_CUSTOM_NS",
                        map_name
                    ));
                }
                Ok([BPFFS_PATH, pin_path].iter().collect())
            }
            _ => {
                // map is not pinned
                Ok(PathBuf::from(""))
            }
        }
    }

    pub fn create_map_path(
        &self,
        map_name: &str,
        params: &SectionParams,
    ) -> Result<PathBuf, String> {
        let map_path = self.get_map_path(map_name, &params.pin_path)?;

        if bpf_map_def::validate_path(&map_path).is_err() {
            return Err(format!("invalid path {:?}", &map_path));
        }
        create_pin_path(&map_path)?;
        return Ok(map_path);
    }

    pub fn validate_path(path: &Path) -> ::std::io::Result<PathBuf> {
        if !path.starts_with(BPFFS_PATH) {
            Err(Error::new(
                ErrorKind::Other,
                "path doesn't start with bpffs path",
            ))
        } else {
            path.canonicalize()
        }
    }
}

fn perf_event_open_map(pid: i32, cpu: u32, group_fd: i32, flags: u64) -> i32 {
    let attr: perf_event_attr = perf_event_attr::gen_perf_event_attr_open_map(
        perf_type_id_PERF_TYPE_SOFTWARE,
        perf_event_sample_format_PERF_SAMPLE_RAW,
        1,
        ::std::mem::size_of::<perf_event_attr>() as u32,
        perf_sw_ids_PERF_COUNT_SW_BPF_OUTPUT as u64,
    );
    unsafe {
        syscall!(
            PERF_EVENT_OPEN,
            &attr as *const _ as usize,
            pid,
            cpu,
            group_fd,
            flags
        ) as i32
    }
}


impl Module {
    fn elf_read_license(&self) -> Result<String, String> {
        match self.file {
            Some(ref f) => {
                println!("File: {}", &self.file_name);
                for s in &f.sections {
                    println!("section name: {}", s.shdr.name);
                }
                match f.get_section("license") {
                    Some(ref s) => match ::std::str::from_utf8(&s.data) {
                        Ok(res) => Ok(res.to_string()),
                        Err(e) => Err(format!("Fail to convert result to String: {}", e)),
                    },
                    None => Err("Failed to look up license section".to_string()),
                }
            },
            None => panic!("Need to load module first!")
        }
    }

    fn elf_read_version(&self) -> Result<u32, String> {
        match self.file {
            Some(ref f) => {
                match f.get_section("version") {
                    Some(s) => {
                        if s.data.len() != 4 {
                            return Err("version is not a __u32".to_string());
                        }
                        let mut buf = Cursor::new(&s.data);
                        match buf.read_u32::<LittleEndian>() {
                            Ok(res) => Ok(res),
                            Err(_) => Err("Fail to read version".to_string()),
                        }
                    }
                    None => Err("Failed to look up version section".to_string()),
                }
            },
            None => panic!("Need to load module first!")
        }
    }

    fn elf_read_maps(
        &self,
        params: &HashMap<String, SectionParams>,
    ) -> Result<HashMap<String, EbpfMap>, String> {
        let mut maps: HashMap<String, EbpfMap> = HashMap::new();
        match self.file {
            Some(ref f) => {
                for sec in &f.sections {
                    if sec.shdr.name.starts_with("maps/") {
                        continue;
                    }
                    let data = &sec.data;
                    if data.len() != ::std::mem::size_of::<bpf_map_def>() {
                        return Err(format!(
                            "only one map with size {} bytes allowed per section (check bpf_map_def)",
                            ::std::mem::size_of::<bpf_map_def>()
                        ));
                    }

                    let name = sec.shdr.name.trim_left_matches("maps/");
                    let map_def = unsafe {
                        let map_def_ptr = &sec.data[0] as *const u8 as *const bpf_map_def;
                        if map_def_ptr.is_null() {
                            continue;
                        } else {
                            &*map_def_ptr
                        }
                    };
                    let map_path = map_def.create_map_path(name, &params[&sec.shdr.name])?;
                    let map = bpf_load_map(map_def, &map_path)?;
                    if let Some(oldMap) = maps.get(name) {
                        return Err(format!("Duplicate map: {} and {}", oldMap.name, name));
                    }
                    maps.insert(
                        name.to_string(),
                        EbpfMap {
                            name: name.to_string(),
                            m: map,
                            headers: Vec::new(),
                            page_count: 0,
                            pmu_fds: Vec::new(),
                        },
                    );
                }
            }
            None => panic!("Need to load module first!")
        }
        Ok(maps)
    }

    fn relocate(&self, data: &Vec<u8>, rdata: &Vec<u8>) -> Result<(), String> {
        let symtab_sec = match self.file {
            Some(ref f) => {
                match f.get_section(".symtab") {
                    Some(s) => s,
                    None => return Err("Fail to get symbol table".to_string()),
                }
            }
            None => panic!("Need to load module first!")
        };
        let symbols = match self.file {
            Some(ref f) => {
                match f.get_symbols(&symtab_sec) {
                    Ok(res) => res,
                    Err(e) => {
                        return Err(format!(
                            "Fail to get symbols from symbol table sections: {:?}",
                            e
                        ))
                    }
                }
            }
            None => panic!("Need to load module first!")
        };
        loop {
            let (symbol, offset) = match self.file {
                Some(ref f) => {
                    match f.ehdr.class {
                        ELFCLASS64 => {
                            let mut buf = Cursor::new(data);
                            match f.ehdr.data {
                                ELFDATA2LSB => {
                                    let off = buf.read_u64::<LittleEndian>().map_err(stringify_stdio)?;
                                    let info = buf.read_u64::<LittleEndian>().map_err(stringify_stdio)?;
                                    let sym_no = info >> 32;
                                    (symbols[(sym_no - 1) as usize].clone(), off)
                                }
                                ELFDATA2MSB => {
                                    let off = buf.read_u64::<BigEndian>().map_err(stringify_stdio)?;
                                    let info = buf.read_u64::<BigEndian>().map_err(stringify_stdio)?;
                                    let sym_no = info >> 32;
                                    (symbols[(sym_no - 1) as usize].clone(), off)
                                }
                                _ => panic!("Unrecognize endian encoding"),
                            }
                        }
                        ELFCLASS32 => {
                            let mut buf = Cursor::new(data);
                            match f.ehdr.data {
                                ELFDATA2LSB => {
                                    let off = buf.read_u32::<LittleEndian>().map_err(stringify_stdio)?;
                                    let info = buf.read_u32::<LittleEndian>().map_err(stringify_stdio)?;
                                    let sym_no = info >> 8;
                                    (symbols[(sym_no - 1) as usize].clone(), off as u64)
                                }
                                ELFDATA2MSB => {
                                    let off = buf.read_u32::<BigEndian>().map_err(stringify_stdio)?;
                                    let info = buf.read_u32::<BigEndian>().map_err(stringify_stdio)?;
                                    let sym_no = info >> 8;
                                    (symbols[(sym_no - 1) as usize].clone(), off as u64)
                                }
                                _ => panic!("Unrecognize endian encoding"),
                            }
                        }
                        _ => panic!("Unrecognize elf class"),
                    }
                }
                None => panic!("Need to load module first!")
            };
            let rinsn = unsafe {
                &mut *(&rdata[offset as usize] as *const u8 as *const bpf_insn as *mut bpf_insn)
            };
            if rinsn.code != (BPF_LD | BPF_IMM | BPF_DW) as u8 {
                let symbol_sec = match self.file {
                    Some(ref f) => &f.sections[symbol.shndx as usize],
                    None => panic!("Need to load module first!")
                };
                return Err(format!(
                    "invalid relocation: symbol name={}\nsymbol section: Name={}, Type={}, Flags={}",
                    symbol.name,
                    symbol_sec.shdr.name,
                    symbol_sec.shdr.shtype,
                    symbol_sec.shdr.flags
                ));
            }

            let symbol_sec = match self.file {
                Some(ref f) => &f.sections[symbol.shndx as usize],
                None => panic!("Need to load module first!")
            };
            if !symbol_sec.shdr.name.starts_with("maps/") {
                return Err(format!(
                    "map location not supported: map {} is in section {} instead of \"maps/{}\"",
                    symbol.name,
                    symbol_sec.shdr.name,
                    symbol.name
                ));
            }
            let name = symbol_sec.shdr.name.trim_left_matches("maps/");
            let m = match self.maps.get(name) {
                Some(res) => res,
                None => {
                    return Err(format!(
                        "relocation error, symbol {} not found in section {}",
                        symbol.name,
                        symbol_sec.shdr.name
                    ))
                }
            };
            rinsn.set_src_reg(BPF_PSEUDO_MAP_FD as u8);
            rinsn.imm = m.m.fd;
        }
    }

    pub unsafe fn load(&mut self, params: &HashMap<String, SectionParams>) -> Result<(), String> {
        if self.file_name != "" {
            let path = PathBuf::from(&self.file_name);
            let file = match ::std::fs::File::open(path) {
                Ok(r) => r,
                Err(e) => return Err(format!("Fail to open file {}: {}", self.file_name, e)),
            };
            let mut buf = Vec::new();
            match file.read_to_end(&mut buf) {
                Ok(_) => (),
                Err(e) => return Err(format!("Fail to read file {} to end: {}", self.file_name, e)),
            }
            self.file = Some(match elf::File::open_path(&path) {
                Ok(f) => f,
                Err(_) => panic!("Fail to open file: {}", &self.file_name),
            });
        }

        let license = self.elf_read_license()?;

        let version = {
            let mut v = self.elf_read_version()?;
            if v == USE_CURRENT_KERNEL_VERSION {
                v = current_kernel_version()?;
            }
            v
        };
        self.maps = self.elf_read_maps(params)?;

        match self.file {
            Some(ref f) => {
                let mut processed = vec![false; f.sections.len()];
                for (idx, sec) in f.sections.iter().enumerate() {
                    if processed[idx] {
                        continue;
                    }

                    let data = &sec.data;
                    if data.is_empty() {
                        continue;
                    }

                    if sec.shdr.shtype == SHT_REL {
                        let rsec = &f.sections[sec.shdr.info as usize];
                        processed[idx] = true;
                        processed[sec.shdr.info as usize] = true;
                        let sec_name = &rsec.shdr.name;
                        let is_kprobe = sec_name.starts_with("kprobe/");
                        let is_kretprobe = sec_name.starts_with("kretprobe/");
                        let is_cgroup_skb = sec_name.starts_with("cgroup/skb");
                        let is_cgroup_sock = sec_name.starts_with("cgroup/sock");
                        let is_socket_filter = sec_name.starts_with("socket");
                        let is_tracepoint = sec_name.starts_with("tracepoint/");
                        let is_sched_cls = sec_name.starts_with("sched_cls/");
                        let is_sched_act = sec_name.starts_with("sched_act/");

                        let progType = {
                            if is_kprobe || is_kretprobe {
                                bpf_prog_type_BPF_PROG_TYPE_KPROBE
                            } else if is_cgroup_skb {
                                bpf_prog_type_BPF_PROG_TYPE_CGROUP_SKB
                            } else if is_cgroup_sock {
                                bpf_prog_type_BPF_PROG_TYPE_CGROUP_SOCK
                            } else if is_socket_filter {
                                bpf_prog_type_BPF_PROG_TYPE_SOCKET_FILTER
                            } else if is_tracepoint {
                                bpf_prog_type_BPF_PROG_TYPE_TRACEPOINT
                            } else if is_sched_act {
                                bpf_prog_type_BPF_PROG_TYPE_SCHED_ACT
                            } else if is_sched_cls {
                                bpf_prog_type_BPF_PROG_TYPE_SCHED_CLS
                            } else {
                                panic!("Invalid prog type");
                            }
                        };

                        if is_kprobe || is_kretprobe || is_cgroup_sock || is_cgroup_skb || is_socket_filter
                            || is_tracepoint || is_sched_act || is_sched_cls
                        {
                            let rdata = &rsec.data;
                            if rdata.len() == 0 {
                                continue;
                            }

                            self.relocate(data, rdata)?;

                            let insns = &rdata[0] as *const u8 as *const bpf_insn;
                            let prog_fd = bpf_prog_load(
                                progType,
                                insns,
                                rsec.shdr.size as u32,
                                license.as_ptr() as *const u8,
                                version,
                                self.log.as_ptr() as *const u8,
                                self.log.len() as u32,
                            );
                            if prog_fd < 0 {
                                return Err(format!(
                                    "error while loading {}: \n{}",
                                    sec_name,
                                    ::std::str::from_utf8(&self.log).unwrap()
                                ));
                            }
                            if is_kprobe || is_kretprobe {
                                self.probes.insert(
                                    sec_name.to_string(),
                                    Kprobe {
                                        insns: insns as usize,
                                        fd: prog_fd,
                                        efd: -1,
                                    },
                                );
                            } else if is_cgroup_sock || is_cgroup_skb {
                                self.cgroup_programs.insert(
                                    sec_name.to_string(),
                                    CgroupProgram {
                                        insns: insns as usize,
                                        fd: prog_fd,
                                    },
                                );
                            } else if is_socket_filter {
                                self.socket_filters.insert(
                                    sec_name.to_string(),
                                    SocketFilter {
                                        insns: insns as usize,
                                        fd: prog_fd,
                                    },
                                );
                            } else if is_tracepoint {
                                self.tracepoint_programs.insert(
                                    sec_name.to_string(),
                                    TracepointProgram {
                                        insns: insns as usize,
                                        fd: prog_fd,
                                        efd: -1,
                                    },
                                );
                            } else if is_sched_cls || is_sched_act {
                                self.sched_programs.insert(
                                    sec_name.to_string(),
                                    SchedProgram {
                                        insns: insns as usize,
                                        fd: prog_fd,
                                    },
                                );
                            }
                        }
                    }
                }

                for (idx, sec) in f.sections.iter().enumerate() {
                    if processed[idx] {
                        continue;
                    }

                    let sec_name = &sec.shdr.name;
                    let is_kprobe = sec_name.starts_with("kprobe/");
                    let is_kretprobe = sec_name.starts_with("kretprobe/");
                    let is_cgroup_skb = sec_name.starts_with("cgroup/skb");
                    let is_cgroup_sock = sec_name.starts_with("cgroup/sock");
                    let is_socket_filter = sec_name.starts_with("socket");
                    let is_tracepoint = sec_name.starts_with("tracepoint/");
                    let is_sched_cls = sec_name.starts_with("sched_cls/");
                    let is_sched_act = sec_name.starts_with("sched_act/");

                    let progType = {
                        if is_kprobe || is_kretprobe {
                            bpf_prog_type_BPF_PROG_TYPE_KPROBE
                        } else if is_cgroup_skb {
                            bpf_prog_type_BPF_PROG_TYPE_CGROUP_SKB
                        } else if is_cgroup_sock {
                            bpf_prog_type_BPF_PROG_TYPE_CGROUP_SOCK
                        } else if is_socket_filter {
                            bpf_prog_type_BPF_PROG_TYPE_SOCKET_FILTER
                        } else if is_tracepoint {
                            bpf_prog_type_BPF_PROG_TYPE_TRACEPOINT
                        } else if is_sched_act {
                            bpf_prog_type_BPF_PROG_TYPE_SCHED_ACT
                        } else if is_sched_cls {
                            bpf_prog_type_BPF_PROG_TYPE_SCHED_CLS
                        } else {
                            panic!("Invalid prog type");
                        }
                    };

                    if is_kprobe || is_kretprobe || is_cgroup_sock || is_cgroup_skb || is_socket_filter
                        || is_tracepoint || is_sched_act || is_sched_cls
                    {
                        let data = &sec.data;
                        if data.len() == 0 {
                            continue;
                        }

                        let insns = &data[0] as *const u8 as *const bpf_insn;
                        let prog_fd = bpf_prog_load(
                            progType,
                            insns,
                            sec.shdr.size as u32,
                            license.as_ptr() as *const u8,
                            version,
                            self.log.as_ptr() as *const u8,
                            self.log.len() as u32,
                        );
                        if prog_fd < 0 {
                            return Err(format!(
                                "error while loading {}: \n{}",
                                sec_name,
                                ::std::str::from_utf8(&self.log).unwrap()
                            ));
                        }
                        if is_kprobe || is_kretprobe {
                            self.probes.insert(
                                sec_name.to_string(),
                                Kprobe {
                                    insns: insns as usize,
                                    fd: prog_fd,
                                    efd: -1,
                                },
                            );
                        } else if is_cgroup_sock || is_cgroup_skb {
                            self.cgroup_programs.insert(
                                sec_name.to_string(),
                                CgroupProgram {
                                    insns: insns as usize,
                                    fd: prog_fd,
                                },
                            );
                        } else if is_socket_filter {
                            self.socket_filters.insert(
                                sec_name.to_string(),
                                SocketFilter {
                                    insns: insns as usize,
                                    fd: prog_fd,
                                },
                            );
                        } else if is_tracepoint {
                            self.tracepoint_programs.insert(
                                sec_name.to_string(),
                                TracepointProgram {
                                    insns: insns as usize,
                                    fd: prog_fd,
                                    efd: -1,
                                },
                            );
                        } else if is_sched_cls || is_sched_act {
                            self.sched_programs.insert(
                                sec_name.to_string(),
                                SchedProgram {
                                    insns: insns as usize,
                                    fd: prog_fd,
                                },
                            );
                        }
                    }
                }
            }
            None => panic!("Need to load module first!")
        }
        return self.initialize_perf_maps(params);
    }

    fn initialize_perf_maps(
        &mut self,
        params: &HashMap<String, SectionParams>,
    ) -> Result<(), String> {
        for (name, m) in self.maps.iter_mut() {
            if m.m.def.type_ != bpf_map_type_BPF_MAP_TYPE_PERF_EVENT_ARRAY as u32 {
                continue;
            }

            let pg_size = match nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)
                .map_err(|e| format!("Fail to get page size: {}", e))?
            {
                Some(res) => res,
                None => return Err("Fail to get page size".to_string()),
            };
            m.page_count = 8; // reasonable default

            let sec_name = format!("maps/{}", name);
            if let Some(param) = params.get(&sec_name) {
                if param.skip_perf_map_initialization {
                    continue;
                }
                if param.perf_ring_buffer_page_count > 0 {
                    if param.perf_ring_buffer_page_count & (param.perf_ring_buffer_page_count - 1)
                        != 0
                    {
                        return Err(format!(
                            "number of pages {} must be strictly positive and a power of 2",
                            param.perf_ring_buffer_page_count
                        ));
                    }
                    m.page_count = param.perf_ring_buffer_page_count as u32;
                }
            }
            let mut cpus = cpuonline::cpuonline::get()?;

            for cpu in cpus.iter_mut() {
                let pmufd = perf_event_open_map(-1, *cpu, -1, PERF_FLAG_FD_CLOEXEC as u64);
                if pmufd < 0 {
                    return Err("Fail to call perf_event_open".to_string());
                }

                let mmap_size = pg_size * (m.page_count as i64 + 1);

                let base = unsafe {
                    nix::sys::mman::mmap(
                        ::std::ptr::null_mut(),
                        mmap_size as usize,
                        nix::sys::mman::PROT_READ | nix::sys::mman::PROT_WRITE,
                        nix::sys::mman::MAP_SHARED,
                        pmufd,
                        0,
                    ).map_err(|e| format!("Fail to mmap: {}", e))?
                };

                let ret = unsafe { syscall!(IOCTL, pmufd, PERF_EVENT_IOC_ENABLE, 0) };
                if ret != 0 {
                    return Err(format!(
                        "Error enabling perf event: {}",
                        Error::last_os_error().raw_os_error().unwrap()
                    ));
                }

                let ret = unsafe {
                    bpf_update_elem(
                        m.m.fd,
                        cpu as *mut u32 as *mut _,
                        &pmufd as *const _ as *mut _,
                        BPF_ANY as u64,
                    )
                };
                if ret != 0 {
                    return Err(format!(
                        "Cannot assign perf fd to map {} cpu {})",
                        name,
                        cpu
                    ));
                }
                m.pmu_fds.push(pmufd);
                m.headers.push(base as *mut perf_event_mmap_page);
            }
        }
        Ok(())
    }
}
