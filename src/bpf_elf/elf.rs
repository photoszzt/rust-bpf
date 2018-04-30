extern crate bcc_sys;
extern crate failure;
extern crate libc;
extern crate nix;
extern crate xmas_elf;

use bcc_sys::bccapi::{bpf_obj_get, bpf_obj_pin, bpf_update_elem};
use bpf_elf::bpf::bpf_attr_ext;
use bpf_elf::bpf_bindings::*;
use bpf_elf::kernel_version::*;
use bpf_elf::module::*;
use bpf_elf::perf_event::PERF_EVENT_IOC_ENABLE;
use bpf_elf::pinning::BPFDIRGLOBALS;
use bpffs::{mounted, BPFFS_PATH};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use cpuonline;
use failure::{Error, err_msg};
use perf_event_bindings::*;
use std::collections::HashMap;
use std::default::Default;
use std::ffi::{CStr, CString};
use std::io::Cursor;
use std::io::Error as IOError;
use std::io::ErrorKind;
use std::path::Path;
use std::path::PathBuf;
use xmas_elf::header::Data;
use xmas_elf::sections::{SectionData, ShType};
use xmas_elf::symbol_table::Entry;

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

fn bpf_create_map(map_type: u32, key_size: u32, value_size: u32, max_entries: u32) -> i32 {
    let attr = bpf_attr::bpf_attr_map_create(map_type, key_size, value_size, max_entries, 0);
    let mut ret = unsafe {
        syscall!(
            BPF,
            bpf_cmd_BPF_MAP_CREATE,
            &attr as *const _ as usize,
            ::std::mem::size_of::<bpf_attr>()
        ) as i32
    };
    if -ret == libc::EPERM {
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
                    ) as i32;
                } else {
                    println!(
                        "setrlimit() failed with errno={}",
                        IOError::last_os_error().raw_os_error().unwrap()
                    );
                    return -1;
                }
            }
        }
    }
    return ret;
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
        ) as i32
    };
    if -ret == libc::EPERM {
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
                    ) as i32;
                } else {
                    println!(
                        "setrlimit() failed with errno={}",
                        IOError::last_os_error().raw_os_error().unwrap()
                    );
                    return -1;
                }
            }
        }
    }
    return ret;
}

fn bpf_load_map(map_def: &bpf_map_def, path: &PathBuf) -> Result<bpf_map, Error> {
    let mut map = bpf_map {
        fd: 1,
        def: map_def.clone(),
    };
    let mut do_pin = false;
    if map_def.pinning == PIN_OBJECT_NS {
        return Err(err_msg("Not support object pinning"));
    } else if map_def.pinning == PIN_GLOBAL_NS || map_def.pinning == PIN_CUSTOM_NS {
        if nix::sys::stat::stat(path).is_ok() {
            let path_cstr = CString::new(path.to_str().unwrap_or(""))?;
                //.map_err(|e| format!("Fail to convert to c string: {}", e))?;
            let fd = unsafe { bpf_obj_get(path_cstr.as_ptr()) };
            if fd < 0 {
                return Err(err_msg("Fail to get pinned obj fd"));
            }
            map.fd = fd as i32;
            return Ok(map);
        } else {
            do_pin = true;
        }
    }
    map.fd = bpf_create_map(
        map_def.type_,
        map_def.key_size,
        map_def.value_size,
        map_def.max_entries,
    );
    if map.fd < 0 {
        return Err(err_msg("Fail to create map"));
    }
    if do_pin {
        let path_cstr = CString::new(path.to_str().unwrap_or(""))?;
        let ret = unsafe { bpf_obj_pin(map.fd, path_cstr.as_ptr()) };
        if ret < 0 {
            return Err(err_msg("Fail to pin object"));
        }
    }
    Ok(map)
}

fn create_pin_path(path: &Path) -> Result<(), Error> {
    mounted()?;
    let parent = match path.parent() {
        Some(d) => d,
        None => return Err(format_err!("Fail to get parent directory of {:?}", path)),
    };
    ::std::fs::create_dir_all(parent).map_err(|e| e.into())
}

impl bpf_map_def {
    pub fn get_map_path(&self, map_name: &str, pin_path: Option<&str>) -> Result<PathBuf, Error> {
        match self.pinning {
            PIN_OBJECT_NS => Err(err_msg("Not implemented yet")),
            PIN_GLOBAL_NS => {
                let namespace = unsafe {
                    match ::std::ffi::CStr::from_ptr(self.namespace.as_ptr()).to_str() {
                        Ok(res) => res,
                        Err(e) => {
                            return Err(format_err!(
                                "Fail to convert namespace to valid utf8 str: {}",
                                e
                            ))
                        }
                    }
                };
                if namespace == "" {
                    return Err(format_err!("map {} has empty namespace", map_name));
                }
                Ok([BPFFS_PATH, namespace, BPFDIRGLOBALS, map_name]
                    .iter()
                    .collect())
            }
            PIN_CUSTOM_NS => {
                if pin_path.is_none() {
                    return Err(format_err!(
                        "no pin path given for map {} with PIN_CUSTOM_NS",
                        map_name
                    ));
                }
                Ok([BPFFS_PATH, pin_path.unwrap()].iter().collect())
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
        params: Option<&SectionParams>,
    ) -> Result<PathBuf, Error> {
        let map_path = self.get_map_path(map_name, params.map(|p| p.pin_path.as_str()))?;
        if map_path != Path::new("") {
            if bpf_map_def::validate_path(&map_path).is_err() {
                return Err(format_err!("invalid path {:?}", &map_path));
            }
            create_pin_path(&map_path)?;
        }
        return Ok(map_path);
    }

    pub fn validate_path(path: &Path) -> ::std::io::Result<()> {
        if !path.starts_with(BPFFS_PATH) {
            Err(::std::io::Error::new(
                ErrorKind::Other,
                "path doesn't start with bpffs path",
            ))
        } else {
            Ok(())
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

impl<'a> Module<'a> {
    fn elf_read_license(&self) -> Result<&'a CStr, Error> {
        match self.file.find_section_by_name("license") {
            Some(s) => CStr::from_bytes_with_nul(s.raw_data(&self.file))
                .map_err(|e| format_err!("Fail to convert to CStr: {}", e)),
            None => Err(err_msg("Failed to look up license section")),
        }
    }

    fn elf_read_version(&self) -> Result<u32, Error> {
        match self.file.find_section_by_name("version") {
            Some(s) => {
                let data = s.raw_data(&self.file);
                if data.len() != 4 {
                    return Err(format_err!("version is not a __u32"));
                }
                let mut buf = Cursor::new(data);
                match self.file.header.pt1.data() {
                    Data::LittleEndian => buf.read_u32::<LittleEndian>().map_err(|e| e.into()),
                    Data::BigEndian => buf.read_u32::<BigEndian>().map_err(|e| e.into()),
                    _ => Err(err_msg("Unrecognized endien")),
                }
            }
            None => Err(err_msg("Failed to look up version section")),
        }
    }

    fn elf_read_maps(
        &self,
        params: &HashMap<String, SectionParams>,
    ) -> Result<HashMap<String, EbpfMap>, Error> {
        let mut maps: HashMap<String, EbpfMap> = HashMap::new();
        let mut sect_iter = self.file.section_iter();
        sect_iter.next();
        for sec in sect_iter {
            let name = sec.get_name(&self.file).map_err(|e| format_err!("{}", e))?;
            if !name.starts_with("maps/") {
                continue;
            }
            let data = sec.raw_data(&self.file);
            if data.len() != ::std::mem::size_of::<bpf_map_def>() {
                return Err(format_err!(
                    "only one map with size {} bytes allowed per section (check bpf_map_def)",
                    ::std::mem::size_of::<bpf_map_def>()
                ));
            }

            let trim_name = name.trim_left_matches("maps/");
            let map_def = unsafe {
                let map_def_ptr = &data[0] as *const u8 as *const bpf_map_def;
                if map_def_ptr.is_null() {
                    continue;
                } else {
                    &*map_def_ptr
                }
            };
            let map_path = map_def.create_map_path(trim_name, params.get(name))?;
            let map = bpf_load_map(map_def, &map_path)?;
            if let Some(oldMap) = maps.get(trim_name) {
                return Err(format_err!("Duplicate map: {} and {}", oldMap.name, trim_name));
            }
            maps.insert(
                trim_name.to_string(),
                EbpfMap {
                    name: trim_name.to_string(),
                    m: map,
                    headers: Vec::new(),
                    page_count: 0,
                    pmu_fds: Vec::new(),
                },
            );
        }
        Ok(maps)
    }

    fn process_symbol<T: Entry>(
        &self,
        symbol: &T,
        rdata: &[u8],
        offset: usize,
    ) -> Result<(), Error> {
        let rinsn =
            unsafe { &mut *(&rdata[offset] as *const u8 as *const bpf_insn as *mut bpf_insn) };
        if rinsn.code != (BPF_LD | BPF_IMM | BPF_DW) as u8 {
            let symbol_sec = self.file
                .section_header(symbol.shndx())
                .map_err(|e| format_err!("{}", e))?;
            return Err(format_err!(
                "invalid relocation: symbol name={}\nsymbol section: Name={}, Type={:?}, Flags={}",
                symbol.get_name(&self.file).unwrap(),
                symbol_sec.get_name(&self.file).unwrap(),
                symbol_sec.get_type().unwrap(),
                symbol_sec.flags()
            ));
        }

        let symbol_sec = self.file
            .section_header(symbol.shndx())
            .map_err(|e| format_err!("{}", e))?;
        let symbol_sec_name = symbol_sec.get_name(&self.file).map_err(|e| format_err!("{}", e))?;
        let symbol_name = symbol.get_name(&self.file).map_err(|e| format_err!("{}", e))?;
        if !symbol_sec_name.starts_with("maps/") {
            return Err(format_err!(
                "map location not supported: map {} is in section {} instead of \"maps/{}\"",
                symbol_name,
                symbol_sec_name,
                symbol_name,
            ));
        }
        let trim_symbol_sec_name = symbol_sec_name.trim_left_matches("maps/");
        let m = match self.maps.get(trim_symbol_sec_name) {
            Some(res) => res,
            None => {
                return Err(format_err!(
                    "relocation error, symbol {} not found in section {}",
                    symbol_name, symbol_sec_name
                ))
            }
        };
        rinsn.set_src_reg(BPF_PSEUDO_MAP_FD as u8);
        rinsn.imm = m.m.fd;
        Ok(())
    }

    fn relocate(&self, data: &SectionData, rdata: &[u8]) -> Result<(), Error> {
        let symtab_sec = match self.file.find_section_by_name(".symtab") {
            Some(s) => s,
            None => return Err(format_err!("Fail to get symbol table")),
        };
        let symbols = symtab_sec.get_data(&self.file).map_err(|e| format_err!("{}", e))?;
        if let &SectionData::Rel64(r64_arr) = data {
            for rel in r64_arr {
                let offset = rel.get_offset();
                let sym_no = rel.get_symbol_table_index();
                match symbols {
                    SectionData::SymbolTable64(ss) => {
                        let symbol = &ss[(sym_no - 1) as usize];
                        self.process_symbol(symbol, rdata, offset as usize)?;
                    }
                    _ => panic!(
                        "Wrong symbol table entry, expecting 64 bit symbol table entry".to_string()
                    ),
                }
            }
            Ok(())
        } else if let &SectionData::Rel32(r32_arr) = data {
            for rel in r32_arr {
                let offset = rel.get_offset();
                let sym_no = rel.get_symbol_table_index();
                match symbols {
                    SectionData::SymbolTable32(ss) => {
                        let symbol = &ss[(sym_no - 1) as usize];
                        self.process_symbol(symbol, rdata, offset as usize)?;
                    }
                    _ => panic!(
                        "Wrong symbol table entry, expecting 64 bit symbol table entry".to_string()
                    ),
                }
            }
            Ok(())
        } else {
            Err(format_err!("Wrong section data, expecting Rel"))
        }
    }

    pub fn load(&mut self, params: &HashMap<String, SectionParams>) -> Result<(), Error> {
        let license = self.elf_read_license()?;

        let version = {
            let mut v = self.elf_read_version()?;
            if v == USE_CURRENT_KERNEL_VERSION {
                v = current_kernel_version()?;
            }
            v
        };
        self.maps = self.elf_read_maps(params)?;
        let length = self.file.section_iter().count();
        let mut processed = vec![false; length];
        for (idx, sec) in self.file.section_iter().enumerate() {
            // Need to get over null section
            if idx == 0 {
                processed[idx] = true;
                continue;
            }
            if processed[idx] {
                continue;
            }

            if sec.raw_data(&self.file).is_empty() {
                continue;
            }

            let sec_shtype = sec.get_type().map_err(|e| format_err!("{}", e))?;
            match sec_shtype {
                ShType::Rel => {
                    let data = sec.get_data(&self.file).map_err(|e| format_err!("{}", e))?;
                    let rsec = self.file.section_header(sec.info() as u16).map_err(|e| format_err!("{}", e))?;
                    processed[idx] = true;
                    processed[sec.info() as usize] = true;
                    let sec_name = rsec.get_name(&self.file).map_err(|e| format_err!("{}", e))?;
                    let is_kprobe = sec_name.starts_with("kprobe/");
                    let is_kretprobe = sec_name.starts_with("kretprobe/");
                    let is_cgroup_skb = sec_name.starts_with("cgroup/skb");
                    let is_cgroup_sock = sec_name.starts_with("cgroup/sock");
                    let is_socket_filter = sec_name.starts_with("socket");
                    let is_tracepoint = sec_name.starts_with("tracepoint/");
                    let is_sched_cls = sec_name.starts_with("sched_cls/");
                    let is_sched_act = sec_name.starts_with("sched_act/");

                    if is_kprobe || is_kretprobe || is_cgroup_sock || is_cgroup_skb
                        || is_socket_filter || is_tracepoint || is_sched_act
                        || is_sched_cls
                    {
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

                        let rdata = rsec.raw_data(&self.file);
                        if rdata.len() == 0 {
                            continue;
                        }

                        self.relocate(&data, rdata)?;

                        let insns = &rdata[0] as *const u8 as *const bpf_insn;
                        let prog_fd = bpf_prog_load(
                            progType,
                            insns,
                            rsec.size() as u32,
                            license.as_ptr() as *const u8,
                            version,
                            self.log.as_ptr() as *const u8,
                            self.log.len() as u32,
                        );
                        if prog_fd < 0 {
                            return Err(format_err!(
                                "error while loading {}, {}: \n{}",
                                sec_name,
                                -prog_fd,
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
                _ => (),
            }
        }

        for (idx, sec) in self.file.section_iter().enumerate() {
            // Need to get over null section
            if idx == 0 {
                processed[idx] = true;
                continue;
            }
            if processed[idx] {
                continue;
            }
            let sec_name = sec.get_name(&self.file).map_err(|e| format_err!("{}", e))?;
            let is_kprobe = sec_name.starts_with("kprobe/");
            let is_kretprobe = sec_name.starts_with("kretprobe/");
            let is_cgroup_skb = sec_name.starts_with("cgroup/skb");
            let is_cgroup_sock = sec_name.starts_with("cgroup/sock");
            let is_socket_filter = sec_name.starts_with("socket");
            let is_tracepoint = sec_name.starts_with("tracepoint/");
            let is_sched_cls = sec_name.starts_with("sched_cls/");
            let is_sched_act = sec_name.starts_with("sched_act/");

            if is_kprobe || is_kretprobe || is_cgroup_sock || is_cgroup_skb || is_socket_filter
                || is_tracepoint || is_sched_act || is_sched_cls
            {
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

                let data = sec.raw_data(&self.file);
                if data.len() == 0 {
                    continue;
                }

                let insns = &data[0] as *const u8 as *const bpf_insn;
                let prog_fd = bpf_prog_load(
                    progType,
                    insns,
                    sec.size() as u32,
                    license.as_ptr() as *const u8,
                    version,
                    self.log.as_ptr() as *const u8,
                    self.log.len() as u32,
                );
                if prog_fd < 0 {
                    return Err(format_err!(
                        "error while loading {}, {}: \n{}",
                        sec_name,
                        -prog_fd,
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
        return self.initialize_perf_maps(params);
    }

    fn initialize_perf_maps(
        &mut self,
        params: &HashMap<String, SectionParams>,
    ) -> Result<(), Error> {
        for (name, m) in self.maps.iter_mut() {
            if m.m.def.type_ != bpf_map_type_BPF_MAP_TYPE_PERF_EVENT_ARRAY as u32 {
                continue;
            }

            let pg_size = match nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)?
            {
                Some(res) => res,
                None => return Err(format_err!("Fail to get page size")),
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
                        return Err(format_err!(
                            "number of pages {} must be strictly positive and a power of 2",
                            param.perf_ring_buffer_page_count
                        ));
                    }
                    m.page_count = param.perf_ring_buffer_page_count as u32;
                }
            }
            let mut cpus = cpuonline::get()?;

            for cpu in cpus.iter_mut() {
                let pmufd = perf_event_open_map(-1, *cpu, -1, PERF_FLAG_FD_CLOEXEC as u64);
                if pmufd < 0 {
                    return Err(format_err!("Fail to call perf_event_open: {}", pmufd));
                }

                let mmap_size = pg_size * (m.page_count as i64 + 1);

                let base = unsafe {
                    nix::sys::mman::mmap(
                        ::std::ptr::null_mut(),
                        mmap_size as usize,
                        nix::sys::mman::ProtFlags::PROT_READ
                            | nix::sys::mman::ProtFlags::PROT_WRITE,
                        nix::sys::mman::MapFlags::MAP_SHARED,
                        pmufd,
                        0,
                    )?
                };

                let ret = unsafe { syscall!(IOCTL, pmufd, PERF_EVENT_IOC_ENABLE, 0) };
                if ret != 0 {
                    return Err(format_err!("Error enabling perf event: {}", ret as i32));
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
                    return Err(format_err!(
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
