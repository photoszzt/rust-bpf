extern crate bcc_sys;
extern crate nix;
extern crate num_cpus;
extern crate regex;

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use bcc_sys::bccapi::{bpf_attach_kprobe, bpf_detach_kprobe, bpf_detach_uprobe, bpf_function_size,
                      bpf_function_start, bpf_module_create_c_from_string, bpf_module_destroy,
                      bpf_module_kern_version, bpf_module_license, bpf_probe_attach_type,
                      bpf_prog_load, perf_reader_free, bpf_attach_uprobe};
use std::os::raw::{c_void, c_char};
use regex::Regex;
use bcc::symbol::resolve_symbol_path;

#[derive(Debug, Default)]
pub struct Module {
    p: usize,
    funcs: HashMap<CString, i32>,
    kprobes: HashMap<CString, usize>,
    uprobes: HashMap<CString, usize>,
}

lazy_static! {
    static ref DEFAULT_C_FLAGS: String = format!("-DNUMCPUS={}", num_cpus::get());
    static ref KPROBE_REGEX: Regex = Regex::new(r"[+.]").unwrap();
    static ref UPROBE_REGEX: Regex = Regex::new(r"[^a-zA-Z0-9_]").unwrap();
}


pub fn new_module(code: &CStr, cflags: &Vec<CString>) -> Result<Module, String> {
    let mut cflagsC = {
        let mut cFlagsC = cflags.clone();
        cFlagsC.push(CString::new(DEFAULT_C_FLAGS.as_bytes())
            .map_err(|e| format!("Fail to construct cstring from: {}", e))?);
        cFlagsC
    };
    let c = unsafe {
        bpf_module_create_c_from_string(
            code.as_ptr(),
            2,
            cflagsC.as_mut_ptr() as *mut _,
            cflagsC.len() as i32,
        )
    };
    if c.is_null() {
        return Err("Fail to construct the module".to_string());
    }
    return Ok(Module {
        p: c as usize,
        ..Default::default()
    });
}

impl Module {
    pub fn close(self) -> Result<(), String> {
        unsafe {
            bpf_module_destroy(self.p as *mut c_void);
        }
        for (k, v) in self.kprobes {
            unsafe {
                perf_reader_free(v as *mut c_void);
            }
            let ret = unsafe { bpf_detach_kprobe(k.as_ptr()) };
            if ret < 0 {
                return Err("Fail to detach kprobe".to_string());
            }
        }
        for (k, v) in self.uprobes {
            unsafe {
                perf_reader_free(v as *mut ::std::os::raw::c_void);
            }
            let ret = unsafe { bpf_detach_uprobe(k.as_ptr()) };
            if ret < 0 {
                return Err("Fail to detach kprobe".to_string());
            }
        }
        for (_, fd) in self.funcs {
            nix::unistd::close(fd).map_err(|e| format!("Fail to close fd: {}", e))?;
        }
        Ok(())
    }

    /// loads a program of type BPF_PROG_TYPE_SCHED_ACT.
    pub fn load_net(&mut self, name: &CStr) -> Result<i32, String> {
        self.load(
            name,
            bcc_sys::bccapi::bpf_prog_type::BPF_PROG_TYPE_SCHED_ACT,
        )
    }

    /// loads a program of type BPF_PROG_TYPE_SCHED_KPROBE.
    pub fn load_kprobe(&mut self, name: &CStr) -> Result<i32, String> {
        self.load(name, bcc_sys::bccapi::bpf_prog_type::BPF_PROG_TYPE_KPROBE)
    }

    /// loads a program of type BPF_PROG_TYPE_SCHED_KPROBE.
    pub fn load_uprobe(&mut self, name: &CStr) -> Result<i32, String> {
        self.load(name, bcc_sys::bccapi::bpf_prog_type::BPF_PROG_TYPE_KPROBE)
    }

    fn load(
        &mut self,
        name: &CStr,
        prog_type: bcc_sys::bccapi::bpf_prog_type,
    ) -> Result<i32, String> {
        if let Some(fd) = self.funcs.get(name) {
            return Ok(*fd);
        }
        let fd = self.load_helper(name, prog_type)?;
        self.funcs.insert(name.to_owned(), fd);
        Ok(fd)
    }

    fn load_helper(
        &self,
        name: &CStr,
        prog_type: bcc_sys::bccapi::bpf_prog_type,
    ) -> Result<i32, String> {
        let start = unsafe { bpf_function_start(self.p as *mut c_void, name.as_ptr()) };
        let size = unsafe { bpf_function_size(self.p as *mut c_void, name.as_ptr()) };
        let license = unsafe { bpf_module_license(self.p as *mut c_void) };
        let version = unsafe { bpf_module_kern_version(self.p as *mut c_void) };
        if start.is_null() {
            return Err(format!("Module: unable to find {}", name.to_string_lossy()));
        }
        let logbuf = [0u8; 65536];
        let fd = unsafe {
            bpf_prog_load(
                prog_type,
                start as *const c_void as *const _,
                size as i32,
                license,
                version,
                logbuf.as_ptr() as *const i8 as *mut _,
                logbuf.len() as u32,
            )
        };
        if fd < 0 {
            let msg = String::from_utf8_lossy(&logbuf);
            if msg.len() > 0 {
                return Err(format!("error loading BPF program: {}", msg));
            }
            return Err(format!("error loading BPF program: {}", fd));
        }
        return Ok(fd);
    }

    fn attach_probe(
        &mut self,
        ev_name: String,
        attach_type: bpf_probe_attach_type,
        fn_name: &str,
        fd: i32,
    ) -> Result<(), String> {
        let ev_name_c =
            CString::new(ev_name).map_err(|e| format!("Fail to convert to c style string: {}", e))?;
        let fn_name_c =
            CString::new(fn_name).map_err(|e| format!("Fail to convert to c style string: {}", e))?;
        if self.kprobes.get(&ev_name_c).is_some() {
            return Ok(());
        }
        let ret = unsafe {
            bpf_attach_kprobe(
                fd,
                attach_type,
                ev_name_c.as_ptr(),
                fn_name_c.as_ptr(),
                -1,
                0,
                -1,
                None,
                ::std::ptr::null_mut(),
            )
        };
        if ret.is_null() {
            return Err("Failed to attach BPF kprobe".to_string());
        }
        self.kprobes.insert(ev_name_c, ret as usize);
        Ok(())
    }

    /// attach a kprobe fd to a function.
    pub fn attach_kprobe(&mut self, fn_name: &str, fd: i32) -> Result<(), String> {
        let ev_name = format!("p_{}", KPROBE_REGEX.replace_all(fn_name, "_"));
        self.attach_probe(ev_name, bpf_probe_attach_type::BPF_PROBE_ENTRY, fn_name, fd)
    }

    /// attach a kretprobe fd to a function.
    pub fn attach_kretprobe(&mut self, fn_name: &str, fd: i32) -> Result<(), String> {
        let ev_name = format!("r_{}", KPROBE_REGEX.replace_all(fn_name, "_"));
        self.attach_probe(
            ev_name,
            bpf_probe_attach_type::BPF_PROBE_RETURN,
            fn_name,
            fd,
        )
    }

    fn attach_uprobe_helper(&self, ev_name: String, attach_type: bpf_probe_attach_type,
                            path: *const c_char, addr: u64, fd: i32, pid: i32) -> Result<(), String> {
        let ev_name_c =
            CString::new(ev_name).map_err(|e| format!("Fail to convert to c style string: {}", e))?;
        let res = unsafe {
            bpf_attach_uprobe(fd, attach_type, ev_name_c.as_ptr(), path, addr, pid, 0, -1,
                              None, ::std::ptr::null_mut())
        };
        if res.is_null() {
            return Err("Failed to attach BPF uprobe".to_string());
        }
        self.uprobes.insert(ev_name_c, res as usize);
        Ok(())
    }

    // attach a uprobe fd to the symbol in the library or binary 'name'
    // The 'name' argument can be given as either a full library path (/usr/lib/..),
    // a library without the lib prefix, or as a binary with full path (/bin/bash)
    // A pid can be given to attach to, or -1 to attach to all processes.
    pub fn attach_uprobe(&self, name: &str, symbol: &str, fd: i32, pid: i32)
       -> Result<(), String> {
        let (path, addr) = resolve_symbol_path(name, symbol, 0x0, pid)?;
        let path_str = unsafe {
            CStr::from_ptr(path).to_str().map_err(|e| format!("Fail to convert path to Rust str: {}", e))
        }?;
        let ev_name = format!("p_{}_0x{}", UPROBE_REGEX.replace_all(path_str, "_"), addr);
        self.attach_uprobe_helper(ev_name, bpf_probe_attach_type::BPF_PROBE_ENTRY, path, addr, fd, pid)
    }

    // attaches a uprobe fd to all symbols in the library or binary
    // 'name' that match a given pattern.
    // The 'name' argument can be given as either a full library path (/usr/lib/..),
    // a library without the lib prefix, or as a binary with full path (/bin/bash)
    // A pid can be given, or -1 to attach to all processes
    pub fn attach_matching_uprobes(&self, name: &str, match_str: &str, fd: i32, pid: i32) -> Result<(), String> {
        Ok(())
    }
}
