extern crate bcc_sys;
extern crate nix;
extern crate num_cpus;
extern crate regex;

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use bcc_sys::bccapi::{bpf_attach_kprobe, bpf_detach_kprobe, bpf_detach_uprobe, bpf_function_size,
                      bpf_function_start, bpf_module_create_c_from_string, bpf_module_destroy,
                      bpf_module_kern_version, bpf_module_license, bpf_probe_attach_type,
                      bpf_prog_load, perf_reader_free};
use std::os::raw::c_void;
use regex::Regex;

lazy_static! {
    static ref DEFAULT_C_FLAGS: String = format!("-DNUMCPUS={}", num_cpus::get());
    static ref KPROBE_REGEX: Regex = Regex::new(r"[+.]").unwrap();
    static ref UPROBE_REGEX: Regex = Regex::new(r"[^a-zA-Z0-9_]").unwrap();
}

#[derive(Debug, Default)]
pub struct Module {
    p: usize,
    funcs: HashMap<CString, i32>,
    kprobes: HashMap<CString, usize>,
    uprobes: HashMap<CString, usize>,
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
            return Err("Failed to attach BPF uprobe".to_string());
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

    // pub fn attach_uprobe(&self, name: &str, symbol: &str, fd: i32, pid: i32)
    //    -> Result<(), String> {
    //
    // }
}
