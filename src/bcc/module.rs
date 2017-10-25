extern crate num_cpus;
extern crate bcc_sys;

use std::collections::HashMap;
use std::ffi::{CString, CStr};
use bcc_sys::bccapi::{bpf_module_create_c_from_string, bpf_module_destroy, perf_reader_free};
use std::os::raw::c_void;

lazy_static! {
    static ref default_c_flags: String = format!("-DNUMCPUS={}", num_cpus::get());
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
        cFlagsC.push(CString::new(default_c_flags.as_bytes())
                     .map_err(|e| format!("Fail to construct cstring from: {}", e))?);
        cFlagsC
    };
    let c = unsafe {
        bpf_module_create_c_from_string(code.as_ptr(), 2,
                                        cflagsC.as_mut_ptr() as *mut _,
                                        cflagsC.len() as i32)
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
    pub fn close(self) -> Result<(), String>{
        unsafe {
            bpf_module_destroy(self.p);
        }
        for (k, v) in self.kprobes {
            unsafe {
                perf_reader_free(v as *mut ::std::os::raw::c_void);
            }
            let ret = unsafe {
                bpf_detach_kprobe(k.as_mut_ptr());
            };
            if ret < 0 {
                return Err("Fail to detach kprobe".to_string());
            }
        }
        for (k, v) in self.uprobes {
            unsafe {
                perf_reader_free(v as *mut ::std::os::raw::c_void);
            }
            let ret = unsafe {
                bpf_detach_uprobe(k.as_mut_ptr());
            };
            if ret < 0 {
                return Err("Fail to detach kprobe".to_string());
            }
        }
        for (_, fd) in self.funcs {
            nix::unistd::close(fd);
        }
        Ok(())
    }

    pub fn load(&self, name: &CStr, prog_type: int) -> Result<int, String> {
        if let Some(fd) = self.funcs.get(name) {
            return Ok(fd)
        }
    }

    fn load_helper(&self, name: &CStr, prog_type: int) -> Result<int, String> {
        let start = unsafe {
            bpf_function_start(self.p as *mut c_void, name.as_ptr())
        };
        let size = unsafe {
            bpf_function_size(self.p as *mut c_void, name.as_ptr())
        };
        let license = unsafe {
            bpf_module_license(self.p as *mut c_void)
        };
        let version = unsafe {
            bpf_module_kern_version(self.p as *mut c_void)
        };
        if start.is_null() {
            return Err("Module: unable to find {}", name);
        }
        let logbuf = [u8; 65536];
        let fd = unsafe {
            bpf_prog_load(prog_type, start, size, license, version, &logbuf.as_ptr(), logbuf.len())
        };
        if fd < 0 {
            let msg = String::from_utf8_lossy(logbuf);
            if msg.len() > 0 {
                return Err(format!("error loading BPF program: {}", msg));
            }
            return Err(format!("error loading BPF program: {}", fd));
        }
        return Ok(fd)
    }
}
