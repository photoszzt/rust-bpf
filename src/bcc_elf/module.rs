extern crate nix;

use std::collections::HashMap;
use bpf_bindings::*;
use elf;
use bcc_elf::elf::EbpfMap;
use std::fs::OpenOptions;
use std::io::{Error, ErrorKind};
use perf_event_bindings::{perf_type_id, perf_event_attr, PERF_FLAG_FD_CLOEXEC,
                          perf_event_sample_format};
use bcc_elf::perf_event::{PERF_EVENT_IOC_ENABLE, PERF_EVENT_IOC_SET_BPF};
use std::str::FromStr;
use std::io::{Read, Write};

pub struct Module {
    pub file_name: String,
    pub file: elf::File,
    pub log: Vec<u8>,
    pub maps: HashMap<String, EbpfMap>,
    pub probes: HashMap<String, Kprobe>,
    pub cgroup_programs: HashMap<String, CgroupProgram>,
    pub socket_filters: HashMap<String, SocketFilter>,
    pub tracepoint_programs: HashMap<String, TracepointProgram>,
    pub sched_programs: HashMap<String, SchedProgram>,
}

#[derive(Debug, Default, Clone)]
pub struct Kprobe {
    pub name: String,
    pub insns: usize,
    pub fd: i32,
    pub efd: i32,
}

#[derive(Debug, Default, Clone)]
pub struct CgroupProgram {
    pub name: String,
    pub insns: usize,
    pub fd: i32,
}

#[derive(Debug, Default, Clone)]
pub struct SocketFilter {
    pub name: String,
    pub insns: usize,
    pub fd: i32,
}

#[derive(Debug, Default, Clone)]
pub struct TracepointProgram {
    pub name: String,
    pub insns: usize,
    pub fd: i32,
    pub efd: i32,
}

#[derive(Debug, Default, Clone)]
pub struct SchedProgram {
    pub name: String,
    pub insns: usize,
    pub fd: i32,
}

const kprobe_events_filename: &'static str = "/sys/kernel/debug/tracing/kprobe_events";

fn perf_event_open_tracepoint(tracepoint_id: u64, pid: i32, cpu: u32, group_fd: i32, flags: u64) -> i32 {
    let attr: perf_event_attr =
        perf_event_attr::gen_perf_event_attr_open_tracepoint(perf_type_id::PERF_TYPE_TRACEPOINT,
                                                             perf_event_sample_format::PERF_SAMPLE_RAW,
                                                             1,
                                                             1,
                                                             tracepoint_id as u64);
    unsafe {
        syscall!(PERF_EVENT_OPEN,
                 &attr as *const _ as usize,
                 pid, cpu, group_fd, flags) as i32
    }
}

fn write_kprobe_event(probe_type: &str, event_name: &str, func_name: &str, maxactive_str: &str)
                      -> Result<i32, ::std::io::Error> {
    let f = OpenOptions::new().append(true).open(kprobe_events_filename)?;
    let cmd = format!("{}{}:{} {}", probe_type, maxactive_str, event_name, func_name);
    f.write_all(cmd.as_bytes())?;

    let mut found_kprobeid = true;
    let kprobeIdFile = match OpenOptions::new().read(true)
        .open(format!("/sys/kernel/debug/tracing/events/kprobes/{}/id", event_name)) {
            Ok(res) => res,
            Err(e) => {
                if e.kind() == ErrorKind::NotFound {
                    return Err(Error::new(ErrorKind::Other, "Can't find kprobe id"));
                } else {
                    return Err(e)
                }
            }
        };
    let buffer = String::new();
    kprobeIdFile.read_to_string(&mut buffer)?;
    let kprobe_id = i32::from_str(buffer.trim()).map_err(|e| Error::new(ErrorKind::Other, format!("{}", e)))?;
    return Ok(kprobe_id);
}

fn perf_event_open_tracepoint_ioctl(id: u64, prog_fd: i32) -> Result<i32, String>{
    let efd = perf_event_open_tracepoint(id, -1, 0, -1, PERF_FLAG_FD_CLOEXEC as u64);
    if efd < 0 {
        return Err(format!("perf event open error: {}", nix::errno::errno()));
    }
    let ret = unsafe {
        syscall!(IOCTL, efd, PERF_EVENT_IOC_ENABLE, 0)
    };
    if ret != 0 {
        return Err(format!("Error enabling perf event: {}", nix::errno::errno()));
    }
    let ret = unsafe {
        syscall!(IOCTL, efd, PERF_EVENT_IOC_SET_BPF, prog_fd, 0)
    };
    if ret != 0 {
        return Err(format!("Error attaching bpf program to perf event: {}", nix::errno::errno()));
    }
    Ok(efd)
}

fn write_tracepoint_event(category: &str, name: &str) -> Result<i32, String> {
    let tracepoint_f_str = format!("/sys/kernel/debug/tracing/events/{}/{}/id", category, name);
    let tracepoint_file = OponOptions::new().read(true)
        .open(tracepoint_f_str)
        .map_err(|e| format!("Cannot open tracepoint id {}: {}", tracepoint_f_str, e))?;
    let buffer = String::new();
    tracepoint_file.read_to_string(&mut buffer).map_err(|e| format!("Cannot read tracepoint file: {}", e))?;
    let tracepoint_id = i32::from_str(buffer.trim()).map_err(|e| format!("Invalid tracepoint id: {}", e))?;
    return Ok(tracepoint_id);
}

impl Module {
    /// EnableKprobe enables a kprobe/kretprobe identified by secName.
    /// For kretprobes, you can configure the maximum number of instances
    /// of the function that can be probed simultaneously with maxactive.
    /// If maxactive is 0 it will be set to the default value: if CONFIG_PREEMPT is
    /// enabled, this is max(10, 2*NR_CPUS); otherwise, it is NR_CPUS.
    /// For kprobes, maxactive is ignored.
    pub fn enable_kprobe(&self, sec_name: &str, maxactive: u32) -> Result<(), String> {
        let is_kretprobe = sec_name.starts_with("kretprobe/");
        let probe = self.probes.get_mut(sec_name).unwrap();
        let prog_fd = probe.fd;
        let maxactive_str;
        let probe_type;
        let func_name;
        if is_kretprobe {
            probe_type = "r";
            func_name = sec_name.trim_left_matches("kretprobe/");
            if maxactive > 0 {
                maxactive_str = format!("{}", maxactive);
            }
        } else {
            probe_type = "p";
            func_name = sec_name.trim_left_matches("kprobe/");
        }
        let event_name = format!("{}{}", probe_type, func_name);
        let kprobeid_res = write_kprobe_event(probe_type, &event_name, func_name, &maxactive_str);
        let kprobeid;
        if let Err(e) = kprobeid_res {
            if e.kind() == ErrorKind::Other {
                if let Some(inner_err) = e.get_ref() {
                    if inner_err.description() == "Can't find kprobe id" {
                        kprobeid = write_kprobe_event(probe_type, &event_name, func_name, "").map_err(|e| format!("Fail to write kprobe event: {}", e))?;
                    }
                }
            } else {
                return Err(format!("Fail to write kprobe event: {}", e));
            }
        } else {
            kprobeid = kprobeid_res.unwrap();
        }
        probe.efd = perf_event_open_tracepoint_ioctl(kprobeid as u64, prog_fd)?;
        Ok(())
    }

    pub fn enable_tracepoint(&self, sec_name: &str) -> Result<(), String> {
        
    }
}
