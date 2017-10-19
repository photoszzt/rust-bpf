extern crate nix;

use std::collections::HashMap;
use bpf_bindings::*;
use elf;
use bcc_elf::elf::EbpfMap;
use std::fs::OpenOptions;
use perf_event_bindings::PERF_FLAG_FD_CLOEXEC;

use perf_event::{PERF_EVENT_IOC_ENABLE, PERF_EVENT_IOC_SET_BPF};

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
                      -> Result<i32, String> {
    let f = OpenOptions.append(true).open(kprobe_events_filename)
        .map_err(|e| format!("Fail to open file: ", e))?;
    let cmd = format!("{}{}:{} {}", probe_type, maxactive_str, event_name, func_name);
    f.write_all(cmd.as_bytes()).map_err(|e| format!("Fail writing string to file: {}", e))?;

    let kprobeIdFile = OpenOptions::new().read(true)
        .open(format!("/sys/kernel/debug/tracing/events/kprobes/{}/id", event_name));
    let buffer = String::new();
    // TODO
    kprobeIdFile.read_to_string(&mut buffer)
        .map_err(|e| format!("Fail to read file content to string: {}", e))?;
    let kprobe_id = i32::from_str(buffer.trim())
        .map_err(|e| format!("Fail to convert kprobe_id to integer: {}", e))?;
    return Ok(kprobe_id);
}

fn perf_event_open_tracepoint(id: u32, prog_fd: i32) -> Result<i32, String>{
    let efd = perf_event_open_tracepoint(id, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
    if efd < 0 {
        return Err("perf event open error: {}", ::std::io::Error::last_os_error().raw_os_error().unwrap());
    }
    let ret = unsafe {
        syscall!(IOCTL, efd, PERF_EVENT_IOC_ENABLE, 0)
    };
    if ret != 0 {
        return Err("Error enabling perf event: {}", nix::errno);
    }
    let ret = unsafe {
        syscall!(IOCTL, efd, PERF_EVENT_IOC_SET_BPF, prog_fd, 0)
    };
    if ret != 0 {
        return Err("Error attaching bpf program to perf event: {}", nix::errno);
    }
    Ok(efd)
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
        let probe = self.probes[sec_name];
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
        let kprobeid = write_kprobe_event(probe_type, event_name, func_name, maxactive_str)?;
    }
}
