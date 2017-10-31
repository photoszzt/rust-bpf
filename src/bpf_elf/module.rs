extern crate bcc_sys;
extern crate libc;
extern crate nix;

use std::collections::HashMap;
use bcc_sys::bccapi::*;
use elf;
use bpf_elf::elf::EbpfMap;
use std::fs::{File, OpenOptions};
use std::io::{Error, ErrorKind};
use perf_event_bindings::*;
use bpf_elf::perf_event::{PERF_EVENT_IOC_ENABLE, PERF_EVENT_IOC_SET_BPF};
use std::str::FromStr;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use bpf::{bpf_prog_attach, bpf_prog_detach};
use bpf_elf;

pub struct Module {
    pub file_name: String,
    pub file: Option<elf::File>,
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
    pub insns: usize,
    pub fd: i32,
    pub efd: i32,
}

#[derive(Debug, Default, Clone)]
pub struct CgroupProgram {
    pub insns: usize,
    pub fd: i32,
}

#[derive(Debug, Default, Clone)]
pub struct SocketFilter {
    pub insns: usize,
    pub fd: i32,
}

#[derive(Debug, Default, Clone)]
pub struct TracepointProgram {
    pub insns: usize,
    pub fd: i32,
    pub efd: i32,
}

#[derive(Debug, Default, Clone)]
pub struct SchedProgram {
    pub insns: usize,
    pub fd: i32,
}

#[derive(Debug, Default, Clone)]
pub struct CloseOptions {
    unpin: bool,
    pin_path: String,
}

const kprobe_events_filename: &'static str = "/sys/kernel/debug/tracing/kprobe_events";

pub fn new_module(file_name: String) -> Module {
    Module {
        file_name,
        file: None,
        log: Vec::new(),
        maps: HashMap::new(),
        probes: HashMap::new(),
        cgroup_programs: HashMap::new(),
        socket_filters: HashMap::new(),
        tracepoint_programs: HashMap::new(),
        sched_programs: HashMap::new(),
    }
}

impl CgroupProgram {
    pub fn attach_cgroup_program(
        &self,
        cgroup_path: &str,
        attach_type: bpf_attach_type,
    ) -> Result<(), String> {
        let f = File::open(cgroup_path)
            .map_err(|e| format!("Error opening cgroup {}: {}", cgroup_path, e))?;
        let cgroup_fd = f.as_raw_fd();
        let ret = bpf_prog_attach(self.fd as u32, cgroup_fd as u32, attach_type);
        if ret < 0 {
            return Err(format!(
                "Failed to attach prog to cgroup {}: {}",
                cgroup_path,
                nix::errno::errno()
            ));
        }
        Ok(())
    }

    pub fn detach_cgroup_program(
        &self,
        cgroup_path: &str,
        attach_type: bpf_attach_type,
    ) -> Result<(), String> {
        let f = File::open(cgroup_path)
            .map_err(|e| format!("Error opening cgroup {}: {}", cgroup_path, e))?;
        let cgroup_fd = f.as_raw_fd();
        let ret = bpf_prog_detach(self.fd as u32, cgroup_fd as u32, attach_type);
        if ret < 0 {
            return Err(format!(
                "Failed to detach prog to cgroup {}: {}",
                cgroup_path,
                nix::errno::errno()
            ));
        }
        Ok(())
    }
}

impl SocketFilter {
    unsafe fn bpf_attach_socket(sock: i32, fd: i32) -> i32 {
        libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_BPF,
            &fd as *const i32 as *const _,
            ::std::mem::size_of::<i32>() as u32,
        )
    }

    unsafe fn bpf_detach_socket(sock: i32) -> i32 {
        libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_DETACH_BPF,
            ::std::ptr::null(),
            ::std::mem::size_of::<i32>() as u32,
        )
    }

    pub fn attach_socket_filter(&self, sock_fd: i32) -> Result<(), String> {
        let ret = unsafe { SocketFilter::bpf_attach_socket(sock_fd, self.fd) };
        if ret < 0 {
            return Err(format!(
                "Error attaching BPF socket filter: {}",
                nix::errno::errno()
            ));
        }
        Ok(())
    }

    pub fn detach_socket_filter(sock_fd: i32) -> Result<(), String> {
        let ret = unsafe { SocketFilter::bpf_detach_socket(sock_fd) };
        if ret < 0 {
            return Err(format!(
                "Error detaching BPF socket filter: {}",
                nix::errno::errno()
            ));
        }
        Ok(())
    }
}

impl Kprobe {
    fn perf_event_open_tracepoint(id: u64, prog_fd: i32) -> Result<i32, String> {
        let efd = TracepointProgram::perf_event_open_tracepoint(
            id,
            -1,
            0,
            -1,
            PERF_FLAG_FD_CLOEXEC as u64,
        );
        if efd < 0 {
            return Err(format!("perf event open error: {}", nix::errno::errno()));
        }
        let ret = unsafe { syscall!(IOCTL, efd, PERF_EVENT_IOC_ENABLE, 0) };
        if ret != 0 {
            return Err(format!(
                "Error enabling perf event: {}",
                nix::errno::errno()
            ));
        }
        let ret = unsafe { syscall!(IOCTL, efd, PERF_EVENT_IOC_SET_BPF, prog_fd, 0) };
        if ret != 0 {
            return Err(format!(
                "Error attaching bpf program to perf event: {}",
                nix::errno::errno()
            ));
        }
        Ok(efd)
    }

    fn write_kprobe_event(
        probe_type: &str,
        event_name: &str,
        func_name: &str,
        maxactive_str: &str,
    ) -> Result<i32, ::std::io::Error> {
        let mut f = OpenOptions::new().append(true).open(kprobe_events_filename)?;
        let cmd = format!(
            "{}{}:{} {}",
            probe_type,
            maxactive_str,
            event_name,
            func_name
        );
        f.write_all(cmd.as_bytes())?;

        let mut kprobeIdFile = match OpenOptions::new().read(true).open(format!(
            "/sys/kernel/debug/tracing/events/kprobes/{}/id",
            event_name
        )) {
            Ok(res) => res,
            Err(e) => if e.kind() == ErrorKind::NotFound {
                return Err(Error::new(ErrorKind::Other, "Can't find kprobe id"));
            } else {
                return Err(e);
            },
        };
        let mut buffer = String::new();
        kprobeIdFile.read_to_string(&mut buffer)?;
        let kprobe_id = i32::from_str(buffer.trim())
            .map_err(|e| Error::new(ErrorKind::Other, format!("{}", e)))?;
        return Ok(kprobe_id);
    }

    pub fn enable_kprobe(&mut self, sec_name: &str, maxactive: i32) -> Result<(), String> {
        let prog_fd = self.fd;
        let (probe_type, func_name, maxactive_str) = if sec_name.starts_with("kretprobe/") {
            let probe_type = "r";
            let func_name = sec_name.trim_left_matches("kretprobe/");
            let maxactive_str = if maxactive > 0 {
                format!("{}", maxactive)
            } else {
                "".to_string()
            };
            (probe_type, func_name, maxactive_str)
        } else {
            let probe_type = "p";
            let func_name = sec_name.trim_left_matches("kprobe/");
            (probe_type, func_name, "".to_string())
        };
        let event_name = format!("{}{}", probe_type, func_name);
        let kprobeid_res =
            Kprobe::write_kprobe_event(probe_type, &event_name, func_name, &maxactive_str);
        let kprobeid;
        if let Err(e) = kprobeid_res {
            if e.kind() == ErrorKind::Other && e.get_ref().map_or(false, |inner_err| {
                inner_err.description() == "Can't find kprobe id"
            }) {
                kprobeid = Kprobe::write_kprobe_event(probe_type, &event_name, func_name, "")
                    .map_err(|e| format!("Fail to write kprobe event: {}", e))?;
            } else {
                return Err(format!("Fail to write kprobe event: {}", e));
            }
        } else {
            kprobeid = kprobeid_res.unwrap();
        }
        self.efd = Kprobe::perf_event_open_tracepoint(kprobeid as u64, prog_fd)?;
        Ok(())
    }

    pub fn disable_kprobe(event_name: &str) -> Result<(), String> {
        let mut f = OpenOptions::new()
            .append(true)
            .open(kprobe_events_filename)
            .map_err(|e| {
                format!("Fail to open file {}: {}", kprobe_events_filename, e)
            })?;
        let cmd = format!("-:{}\n", event_name);
        if let Err(e) = f.write_all(cmd.as_bytes()) {
            if e.kind() == ErrorKind::NotFound {
                return Ok(());
            } else {
                return Err(format!("Cannot write {} to kprobe_events: {}", cmd, e));
            }
        }
        Ok(())
    }
}

impl TracepointProgram {
    fn perf_event_open_tracepoint(
        tracepoint_id: u64,
        pid: i32,
        cpu: u32,
        group_fd: i32,
        flags: u64,
    ) -> i32 {
        let attr: perf_event_attr = perf_event_attr::gen_perf_event_attr_open_tracepoint(
            perf_type_id_PERF_TYPE_TRACEPOINT,
            perf_event_sample_format_PERF_SAMPLE_RAW,
            1,
            1,
            tracepoint_id as u64,
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

    fn write_tracepoint_event(category: &str, name: &str) -> Result<i32, String> {
        let tracepoint_f_str = format!("/sys/kernel/debug/tracing/events/{}/{}/id", category, name);
        let mut tracepoint_file = OpenOptions::new()
            .read(true)
            .open(&tracepoint_f_str)
            .map_err(|e| {
                format!("Cannot open tracepoint id {}: {}", &tracepoint_f_str, e)
            })?;
        let mut buffer = String::new();
        tracepoint_file
            .read_to_string(&mut buffer)
            .map_err(|e| format!("Cannot read tracepoint file: {}", e))?;
        let tracepoint_id =
            i32::from_str(buffer.trim()).map_err(|e| format!("Invalid tracepoint id: {}", e))?;
        return Ok(tracepoint_id);
    }

    pub fn enable_tracepoint(&mut self, sec_name: &str) -> Result<(), String> {
        let tracepoint_group: Vec<&str> = sec_name.splitn(3, "/").collect();
        let category = tracepoint_group[1];
        let name = tracepoint_group[2];
        let tracepoint_id = TracepointProgram::write_tracepoint_event(category, name)?;
        self.efd = Kprobe::perf_event_open_tracepoint(tracepoint_id as u64, self.fd)?;
        Ok(())
    }
}

impl EbpfMap {
    pub fn unpin(&self, pin_path: &str, sec_name: &str) -> Result<(), String> {
        let map_path = self.m.def.get_map_path(sec_name, pin_path)?;
        ::std::fs::remove_file(map_path).map_err(|e| format!("Fail to remove file: {}", e))?;
        Ok(())
    }
}

impl Module {
    /// EnableKprobe enables a kprobe/kretprobe identified by secName.
    /// For kretprobes, you can configure the maximum number of instances
    /// of the function that can be probed simultaneously with maxactive.
    /// If maxactive is 0 it will be set to the default value: if CONFIG_PREEMPT is
    /// enabled, this is max(10, 2*NR_CPUS); otherwise, it is NR_CPUS.
    /// For kprobes, maxactive is ignored.
    pub fn enable_kprobe(&mut self, sec_name: &str, maxactive: i32) -> Result<(), String> {
        let probe = self.probes
            .get_mut(sec_name)
            .ok_or(format!("no such kprobe {}", sec_name))?;
        return probe.enable_kprobe(sec_name, maxactive);
    }

    pub fn enable_tracepoint(&mut self, sec_name: &str) -> Result<(), String> {
        let prog = self.tracepoint_programs
            .get_mut(sec_name)
            .ok_or(format!("No such tracepoint program {}", sec_name))?;
        return prog.enable_tracepoint(sec_name);
    }

    pub fn enable_kprobes(&mut self, maxactive: i32) -> Result<(), String> {
        for (name, m) in &mut self.probes {
            m.enable_kprobe(&name, maxactive)?;
        }
        Ok(())
    }

    pub fn close_probes(&mut self) -> Result<(), String> {
        for (name, probe) in self.probes.iter_mut() {
            if probe.efd != -1 {
                if let Err(e) = nix::unistd::close(probe.efd) {
                    return Err(format!("Error closing perf event fd: {}", e));
                }
                probe.efd = -1;
            }
            if let Err(e) = nix::unistd::close(probe.fd) {
                return Err(format!("Error closing probe fd: {}", e));
            }
            let is_kretprobe = name.starts_with("kretprobe/");
            if is_kretprobe {
                let funcName = name.trim_left_matches("kretprobe/");
                Kprobe::disable_kprobe(&format!("r{}", &funcName))?;
            } else {
                let funcName = name.trim_left_matches("kprobe/");
                Kprobe::disable_kprobe(&format!("p{}", &funcName))?;
            }
        }
        Ok(())
    }

    pub fn close_tracepoint_programs(&mut self) -> Result<(), String> {
        for (_, program) in self.tracepoint_programs.iter_mut() {
            if program.efd != -1 {
                if let Err(e) = nix::unistd::close(program.efd) {
                    return Err(format!("Error closing perf event fd: {}", e));
                }
                program.efd = -1;
            }
            if let Err(e) = nix::unistd::close(program.fd) {
                return Err(format!("Error closing tracepoint program fd: {}", e));
            }
        }
        Ok(())
    }

    pub fn close_cgroup_programs(&self) -> Result<(), String> {
        for (_, program) in &self.cgroup_programs {
            if let Err(e) = nix::unistd::close(program.fd) {
                return Err(format!("Error closing cgroup program fd: {}", e));
            }
        }
        Ok(())
    }

    pub fn close_socket_filters(&self) -> Result<(), String> {
        for (_, filter) in &self.socket_filters {
            if let Err(e) = nix::unistd::close(filter.fd) {
                return Err(format!("Error closing socket filter fd: {}", e));
            }
        }
        Ok(())
    }

    pub fn close_maps<'a>(
        &self,
        options: Option<&'a HashMap<String, CloseOptions>>,
    ) -> Result<(), String> {
        for (name, m) in &self.maps {
            if let Some(ops) = options {
                if let Some(option) = ops.get(&format!("maps/{}", name)) {
                    if option.unpin {
                        let map_def = m.m.def;
                        let pin_path = match map_def.pinning {
                            bpf_elf::elf::PIN_CUSTOM_NS => &option.pin_path,
                            bpf_elf::elf::PIN_GLOBAL_NS => "",
                            bpf_elf::elf::PIN_OBJECT_NS => {
                                return Err(
                                    "unpinning with PIN_OBJECT_NS is to be implemented".to_string(),
                                )
                            }
                            _ => return Err(format!("Unrecognized pinning: {}", map_def.pinning)),
                        };
                        m.unpin(pin_path, &name)?;
                    }
                }
            }
            for fd in &m.pmu_fds {
                if let Err(e) = nix::unistd::close(*fd) {
                    return Err(format!("Error closing perf event fd: {}", e));
                }
            }
            if let Err(e) = nix::unistd::close(m.m.fd) {
                return Err(format!("Error closing map fd: {}", e));
            }
        }
        Ok(())
    }

    // Close takes care of terminating all underlying BPF programs and structures.
    // That is:
    //
    // * Closing map file descriptors and unpinning them where applicable
    // * Detaching BPF programs from kprobes and closing their file descriptors
    // * Closing cgroup-bpf file descriptors
    // * Closing socket filter file descriptors
    //
    // It doesn't detach BPF programs from cgroups or sockets because they're
    // considered resources the user controls.
    // It also doesn't unpin pinned maps. Use CloseExt and set Unpin to do this.
    pub fn close(&mut self) -> Result<(), String> {
        return self.close_ext(None);
    }

    pub fn close_ext<'a>(
        &mut self,
        options: Option<&'a HashMap<String, CloseOptions>>,
    ) -> Result<(), String> {
        self.close_maps(options)?;
        self.close_probes()?;
        self.close_cgroup_programs()?;
        self.close_tracepoint_programs()?;
        self.close_socket_filters()?;
        Ok(())
    }
}
