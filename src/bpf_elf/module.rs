extern crate libc;
extern crate nix;
extern crate xmas_elf;

use bpf_elf;
use bpf_elf::bpf::{bpf_prog_attach, bpf_prog_detach};
use bpf_elf::bpf_bindings::*;
use bpf_elf::elf::EbpfMap;
use bpf_elf::perf_event::{PERF_EVENT_IOC_ENABLE, PERF_EVENT_IOC_SET_BPF};
use perf_event_bindings::*;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind};
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::str::FromStr;
use xmas_elf::{header, ElfFile};
use failure::Error;

pub struct Module<'a> {
    pub file: xmas_elf::ElfFile<'a>,
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

impl CloseOptions {
    pub fn new(unpin: bool, pin_path: String) -> CloseOptions {
        CloseOptions { unpin, pin_path }
    }
}

const KPROBE_EVENTS_FILENAME: &'static str = "/sys/kernel/debug/tracing/kprobe_events";

impl CgroupProgram {
    pub fn attach_cgroup_program(
        &self,
        cgroup_path: &str,
        attach_type: bpf_attach_type,
    ) -> Result<(), Error> {
        let f = File::open(cgroup_path)?;
        let cgroup_fd = f.as_raw_fd();
        let ret = bpf_prog_attach(self.fd as u32, cgroup_fd as u32, attach_type);
        if ret < 0 {
            return Err(format_err!(
                "Failed to attach prog to cgroup {}: {}",
                cgroup_path, -ret
            ));
        }
        Ok(())
    }

    pub fn detach_cgroup_program(
        &self,
        cgroup_path: &str,
        attach_type: bpf_attach_type,
    ) -> Result<(), Error> {
        let f = File::open(cgroup_path)?;
        let cgroup_fd = f.as_raw_fd();
        let ret = bpf_prog_detach(self.fd as u32, cgroup_fd as u32, attach_type);
        if ret < 0 {
            return Err(format_err!(
                "Failed to detach prog to cgroup {}: {}",
                cgroup_path, -ret
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

    pub fn attach_socket_filter(&self, sock_fd: i32) -> Result<(), Error> {
        let ret = unsafe { SocketFilter::bpf_attach_socket(sock_fd, self.fd) };
        if ret < 0 {
            return Err(format_err!(
                "Error attaching BPF socket filter: {}",
                nix::errno::errno()
            ));
        }
        Ok(())
    }

    pub fn detach_socket_filter(sock_fd: i32) -> Result<(), Error> {
        let ret = unsafe { SocketFilter::bpf_detach_socket(sock_fd) };
        if ret < 0 {
            return Err(format_err!(
                "Error detaching BPF socket filter: {}",
                nix::errno::errno()
            ));
        }
        Ok(())
    }
}

impl Kprobe {
    fn perf_event_open_tracepoint(id: u64, prog_fd: i32) -> Result<i32, Error> {
        let efd = TracepointProgram::perf_event_open_tracepoint(
            id,
            -1,
            0,
            -1,
            PERF_FLAG_FD_CLOEXEC as u64,
        );
        if efd < 0 {
            return Err(format_err!("perf event open error: {}", nix::errno::errno()));
        }
        let ret = unsafe { syscall!(IOCTL, efd, PERF_EVENT_IOC_ENABLE, 0) as i32 };
        if ret != 0 {
            return Err(format_err!("Error enabling perf event: {}", -ret));
        }
        let ret = unsafe { syscall!(IOCTL, efd, PERF_EVENT_IOC_SET_BPF, prog_fd, 0) as i32 };
        if ret != 0 {
            return Err(format_err!(
                "Error attaching bpf program to perf event: {}",
                -ret
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
        let mut f = OpenOptions::new()
            .append(true)
            .open(KPROBE_EVENTS_FILENAME)?;
        let cmd = format!(
            "{}{}:{} {}",
            probe_type, maxactive_str, event_name, func_name
        );
        f.write_all(cmd.as_bytes())?;

        let mut kprobeIdFile = OpenOptions::new().read(true).open(format!(
            "/sys/kernel/debug/tracing/events/kprobes/{}/id",
            event_name))?;
        let mut buffer = String::new();
        kprobeIdFile.read_to_string(&mut buffer)?;
        return i32::from_str(buffer.trim()).map_err(|e| ::std::io::Error::new(ErrorKind::Other, "Fail to convert to i32"));
    }

    pub fn enable_kprobe(&mut self, sec_name: &str, maxactive: i32) -> Result<(), Error> {
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
                kprobeid = Kprobe::write_kprobe_event(probe_type, &event_name, func_name, "")?;
            } else {
                return Err(format_err!("Fail to write kprobe event: {}", e));
            }
        } else {
            kprobeid = kprobeid_res.unwrap();
        }
        self.efd = Kprobe::perf_event_open_tracepoint(kprobeid as u64, prog_fd)?;
        Ok(())
    }

    pub fn disable_kprobe(event_name: &str) -> Result<(), Error> {
        let mut f = OpenOptions::new()
            .append(true)
            .open(KPROBE_EVENTS_FILENAME)
            .map_err(|e| format_err!("Fail to open file {}: {}", KPROBE_EVENTS_FILENAME, e))?;
        let cmd = format!("-:{}\n", event_name);
        if let Err(e) = f.write_all(cmd.as_bytes()) {
            if e.kind() == ErrorKind::NotFound {
                return Ok(());
            } else {
                return Err(format_err!("Cannot write {} to kprobe_events: {}", cmd, e));
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

    fn write_tracepoint_event(category: &str, name: &str) -> Result<i32, Error> {
        let tracepoint_f_str = format!("/sys/kernel/debug/tracing/events/{}/{}/id", category, name);
        let mut tracepoint_file = OpenOptions::new()
            .read(true)
            .open(&tracepoint_f_str)
            .map_err(|e| format_err!("Cannot open tracepoint id {}: {}", &tracepoint_f_str, e))?;
        let mut buffer = String::new();
        tracepoint_file
            .read_to_string(&mut buffer)
            .map_err(|e| format_err!("Cannot read tracepoint file: {}", e))?;
        let tracepoint_id =
            i32::from_str(buffer.trim()).map_err(|e| format_err!("Invalid tracepoint id: {}", e))?;
        return Ok(tracepoint_id);
    }

    pub fn enable_tracepoint(&mut self, sec_name: &str) -> Result<(), Error> {
        let tracepoint_group: Vec<&str> = sec_name.splitn(3, "/").collect();
        let category = tracepoint_group[1];
        let name = tracepoint_group[2];
        let tracepoint_id = TracepointProgram::write_tracepoint_event(category, name)?;
        self.efd = Kprobe::perf_event_open_tracepoint(tracepoint_id as u64, self.fd)?;
        Ok(())
    }
}

impl EbpfMap {
    pub fn unpin(&self, pin_path: &str, sec_name: &str) -> Result<(), Error> {
        let map_path = self.m.def.get_map_path(sec_name, Some(pin_path))?;
        ::std::fs::remove_file(map_path)?;
        Ok(())
    }
}

impl<'a> Module<'a> {
    pub fn read_from_file<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        ::std::fs::File::open(path)?.read_to_end(&mut buf)?;
        Ok(buf)
    }

    pub fn new(buf: &'a Vec<u8>) -> Result<Module<'a>, Error> {
        let elf_file = ElfFile::new(buf).map_err(|e| format_err!("Fail to parse elf file: {}", e))?;
        header::sanity_check(&elf_file).map_err(|e| format_err!("{}", e))?;
        Ok(Module {
            file: elf_file,
            log: vec![0; 524288],
            maps: HashMap::new(),
            probes: HashMap::new(),
            cgroup_programs: HashMap::new(),
            socket_filters: HashMap::new(),
            tracepoint_programs: HashMap::new(),
            sched_programs: HashMap::new(),
        })
    }

    /// EnableKprobe enables a kprobe/kretprobe identified by secName.
    /// For kretprobes, you can configure the maximum number of instances
    /// of the function that can be probed simultaneously with maxactive.
    /// If maxactive is 0 it will be set to the default value: if CONFIG_PREEMPT is
    /// enabled, this is max(10, 2*NR_CPUS); otherwise, it is NR_CPUS.
    /// For kprobes, maxactive is ignored.
    pub fn enable_kprobe(&mut self, sec_name: &str, maxactive: i32) -> Result<(), Error> {
        let probe = self.probes
            .get_mut(sec_name)
            .ok_or(format_err!("no such kprobe {}", sec_name))?;
        return probe.enable_kprobe(sec_name, maxactive);
    }

    pub fn enable_tracepoint(&mut self, sec_name: &str) -> Result<(), Error> {
        let prog = self.tracepoint_programs
            .get_mut(sec_name)
            .ok_or(format_err!("No such tracepoint program {}", sec_name))?;
        return prog.enable_tracepoint(sec_name);
    }

    pub fn enable_kprobes(&mut self, maxactive: i32) -> Result<(), Error> {
        for (name, m) in &mut self.probes {
            m.enable_kprobe(&name, maxactive)?;
        }
        Ok(())
    }

    pub fn close_probes(&mut self) -> Result<(), Error> {
        for (name, probe) in self.probes.iter_mut() {
            if probe.efd != -1 {
                if let Err(e) = nix::unistd::close(probe.efd) {
                    return Err(format_err!("Error closing perf event fd: {}", e));
                }
                probe.efd = -1;
            }
            if let Err(e) = nix::unistd::close(probe.fd) {
                return Err(format_err!("Error closing probe fd: {}", e));
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

    pub fn close_tracepoint_programs(&mut self) -> Result<(), Error> {
        for (_, program) in self.tracepoint_programs.iter_mut() {
            if program.efd != -1 {
                if let Err(e) = nix::unistd::close(program.efd) {
                    return Err(format_err!("Error closing perf event fd: {}", e));
                }
                program.efd = -1;
            }
            if let Err(e) = nix::unistd::close(program.fd) {
                return Err(format_err!("Error closing tracepoint program fd: {}", e));
            }
        }
        Ok(())
    }

    pub fn close_cgroup_programs(&self) -> Result<(), Error> {
        for (_, program) in &self.cgroup_programs {
            if let Err(e) = nix::unistd::close(program.fd) {
                return Err(format_err!("Error closing cgroup program fd: {}", e));
            }
        }
        Ok(())
    }

    pub fn close_socket_filters(&self) -> Result<(), Error> {
        for (_, filter) in &self.socket_filters {
            if let Err(e) = nix::unistd::close(filter.fd) {
                return Err(format_err!("Error closing socket filter fd: {}", e));
            }
        }
        Ok(())
    }

    pub fn close_maps(
        &self,
        options: Option<&'a HashMap<String, CloseOptions>>,
    ) -> Result<(), Error> {
        for (name, m) in &self.maps {
            if let Some(ops) = options {
                if let Some(option) = ops.get(&format!("maps/{}", name)) {
                    if option.unpin {
                        let map_def = m.m.def;
                        let pin_path = match map_def.pinning {
                            bpf_elf::elf::PIN_CUSTOM_NS => &option.pin_path,
                            bpf_elf::elf::PIN_GLOBAL_NS => "",
                            bpf_elf::elf::PIN_OBJECT_NS => {
                                return Err(format_err!("unpinning with PIN_OBJECT_NS is to be implemented"))
                            }
                            _ => return Err(format_err!("Unrecognized pinning: {}", map_def.pinning)),
                        };
                        m.unpin(pin_path, &name)?;
                    }
                }
            }
            for fd in &m.pmu_fds {
                if let Err(e) = nix::unistd::close(*fd) {
                    return Err(format_err!("Error closing perf event fd: {}", e));
                }
            }
            if let Err(e) = nix::unistd::close(m.m.fd) {
                return Err(format_err!("Error closing map fd: {}", e));
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
    pub fn close(&mut self) -> Result<(), Error> {
        return self.close_ext(None);
    }

    pub fn close_ext(
        &mut self,
        options: Option<&'a HashMap<String, CloseOptions>>,
    ) -> Result<(), Error> {
        self.close_maps(options)?;
        self.close_probes()?;
        self.close_cgroup_programs()?;
        self.close_tracepoint_programs()?;
        self.close_socket_filters()?;
        Ok(())
    }
}
