use std::collections::HashMap;
use bpf_bindings::*;
use elf;
use bcc_elf::elf::EbpfMap;

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
