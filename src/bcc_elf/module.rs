use std::collections::HashMap;
use std::fs::File;
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
}

#[derive(Debug, Default, Clone)]
pub struct Kprobe {
    name: String,
    insns: usize,
    fd: i32,
    efd: i32,
}

#[derive(Debug, Default, Clone)]
pub struct CgroupProgram {
    name: String,
    insns: usize,
    fd: i32,
}

#[derive(Debug, Default, Clone)]
pub struct SocketFilter {
    name: String,
    insns: usize,
    fd: i32,
}

#[derive(Debug, Default, Clone)]
pub struct TracepointProgram {
    name: String,
    insns: usize,
    fd: i32,
    efd: i32,
}

impl Module {
    pub fn new_module() -> Module {
        Default::default()
    }
}
