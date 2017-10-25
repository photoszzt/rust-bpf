use bpf_elf::module::Module;

pub struct PerfMap {
    name: String,
    program: Module,
    page_count: u32,
}
