use bpf_elf::module::Module;

pub struct PerfMap<'a> {
    name: String,
    program: &'a Module,
    page_count: u32,
}
