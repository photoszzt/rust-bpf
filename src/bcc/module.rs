use std::collections::HashMap;
use std::ffi::CString;

#[derive(Debug, Default, Copy)]
pub struct Module {
    p: usize;
    funcs: HashMap<String, i32>;
    kprobes: HashMap<String, usize>;
    uprobes: HashMap<String, usize>;
}

pub fn new_module(code: &str, cflags: &Vec<CString>) -> Module {
    
}
