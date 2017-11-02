#[macro_use]
extern crate quote;
extern crate rust_bpf;

use rust_bpf::bcc;
use std::ffi::CString;

#[test]
fn test_module_load_bcc() {
    let simple_prog = quote! {
        BPF_TABLE("hash", int, int, table1, 10);
        int func1(void *ctx) {
            return 0;
        }
    }.to_string();
    println!("program string: {}", &simple_prog);
    let code = CString::new(simple_prog).unwrap();
    let cflags = Vec::new();
    let res = bcc::module::new_module(&code, &cflags);
    assert!(res.is_ok(), "Fail to create program: {:?}", res);
    let mut b = res.unwrap();
    let fn_name = CString::new("func1").unwrap();
    let p = b.load_kprobe(fn_name);
    assert!(p.is_ok(), "Fail to load kprobe: {:?}", p);
    let res = b.close();
    assert!(res.is_ok(), "Fail to close module: {:?}", res);
}
