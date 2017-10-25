use bcc_sys::bccapi::{bcc_resolve_symname, bcc_symbol, bcc_symbol_option};
use std::os::raw::c_char;
use std::ffi::CString;

#[derive(Debug, Default, Clone)]
pub struct SymbolAddress {
    name: String,
    addr: u64,
}

/// returns the file and offset to locate symname in module
pub fn resolve_symbol_path(
    module: &str,
    symname: &str,
    addr: u64,
    pid: i32,
) -> Result<(*const c_char, u64), String> {
    let pid = if pid == -1 { 0 } else { pid };
    let mut symbol: bcc_symbol = Default::default();
    let mut symbol_option: bcc_symbol_option = Default::default();
    let module_c = match CString::new(module) {
        Ok(r) => r,
        Err(e) => return Err(format!("Fail to convert {} to c string: {}", module, e)),
    };
    let symname_c = match CString::new(symname) {
        Ok(r) => r,
        Err(e) => return Err(format!("Fail to convert {} to c string: {}", symname, e)),
    };
    let ret = unsafe {
        bcc_resolve_symname(
            module_c.as_ptr(),
            symname_c.as_ptr(),
            addr,
            pid,
            &mut symbol_option as *mut _,
            &mut symbol as *mut _,
        )
    };
    if ret == 0 {
        Ok((symbol.module, symbol.offset))
    } else {
        Err(format!(
            "Unable to locate symbol {} in module {}",
            symname,
            module
        ))
    }
}
