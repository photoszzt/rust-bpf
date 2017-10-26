extern crate regex;

use bcc_sys::bccapi::{bcc_resolve_symname, bcc_symbol, bcc_symbol_option};
use std::os::raw::c_char;
use std::ffi::CString;
use regex::Regex;
use std::sync::Mutex;
use std::collections::HashMap;

#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct SymbolAddress {
    name: *const ::std::os::raw::c_char,
    addr: u64,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct SymbolCache {
    cache: HashMap<String, Vec<SymbolAddress>>,
    current_module: String,
    lock: Mutex<u32>,
}

lazy_static! {
    static ref symbol_cache: SymbolCache = Default::default();
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

fn get_user_symbols_and_address<'a>(module: &str) -> Result<&'a Vec<SymbolAddress>, String> {
    symbol_cache.lock.lock().unwrap();
    if let Some(list) = symbol_cache.cache.get(module) {
        return Ok(list);
    }
    symbol_cache.cache.insert(module.to_string(), Vec::new());
    symbol_cache.current_module = module.to_string();

    let module_c = match CString::new(module) {
        Ok(r) => r,
        Err(e) => return Err(format!("Fail to convert {} to c string: {}", module, e)),
    };
    let res = unsafe {
        bcc_foreach_symbol(module_c.as_ptr(), Some(foreach_symbol_callback))
    };
    if res < 0 {
        return Err(format!("Unable to list symbols for {}", module));
    }
    return Ok(symbol_cache.cache[module])
}

/// foreach_symbol_callback is a gateway function that will be exported to C
/// so that it can be referenced as a function pointer
#[no_mangle]
unsafe extern "C" fn foreach_symbol_callback(symname: *const ::std::os::raw::c_char,
                                             addr: u64) -> ::std::os::raw::c_int {
    let list = symbol_cache.get_mut(symbol_cache.current_module);
    list.push(SymbolAddress {
        name: symname,
        addr: addr,
    });
    return 0;
}

pub fn match_user_symbols(module: &str, match_str: &str) -> Result<Vec<SymbolAddress>, String> {
    let r = match Regex::new(match_str) {
        Ok(r) => r,
        Err(e) => return Err(format!("Fail to compile regex: {}", e)),
    };
    let symbols = get_user_symbols_and_address(module)?;
    for sym in &symbols {
        let symname = match unsafe {
            CStr::from_ptr(sym.name).to_str()
        } {
            Ok(r) => r,
            Err(e) => return Err(format!("Fail to convert from char* to CStr: {}", e)),
        };
        
    }
    Ok(())
}
