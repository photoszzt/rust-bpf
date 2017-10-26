extern crate regex;

use bcc_sys::bccapi::{bcc_resolve_symname, bcc_symbol, bcc_symbol_option,
bcc_foreach_function_symbol};
use std::os::raw::c_char;
use std::ffi::CString;
use regex::Regex;
use std::sync::Mutex;
use std::collections::HashMap;
use std::ffi::CStr;
use std::sync::Arc;

#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct SymbolAddress {
    pub name: CString,
    pub addr: u64,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct SymbolCache {
    cache: HashMap<String, Vec<SymbolAddress>>,
    current_module: Arc<String>,
}

lazy_static! {
    static ref symbol_cache: Mutex<SymbolCache> = Mutex::new(Default::default());
}

/// returns the file and offset to locate symname in module
pub fn resolve_symbol_path(
    module: &str,
    symname: *const i8,
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
    let ret = unsafe {
        bcc_resolve_symname(
            module_c.as_ptr(),
            symname,
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
            "Unable to locate symbol in module {}",
            module
        ))
    }
}

fn get_user_symbols_and_address<'a>(sc: &'a mut SymbolCache, module: &'a str)
                                    -> Result<&'a Vec<SymbolAddress>, String> {
    let list = sc.cache.entry(module.to_string()).or_insert(Vec::new());
    if list.len() == 0 {
        sc.current_module = Arc::new(module.to_string());

        let module_c = match CString::new(module) {
            Ok(r) => r,
            Err(e) => return Err(format!("Fail to convert {} to c string: {}", module, e)),
        };
        let res = unsafe {
            bcc_foreach_function_symbol(module_c.as_ptr(), Some(foreach_symbol_callback))
        };
        if res < 0 {
            return Err(format!("Unable to list symbols for {}", module));
        }
    }
    return Ok(list);
}

/// foreach_symbol_callback is a gateway function that will be exported to C
/// so that it can be referenced as a function pointer
unsafe extern "C" fn foreach_symbol_callback(symname: *const ::std::os::raw::c_char,
                                             addr: u64) -> ::std::os::raw::c_int {
    let mut sc = match symbol_cache.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let cm = sc.current_module.clone();
    let list = sc.cache.get_mut(&*cm).unwrap();
    let symname_r = match CStr::from_ptr(symname).to_str() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Fail to convert {:p} to Rust str: {}", symname, e);
            return -1;
        }
    };
    list.push(SymbolAddress {
        name: CString::new(symname_r).unwrap(),
        addr: addr,
    });
    return 0;
}

pub fn match_user_symbols(module: &str, match_str: &str) -> Result<Vec<SymbolAddress>, String> {
    let r = match Regex::new(match_str) {
        Ok(r) => r,
        Err(e) => return Err(format!("Fail to compile regex: {}", e)),
    };
    let mut sc = symbol_cache.lock().unwrap();
    let symbols = get_user_symbols_and_address(&mut sc, module)?;
    let mut matched_symbol = Vec::new();
    for sym in symbols {
        if r.is_match(sym.name.to_str().unwrap()) {
            matched_symbol.push(sym.clone());
        }
    }
    Ok(matched_symbol)
}
