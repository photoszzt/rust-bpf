extern crate bcc_sys;

use bcc::module::Module;
use bcc::module::TableDesc;
use bcc_sys::bccapi::{bpf_table_key_size_id, bpf_table_leaf_size_id,
bpf_update_elem, bpf_delete_elem,}
use std::ffi::CString;

use std::os::raw::c_void;

pub struct Table<'a> {
    pub id: usize,
    pub module: &'a Module,
}

pub fn new_table<'a> (id: i32, module: &'a Module) -> Table {
    Table {
        id,
    }
}

impl Table {
    pub fn table_desc(&self) -> Result<TableDesc, String> {
        self.module.table_desc(self.module, self.id)
    } 

    pub fn key_to_bytes(&self, key_str: &str) -> Result<Vec<u8>, String> {
        let key_size = unsafe {
            bpf_table_key_size_id(self.module.p as *mut c_void, self.id)
        };
        let key = vec![0; key_size];
        let key_c = match CString::from(key_str) {
            Ok(r) => r,
            Err(e) => return Err(format!("Fail to convert {} to c string: {}", key_str, e)),
        };
        let r  = unsafe {
            bpf_table_key_sscanf(self.module, self.id, key_c.as_ptr(), key.as_ptr());
        };
        if r != 0 {
            return Err(format!("error scanning key {} from string", key_str));
        }
        return Ok(key)
    }

    pub fn leaf_to_bytes(&self, leaf_str: &str) -> Result<Vec<i8>, String> {
        let leaf_size = unsafe {
            bpf_table_leaf_size_id(self.module.p as *mut c_void, self.id)
        };
        let leaf = vec![0; leaf_size];
        let leaf_c = match CString::from(leaf_str) {
            Ok(r) => r,
            Err(e) => return Err(format!("Fail to convert {} to c string: {}", leaf_str, e)),
        };
        let r = unsafe {
            bpf_table_leaf_sscanf(self.module, self.id, leaf_c.as_ptr(), leaf.as_ptr())
        };
        if r != 0 {
            return Err(format!("error scanning leaf {} from string", key_str));
        }
        return Ok(leaf)
    }

    pub fn get(&self, key_str: &str) -> Result<Option<String>, String> {
        let fd = unsafe {
            bpf_table_fd_id(self.module, self.id)
        };
        let leaf_size = unsafe {
            bpf_table_leaf_size_id(self.module, self.id)
        };
        let key = self.key_to_bytes(key_str)?;
        let leaf = vec![0; leaf_size];
        let r = unsafe {
            bpf_lookup_elem(fd, key.as_ptr(), leaf.as_ptr())
        };
        if r != 0 {
            return Ok(None);
        }
        let leaf_str = vec![0; leaf_size*8];
        let r = unsafe {
            bpf_table_leaf_snprintf(self.module,
            self.id, leaf_str.as_ptr(), leaf_str.len(), leaf.as_ptr())
        };
        if r != 0 {
            return Ok(None)
        }
        let value = match String::from_utf8(leaf_str) {
            Ok(v) => v,
            Err(e) => return Err(format!("Fail to convert to String")),
        };
        return Ok(Some(value));
    }

    pub fn set(&self, key_str: &str, leaf_str: &str) -> Result<(), String> {
        let fd = unsafe {
            bpf_table_fd_id(self.module.p as *mut c_void, self.id)
        };
        let key = self.key_to_bytes(key_str)?;
        let leaf = self.leaf_to_bytes(leaf_str)?;
        let r = unsafe {
            bpf_update_elem(fd, key.as_ptr(), leaf.as_ptr(), 0)
        };
        if r != 0 {
            return Err(format!("Table.set: unable to update element ({}={}): {}",
             key_str, leaf_str, r));
        }
        Ok(())
    }

    pub fn delete(&self, key_str: &str) -> Result<(), String> {
        let fd = unsafe {
            bpf_table_fd_id(self.module.p as *mut c_void, self.id)
        };
        let key = key_to_bytes(key_str)?;
        let r = unsafe {
            bpf_delete_elem(fd, key.as_ptr())
        };
        if r != 0 {
            return Err(format!("Table.delete: unable to delete element ({}): {}", key_str, r));
        }
        Ok(())
    }
}