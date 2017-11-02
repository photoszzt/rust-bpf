extern crate bcc_sys;

use bcc::module::Module;
use bcc::module::TableDesc;
use bcc_sys::bccapi::{bpf_table_key_size_id, bpf_table_leaf_size_id, bpf_update_elem, bpf_delete_elem, bpf_table_key_sscanf, bpf_table_leaf_sscanf, bpf_table_fd_id, bpf_lookup_elem, bpf_table_leaf_snprintf, bpf_get_next_key, bpf_get_first_key, bpf_table_key_snprintf};
use std::ffi::CString;

use std::os::raw::c_void;

pub struct Table<'a> {
    pub id: usize,
    pub module: &'a Module,
}

pub struct TableIterator<'a> {
    table: &'a Table<'a>,
    key: Vec<u8>,
    fd: i32,
    key_size: usize,
    leaf_size: usize,
    init: bool,
}

pub fn new_table<'a>(id: usize, module: &'a Module) -> Table {
    Table { id, module }
}

impl<'a> Table<'a> {
    pub fn table_desc(&self) -> Result<TableDesc, String> {
        self.module.table_desc(self.id as u64)
    }

    fn key_to_bytes(&self, key_str: &str) -> Result<Vec<u8>, String> {
        let key_size = unsafe { bpf_table_key_size_id(self.module.p as *mut c_void, self.id) };
        let key = vec![0; key_size];
        let key_c = match CString::new(key_str) {
            Ok(r) => r,
            Err(e) => return Err(format!("Fail to convert {} to c string: {}", key_str, e)),
        };
        let r = unsafe {
            bpf_table_key_sscanf(
                self.module.p as *mut c_void,
                self.id,
                key_c.as_ptr(),
                key.as_ptr() as *mut _,
            )
        };
        if r != 0 {
            return Err(format!("error scanning key {} from string", key_str));
        }
        return Ok(key);
    }

    fn leaf_to_bytes(&self, leaf_str: &str) -> Result<Vec<i8>, String> {
        let leaf_size = unsafe { bpf_table_leaf_size_id(self.module.p as *mut c_void, self.id) };
        let leaf = vec![0; leaf_size];
        let leaf_c = match CString::new(leaf_str) {
            Ok(r) => r,
            Err(e) => return Err(format!("Fail to convert {} to c string: {}", leaf_str, e)),
        };
        let r = unsafe {
            bpf_table_leaf_sscanf(
                self.module.p as *mut c_void,
                self.id,
                leaf_c.as_ptr(),
                leaf.as_ptr() as *mut _,
            )
        };
        if r != 0 {
            return Err(format!("error scanning leaf {} from string", leaf_str));
        }
        return Ok(leaf);
    }

    pub fn get(&self, key_str: &str) -> Result<Option<String>, String> {
        let fd = unsafe { bpf_table_fd_id(self.module.p as *mut c_void, self.id) };
        let leaf_size = unsafe { bpf_table_leaf_size_id(self.module.p as *mut c_void, self.id) };
        let key = self.key_to_bytes(key_str)?;
        let leaf = vec![0; leaf_size];
        let r = unsafe { bpf_lookup_elem(fd, key.as_ptr() as *mut _, leaf.as_ptr() as *mut _) };
        if r != 0 {
            return Ok(None);
        }
        let leaf_str = vec![0; leaf_size * 8];
        let r = unsafe {
            bpf_table_leaf_snprintf(
                self.module.p as *mut c_void,
                self.id,
                leaf_str.as_ptr() as *mut _,
                leaf_str.len(),
                leaf.as_ptr() as *const _,
            )
        };
        if r != 0 {
            return Ok(None);
        }
        let value = match String::from_utf8(leaf_str) {
            Ok(v) => v,
            Err(e) => return Err(format!("Fail to convert to String: {}", e)),
        };
        return Ok(Some(value));
    }

    pub fn set(&self, key_str: &str, leaf_str: &str) -> Result<(), String> {
        let fd = unsafe { bpf_table_fd_id(self.module.p as *mut c_void, self.id) };
        let key = self.key_to_bytes(key_str)?;
        let leaf = self.leaf_to_bytes(leaf_str)?;
        let r = unsafe { bpf_update_elem(fd, key.as_ptr() as *mut _, leaf.as_ptr() as *mut _, 0) };
        if r != 0 {
            return Err(format!(
                "Table.set: unable to update element ({}={}): {}",
                key_str,
                leaf_str,
                r
            ));
        }
        Ok(())
    }

    pub fn delete(&self, key_str: &str) -> Result<(), String> {
        let fd = unsafe { bpf_table_fd_id(self.module.p as *mut c_void, self.id) };
        let key = self.key_to_bytes(key_str)?;
        let r = unsafe { bpf_delete_elem(fd, key.as_ptr() as *mut _) };
        if r != 0 {
            return Err(format!(
                "Table.delete: unable to delete element ({}): {}",
                key_str,
                r
            ));
        }
        Ok(())
    }
}

impl<'a> IntoIterator for &'a Table<'a> {
    type Item = (String, String);
    type IntoIter = TableIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        let p = self.module.p as *mut c_void;
        let fd = unsafe { bpf_table_fd_id(p, self.id) };
        let key_size = unsafe { bpf_table_key_size_id(p, self.id) };
        let leaf_size = unsafe { bpf_table_leaf_size_id(p, self.id) };
        TableIterator {
            table: self,
            key: vec![0; key_size],
            fd,
            key_size,
            leaf_size,
            init: false,
        }
    }
}

impl<'a> Iterator for TableIterator<'a> {
    type Item = (String, String);

    fn next(&mut self) -> Option<Self::Item> {
        let p = self.table.module.p as *mut c_void;
        let leaf = vec![0u8; self.leaf_size];
        let key_str = vec![0; self.key_size * 8];
        let leaf_str = vec![0; self.leaf_size * 8];
        let mut r;
        if !self.init {
            r = unsafe { bpf_get_first_key(self.fd, self.key.as_ptr() as *mut _, self.key.len()) };
            if r < 0 {
                return None;
            }
            self.init = true;
        } else {
            r = unsafe {
                bpf_get_next_key(
                    self.fd,
                    self.key.as_ptr() as *mut _,
                    self.key.as_ptr() as *mut _,
                )
            };
            if r != 0 {
                return None;
            }
        }
        r = unsafe {
            bpf_lookup_elem(
                self.fd,
                self.key.as_ptr() as *mut _,
                leaf.as_ptr() as *mut _,
            )
        };
        if r != 0 {
            return None;
        }
        r = unsafe {
            bpf_table_key_snprintf(
                p,
                self.table.id,
                key_str.as_ptr() as *mut _,
                key_str.len(),
                self.key.as_ptr() as *mut _,
            )
        };
        if r != 0 {
            return None;
        }
        r = unsafe {
            bpf_table_leaf_snprintf(
                p,
                self.table.id,
                leaf_str.as_ptr() as *mut _,
                leaf_str.len(),
                leaf.as_ptr() as *mut _,
            )
        };
        if r != 0 {
            return None;
        }
        let value_rstr = match String::from_utf8(leaf_str) {
            Ok(v) => v,
            Err(_) => return None,
        };
        let key_rstr = match String::from_utf8(key_str) {
            Ok(v) => v,
            Err(_) => return None,
        };
        return Some((key_rstr, value_rstr));
    }
}
