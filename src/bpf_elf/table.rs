extern crate libc;
extern crate nix;

use bcc_sys::bccapi::{bpf_delete_elem, bpf_lookup_elem, bpf_update_elem};
use bpf_elf::elf::EbpfMap;
use std::os::raw::c_void;

impl EbpfMap {
    /// stores value and key in the map.
    /// The flags can have the following values:
    /// BPF_ANY to create new element or update existing;
    /// BPF_NOEXIST to create new element if it didn't exist;
    /// BPF_EXIST to update existing element.
    pub fn update_element(
        &self,
        key: *mut c_void,
        value: *mut c_void,
        flags: u64,
    ) -> Result<(), String> {
        let ret = unsafe { bpf_update_elem(self.m.fd, key, value, flags) };
        if ret < 0 {
            return Err(format!("Unable to update element: {}", nix::errno::errno()));
        }
        Ok(())
    }

    /// looks up the given key in the the map.
    /// The value is stored in the value.
    pub fn lookup_element(&self, key: *mut c_void, value: *mut c_void) -> Result<(), String> {
        let ret = unsafe { bpf_lookup_elem(self.m.fd, key, value) };
        if ret < 0 {
            return Err(format!("Unable to lookup element: {}", nix::errno::errno()));
        }
        Ok(())
    }

    pub fn delete_element(&self, key: *mut c_void) -> Result<(), String> {
        let ret = unsafe { bpf_delete_elem(self.m.fd, key) };
        if ret < 0 {
            return Err(format!("Unable to delete element: {}", nix::errno::errno()));
        }
        Ok(())
    }
}
