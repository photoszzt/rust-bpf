extern crate bcc_sys;

use bcc_sys::bccapi::*;

#[repr(C)]
#[derive(Copy)]
pub struct bpf_map_def {
    pub type_: ::std::os::raw::c_uint,
    pub key_size: ::std::os::raw::c_uint,
    pub value_size: ::std::os::raw::c_uint,
    pub max_entries: ::std::os::raw::c_uint,
    pub map_flags: ::std::os::raw::c_uint,
    pub pinning: ::std::os::raw::c_uint,
    pub namespace: [::std::os::raw::c_char; 256usize],
}
impl Clone for bpf_map_def {
    fn clone(&self) -> Self { *self }
}

pub trait bpf_attr_ext {
    fn bpf_attr_map_create(map_type: u32,
                           key_size: u32,
                           value_size: u32,
                           max_entries: u32,
                           map_flags: u32) -> bpf_attr;
    fn bpf_attr_elem_value(map_fd: u32,
                           key: u64,
                           value: u64,
                           flags: u64) -> bpf_attr;
    fn bpf_attr_elem_next_key(map_fd: u32,
                              key: u64,
                              next_key: u64,
                              flags: u64) -> bpf_attr;
    fn bpf_attr_prog_load(prog_type: u32,
                          insn_cnt: u32,
                          insns: u64,
                          license: u64,
                          log_level: u32,
                          log_size: u32,
                          log_buf: u64,
                          kern_version: u32) -> bpf_attr;
    fn bpf_attr_obj(pathname: u64,
                    bpf_fd: u32) -> bpf_attr;
    fn bpf_attr_att_det(target_fd: u32,
                        attach_bpf_fd: u32,
                        attach_type: u32) -> bpf_attr;
}


impl bpf_attr_ext for bpf_attr {
    fn bpf_attr_map_create(map_type: u32,
                           key_size: u32,
                           value_size: u32,
                           max_entries: u32,
                           map_flags: u32) -> bpf_attr {
        bpf_attr {
            __bindgen_anon_1: bpf_attr__bindgen_ty_1 {
                map_type,
                key_size,
                value_size,
                max_entries,
                map_flags,
                inner_map_fd: 0,
                numa_node: 0,
                map_name: [0; 16usize],
            },
        }
    }

    fn bpf_attr_elem_value(map_fd: u32,
                           key: u64,
                           value: u64,
                           flags: u64) -> bpf_attr {
        bpf_attr {
            __bindgen_anon_2: bpf_attr__bindgen_ty_2 {
                map_fd,
                key,
                __bindgen_anon_1: bpf_attr__bindgen_ty_2__bindgen_ty_1 {
                    value,
                },
                flags,
            },
        }
    }

    fn bpf_attr_elem_next_key(map_fd: u32,
                              key: u64,
                              next_key: u64,
                              flags: u64) -> bpf_attr {
        bpf_attr {
            __bindgen_anon_2: bpf_attr__bindgen_ty_2 {
                map_fd,
                key,
                __bindgen_anon_1: bpf_attr__bindgen_ty_2__bindgen_ty_1 {
                    next_key,
                },
                flags,
            },
        }
    }

    fn bpf_attr_prog_load(prog_type: u32,
                          insn_cnt: u32,
                          insns: u64,
                          license: u64,
                          log_level: u32,
                          log_size: u32,
                          log_buf: u64,
                          kern_version: u32) -> bpf_attr {
        bpf_attr {
            __bindgen_anon_3: bpf_attr__bindgen_ty_3 {
                prog_type,
                insn_cnt,
                insns,
                license,
                log_level,
                log_size,
                log_buf,
                kern_version,
                prog_flags: 0,
                prog_name: [0; 16usize],
            },
        }
    }

    fn bpf_attr_obj(pathname: u64,
                    bpf_fd: u32) -> bpf_attr {
        bpf_attr {
            __bindgen_anon_4: bpf_attr__bindgen_ty_4 {
                pathname,
                bpf_fd,
            },
        }
    }

    fn bpf_attr_att_det(target_fd: u32,
                        attach_bpf_fd: u32,
                        attach_type: u32) -> bpf_attr {
        bpf_attr {
            __bindgen_anon_5: bpf_attr__bindgen_ty_5 {
                target_fd,
                attach_bpf_fd,
                attach_type,
                attach_flags: 0,
            },
        }
    }
}

pub fn bpf_verify_program(prog_type: bpf_prog_type,
                          insns: u64,
                          insns_cnt: usize,
                          license: *const char,
                          kern_version: u32,
                          log_buf: &mut Vec<u8>,
                          log_buf_sz: usize,
                          log_level: u32) -> usize {
    let attr = bpf_attr::bpf_attr_prog_load(
        prog_type as u32,
        insns_cnt as u32,
        insns,
        license as u64,
        log_level,
        log_buf_sz as u32,
        log_buf.as_mut_ptr() as u64,
        kern_version,
    );

    log_buf[0] = 0;

    unsafe {
        syscall!(BPF, bpf_cmd::BPF_PROG_LOAD,
                 &attr as *const _ as usize,
                 ::std::mem::size_of::<bpf_attr>())
    }
}

pub fn bpf_prog_attach(prog_fd: u32,
                       target_fd: u32,
                       att_type: bpf_attach_type,
                       ) -> i32 {
    let attr = bpf_attr::bpf_attr_att_det(target_fd,
                                          prog_fd,
                                          att_type as u32);

    unsafe {
        syscall!(BPF, bpf_cmd::BPF_PROG_ATTACH,
                 &attr as *const _ as usize,
                 ::std::mem::size_of::<bpf_attr>()) as i32
    }
}

pub fn bpf_prog_detach(prog_fd: u32,
                       target_fd: u32,
                       att_type: bpf_attach_type,
                       ) -> i32 {
    let attr = bpf_attr::bpf_attr_att_det(target_fd,
                                          prog_fd,
                                          att_type as u32);

    unsafe {
        syscall!(BPF, bpf_cmd::BPF_PROG_DETACH,
                 &attr as *const _ as usize,
                 ::std::mem::size_of::<bpf_attr>()) as i32
    }
}
