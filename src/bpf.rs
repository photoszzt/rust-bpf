use bpf_bindings::*;
use std::os::raw::c_void;

impl bpf_attr {
    pub fn bpf_attr_map_create(map_type: __u32,
                               key_size: __u32,
                               value_size: __u32,
                               max_entries: __u32,
                               map_flags: __u32) -> bpf_attr {
        bpf_attr {
            __bindgen_anon_1: bpf_attr__bindgen_ty_1 {
                map_type,
                key_size,
                value_size,
                max_entries,
                map_flags,
            },
        }
    }

    pub fn bpf_attr_elem_value(map_fd: __u32,
                                     key: __u64,
                                     value: __u64,
                                     flags: __u64) -> bpf_attr {
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

    pub fn bpf_attr_elem_next_key(map_fd: __u32,
                                        key: __u64,
                                        next_key: __u64,
                                        flags: __u64) -> bpf_attr {
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

    pub fn bpf_attr_prog_load(prog_type: __u32,
                              insn_cnt: __u32,
                              insns: __u64,
                              license: __u64,
                              log_level: __u32,
                              log_size: __u32,
                              log_buf: __u64,
                              kern_version: __u32) -> bpf_attr {
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
            },
        }
    }

    pub fn bpf_attr_obj(pathname: __u64,
                        bpf_fd: __u32) -> bpf_attr {
        bpf_attr {
            __bindgen_anon_4: bpf_attr__bindgen_ty_4 {
                pathname,
                bpf_fd,
            },
        }
    }

    pub fn bpf_attr_att_det(target_fd: __u32,
                            attach_bpf_fd: __u32,
                            attach_type: __u32) -> bpf_attr {
        bpf_attr {
            __bindgen_anon_5: bpf_attr__bindgen_ty_5 {
                target_fd,
                attach_bpf_fd,
                attach_type,
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

pub fn bpf_map_update_elem(fd: u32,
                           key: *const c_void,
                           value: *mut c_void,
                           flags: u64) -> usize {
    let attr = bpf_attr::bpf_attr_elem_value(fd,
                                             key as u64,
                                             value as u64,
                                             flags);
    unsafe {
        syscall!(BPF, bpf_cmd::BPF_MAP_UPDATE_ELEM,
                 &attr as *const _ as usize,
                 ::std::mem::size_of::<bpf_attr>())
    }
}

pub fn bpf_map_lookup_elem(fd: u32,
                           key: *const c_void,
                           value: *mut c_void) -> usize {
    let attr = bpf_attr::bpf_attr_elem_value(fd,
                                        key as u64,
                                        value as u64,
                                        0);
    unsafe {
        syscall!(BPF, bpf_cmd::BPF_MAP_LOOKUP_ELEM,
                 &attr as *const _ as usize,
                 ::std::mem::size_of::<bpf_attr>())
    }
}

pub fn bpf_map_delete_elem(fd: u32,
                           key: *const c_void,
                           ) -> usize {
    let attr = bpf_attr::bpf_attr_elem_value(fd,
                                        key as u64,
                                        0,
                                        0);
    unsafe {
        syscall!(BPF, bpf_cmd::BPF_MAP_DELETE_ELEM,
                 &attr as *const _ as usize,
                 ::std::mem::size_of::<bpf_attr>())
    }
}

pub fn bpf_map_get_next_key(fd: u32,
                           key: *const c_void,
                            next_key: *mut c_void) -> usize {
    let attr = bpf_attr::bpf_attr_elem_value(fd,
                                        key as u64,
                                        next_key as u64,
                                        0);
    unsafe {
        syscall!(BPF, bpf_cmd::BPF_MAP_GET_NEXT_KEY,
                 &attr as *const _ as usize,
                 ::std::mem::size_of::<bpf_attr>())
    }
}

pub fn bpf_obj_pin(fd: u32,
                   pathname: *const u8) -> i32 {
    let attr = bpf_attr::bpf_attr_obj(pathname as u64, fd);


    unsafe {
        syscall!(BPF, bpf_cmd::BPF_OBJ_PIN,
                 &attr as *const _ as usize,
                 ::std::mem::size_of::<bpf_attr>()) as i32
    }
}

pub fn bpf_obj_get(pathname: *const u8) -> i32 {
    let attr = bpf_attr::bpf_attr_obj(pathname as u64, 0);


    unsafe {
        syscall!(BPF, bpf_cmd::BPF_OBJ_GET,
                 &attr as *const _ as usize,
                 ::std::mem::size_of::<bpf_attr>()) as i32
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
