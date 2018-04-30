use bpf_elf::bpf_bindings::*;

pub trait bpf_attr_ext {
    fn bpf_attr_map_create(
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        map_flags: u32,
    ) -> bpf_attr;
    fn bpf_attr_elem_value(map_fd: u32, key: u64, value: u64, flags: u64) -> bpf_attr;
    fn bpf_attr_elem_next_key(map_fd: u32, key: u64, next_key: u64, flags: u64) -> bpf_attr;
    fn bpf_attr_prog_load(
        prog_type: u32,
        insn_cnt: u32,
        insns: u64,
        license: u64,
        log_level: u32,
        log_size: u32,
        log_buf: u64,
        kern_version: u32,
    ) -> bpf_attr;
    fn bpf_attr_obj(pathname: u64, bpf_fd: u32) -> bpf_attr;
    fn bpf_attr_att_det(target_fd: u32, attach_bpf_fd: u32, attach_type: u32) -> bpf_attr;
}

impl bpf_attr_ext for bpf_attr {
    fn bpf_attr_map_create(
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        map_flags: u32,
    ) -> bpf_attr {
        unsafe {
            let mut x = ::std::mem::zeroed::<bpf_attr>();
            x.__bindgen_anon_1.map_type = map_type;
            x.__bindgen_anon_1.key_size = key_size;
            x.__bindgen_anon_1.value_size = value_size;
            x.__bindgen_anon_1.max_entries = max_entries;
            x.__bindgen_anon_1.map_flags = map_flags;
            x
        }
    }

    fn bpf_attr_elem_value(map_fd: u32, key: u64, value: u64, flags: u64) -> bpf_attr {
        unsafe {
            let mut x = ::std::mem::zeroed::<bpf_attr>();
            x.__bindgen_anon_2.map_fd = map_fd;
            x.__bindgen_anon_2.key = key;
            x.__bindgen_anon_2.__bindgen_anon_1 = bpf_attr__bindgen_ty_2__bindgen_ty_1 { value };
            x.__bindgen_anon_2.flags = flags;
            x
        }
    }

    fn bpf_attr_elem_next_key(map_fd: u32, key: u64, next_key: u64, flags: u64) -> bpf_attr {
        unsafe {
            let mut x = ::std::mem::zeroed::<bpf_attr>();
            x.__bindgen_anon_2.map_fd = map_fd;
            x.__bindgen_anon_2.key = key;
            x.__bindgen_anon_2.__bindgen_anon_1 = bpf_attr__bindgen_ty_2__bindgen_ty_1 { next_key };
            x.__bindgen_anon_2.flags = flags;
            x
        }
    }

    fn bpf_attr_prog_load(
        prog_type: u32,
        insn_cnt: u32,
        insns: u64,
        license: u64,
        log_level: u32,
        log_size: u32,
        log_buf: u64,
        kern_version: u32,
    ) -> bpf_attr {
        unsafe {
            let mut x = ::std::mem::zeroed::<bpf_attr>();
            x.__bindgen_anon_3.prog_type = prog_type;
            x.__bindgen_anon_3.insn_cnt = insn_cnt;
            x.__bindgen_anon_3.insns = insns;
            x.__bindgen_anon_3.license = license;
            x.__bindgen_anon_3.log_level = log_level;
            x.__bindgen_anon_3.log_size = log_size;
            x.__bindgen_anon_3.log_buf = log_buf;
            x.__bindgen_anon_3.kern_version = kern_version;
            x
        }
    }

    fn bpf_attr_obj(pathname: u64, bpf_fd: u32) -> bpf_attr {
        unsafe {
            let mut x = ::std::mem::zeroed::<bpf_attr>();
            x.__bindgen_anon_4.pathname = pathname;
            x.__bindgen_anon_4.bpf_fd = bpf_fd;
            x
        }
    }

    fn bpf_attr_att_det(target_fd: u32, attach_bpf_fd: u32, attach_type: u32) -> bpf_attr {
        unsafe {
            let mut x = ::std::mem::zeroed::<bpf_attr>();
            x.__bindgen_anon_5.target_fd = target_fd;
            x.__bindgen_anon_5.attach_bpf_fd = attach_bpf_fd;
            x.__bindgen_anon_5.attach_type = attach_type;
            x
        }
    }
}

pub fn bpf_verify_program(
    prog_type: bpf_prog_type,
    insns: u64,
    insns_cnt: usize,
    license: *const char,
    kern_version: u32,
    log_buf: &mut Vec<u8>,
    log_buf_sz: usize,
    log_level: u32,
) -> usize {
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
        syscall!(
            BPF,
            bpf_cmd_BPF_PROG_LOAD,
            &attr as *const _ as usize,
            ::std::mem::size_of::<bpf_attr>()
        )
    }
}

pub fn bpf_prog_attach(prog_fd: u32, target_fd: u32, att_type: bpf_attach_type) -> i32 {
    let attr = bpf_attr::bpf_attr_att_det(target_fd, prog_fd, att_type as u32);

    unsafe {
        syscall!(
            BPF,
            bpf_cmd_BPF_PROG_ATTACH,
            &attr as *const _ as usize,
            ::std::mem::size_of::<bpf_attr>()
        ) as i32
    }
}

pub fn bpf_prog_detach(prog_fd: u32, target_fd: u32, att_type: bpf_attach_type) -> i32 {
    let attr = bpf_attr::bpf_attr_att_det(target_fd, prog_fd, att_type as u32);

    unsafe {
        syscall!(
            BPF,
            bpf_cmd_BPF_PROG_DETACH,
            &attr as *const _ as usize,
            ::std::mem::size_of::<bpf_attr>()
        ) as i32
    }
}
