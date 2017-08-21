extern crate libc;
extern crate nix;

const BPFFS_PATH: &'static str = "/sys/fs/bpf";

static FS_MAGIC_BPFFS: i32 = 0;

pub unsafe fn init() {
    // https://github.com/coreutils/coreutils/blob/v8.27/src/stat.c#L275
    // https://github.com/torvalds/linux/blob/v4.8/include/uapi/linux/magic.h#L80
    let magic = 0xCAFE4A11;
    // 0xCAFE4A11 overflows an int32, which is what's expected by Statfs_t.Type in 32bit platforms.
    // To avoid conditional compilation for all 32bit/64bit platforms, we use an unsafe cast
    FS_MAGIC_BPFFS = magic as i32;
}

// IsMounted checks if the BPF fs is mounted already
pub unsafe fn is_mounted() -> Result {
    let data = libc::statfs::default();
    match nix::sys::statfs(BPFS_PATH, &data.as_ptr()) {
        Ok(_) => Ok(data.f_type == FS_MAGIC_BPFS),
        Err(res) => {
            Err(format!("Cannot statfs {}: {}", BPFS_PATH, res.description()));
        }
    }
}

pub unsafe fn mounted() -> Result {
    match is_mounted() {
        Ok(res) => {
            if !res {
                match nix::mount::mount(Some(BPFS_PATH),
                BPFS_PATH,
                Some("bpf"),
                0,
                None) {
                    Ok(_),
                    Err(res) => {
                        Err(format!("Error mounting {}: {}",
                                    BPFS_PATH,
                                    res.description()))
                    }
                }
            } else {
                Ok(res)
            }
        },
        Err
    }
}
