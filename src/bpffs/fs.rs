extern crate libc;
extern crate nix;
use std::error::Error;
use self::nix::NixPath;

const BPFFS_PATH: &'static str = "/sys/fs/bpf";
const FSTYPE: &'static str = "bpf";

static FS_MAGIC_BPFFS: i32 = 0xCAFE4A11;
const NONE: Option<&'static [u8]> = None;

// IsMounted checks if the BPF fs is mounted already
pub fn is_mounted() -> Result<bool, String> {
    let mut data: libc::statfs = unsafe { ::std::mem::zeroed() };
    match nix::sys::statfs::statfs(BPFFS_PATH, &mut data) {
        Ok(_) => Ok(data.f_type == FS_MAGIC_BPFFS as i64),
        Err(res) => {
            Err(format!("Cannot statfs {}: {}", BPFFS_PATH, res.description()))
        }
    }
}

pub unsafe fn mounted() -> Result<(), String> {
    match is_mounted() {
        Ok(res) => {
            if !res {
                let res_mount = nix::mount::mount(Some(BPFFS_PATH), BPFFS_PATH, Some(FSTYPE),
                                                  nix::mount::MsFlags::from_bits_truncate(0),
                                                  NONE);
                if res_mount.is_err() {
                    return Err("Fail to mount".to_string());
                } else {
                    return Ok(())
                }
            } else {
                Ok(())
            }
        },
        Err(e) => Err(e)
    }
}
