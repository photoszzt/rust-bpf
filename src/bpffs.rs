extern crate libc;
extern crate nix;
extern crate failure;

use failure::Error;

pub const BPFFS_PATH: &'static str = "/sys/fs/bpf";
const FSTYPE: &'static str = "bpf";

const FS_MAGIC_BPFFS: u32 = 0xCAFE4A11;
const NONE: Option<&'static [u8]> = None;

// IsMounted checks if the BPF fs is mounted already
pub fn is_mounted() -> Result<bool, Error> {
    let mut data: libc::statfs = unsafe { ::std::mem::zeroed() };
    match nix::sys::statfs::statfs(BPFFS_PATH, &mut data) {
        Ok(_) => Ok(data.f_type as i32 == FS_MAGIC_BPFFS as i32),
        Err(res) => Err(format_err!(
            "Cannot statfs {}: {}",
            BPFFS_PATH,
            res.description()
        )),
    }
}

pub fn mounted() -> Result<(), Error> {
    match is_mounted() {
        Ok(res) => if !res {
            if let Err(e) = nix::mount::mount(
                Some(BPFFS_PATH),
                BPFFS_PATH,
                Some(FSTYPE),
                nix::mount::MsFlags::from_bits_truncate(0),
                NONE,
            ) {
                Err(format_err!("Cannot mount {}: {}", BPFFS_PATH, e))
            } else {
                Ok(())
            }
        } else {
            Ok(())
        },
        Err(e) => Err(e),
    }
}
