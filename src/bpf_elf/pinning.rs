extern crate bcc_sys;
extern crate nix;
extern crate failure;

use bcc_sys::bccapi::bpf_obj_pin;
use bpf_elf::bpf_bindings::bpf_map_def;
use bpffs;
use bpffs::BPFFS_PATH;
use std::path::Path;
use std::path::PathBuf;
use failure::Error;

pub const BPFDIRGLOBALS: &'static str = "globals";

fn pin_object_(fd: i32, path: &Path) -> Result<(), Error> {
    if !bpffs::is_mounted()? {
        return Err(format_err!("bpf fs is not mounted at {}", BPFFS_PATH));
    }
    let parent_dir = path.parent().unwrap_or(Path::new("."));
    ::std::fs::create_dir_all(parent_dir)?;
    let stat_res = nix::sys::stat::stat(path);
    if stat_res.is_ok() {
        return Err(format_err!("aborting, found file at {:?}", path));
    }
    let fd = unsafe {
        bpf_obj_pin(
            fd,
            path.to_str().unwrap_or("").as_bytes().as_ptr() as *const i8,
        )
    };
    if fd < 0 {
        return Err(format_err!(
            "Fail to pin object to {}: {}",
            path.to_string_lossy(),
            nix::errno::errno()
        ));
    }
    Ok(())
}

pub fn pin_object_global(fd: i32, namespace: &str, name: &str) -> Result<(), Error> {
    let path: PathBuf = [BPFFS_PATH, namespace, BPFDIRGLOBALS, name]
        .iter()
        .collect();
    return pin_object_(fd, &path);
}

pub fn pin_object(fd: i32, pin_path: &str) -> Result<(), Error> {
    let path = Path::new(pin_path);
    if bpf_map_def::validate_path(path).is_err() {
        return Err(format_err!("Not a valid pin path: {}", pin_path));
    }
    return pin_object_(fd, path);
}
