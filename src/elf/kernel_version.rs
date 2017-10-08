extern crate regex;

lazy_static! {
    static ref VERSION_REGEX: Regex = Regex::new(r"^(\d+)\.(\d+).(\d+).*$").unwrap();
    static ref DEBIAN_VERSION_REGEX: Regix = Regex::new(".* SMP Debian (\d+\.\d+.\d+-\d+) .*").unwrap();
}

fn kernel_version_from_release_string(release_str: String) -> io::Result<u32> {
    let versionParts = VERSION_REGEX.captures(release_str).unwrap();
    if versionParts.len() != 4 {
        return Err(format!("got invalid release version {} (expected format '4.3.2-1')", release_str));
    }
    let major = versionParts.get(1).map_or(0, |m| from_str::<u32>(m.to_str()))?;
    let minor = versionParts.get(2).map_or(0, |m| from_str::<u32>(m.to_str()))?;
    let patch = versionParts.get(3).map_or(0, |m| from_str::<u32>(m.to_str()))?;
    let out = major * 256 * 256 + minor * 256 + patch;
    return out;
}

fn current_version_uname() -> io::Result<u32> {
    let buf = nix::uname();
    let release_str = buf.release().trim();
    return kernel_version_from_release_string(release_str.to_string());
}

fn current_version_ubuntu() -> io::Result<u32> {
    let mut f = std::io::File::open("/proc/version_signature");
    let mut s = String::new();
    f.read_to_string(&mut s)?;
    let splitted = s.split_whitespace().collect();
    return kernel_version_from_release_string(splitted[2])
}

fn current_version_debian() -> io::Result<u32> {
    let mut f = std::io::File::open("/proc/version");
    let mut s = String::new();
    f.read_to_string(&mut s)?;
    let versionParts = DEBIAN_VERSION_REGEX.captures(release_str).unwrap();
    if versionParts.len() != 2 {
        return Err(format!("failed to get kernel version from /proc/version: {}", s);
    }
}
