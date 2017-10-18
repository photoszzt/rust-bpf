extern crate regex;
extern crate nix;


use self::regex::Regex;
use std::fs::File;
use std::str::FromStr;
use std::io::Read;


lazy_static! {
    static ref VERSION_REGEX: Regex = Regex::new(r"^(\d+)\.(\d+).(\d+).*$").unwrap();
    static ref DEBIAN_VERSION_REGEX: Regex = Regex::new(r".* SMP Debian (\d+\.\d+.\d+-\d+) .*").unwrap();
}

fn kernel_version_from_release_string(release_str: &str) -> Result<u32, String> {
    let versionParts = match VERSION_REGEX.captures(release_str) {
        Some(r) => r,
        None => return Err("Fail to find version from strings".to_string()),
    };
    if versionParts.len() != 4 {
        return Err(format!("got invalid release version {} (expected format '4.3.2-1')", release_str));
    }
    let major = versionParts.get(1).map_or(0, |m| u32::from_str(m.as_str()).unwrap());
    let minor = versionParts.get(2).map_or(0, |m| u32::from_str(m.as_str()).unwrap());
    let patch = versionParts.get(3).map_or(0, |m| u32::from_str(m.as_str()).unwrap());
    let out = major * 256 * 256 + minor * 256 + patch;
    return Ok(out);
}

fn current_version_uname() -> Result<u32, String> {
    let buf = nix::sys::utsname::uname();
    let release_str = buf.release().trim();
    return kernel_version_from_release_string(release_str);
}

fn current_version_ubuntu() -> Result<u32, String> {
    let mut f = match File::open("/proc/version_signature") {
        Ok(f) => f,
        Err(e) => return Err(format!("Fail to open file: {}", e)),
    };
    let mut s = String::new();
    match f.read_to_string(&mut s) {
        Ok(_) => (),
        Err(e) => return Err(format!("Failed to read file: {}", e)),
    }
    let splitted: Vec<&str> = s.split_whitespace().collect();
    return kernel_version_from_release_string(splitted[2])
}

fn current_version_debian() -> Result<u32, String> {
    let mut f = match File::open("/proc/version") {
        Ok(f) => f,
        Err(e) => return Err(format!("Fail to open file: {}", e)),
    };
    let mut s = String::new();
    match f.read_to_string(&mut s) {
        Ok(_) => (),
        Err(e) => return Err(format!("Failed to read file: {}", e)),
    };
    let versionParts = DEBIAN_VERSION_REGEX.captures(&s).unwrap();
    if versionParts.len() != 2 {
        return Err(format!("failed to get kernel version from /proc/version: {}", s));
    }
    let matched = versionParts.get(1).map_or("", |m| m.as_str());
    return kernel_version_from_release_string(matched);
}

pub fn current_kernel_version() -> Result<u32, String>{
    let v = current_version_ubuntu();
    if let Ok(version) = v {
        return Ok(version);
    }
    let v = current_version_debian();
    if let Ok(version) = v {
        return Ok(version);
    }
    return current_version_uname();
}

#[cfg(test)]
mod tests {
    use super::kernel_version_from_release_string;

    struct test_data<'a> {
        succeed: bool,
        release_string: &'a str,
        kernel_version: u32,
    }
    lazy_static! {
        static ref test: Vec<test_data<'static>> = vec![
            test_data {succeed: true,  release_string: "4.1.2-3",                kernel_version: 262402},
	          test_data {succeed: true,  release_string: "4.8.14-200.fc24.x86_64", kernel_version: 264206},
	          test_data {succeed: true,  release_string: "4.1.2-3foo",             kernel_version: 262402},
	          test_data {succeed: true,  release_string: "4.1.2foo-1",             kernel_version: 262402},
	          test_data {succeed: true,  release_string: "4.1.2-rkt-v1",           kernel_version: 262402},
	          test_data {succeed: true,  release_string: "4.1.2rkt-v1",            kernel_version: 262402},
	          test_data {succeed: true,  release_string: "4.1.2-3 foo",            kernel_version: 262402},
	          test_data {succeed: false, release_string: "foo 4.1.2-3",            kernel_version: 0},
	          test_data {succeed: true,  release_string: "4.1.2",                  kernel_version: 262402},
	          test_data {succeed: false, release_string: ".4.1.2",                 kernel_version: 0},
	          test_data {succeed: false, release_string: "4.1.",                   kernel_version: 0},
	          test_data {succeed: false, release_string: "4.1",                    kernel_version: 0},
        ];
    }
    #[test]
    fn test_kernel_version_from_release_string() {
        for i in 0..test.len() {
            let t = &test[i];
            let res = kernel_version_from_release_string(t.release_string);
            assert!((t.succeed && res.is_ok()) || (!t.succeed && res.is_err()));
            if let Ok(v) = res {
                assert_eq!(v, t.kernel_version)
            }
        }
    }
}
