use std::fs::File;

const cpuonline: &'static str = "/sys/devices/system/cpu/online";

// loosely based on https://github.com/iovisor/bcc/blob/v0.3.0/src/python/bcc/utils.py#L15
fn read_cpu_range(cpu_range_str: String) {
    
}

pub fn get() -> Result<Vec<u32>, String> {
    let mut f = File::open(cpuonline);
    let mut buffer = String::new();
    match f.read_to_string(&mut buffer) {
        Ok(_) => (),
        Err(e) => return Err(format!("Fail to read {}: {}", cpuonline, e));
    };
}
