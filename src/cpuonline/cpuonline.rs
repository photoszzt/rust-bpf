use std::fs::File;
use std::str::FromStr;
use std::io::Read;

const cpuonline: &'static str = "/sys/devices/system/cpu/online";

// loosely based on https://github.com/iovisor/bcc/blob/v0.3.0/src/python/bcc/utils.py#L15
fn read_cpu_range(cpu_range_str: &str) -> Result<Vec<u32>, String> {
    let mut cpus = Vec::new();
    let cpu_range_str_trim = cpu_range_str.trim();
    for cpu_range in cpu_range_str_trim.split(',') {
        let rangeop: Vec<&str> = cpu_range.splitn(2, '-').collect();
        let first = match u32::from_str(rangeop[0]) {
            Ok(res) => res,
            Err(e) => return Err(format!("Fail to recognize first cpu number: {}", e)),
        };
        if rangeop.len() == 1 {
            cpus.push(first);
            continue;
        }
        let last = match u32::from_str(rangeop[1]) {
            Ok(res) => res,
            Err(e) => return Err(format!("Fail to recognize second cpu number: {}", e)),
        };
        for n in first..last+1 {
            cpus.push(n);
        }
    }
    return Ok(cpus)
}

pub fn get() -> Result<Vec<u32>, String> {
    let mut f = File::open(cpuonline).map_err(|e| format!("{}", e))?;
    let mut buffer = String::new();
    match f.read_to_string(&mut buffer) {
        Ok(_) => (),
        Err(e) => return Err(format!("Fail to read {}: {}", cpuonline, e)),
    };
    return read_cpu_range(&buffer);
}

#[cfg(test)]
mod tests {
    use super::read_cpu_range;

    struct test_data<'a> {
        data: &'a str,
        expected: Vec<u32>,
        valid: bool,
    }

    lazy_static! {
        static ref test: Vec<test_data<'static>> = vec![
		        test_data {
			          data: "",
			          expected: Vec::new(),
			          valid:    false,
		        },
		        test_data {
			          data: "0-3\n",
			          expected: vec!{0, 1, 2, 3},
			          valid:    true,
		        },
		        test_data {
			          data: "   0-2,5",
			          expected: vec!{0, 1, 2, 5},
			          valid:   true,
		        },
		        test_data {
			          data: "0,2,4-5,7-9",
			          expected: vec!{0, 2, 4, 5, 7, 8, 9},
			          valid:   true,
		        },
		        test_data {
			          data: "0,2",
			          expected: vec!{0, 2},
			          valid:   true,
		        },
		        test_data {
			          data: "0",
			          expected: vec!{0},
			          valid:   true,
		        },
		        test_data {
			          data: "-2,5",
			          expected: Vec::new(),
			          valid:   false,
		        },
		        test_data {
			          data: "2-@,5",
			          expected: Vec::new(),
			          valid:   false,
		        },
		        test_data {
			          data: "-",
			          expected: Vec::new(),
			          valid:   false,
		        },
        ];
    }
    #[test]
    fn test_cpu_online() {
        for i in 0..test.len() {
            let t = &test[i];
            let res = read_cpu_range(t.data);
            assert!((t.valid && res.is_ok()) || (!t.valid && res.is_err()));
            if let Ok(v) = res {
                for i in 0..v.len() {
                    assert_eq!(v[i], t.expected[i]);
                }
            }
        };
    }
}
