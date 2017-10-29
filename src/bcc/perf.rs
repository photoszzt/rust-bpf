pub struct PerfMap {
    table: &Table,
    readers: Vec<perf_reader>,
    stop: bool,
}

