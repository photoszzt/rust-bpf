use perf_event_bindings::*;
use std::default::Default;

pub const PERF_EVENT_IOC_ENABLE: u64 = 9216;
pub const PERF_EVENT_IOC_SET_BPF: u64 = 0x40042408;

impl perf_event_attr {
    pub fn gen_perf_event_attr_open_map(perf_type: perf_type_id, sample_type: perf_event_sample_format, wakeup_events: u32, size: u32, config: u64) -> perf_event_attr {
        perf_event_attr {
            type_: perf_type as u32,
            size,
            config,
            sample_type: sample_type as u64,
            __bindgen_anon_2: perf_event_attr__bindgen_ty_2 { wakeup_events },
            ..Default::default()
        }
    }

    pub fn gen_perf_event_attr_open_tracepoint(perf_type: perf_type_id, sample_type: perf_event_sample_format, wakeup_events: u32, sample_period: u64, config: u64) -> perf_event_attr {
        perf_event_attr {
            type_: perf_type as u32,
            config,
            sample_type: sample_type as u64,
            __bindgen_anon_1: perf_event_attr__bindgen_ty_1 { sample_period },
            __bindgen_anon_2: perf_event_attr__bindgen_ty_2 { wakeup_events },
            ..Default::default()
        }
    }
}
