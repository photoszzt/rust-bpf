use perf_event_bindings::*;
use std::default::Default;

impl Default for perf_event_attr {
    fn default() -> perf_event_attr {
        perf_event_attr {
            type_: 0,
            size: 0,
            config: 0,
            __bindgen_anon_1: perf_event_attr__bindgen_ty_1 {
                sample_period: 0,
            },
            sample_type: 0,
            read_format: 0,
            _bitfield_1: 0,
            __bindgen_anon_2: perf_event_attr__bindgen_ty_2 {
                wakeup_events: 0,
            },
            bp_type: 0,
            __bindgen_anon_3: perf_event_attr__bindgen_ty_3 {
                bp_addr: 0,
            },
            __bindgen_anon_4: perf_event_attr__bindgen_ty_4 {
                bp_len: 0,
            },
            branch_sample_type: 0,
            sample_regs_user: 0,
            sample_stack_user: 0,
            clockid: 0,
            sample_regs_intr: 0,
            aux_watermark: 0,
            __reserved_2: 0,
        }
    }
}

impl perf_event_attr {
    pub fn gen_perf_event_attr(perf_type: perf_type_id,
                               sample_type: perf_event_sample_format,
                               wakeup_events: u32,
                               size: u32,
                               config: u32) -> perf_event_attr {
        perf_event_attr {
            type_: perf_type as u32,
            size: size,
            config: config,
            sample_type: sample_type,
            __bindgen_anon_2: perf_event_attr__bindgen_ty_2 {
                wakeup_events: wakeup_events,
            },
            ..Default::default(),
        }
    }
}
