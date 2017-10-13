/* automatically generated by rust-bindgen */

pub const BUF_SIZE_MAP_NS: ::std::os::raw::c_uint = 256;
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_map_def {
    pub type__: ::std::os::raw::c_uint,
    pub key_size: ::std::os::raw::c_uint,
    pub value_size: ::std::os::raw::c_uint,
    pub max_entries: ::std::os::raw::c_uint,
    pub map_flags: ::std::os::raw::c_uint,
    pub pinning: ::std::os::raw::c_uint,
    pub namespace: [::std::os::raw::c_char; 256usize],
}
#[test]
fn bindgen_test_layout_bpf_map_def() {
    assert_eq!(::std::mem::size_of::<bpf_map_def>() , 280usize , concat ! (
               "Size of: " , stringify ! ( bpf_map_def ) ));
    assert_eq! (::std::mem::align_of::<bpf_map_def>() , 4usize , concat ! (
                "Alignment of " , stringify ! ( bpf_map_def ) ));
    assert_eq! (unsafe {
                & ( * ( 0 as * const bpf_map_def ) ) . type_ as * const _ as
                usize } , 0usize , concat ! (
                "Alignment of field: " , stringify ! ( bpf_map_def ) , "::" ,
                stringify ! ( type_ ) ));
    assert_eq! (unsafe {
                & ( * ( 0 as * const bpf_map_def ) ) . key_size as * const _
                as usize } , 4usize , concat ! (
                "Alignment of field: " , stringify ! ( bpf_map_def ) , "::" ,
                stringify ! ( key_size ) ));
    assert_eq! (unsafe {
                & ( * ( 0 as * const bpf_map_def ) ) . value_size as * const _
                as usize } , 8usize , concat ! (
                "Alignment of field: " , stringify ! ( bpf_map_def ) , "::" ,
                stringify ! ( value_size ) ));
    assert_eq! (unsafe {
                & ( * ( 0 as * const bpf_map_def ) ) . max_entries as * const
                _ as usize } , 12usize , concat ! (
                "Alignment of field: " , stringify ! ( bpf_map_def ) , "::" ,
                stringify ! ( max_entries ) ));
    assert_eq! (unsafe {
                & ( * ( 0 as * const bpf_map_def ) ) . map_flags as * const _
                as usize } , 16usize , concat ! (
                "Alignment of field: " , stringify ! ( bpf_map_def ) , "::" ,
                stringify ! ( map_flags ) ));
    assert_eq! (unsafe {
                & ( * ( 0 as * const bpf_map_def ) ) . pinning as * const _ as
                usize } , 20usize , concat ! (
                "Alignment of field: " , stringify ! ( bpf_map_def ) , "::" ,
                stringify ! ( pinning ) ));
    assert_eq! (unsafe {
                & ( * ( 0 as * const bpf_map_def ) ) . namespace as * const _
                as usize } , 24usize , concat ! (
                "Alignment of field: " , stringify ! ( bpf_map_def ) , "::" ,
                stringify ! ( namespace ) ));
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_map {
    pub fd: ::std::os::raw::c_int,
    pub def: bpf_map_def,
}
#[test]
fn bindgen_test_layout_bpf_map() {
    assert_eq!(::std::mem::size_of::<bpf_map>() , 284usize , concat ! (
               "Size of: " , stringify ! ( bpf_map ) ));
    assert_eq! (::std::mem::align_of::<bpf_map>() , 4usize , concat ! (
                "Alignment of " , stringify ! ( bpf_map ) ));
    assert_eq! (unsafe {
                & ( * ( 0 as * const bpf_map ) ) . fd as * const _ as usize }
                , 0usize , concat ! (
                "Alignment of field: " , stringify ! ( bpf_map ) , "::" ,
                stringify ! ( fd ) ));
    assert_eq! (unsafe {
                & ( * ( 0 as * const bpf_map ) ) . def as * const _ as usize }
                , 4usize , concat ! (
                "Alignment of field: " , stringify ! ( bpf_map ) , "::" ,
                stringify ! ( def ) ));
}
