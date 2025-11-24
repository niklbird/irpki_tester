// ffi.rs
#[link(name = "mutate_der")] // the name of your built C++ static/dylib
extern "C" {
    fn mutate_to_der_ffi(
        in_ptr: *const u8,
        in_len: usize,
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
        seed: u64,
        mutate_rounds: i32,
    ) -> bool;

        fn mutate_ffi(
        in_ptr: *const u8,
        in_len: usize,
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
        seed: u64,
        mutate_rounds: i32,
    ) -> bool;


    fn free_buffer(p: *mut core::ffi::c_void);

    fn encode_to_der_ffi(
    in_ptr: *const u8,
        in_len: usize,
        out_ptr: *mut *mut u8,
        out_len: *mut usize) -> bool;
}


pub fn encode_proto_to_der(proto_bytes: &[u8]) -> Result<Vec<u8>, String>{
        unsafe {
        let mut out_ptr: *mut u8 = core::ptr::null_mut();
        let mut out_len: usize = 0;

        println!("{}", proto_bytes.len());
        let ok = encode_to_der_ffi(
            proto_bytes.as_ptr(),
            proto_bytes.len(),
            &mut out_ptr,
            &mut out_len,
        );
        if !ok {
            return Err("FFI encoding failed".to_string());
        }
        // take ownership, copy into Vec, free C buffer
        let slice = std::slice::from_raw_parts(out_ptr, out_len);
        let der = slice.to_vec();
        free_buffer(out_ptr.cast());
        Ok(der)
    }
}

pub fn mutate_pb_to_der(proto_bytes: &[u8], seed: u64, rounds: i32) -> Result<Vec<u8>, String> {
    unsafe {
        let mut out_ptr: *mut u8 = core::ptr::null_mut();
        let mut out_len: usize = 0;
        let ok = mutate_to_der_ffi(
            proto_bytes.as_ptr(),
            proto_bytes.len(),
            &mut out_ptr,
            &mut out_len,
            seed,
            rounds,
        );
        if !ok {
            return Err("FFI mutation failed".to_string());
        }
        // take ownership, copy into Vec, free C buffer
        let slice = std::slice::from_raw_parts(out_ptr, out_len);
        let der = slice.to_vec();
        free_buffer(out_ptr.cast());
        Ok(der)
    }
}

pub fn mutate_pb(proto_bytes: &[u8], seed: u64, rounds: i32) -> Result<Vec<u8>, String> {
    unsafe {
        let mut out_ptr: *mut u8 = core::ptr::null_mut();
        let mut out_len: usize = 0;

        let ok = mutate_ffi(
            proto_bytes.as_ptr(),
            proto_bytes.len(),
            &mut out_ptr,
            &mut out_len,
            seed,
            rounds,
        );
        if !ok {
            return Err("FFI mutation failed".to_string());
        }
        // take ownership, copy into Vec, free C buffer
        let slice = std::slice::from_raw_parts(out_ptr, out_len);
        let der = slice.to_vec();
        free_buffer(out_ptr.cast());
        Ok(der)
    }
}