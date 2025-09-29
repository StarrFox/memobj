use std::ffi::CStr;
use std::fs::File;
use std::io::Write;
use std::os::raw::c_char;
use windows::Win32::Foundation::HINSTANCE;

#[no_mangle]
pub extern "system" fn DllMain(
    _hinst_dll: HINSTANCE,
    _fdw_reason: u32,
    _lpv_reserved: *mut std::ffi::c_void,
) -> u32 {
    1
}


#[no_mangle]
pub extern "C" fn create_file_at_path(path: *const c_char) -> i32 {
    if path.is_null() {
        return 0;
    }
    let c_str = unsafe { CStr::from_ptr(path) };
    match c_str.to_str() {
        Ok(path_str) => {
            if let Ok(mut file) = File::create(path_str) {
                let _ = file.write_all(b"Injection succeeded!");
                1
            } else {
                0
            }
        }
        Err(_) => 0,
    }
}