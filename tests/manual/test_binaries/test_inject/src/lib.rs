use std::ffi::CStr;
use std::fs::File;
use std::io::Write;
use std::os::raw::c_char;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::System::Console::AllocConsole;


#[no_mangle]
extern "system" fn DllMain(
    _hinst_dll: *const u8,
    _fdw_reason: u32,
    _lpv_reserved: *const u8,
) -> bool {
    match _fdw_reason {
        DLL_PROCESS_ATTACH => unsafe { AllocConsole() }.unwrap_or(()),
        _ => ()
    }

    // return True on successful attach
    true
}


#[no_mangle]
pub extern "C" fn create_file_at_path(path: *const c_char) -> bool {
    if path.is_null() {
        return false;
    }

    let c_str = unsafe { CStr::from_ptr(path) };

    let Ok(path_str) = c_str.to_str() else {
        return false;
    };

    let Ok(mut file) = File::create(path_str) else {
        return false;
    };

    file.write_all(b"Injected").is_ok()

}
