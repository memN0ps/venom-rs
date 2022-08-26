use std::ffi::c_void;
use windows_sys::Win32::{System::{Memory::{MEM_RELEASE, VirtualFree}, SystemServices::DLL_PROCESS_ATTACH}, Foundation::{HINSTANCE, BOOL}, UI::WindowsAndMessaging::MessageBoxA};

mod loader;

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "system" fn DllMain(
    _module: HINSTANCE,
    call_reason: u32,
    _reserved: *mut c_void,
) -> BOOL {
    if call_reason == DLL_PROCESS_ATTACH {
        // Cleanup RWX region (thread)
        VirtualFree(_reserved, 0, MEM_RELEASE);
        MessageBoxA(
            0 as _,
            "Rust DLL injected!\0".as_ptr() as _,
            "Rust DLL\0".as_ptr() as _,
            0x0,
        );

        1
    } else {
        1
    }
}