use std::ffi::c_void;
use windows_sys::Win32::{System::{SystemServices::DLL_PROCESS_ATTACH}, Foundation::{HINSTANCE, BOOL}, UI::WindowsAndMessaging::MessageBoxA};

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "system" fn DllMain(
    _module: HINSTANCE,
    call_reason: u32,
    _reserved: *mut c_void,
) -> BOOL {
    if call_reason == DLL_PROCESS_ATTACH {
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

// Think of this as the payload to be executed. Parameter can be called from the injector.
// We can call DLLMain and this function
#[allow(non_snake_case)]
#[allow(dead_code)]
#[no_mangle]
fn SayHello(user_data: *mut c_void, _user_data_len: u32) {
    
    unsafe  {
        MessageBoxA(
            0 as _,
            "SayHello called from\0".as_ptr() as _,
            user_data as _,
            0x0,
        );
    }
}