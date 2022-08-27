use windows_sys::Win32::{System::{Threading::{OpenProcess, PROCESS_ALL_ACCESS}}, Foundation::{CloseHandle}};

use crate::{load_library::load_remote_library, pe_utils::get_process_id_by_name};

mod load_library;
mod pe_utils;

fn main() {
    env_logger::init();
    
    let process_id = get_process_id_by_name("notepad.exe") as u32;
    log::debug!("[+] Process ID: {}", process_id);

    let dll_bytes = include_bytes!(r"C:\Users\memn0ps\Documents\GitHub\srdi-rs\reflective_loader\target\debug\reflective_loader.dll");
    let module_base = dll_bytes.as_ptr() as usize;

    // Get a handle to the target process with PROCESS_ALL_ACCESS
    let process_handle = unsafe { 
        OpenProcess(
            PROCESS_ALL_ACCESS,
            0,
            process_id
        )
    };

    if process_handle == 0 {
        panic!("Failed to open a handle to the target process");
    }

    log::debug!("[+] Process handle: {:?}", process_handle);

    // Load DLL into the target process
    load_remote_library(process_handle, module_base);

    // Close thread handle
    unsafe { CloseHandle(process_handle); };

}