use std::{fs::{self}, slice};

use windows_sys::Win32::System::{SystemServices::IMAGE_DOS_HEADER, Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_NT_OPTIONAL_HDR64_MAGIC}};

use crate::pe_utils::{get_section_pointer_and_size_by_name};

mod pe_utils;

fn main() {
    env_logger::init();

    let dll_bytes = include_bytes!(r"C:\Users\memn0ps\Documents\GitHub\srdi-rs\testdll\target\debug\testdll.dll");    
    let user_function_hash = hash("SayHello");
    log::debug!("User function hash: u32: {:?} Hex: {:#X}", user_function_hash, user_function_hash);
    let user_data = "memN0ps";
    //let _user_data_length = user_data.len();

    let mut data: Vec<u8> = dll_bytes.to_vec();
    let data_size = data.len();
    let mut final_shellcode: Vec<u8> = Vec::new();
    let mut final_size = 0;

    convert_to_shellcode(&mut data, data_size, user_function_hash, user_data, user_data.len() as _, &mut final_shellcode, &mut final_size);

    //let mut file = File::create("shellcode.bin").expect("failed to created a file");

    fs::write(r"..\shellcode.bin", final_shellcode).expect("Failed to write shellcode to a file");
}

//https://github.com/monoxgas/sRDI/blob/master/Native/Loader.cpp
fn convert_to_shellcode(dll_bytes: &mut Vec<u8>, dll_length: usize, user_function: u32, user_data: &str, user_data_length: u32, out_bytes: &mut Vec<u8>, out_length: &mut u32) {
    
    let mut reflective_loader_bytes = include_bytes!(r"C:\Users\memn0ps\Documents\GitHub\srdi-rs\reflective_loader\target\debug\reflective_loader.dll").to_vec();
    let reflective_loader_ptr = reflective_loader_bytes.as_mut_ptr();

    // Get the RDI shellcode .text section pointer and size
    let (text_section_ptr, text_section_size) = unsafe { get_section_pointer_and_size_by_name(reflective_loader_ptr as _, ".text") };
    let mut rdi_shellcode_text_section: Vec<u8> = unsafe { slice::from_raw_parts(text_section_ptr as _, text_section_size).to_vec() };
    let rdi_shellcode_text_section_length = rdi_shellcode_text_section.len();

    if !is_64_dll(dll_bytes.as_mut_ptr() as _) {
        log::debug!("[-] The image provided is not x64 bit");
        panic!("[-] The file is not a x64 dll");
    }


    let mut bootstrap: Vec<u8> = Vec::new();
    const BOOTSTRAP_TOTAL_LENGTH: u32 = 59; // THIS NEEDS TO CHANGE IF THE SHELLCODE BELOW CHANGES

    // call next instruction (Pushes next instruction address to stack)
    bootstrap.push(0xe8);
    bootstrap.push(0x00);
    bootstrap.push(0x00);
    bootstrap.push(0x00);
    bootstrap.push(0x00);
    
    // pop rcx - Capture our current location in memory
    bootstrap.push(0x59);

    // mov r8, rcx - copy our location in memory to r8 before we start modifying RCX
    bootstrap.push(0x49);
    bootstrap.push(0x89);
    bootstrap.push(0xc8);

    // mov edx, <hash of function>
    bootstrap.push(0xba);
    bootstrap.append(&mut user_function.to_le_bytes().to_vec().clone());

    // Setup the location of our user data
    // add r8, <Offset of the DLL> + <Length of DLL>
    bootstrap.push(0x49);
    bootstrap.push(0x81);
    bootstrap.push(0xc0);
    let user_data_offset = (BOOTSTRAP_TOTAL_LENGTH - 5) as u32 + rdi_shellcode_text_section_length as u32 + dll_length as u32;
    bootstrap.append(&mut user_data_offset.to_le_bytes().to_vec().clone());

    // mov r9d, <Length of User Data>
    bootstrap.push(0x41);
    bootstrap.push(0xb9);
    bootstrap.append(&mut user_data_length.to_le_bytes().to_vec().clone());

	// push rsi - save original value
    bootstrap.push(0x56);

    // mov rsi, rsp - store our current stack pointer for later
    bootstrap.push(0x48);
    bootstrap.push(0x89);
    bootstrap.push(0xe6);

    // and rsp, 0x0FFFFFFFFFFFFFFF0 - Align the stack to 16 bytes
    bootstrap.push(0x48);
    bootstrap.push(0x83);
    bootstrap.push(0xe4);
    bootstrap.push(0xf0);

    // sub rsp, 0x30 - Create some breathing room on the stack
    bootstrap.push(0x48);
    bootstrap.push(0x83);
    bootstrap.push(0xec);
    bootstrap.push(6 * 8); // 32 bytes for shadow space + 16 bytes for last args

    // add rcx, <Offset of the DLL>
    bootstrap.push(0x48);
    bootstrap.push(0x81);
    bootstrap.push(0xc1);
    let dll_offset = (BOOTSTRAP_TOTAL_LENGTH - 5) as u32 + rdi_shellcode_text_section_length as u32;
    bootstrap.append(&mut dll_offset.to_le_bytes().to_vec().clone());

    // call - Transfer execution to the RDI (calls reflective loader's .text section)
    bootstrap.push(0xe8);
    let skip_instruction = BOOTSTRAP_TOTAL_LENGTH - bootstrap.len() as u32 - 4 as u32; // Skip over the remainder of instructions
    bootstrap.append(&mut skip_instruction.to_le_bytes().to_vec().clone());
    bootstrap.push(0x00);
    bootstrap.push(0x00);
    bootstrap.push(0x00);

    // mov rsp, rsi - Reset our original stack pointer
    bootstrap.push(0x48);
    bootstrap.push(0x89);
    bootstrap.push(0xf4);

    // pop rsi - Put things back where we left them
    bootstrap.push(0x5e);

    // ret - return to caller
    bootstrap.push(0xc3);
    
    //log::debug!("{:02X?}", bootstrap);
    log::debug!("Size: {:?}", bootstrap.len());

    // Ends up looking like this in memory:
	// Bootstrap shellcode
    // RDI shellcode
    // DLL bytes
    // User data
    *out_length = (bootstrap.len() + rdi_shellcode_text_section_length + dll_length + user_data_length as usize) as u32;
    log::debug!("out_length: {:?}", out_length);

    // Bootstrap shellcode
    out_bytes.append(&mut bootstrap);
    
    out_bytes.append(&mut rdi_shellcode_text_section);    
    //out_bytes.append(&mut rdi_shellcode);

    // DLL bytes
    out_bytes.append(dll_bytes);
    
    // User data
    out_bytes.append(&mut user_data.as_bytes().to_vec());
}

fn is_64_dll(module_base: usize) -> bool {

    let dos_header = module_base as *mut IMAGE_DOS_HEADER;

    #[cfg(target_arch = "x86")]
    let nt_headers = unsafe { (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS32 };
    #[cfg(target_arch = "x86_64")]
    let nt_headers = unsafe { (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64 };

    if unsafe { (*nt_headers).OptionalHeader.Magic } == IMAGE_NT_OPTIONAL_HDR64_MAGIC { //PE64
       return true;
    } 

    return false;
}

// Thanks MaulingMonkey and chrisd :) (Rust Community Discord server #windows-dev)
fn hash(word: &str) -> u32 {
    const HASH_KEY: u32 = 13;
    let mut h = 0_u32;
    for c in word.bytes() {
        h = h.rotate_right(HASH_KEY * 2);
        h += c as u32;
    }
    h.rotate_right(HASH_KEY)
}