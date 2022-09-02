fn main() {
    /* 
    let ntdll = "NTDLL.DLL";
    println!("NTDLL.DLL: {:#x}", hash(ntdll));

    let kernel32 = "KERNEL32.DLL";
    println!("KERNEL32.DLL: {:#x}", hash(kernel32));

    let load_library_a = "LoadLibraryA";
    println!("LoadLibraryA: {:#x}", hash(load_library_a));

    let get_proc_address = "GetProcAddress";
    println!("GetProcAddress: {:#x}", hash(get_proc_address));

    let virtual_alloc = "VirtualAlloc";
    println!("VirtualAlloc: {:#x}", hash(virtual_alloc));

    let virtual_protect = "VirtualProtect";
    println!("VirtualProtect: {:#x}", hash(virtual_protect));

    let flush_instruction_cache = "FlushInstructionCache";
    println!("FlushInstructionCache: {:#x}", hash(flush_instruction_cache));
    */

    let say_hello = "SayHello";
    println!("SayHello: {:#x}", hash(say_hello));

    let user_parameter = "memN0ps";
    println!("user_parameter: {:#x}", hash(user_parameter));
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



