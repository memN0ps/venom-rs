#![feature(const_char_convert)]

mod loader;

fn main() {
    let dll_bytes = include_bytes!("C:\\Users\\User\\Documents\\GitHub\\shellcode_reflective_dll_injection-rs\\testdll\\target\\debug\\testdll.dll");

    env_logger::init();
    
    loader::reflective_loader(dll_bytes);
}
