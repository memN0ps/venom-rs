#![feature(const_char_convert)]

mod loader;

fn main() {
    println!("Reflective DLL Injection");
    loader::reflective_loader();
}
