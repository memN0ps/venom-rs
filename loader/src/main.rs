#![feature(const_char_convert)]

mod loader;

fn main() {
    println!("Hello, world!");
    loader::reflective_loader();
}
