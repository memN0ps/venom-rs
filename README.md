# Shellcode Reflective DLL Injection (sRDI)

Development in progress

## What is it?

Shellcode reflective DLL injection (sRDI) is a process injection technique that allows us to convert a given DLL into a position-independent shellcode which can then be injected using our favorite shellcode injection and execution technique.

## Usage

1. Build `testdll` project (feel free to modify the payload from `MessageBoxA` to whatever you want)
```
cd .\testdll\
cargo build
```

2. Build `reflective_loader` project. The loader will emulate `LoadLibraryA` and do additional things:

* Load required modules and exports by name
* Allocate memory and copy DOS / NT headers and sections into the newly allocated memory (`VirtualAlloc` uses `RW` not `RWX`)
* Process image relocations (rebase image)
* Process image import table (resolve imports)
* Set protection for each section (`VirtualProtect` uses only what is necessary)
* Execute `DllMain` AND `USER_FUNCTION` (export address is retrieved via hash)

```
cd .\reflective_loader\
cargo build
```

3. Run `generate_shellcode` project. This will generate a `shellcode.bin` file that looks like this in memory:

```
-----------------------
| Bootstrap Shellcode |
-----------------------
| Reflective DLL      |
-----------------------
| User DLL            |
-----------------------
| User Data           |
-----------------------
```

```
cd .\generate_shellcode\
cargo run
```

4. Run `inject` or bring your own injector and inject `shellcode.bin` with your favorite shellcode injection and execution technique.

```
cd .\inject\
cargo run
```

## TODO
* Change all exports to be retrieved by hash rather than name
* Stomp / erase DOS and NT headers
* Free shellcode memory and exit thread
* x86 support (mostly already done)

## References and Credits

* https://www.netspi.com/blog/technical/adversary-simulation/srdi-shellcode-reflective-dll-injection/
* https://github.com/monoxgas/sRDI
* https://github.com/stephenfewer/ReflectiveDLLInjection/
* https://discord.com/invite/rust-lang-community (Rust Community #windows-dev channel)
* https://github.com/dismantl/ImprovedReflectiveDLLInjection
* https://disman.tl/2015/01/30/an-improved-reflective-dll-injection-technique.html
* https://bruteratel.com/research/feature-update/2021/06/01/PE-Reflection-Long-Live-The-King/
* https://github.com/Cracked5pider/KaynLdr
* https://github.com/Ben-Lichtman/reloader/
* https://github.com/not-matthias/mmap/
* https://github.com/memN0ps/mmapper-rs
* https://github.com/2vg/blackcat-rs/tree/master/crate/mini-sRDI
* https://github.com/Jaxii/idk-rs/
* https://github.com/janoglezcampos/rust_syscalls/