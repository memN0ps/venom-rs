# Shellcode Reflective DLL Injection (sRDI)

## Description

Shellcode reflective DLL injection (sRDI) is a process injection technique that allows us to convert a given DLL into a position-independent shellcode which can then be injected using our favourite shellcode injection and execution technique.

## Usage

0) [Install Rust](https://www.rust-lang.org/tools/install)

1). Build all of the projects

```
cargo build --release
```

2). Generate the shellcode.

```
Usage: generate_shellcode.exe [OPTIONS] --loader <LOADER> --payload <PAYLOAD> --function <FUNCTION> --parameter <PARAMETER> --output <OUTPUT>
```

3). Bring your own injector (BYOI) and inject the position-independent shellcode with your favourite injection and execution technique.

```
inject.exe <process> <shellcode.bin>
```

* Bootstrap is `bootstrap.asm`
* RDI is `reflective_loader.dll`
* Existing DLL is `payload.dll`
* User-Data is a parameter to `UserFunction` ()`https://127.0.0.1:1337/`)
* Flag allows execution of `DllMain` if `0` or `UserFunction` if not `0`
* Output is PIC shellcode (`shellcode.bin`) as shown below:

[![sRDI](./sRDI.png)](https://www.netspi.com/blog/technical/adversary-simulation/srdi-shellcode-reflective-dll-injection/)

## Example

```
.\generate_shellcode.exe --loader .\reflective_loader.dll --payload .\payload.dll --function UserFunction --parameter https://127.0.0.1:1337/ --output shellcode.bin

Loader Path: .\reflective_loader.dll
Payload Path: .\payload.dll
Output Path: shellcode.bin
[+] Reflective Loader Offset: 0x400
[+] Bootstrap Shellcode Length: 1769
[+] Reflective Loader Length: 3584
[+] Payload DLL Length: 113664
[+] Total Shellcode Length: 118968
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