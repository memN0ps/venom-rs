# Shellcode Reflective DLL Injection (sRDI)

Development is in progress.

## How it works 

1. We calculate our images current base address
    - We use inline assembly to do this to avoid `GetCurrentProcess()`
    - Walk backwards after getting the return address until we see the IMAGE_DOS_HEADER
2. We process the `kernel32.dll` and `ntdll.dll` exports for the functions our loader needs
    - The Process Environment Block Address (PEB) is retrieved using inline assembly (ASM) to avoid `NtQueryInformationProcess()`
    - Exports are retreived via hashes as well as the DLL names
3. We load the image into a new location in memory
    - `VirtualAlloc() or HeapAlloc()` is normally used for this but it was not required as memory was allocated using a Vector (heap) avoiding `RWX`
4. We copy all our sections into the newly allocated memory location
    - The `copy_nonoverlapping()` function is used and `WriteProcessMemory()` is not required as we have access to the memory location when the DLL is injected.
5. We resolve the image imports
6. We rebase our image and perform image base relocations
7. We execute TLS callbacks (ToDo)
    - Not required but very basic anti-debugging technique
8. We calculate the `AddressOfEntryPoint` and call `DllMain()`
9. We return our new entry point address at the end so whatever called us can call Dllmain() if needed.


## References and Credits

* https://github.com/stephenfewer/ReflectiveDLLInjection/ (Special thanks to Stephen Fewer)
* https://discord.com/invite/rust-lang-community (Rust Community)
* https://github.com/Ben-Lichtman/reloader/ (B3NNY)
* https://github.com/memN0ps/mmapper-rs
* https://github.com/monoxgas/sRDI
* https://github.com/2vg/blackcat-rs/tree/master/crate/mini-sRDI