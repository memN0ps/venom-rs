# Shellcode Reflective DLL Injection (sRDI)

Development is in progress.

## Features

* x86_64 and x86 support
* Gets modules and exports by name
* Uses `PAGE_READWRITE` to copy sections and headers (avoids RWX)
    * Sets memory protection for each section manually
    * Frees memory using `VirtualFree` after calling DllMain
* Remove DOS header and NT headers (TODO)
* Use `LdrLoadDll`, `NtAllocateVirtualMemory`, `NtProtectVirtualMemory` (TODO)


## Other names

* Reflective DLL Injection
* Shellcode Reflective DLL Injection
* Reflective PE Injection
* Portable Executable Reflection (PE Reflection)
* Portable Executable (PE Injection)
* Manual Mapping (very very similar to manual mapping)

## References and Credits

* https://github.com/stephenfewer/ReflectiveDLLInjection/
* https://discord.com/invite/rust-lang-community (Rust Community #windows-dev channel)
* https://github.com/dismantl/ImprovedReflectiveDLLInjection
* https://disman.tl/2015/01/30/an-improved-reflective-dll-injection-technique.html
* https://bruteratel.com/research/feature-update/2021/06/01/PE-Reflection-Long-Live-The-King/
* https://github.com/Cracked5pider/KaynLdr
* https://github.com/monoxgas/sRDI
* https://github.com/Ben-Lichtman/reloader/
* https://github.com/not-matthias/mmap/
* https://github.com/memN0ps/mmapper-rs
* https://github.com/2vg/blackcat-rs/tree/master/crate/mini-sRDI
* https://github.com/Jaxii/idk-rs/