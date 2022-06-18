use std::{arch::asm, ffi::{CStr}, collections::BTreeMap, mem::size_of, intrinsics::copy_nonoverlapping};

use winapi::{um::winnt::{PIMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, PIMAGE_NT_HEADERS64, IMAGE_DIRECTORY_ENTRY_EXPORT, PIMAGE_EXPORT_DIRECTORY, IMAGE_DOS_HEADER, PIMAGE_NT_HEADERS32, IMAGE_NT_SIGNATURE, PIMAGE_SECTION_HEADER}};
use ntapi::{ntpebteb::PTEB, ntldr::{PLDR_DATA_TABLE_ENTRY}, ntpsapi::PEB_LDR_DATA};
use wchar::wch;

const KERNEL32DLL_HASH: u32 = fnv1a_hash_32_wstr(wch!("kernel32.dll"));
const NTDLLDLL_HASH: u32 = fnv1a_hash_32_wstr(wch!("ntdll.dll"));

const LOADLIBRARYA_HASH: u32 = fnv1a_hash_32("LoadLibraryA".as_bytes());
const GETPROCADDRESS_HASH: u32 = fnv1a_hash_32("GetProcAddress".as_bytes());
const VIRTUALALLOC_HASH: u32 = fnv1a_hash_32("VirtualAlloc".as_bytes());
const NTFLUSHINSTRUCTIONCACHE_HASH: u32 = fnv1a_hash_32("NtFlushInstructionCache".as_bytes());

pub fn reflective_loader() {
    // STEP 0: calculate our images current base address

    // we will start searching backwards from our callers return address.
	let rip: usize;
	
    unsafe {
        #[cfg(target_arch = "x86")]
        asm!("lea {eip}, [eip]", rip = out(reg) rip);

        #[cfg(target_arch = "x86_64")]
		asm!("lea {rip}, [rip]", rip = out(reg) rip);
	};

    let mut library_address = rip & !0xfff;
    println!("[+] Return address: {:#x}", library_address);

	// loop through memory backwards searching for our images base address
    loop {
        if unsafe { (*(library_address as PIMAGE_DOS_HEADER)).e_magic == IMAGE_DOS_SIGNATURE } {
            let mut header_value = unsafe { (*(library_address as PIMAGE_DOS_HEADER)).e_lfanew } as usize;
            // some x64 dll's can trigger a bogus signature (IMAGE_DOS_SIGNATURE == 'POP r10'),
			// we sanity check the e_lfanew with an upper threshold value of 1024 to avoid problems.
            if header_value >= size_of::<IMAGE_DOS_HEADER>() && header_value < 1024 {

                header_value += library_address;
				// break if we have found a valid MZ/PE header
                if unsafe { (*(header_value as PIMAGE_NT_HEADERS64)).Signature == IMAGE_NT_SIGNATURE 
                    || (*(header_value as PIMAGE_NT_HEADERS32)).Signature == IMAGE_NT_SIGNATURE } {
                    println!("[+] IMAGE_DOS_HEADER: {:#x}", library_address);
                    break;
                }
            }
        }
        library_address -= 1;
    }

    // STEP 1: process the kernels exports for the functions our loader needs...

    // get the Process Enviroment Block
	let teb: PTEB;
	unsafe {
        #[cfg(target_arch = "x86")]
		asm!("mov {teb}, fs:[0x18]", teb = out(reg) teb);

		#[cfg(target_arch = "x86_64")]
		asm!("mov {teb}, gs:[0x30]", teb = out(reg) teb);
	}

	let teb = unsafe { &mut *teb };
	let peb = unsafe { &mut *teb.ProcessEnvironmentBlock };
	let peb_ldr = unsafe { &*peb.Ldr };

    // get kernel32 base address via hash
    let kernel32_base = get_loaded_module_by_hash(peb_ldr, KERNEL32DLL_HASH).expect("failed to kernel32 by hash");
    println!("KERNEL32: {:?}", kernel32_base);
    
    // get ntdll base address via hash
    let ntdll_base = get_loaded_module_by_hash(peb_ldr, NTDLLDLL_HASH).expect("failed to get ntdll by hash");
    println!("NTDLL: {:?}", ntdll_base);

    // get exports by hash and store the their virtual address
    //kernel32
    let loadlibrarya_hash = get_exports_by_hash(kernel32_base, LOADLIBRARYA_HASH).expect("failed to get LoadLibraryA by hash");
    println!("[+] LoadLibraryA {:?}", loadlibrarya_hash);

    let getprocaddress_hash = get_exports_by_hash(kernel32_base, GETPROCADDRESS_HASH).expect("failed to get GetProcAddress by hash");
    println!("[+] GetProcAddress {:?}", getprocaddress_hash);

    let virtualalloc_hash = get_exports_by_hash(kernel32_base, VIRTUALALLOC_HASH).expect("failed to get VirtualAlloc by hash");
    println!("[+] VirtualAlloc {:?}", virtualalloc_hash);

    //ntdll
    let ntflushinstructioncache_hash = get_exports_by_hash(ntdll_base, NTFLUSHINSTRUCTIONCACHE_HASH).expect("failed to get NtFlushInstructionCache by hash");
    println!("[+] NtFlushInstructionCache {:?}", ntflushinstructioncache_hash);


    // STEP 2: load our image into a new permanent location in memory...
    let local_image = copy_sections_to_local_process(library_address);
    println!("[+] Local Image: {:p}", local_image.as_ptr());

    // STEP 4: process our images import table...


    pause();
}

/// Copy sections of the dll to a memory location in local process (heap) and does not use VirtualAlloc or HeapAlloc
fn copy_sections_to_local_process(library_address: usize) -> Vec<u8> {

    let dos_header = library_address as PIMAGE_DOS_HEADER;

    #[cfg(target_arch = "x86")]
    let nt_headers = unsafe { (*dos_header).e_lfanew as PIMAGE_NT_HEADERS32 };

    #[cfg(target_arch = "x86_64")]
    let nt_headers = unsafe { (library_address + (*dos_header).e_lfanew as usize) as PIMAGE_NT_HEADERS64 };

    let image_size = unsafe { (*nt_headers).OptionalHeader.SizeOfImage } as usize ;
    
    // Allocate memory on the heap for the image
    let mut image = vec![0; image_size];

    // get a pointer to the _IMAGE_SECTION_HEADER
    let section_header = unsafe { (&(*nt_headers).OptionalHeader as *const _ as usize + (*nt_headers).FileHeader.SizeOfOptionalHeader as usize) as PIMAGE_SECTION_HEADER };

    for i in unsafe { 0..(*nt_headers).FileHeader.NumberOfSections } {
        // get a reference to the current _IMAGE_SECTION_HEADER
        let section_header_i = unsafe { &*(section_header.add(i as usize)) };

        // get the pointer to current section header's virtual address
        let destination = unsafe { image.as_mut_ptr().offset(section_header_i.VirtualAddress as isize) };
        //println!("destination: {:?}", destination);
        
        // get a pointer to the current section header's data
        let source = library_address as usize + section_header_i.PointerToRawData as usize;
        //println!("source: {:#x}", source);
        
        // get the size of the current section header's data
        let size = section_header_i.SizeOfRawData as usize;
        //println!("Size: {:?}", size);

        // copy section headers into the local process (allocated memory on the heap)
        unsafe { 
            copy_nonoverlapping(
                source as *const std::ffi::c_void, // must be std::ffi::c_void not winapi::c_void or else it fails
                destination as *mut _,
                size,
            )
        };
    }

    image
}

/// Gets exports by hash
fn get_exports_by_hash(module_base: *mut u8, hash: u32) -> Option<*mut u8> {

    // loop through the module exports to find export by hash
    for (name, addr) in unsafe { get_module_exports(module_base) } {
        if fnv1a_hash_32(name.as_bytes()) == hash {
            return Some(addr as _);
        }
    }

    return None;
}

/// Retrieves all function and addresses from the specfied modules
unsafe fn get_module_exports(module_base: *mut u8) -> BTreeMap<String, usize> {
    let mut exports = BTreeMap::new();
    
    let dos_header = module_base as PIMAGE_DOS_HEADER;

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

    println!("[+] Module Base: {:?} Export Directory: {:?} AddressOfNames: {names:p}, AddressOfFunctions: {functions:p}, AddressOfNameOrdinals: {ordinals:p} ", module_base, export_directory);

    for i in 0..(*export_directory).NumberOfNames {

        let name = (module_base as usize + names[i as usize] as usize) as *const i8;

        if let Ok(name) = CStr::from_ptr(name).to_str() {

            let ordinal = ordinals[i as usize] as usize;

            exports.insert(
                name.to_string(),
                module_base as usize + functions[ordinal] as usize,
            );
        }
    }  
    exports
}

/// Gets loaded modules by unique hash
pub fn get_loaded_module_by_hash(ldr: &PEB_LDR_DATA, hash: u32) -> Option<*mut u8> {
	let mut ldr_data_ptr = ldr.InLoadOrderModuleList.Flink as PLDR_DATA_TABLE_ENTRY;
	
    while !ldr_data_ptr.is_null() {
		let ldr_data = unsafe { &*ldr_data_ptr };

		let dll_name = ldr_data.BaseDllName;
		let buffer = dll_name.Buffer;
		
        if buffer.is_null() {
			break;
		}

		let dll_name_wstr = unsafe { core::slice::from_raw_parts(buffer, dll_name.Length as usize / 2) };

		if fnv1a_hash_32_wstr(dll_name_wstr) != hash {
			ldr_data_ptr = ldr_data.InLoadOrderLinks.Flink as PLDR_DATA_TABLE_ENTRY;
			continue;
		}

		return Some(ldr_data.DllBase as _);
	}

	None
}

/* 
unsafe fn rva_to_file_offset_pointer(module_base: usize, mut rva: u32) -> usize {
    let dos_header = module_base as PIMAGE_DOS_HEADER;

    let nt_headers = (module_base as usize + (*dos_header).e_lfanew as usize) as PIMAGE_NT_HEADERS;

    let ref_nt_headers = &*nt_headers;

    let section_header = ((&ref_nt_headers.OptionalHeader as *const _ as usize) 
        + (ref_nt_headers.FileHeader.SizeOfOptionalHeader as usize)) as PIMAGE_SECTION_HEADER;

    let number_of_sections = (*nt_headers).FileHeader.NumberOfSections;
    
    for i in 0..number_of_sections as usize {

        let virt_address = (*section_header.add(i)).VirtualAddress;
        let virt_size = (*section_header.add(i)).Misc.VirtualSize();
        
        if virt_address <= rva && virt_address + virt_size > rva {

            rva -= (*section_header.add(i)).VirtualAddress;
            rva += (*section_header.add(i)).PointerToRawData;
            
            return module_base + rva as usize;
        }
    }

    return 0;
}
*/

//https://github.com/Ben-Lichtman/reloader/blob/7d4e82b64f0ee6bf56dec47153721f62e207faa7/src/helpers.rs#L18
pub const fn fnv1a_hash_32_wstr(wchars: &[u16]) -> u32 {
	const FNV_OFFSET_BASIS_32: u32 = 0x811c9dc5;
	const FNV_PRIME_32: u32 = 0x01000193;

	let mut hash = FNV_OFFSET_BASIS_32;

	let mut i = 0;
	while i < wchars.len() {
		let c = unsafe { char::from_u32_unchecked(wchars[i] as u32).to_ascii_lowercase() };
		hash ^= c as u32;
		hash = hash.wrapping_mul(FNV_PRIME_32);
		i += 1;
	}
	hash
}

//https://github.com/Ben-Lichtman/reloader/blob/7d4e82b64f0ee6bf56dec47153721f62e207faa7/src/helpers.rs#L34
pub const fn fnv1a_hash_32(chars: &[u8]) -> u32 {
	const FNV_OFFSET_BASIS_32: u32 = 0x811c9dc5;
	const FNV_PRIME_32: u32 = 0x01000193;

	let mut hash = FNV_OFFSET_BASIS_32;

	let mut i = 0;
	while i < chars.len() {
		let c = unsafe { char::from_u32_unchecked(chars[i] as u32).to_ascii_lowercase() };
		hash ^= c as u32;
		hash = hash.wrapping_mul(FNV_PRIME_32);
		i += 1;
	}
	hash
}

fn get_input() -> std::io::Result<()> {
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(())
}
/// Used for debugging
fn pause() {
    match get_input() {
        Ok(buffer) => println!("{:?}", buffer),
        Err(error) => println!("error: {}", error),
    };
}
