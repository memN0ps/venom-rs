#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

use core::{ffi::c_void, slice::from_raw_parts, arch::asm};
use std::{collections::BTreeMap, ffi::CStr};
use windows_sys::{
    Win32::{
        Foundation::{HANDLE, UNICODE_STRING, BOOLEAN},
        System::{
            Diagnostics::{Debug::{
                IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER, IMAGE_DIRECTORY_ENTRY_EXPORT,
            }},
            SystemServices::{
                IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE,
            }, WindowsProgramming::{CLIENT_ID}, Kernel::{LIST_ENTRY, NT_TIB}, Threading::PEB,
        },
    },
};

/// Gets exports by name
pub fn get_exports_by_name(module_base: *mut u8, module_name: String) -> Option<*mut u8> {
    // loop through the module exports to find export by name
    for (name, addr) in unsafe { get_module_exports(module_base) } {
        if name == module_name {
            return Some(addr as _);
        }
    }
    return None;
}

/// Retrieves all functions and addresses from the specfied module
pub unsafe fn get_module_exports(module_base: *mut u8) -> BTreeMap<String, usize> {
    let mut exports = BTreeMap::new();

    let dos_header = module_base as *mut IMAGE_DOS_HEADER;

    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        panic!("[-] Failed to get DOS header");
    }

    let nt_header = (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;

    let export_directory = rva_to_file_offset_pointer(
        module_base as usize,
        (*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
            .VirtualAddress as u32,
    ) as *mut IMAGE_EXPORT_DIRECTORY;

    let names = core::slice::from_raw_parts(
        rva_to_file_offset_pointer(module_base as usize, (*export_directory).AddressOfNames)
            as *const u32,
        (*export_directory).NumberOfNames as _,
    );

    let functions = core::slice::from_raw_parts(
        rva_to_file_offset_pointer(module_base as usize, (*export_directory).AddressOfFunctions)
            as *const u32,
        (*export_directory).NumberOfFunctions as _,
    );

    let ordinals = core::slice::from_raw_parts(
        rva_to_file_offset_pointer(
            module_base as usize,
            (*export_directory).AddressOfNameOrdinals,
        ) as *const u16,
        (*export_directory).NumberOfNames as _,
    );

    for i in 0..(*export_directory).NumberOfNames {
        let name = rva_to_file_offset_pointer(module_base as usize, names[i as usize]) as *const i8;

        if let Ok(name) = CStr::from_ptr(name).to_str() {
            let ordinal = ordinals[i as usize] as usize;
            exports.insert(
                name.to_string(),
                rva_to_file_offset_pointer(module_base as usize, functions[ordinal]),
            );
        }
    }
    exports
}

pub unsafe fn rva_to_file_offset_pointer(module_base: usize, mut rva: u32) -> usize {
    let dos_header = module_base as *mut IMAGE_DOS_HEADER;
    
    let nt_headers = (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;

    let ref_nt_headers = &*nt_headers;

    let section_header = ((&ref_nt_headers.OptionalHeader as *const _ as usize)
        + (ref_nt_headers.FileHeader.SizeOfOptionalHeader as usize))
        as *mut IMAGE_SECTION_HEADER;

    let number_of_sections = (*nt_headers).FileHeader.NumberOfSections;

    for i in 0..number_of_sections as usize {
        let virt_address = (*section_header.add(i)).VirtualAddress;
        let virt_size = (*section_header.add(i)).Misc.VirtualSize;

        if virt_address <= rva && virt_address + virt_size > rva {
            rva -= (*section_header.add(i)).VirtualAddress;
            rva += (*section_header.add(i)).PointerToRawData;

            return module_base + rva as usize;
        }
    }
    return 0;
}

/// Get a pointer to the Thread Environment Block (TEB)
pub unsafe fn get_teb() -> *mut TEB 
{
    let teb: *mut TEB;
    asm!("mov {teb}, gs:[0x30]", teb = out(reg) teb);
    teb
}

/// Get a pointer to the Process Environment Block (PEB)
pub unsafe fn get_peb() -> *mut PEB 
{
    let teb = get_teb();
    let peb = (*teb).ProcessEnvironmentBlock;
    peb
}

pub unsafe fn get_loaded_module_by_name(module_name: &[u8]) -> Option<*mut u8> 
{
    let peb = get_peb();
    let peb_ldr_data_ptr = (*peb).Ldr as *mut PEB_LDR_DATA;
    let mut module_list = (*peb_ldr_data_ptr).InLoadOrderModuleList.Flink as *mut LDR_DATA_TABLE_ENTRY;

    while !(*module_list).DllBase.is_null() 
    {
        let dll_buffer_ptr = (*module_list).BaseDllName.Buffer;
        let dll_length = (*module_list).BaseDllName.Length as usize;
        let dll_name_slice = from_raw_parts(dll_buffer_ptr as *const u8, dll_length);

        if module_name == dll_name_slice
        {
            return Some((*module_list).DllBase as _);
        }

        module_list = (*module_list).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
    }

    return None;
}

pub unsafe fn get_section_header_by_hash(module_base: *mut u8, section_hash: u32) -> Option<*mut IMAGE_SECTION_HEADER> {
    let dos_header = module_base as *mut IMAGE_DOS_HEADER;
    
    let nt_headers = (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;

    let section_header = (&(*nt_headers).OptionalHeader as *const _ as usize
        + (*nt_headers).FileHeader.SizeOfOptionalHeader as usize)
        as *mut IMAGE_SECTION_HEADER;

    for i in 0..(*nt_headers).FileHeader.NumberOfSections as usize {
        let section_name = (*section_header.add(i)).Name;
        //log::info!("{}", std::str::from_utf8(&section_name).unwrap());

        if section_hash == dbj2_hash(&section_name) {
            return Some(section_header);
        }
    }

    None
}

/// Get a pointer to IMAGE_DOS_HEADER
pub unsafe fn get_dos_header(module_base: *mut u8) -> Option<*mut IMAGE_DOS_HEADER> 
{
    let dos_header = module_base as *mut IMAGE_DOS_HEADER;

    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE 
    {
        return None;
    }

    return Some(dos_header);
}

/// Get a pointer to IMAGE_NT_HEADERS64 x86_64
pub unsafe fn get_nt_headers(module_base: *mut u8) -> Option<*mut IMAGE_NT_HEADERS64> 
{
    let dos_header = get_dos_header(module_base)?;

    let nt_headers = (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;

    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE as _ 
    {
        return None;
    }

    return Some(nt_headers);
}

pub fn dbj2_hash(buffer: &[u8]) -> u32 
{
    let mut hash: u32 = 5381;
    let mut i: usize = 0;
    let mut char: u8;

    while i < buffer.len() 
    {
        char = buffer[i];
        
        if char == 0 
        {
            i += 1;
            continue;
        }
        
        if char >= ('a' as u8) 
        {
            char -= 0x20;
        }

        hash = ((hash << 5).wrapping_add(hash)) + char as u32;
        i += 1;
    }

    return hash;
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