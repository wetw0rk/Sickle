import sys
import cmd

from keystone import *

from sickle.formats import *

from sickle.common.handlers.format_handler import FormatHandler
from sickle.common.lib.reversing.assembler import Assembler
from sickle.common.lib.generic.convert import from_hex_to_raw
from sickle.common.lib.reversing.disassembler import Disassembler

class Module():

    name = "ASM Shell"

    module = "asm_shell"

    example_run = f"{sys.argv[0]} -a x64 -m {module} -f c"

    platform = "Multi"

    arch = "Multi"

    author = ["wetw0rk"]
   
    ring = "N/A"
 
    tested_platforms = ["Linux"]

    summary = "Interactive assembler and disassembler"

    description = """
    ASM Shell is as the name suggests an "Assembly Shell". It currently can be used
    to convert assembler code to opcode and vice versa. 
    """

    arguments = None

    def __init__(self, arg_object):
        self.varname  = arg_object["variable name"]
        self.arch     = arg_object["architecture"]
        self.format   = arg_object["format"]
        self.modes    = Assembler(self.arch).get_ks_arch_modes()

        self.format_module = FormatHandler(self.format, b"", None, "buf").get_language_formatter()
        self.disassembler = Disassembler(self.arch)

        return

    def do_thing(self):
        print(f"[*] ASM Shell loaded for {self.arch} architecture\n")

        mode = self.modes[self.arch]
        asm_loop = AsmShell()

        asm_loop.ks = mode
        asm_loop.fm = self.format_module
        asm_loop.disassembler = self.disassembler

        asm_loop.cmdloop()

class AsmShell(cmd.Cmd):
    prompt = "sickle > "

    def do_EOF(self, line):
        return True

    def do_d(self, line):
        """d [48ffc0]
        Convert opcode to assembly language"""
        raw_bytes = from_hex_to_raw(line)

        try:
            results = self.disassembler.get_linear_sweep(raw_bytes)
            if (results != None):
                for i in range(len(results["opcodes"])):
                    print(f"{results['opcodes'][i]:<32} -> {results['assembly'][i]}")
        except Exception as e:
            print(f"Error: {e}")

        return

    def do_a(self, line):
        """a [xor rax rax ; inc rax]
        Convert assembly language to opcodes"""
        try:
            encoding, count = self.ks.asm(line.encode())
        except Exception as e:
            print(f"Error: {e}")
            return

        hex_line = ""
        li = self.fm.get_language_information()
        for i in range(len(encoding)):
            hex_line += ("{:02x}".format(encoding[i]))

        self.fm.raw_bytes = from_hex_to_raw(hex_line)
        opcode_line = self.fm.get_generated_lines(True, True)[0]

        if (li['single line comment'] != None):
            print(f"{opcode_line} {li['single line comment']} {line}")
        else:
            print(opcode_line)

        return
