import os
import sys
import binascii

from sickle.common.lib.generic.mparser import argument_check
from sickle.common.lib.generic.extract import read_bytes_from_file

from sickle.common.lib.generic.colors import Colors
from sickle.common.lib.generic.colors import ansi_ljust
from sickle.common.lib.generic.colors import ansi_rjust
from sickle.common.lib.generic.colors import ansi_center

from sickle.common.lib.reversing.disassembler import Disassembler

class Module():

    author      = "wetw0rk"
    module_name = "diff"
    description = "Compare two binaries / shellcode(s). Supports hexdump, byte, raw, and asm modes"
    example_run = f"{sys.argv[0]} -a x64 -m diff -r original_shellcode BINFILE=modified_shellcode MODE=asm"

    arguments = {}

    arguments["BINFILE"] = {}
    arguments["BINFILE"]["optional"] = "no"
    arguments["BINFILE"]["description"] = "Additional binaries needed to perform diff"
    arguments["BINFILE"]["options"] = {"<file>": "File to be parsed"}

    arguments["MODE"] = {}
    arguments["MODE"]["optional"] = "no"
    arguments["MODE"]["description"] = "Method in which to output diff results"
    arguments["MODE"]["options"] = { "hexdump": "Output will include both hexadecimal opcodes and ASCII similiar to hexdump",
                                     "byte": "Output will be byte by byte and include individual char representation",
                                     "raw": "Output in \"raw\" format, this is similiar to pythons repr() function",
                                     "asm": "Output disassembled opcodes to selected assembly language" }

    def __init__(self, arg_object):
        self.arg_list    = arg_object["positional arguments"] 
        self.arch        = arg_object["architecture"]

        # Information for primary file / 1st source
        self.p_raw_bytes = arg_object["raw bytes"]
        self.p_size      = arg_object["num bytes"]
        self.p_src       = arg_object["source"]

        # Information for secondary file / 2nd source
        self.s_raw_bytes = None
        self.s_size      = None
        self.s_src       = None

        # variables used throughout the module there may be a better
        # method to avoid truncation, but manual exclusion eliminates
        # dependencies
        self.added   = Colors.GREEN
        self.changed = Colors.YELLOW
        self.deleted = Colors.RED
        self.alike   = ""
        self.ccolor  = ""

        self.badbytes = \
        [
            "\x00","\x01","\x02","\x03","\x04","\x05","\x06","\x07","\x08","\x09","\x0a",
            "\x0b","\x0c","\x0d","\x0e","\x0f","\x10","\x11","\x12","\x13","\x14","\x15",
            "\x16","\x17","\x18","\x19","\x1a","\x1b","\x1c","\x1d","\x1e","\x1f","\x7f",
            "\x80","\x81","\x82","\x83","\x84","\x85","\x86","\x87","\x88","\x89","\x8a",
            "\x8b","\x8c","\x8d","\x8e","\x8f","\x90","\x91","\x92","\x93","\x94","\x95",
            "\x96","\x97","\x98","\x99","\x9a","\x9b","\x9c","\x9d","\x9e","\x9f","\xa0"
        ]

    def do_thing(self):

        # Upon success a dictionary should be returned (e.g {"BINFILE": "", "MODE": ""})
        argv_dict = argument_check(Module.arguments, self.arg_list)
        if (argv_dict == None):
            exit(-1)

        ###
        # Having obtained the argument dictionary we need to sanity check the arguments
        # for the supported modes.
        ###
        diff_mode = argv_dict["MODE"]
        supported_diff_modes = Module.arguments["MODE"]["options"].keys()
        if (diff_mode not in supported_diff_modes):
            sys.exit(f'MODE: {diff_mode} not supported by module')

        # Extract opcodes from the second file
        self.s_src = argv_dict["BINFILE"]
        if os.path.isfile(self.s_src) is False:
            sys.exit(f"Error dumping {self.s_src}. Is file present?")
        else:
            self.s_raw_bytes = read_bytes_from_file(self.s_src)
            self.s_size = len(self.s_raw_bytes)

        # All diffing modes EXCEPT asm currently require the diff to occur
        # before formatting to the user
        if (diff_mode != "asm"):
            pre_diff = self.get_byte_diff()

        self.print_legend()
        if (diff_mode in supported_diff_modes):
            if diff_mode == "hexdump":
                self.print_hexdump(pre_diff)
            elif diff_mode == "byte":
                self.print_bytedump(pre_diff)
            elif diff_mode == "raw":
                self.print_raw_repr(pre_diff)
            else:
                self.print_asm_diff()

        exit(0)

    def print_asm_diff(self):
        disassembler = Disassembler(self.arch)

        p_analysis = disassembler.get_generic_bin_analysis(self.p_raw_bytes)
        p_alpha = p_analysis["alphanumeric"]
        p_addr = p_analysis["addresses"]
        p_ins = p_analysis["assembly"]
        p_ops = p_analysis["opcodes"]

        s_analysis = disassembler.get_generic_bin_analysis(self.s_raw_bytes)
        s_alpha = s_analysis["alphanumeric"]
        s_addr = s_analysis["addresses"]
        s_ins = s_analysis["assembly"]
        s_ops = s_analysis["opcodes"]

        # Determine the loop counter based on the largest disassembly length
        if len(p_ins) > len(s_ins):
            loopc = len(p_ins)
        else:
            loopc = len(s_ins)

        for i in range(loopc):
            # Opcodes
            try:
                if (p_ops[i] != s_ops[i]):
                    p_ops[i] = f"{self.changed}{p_ops[i]}{Colors.END}"
                    s_ops[i] = f"{self.changed}{s_ops[i]}{Colors.END}"
            except IndexError:
                if len(s_ops) > len(p_ops):
                    s_ops[i] = f"{self.added}{s_ops[i]}{Colors.END}"
                else:
                    p_ops[i] = f"{self.deleted}{p_ops[i]}{Colors.END}"

            # Instructions
            try:
                if p_ins[i] != s_ins[i]:
                    p_ins[i] = f"{self.changed}{p_ins[i]}{Colors.END}"
                    s_ins[i] = f"{self.changed}{s_ins[i]}{Colors.END}"
            except IndexError:
                if len(s_ins) > len(p_ins):
                    s_ins[i] = f"{self.added}{s_ins[i]}{Colors.END}"
                else:
                    p_ins[i] = f"{self.deleted}{p_ins[i]}{Colors.END}"

        # Setup, format, and print the headers
        p_block_lines = disassembler.get_fmt_block(p_addr, p_ops, p_ins)
        s_block_lines = disassembler.get_fmt_block(s_addr, s_ops, s_ins)

        pblock_line_length = (len(p_block_lines[0])-4)
        sblock_line_length = (len(s_block_lines[0])-4)

        headers  = []
        headers += ansi_center(f"{Colors.BOLD}{Colors.BLUE}{self.p_src}{Colors.END}", pblock_line_length),
        headers += ansi_center(f"{Colors.BOLD}{Colors.BLUE}{self.s_src}{Colors.END}", sblock_line_length), 
        headers += ansi_ljust(f"{Colors.BOLD}{Colors.BLUE}Architecture{Colors.END}: {self.arch}", pblock_line_length),
        headers += ansi_ljust(f"{Colors.BOLD}{Colors.BLUE}Architecture{Colors.END}: {self.arch}", sblock_line_length),
        headers += ansi_ljust(f"{Colors.BOLD}{Colors.BLUE}Alphanumeric{Colors.END}: {p_alpha}", pblock_line_length),
        headers += ansi_ljust(f"{Colors.BOLD}{Colors.BLUE}Alphanumeric{Colors.END}: {s_alpha}", sblock_line_length),
        headers += ansi_ljust(f"{Colors.BOLD}{Colors.BLUE}Size (bytes){Colors.END}: {len(self.p_raw_bytes)}", pblock_line_length),
        headers += ansi_ljust(f"{Colors.BOLD}{Colors.BLUE}Size (bytes){Colors.END}: {self.s_size}", sblock_line_length),

        print(p_block_lines[0] + ' ' + s_block_lines[0])
        for i in range(len(headers)):
            sys.stdout.write(f"| {headers[i]} |")
            if ((i % 2) != 0):
                sys.stdout.write('\n')
            else:
                sys.stdout.write(' ')

        # Determine the amount of loops based of the largest block
        if (len(p_block_lines) > len(s_block_lines)):
            loopc = len(p_block_lines)
        else:
            loopc = len(s_block_lines)

        # Print the ASM blocks
        for i in range(loopc):
            try:
                print(p_block_lines[i] + ' ' + s_block_lines[i])
            except IndexError:
                if (len(s_addr) > len(p_addr)):
                    print((' ' * (len(p_block_lines[0]) + 1)) + s_block_lines[i])
                else:
                    print(p_block_lines[i] + (' ' * (len(s_block_lines[0]) + 1)))

    def print_raw_repr(self, results):
        strs = ["", ""]

        for i in range(len(results)):
            for j in range(len(results[i])):
                c = results[i][j]
                if self.added in c:
                    self.ccolor = self.added
                elif self.changed in c:
                    self.ccolor = self.changed
                elif self.deleted in c:
                    self.ccolor = self.deleted
                else:
                    self.ccolor = self.alike

                c = int(c.lstrip(self.ccolor).lstrip(' '))
                c = repr(chr(c))[1:-1]
                strs[i] += f"{self.ccolor}{c}{Colors.END}"
        
        print(f"{Colors.BOLD}{Colors.BLUE}{self.p_src} ({len(self.p_raw_bytes)} bytes){Colors.END}: {strs[0]}\n")
        print(f"{Colors.BOLD}{Colors.BLUE}{self.s_src} ({len(self.s_raw_bytes)} bytes){Colors.END}: {strs[1]}\n")

    def print_bytedump(self, results):
    
        headers  = []
        headers += ansi_center(f"{Colors.BOLD}{Colors.BLUE}{self.p_src} ({len(self.p_raw_bytes)} bytes){Colors.END}", 60),
        headers += ansi_center(f"{Colors.BOLD}{Colors.BLUE}{self.s_src} ({len(self.p_raw_bytes)} bytes){Colors.END}", 60),
        headers += " "
        headers += " "
        headers += ansi_center(f"{Colors.BOLD}{Colors.BLUE}BYTES    RAW{Colors.END}", 60),
        headers += ansi_center(f"{Colors.BOLD}{Colors.BLUE}BYTES    RAW{Colors.END}", 60),

        for i in range(len(headers)):
            sys.stdout.write(headers[i])
            if ((i % 2) != 0):
                sys.stdout.write('\n')
        sys.stdout.write('\n')

        if len(results[0]) > len(results[1]):
            loopc = len(results[0])
        else:
            loopc = len(results[1])

        hex_byte = [
            "", # FILE1
            ""  # FILE2
        ]
        asc_byte = [
            "", # FILE1
            ""  # FILE2
        ]

        # similiar operation to hexdump mode
        index = 0
        for i in range(loopc):
            try:
                if results[0][i] != results[1][i]:
                    self.ccolor = self.changed
                else:
                    self.ccolor = self.alike

                r0 = int(results[0][i].lstrip(self.ccolor).lstrip(' '))
                r1 = int(results[1][i].lstrip(self.ccolor).lstrip(' '))
  
                hex_byte[0] = ansi_rjust(f"{self.ccolor}{hex(r0)[2:]:0>2}{Colors.END}", 26)
                hex_byte[1] = ansi_rjust(f"{self.ccolor}{hex(r1)[2:]:0>2}{Colors.END}", 49)

                asc_byte[0] = ansi_rjust(f"{self.ccolor}{repr(chr(r0))}{Colors.END}", 9)
                asc_byte[1] = ansi_rjust(f"{self.ccolor}{repr(chr(r1))}{Colors.END}", 9)

                print(f"{hex_byte[0]} {asc_byte[0]} {hex_byte[1]} {asc_byte[1]}")
                index += 1
            except IndexError:
                if len(results[1]) > len(results[0]):
                    self.ccolor = self.added
                    while index != loopc:
                        r1 = int(results[1][index].lstrip(self.ccolor).lstrip(' '))
                        hex_byte[1] = ansi_rjust(f"{self.ccolor}{hex(r1)[2:]:0>2}{Colors.END}", 86)
                        asc_byte[1] = ansi_rjust(f"{self.ccolor}{repr(chr(r1))}{Colors.END}", 9)

                        print(f"{hex_byte[1]} {asc_byte[1]}")
                        index += 1
                else:
                    self.ccolor = self.deleted
                    while index != loopc:
                        r0 = int(results[0][index].lstrip(self.ccolor).lstrip(' '))
                        hex_byte[0] = ansi_rjust(f"{self.ccolor}{hex(r0)[2:]:0>2}{Colors.END}", 26)
                        asc_byte[0] = ansi_rjust(f"{self.ccolor}{repr(chr(r0))}{Colors.END}", 9)

                        print(f"{hex_byte[0]} {asc_byte[0]}")
                        index += 1

    def print_hexdump(self, results):

        headers  = []
        headers += ansi_center(f"{Colors.BOLD}{Colors.BLUE}{self.p_src} ({len(self.p_raw_bytes)} bytes){Colors.END}", 67+16),
        headers += ansi_center(f"{Colors.BOLD}{Colors.BLUE}{self.s_src} ({len(self.s_raw_bytes)} bytes){Colors.END}", 67),

        for i in range(len(headers)):
            sys.stdout.write(headers[i])
            if ((i % 2) != 0):
                sys.stdout.write('\n')
        sys.stdout.write('\n')

        chunks  = [
            [results[0][i:i + 16] for i in range(0, len(results[0]), 16)], # FILE1
            [results[1][i:i + 16] for i in range(0, len(results[1]), 16)]  # FILE2
        ]

        hexdump_strs = [
            [], # FILE1
            []  # FILE2
        ]

        ascii_strs = [
            [], # FILE1
            []  # FILE1
        ]

        index = 0
        tmp = ""
        c = 0

        # format opcodes and ASCII strings to later be printed
        for i in range(len(chunks)):
            for j in range(len(chunks[i])):
                for k in range(len(chunks[i][j])):
                    clist = chunks[i][j]
          
                    if self.added in clist[k]:
                        self.ccolor = self.added
                    elif self.changed in clist[k]:
                        self.ccolor = self.changed
                    elif self.deleted in clist[k]:
                        self.ccolor = self.deleted
                    else:
                        self.ccolor = self.alike

                    c = int(clist[k].lstrip(self.ccolor).lstrip(' '))
                    c = f"{hex(c)[2:]:0>2}"

                    tmp += f" {self.ccolor}{c}{Colors.END}"

                hexdump_strs[i] += tmp.lstrip(' '),
                tmp = ""

                for k in range(len(chunks[i][j])):
                    clist = chunks[i][j]

                    if self.added in clist[k]:
                        self.ccolor = self.added
                    elif self.changed in clist[k]:
                        self.ccolor = self.changed
                    elif self.deleted in clist[k]:
                        self.ccolor = self.deleted
                    else:
                        self.ccolor = self.alike

                    c = int(clist[k].lstrip(self.ccolor).lstrip(' '))
                    c = chr(c)
          
                    if c in self.badbytes:
                        c = '.'

                    tmp += f"{self.ccolor}{c}{Colors.END}"

                ascii_strs[i] += tmp,
                tmp = ""

        # print results, we will leverage the indexerror to detect
        # any additional bytes
        if len(hexdump_strs[0]) > len(hexdump_strs[1]):
            hexdump_loopc = len(hexdump_strs[0])
        else:
            hexdump_loopc = len(hexdump_strs[1])

        ao = ""
        index = 0
        hex_str = ["", ""]
        ascii_str = ["", ""]
        for i in range(hexdump_loopc):
            try:
                ao = hex(i * 16)[2:]

                hex_str[0] = ansi_ljust(hexdump_strs[0][i], 48)
                hex_str[1] = ansi_ljust(hexdump_strs[1][i], 48)

                ascii_str[0] = ansi_ljust(f"|{ascii_strs[0][i]}|", 18)
                ascii_str[1] = ansi_ljust(f"|{ascii_strs[1][i]}|", 18)

                index += 1
                print(f"{ao:0>16} {hex_str[0]} {ascii_str[0]} {hex_str[1]} {ascii_str[1]}")
            except IndexError:
                if len(hexdump_strs[1]) > len(hexdump_strs[0]):
                    self.ccolor = self.added
                    while index != hexdump_loopc:
                        ao = hex(index * 16)[2:]
                        ao = f"{ao:0>16}"
                        ao = ansi_ljust(ao, 84)

                        hex_str[1] = ansi_ljust(hexdump_strs[1][index], 48)

                        ascii_str[1] = ansi_ljust(f"|{ascii_strs[1][index]}|", 18)

                        print(f"{ao:0>16} {hex_str[1]} {ascii_str[1]}")
                        index += 1

                else:
                    self.ccolor = self.deleted
                    while index != hexdump_loopc:
                        ao = hex(index * 16)[2:]
                        ao = f"{ao:0>16}"

                        hex_str[0] = ansi_ljust(hexdump_strs[0][index], 48)
                        ascii_str[0] = ansi_ljust(f"|{ascii_strs[0][index]}|", 18)
              
                        print(f"{ao:0>16} {hex_str[0]} {ascii_str[0]}")
                        index += 1

        print("")

    def get_byte_diff(self):
        results = [
            [], # List of diffed bytes for file one
            []  # List of diffed btyes for file two
        ]

        if (self.s_size > self.p_size):
            loopc = self.s_size
        else:
            loopc = self.p_size

        # Format each byte into a color + ascii int
        index = 0
        for i in range(loopc):
            try:
                if (self.p_raw_bytes[i] != self.s_raw_bytes[i]):
                    self.ccolor = self.changed
                else:
                    self.ccolor = self.alike

                results[0] += f"{self.ccolor} {self.p_raw_bytes[i]:0>2}",
                results[1] += f"{self.ccolor} {self.s_raw_bytes[i]:0>2}",
                index += 1
            except IndexError:
                if (self.s_size > self.p_size):
                    self.ccolor = self.added
                    while index != self.s_size:
                        results[1] += f"{self.ccolor} {self.s_raw_bytes[index]:0>2}",
                        index += 1
                else:
                    self.ccolor = self.deleted
                    while index != self.p_size:
                        results[0] += f"{self.ccolor} {self.p_raw_bytes[index]:0>2}",
                        index += 1

        return results

    def print_legend(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}Legend{Colors.END}\n")
        print(f"\t[ {Colors.BOLD}Alike{Colors.END} ]")
        print(f"\t[{Colors.BOLD}{Colors.GREEN} Added {Colors.END}]")
        print(f"\t[{Colors.BOLD}{Colors.YELLOW}Changed{Colors.END}]")
        print(f"\t[{Colors.BOLD}{Colors.RED}Deleted{Colors.END}]\n")
