import sys
import binascii

from capstone import *

from sickle.common.lib.generic.colors import Colors
from sickle.common.lib.generic.colors import ansi_ljust
from sickle.common.lib.generic.colors import ansi_center
from sickle.common.lib.reversing.disassembler import Disassembler

class Module():

    name = "Disassembler"

    module = "disassemble"

    example_run = f"{sys.argv[0]} -a x64 -m {module} -r shellcode"

    platform = "N/A"

    arch = 'Multi'

    ring = "N/A"

    author = ["wetw0rk"]

    tested_platforms = ["Linux", "Windows"]

    summary = "Simple linear disassembler for multiple architectures"

    description = """
    Simple linear disassembler for multiple architectures
    """

    arguments = None

    def __init__(self, arg_object):
        
        self.raw_bytes = arg_object["raw bytes"]
        self.source = arg_object["source"]
        self.arch = arg_object["architecture"]

    def do_thing(self):
        
        completed_check = []
        disassembler = Disassembler(self.arch)
        
        analysis = disassembler.get_generic_bin_analysis(self.raw_bytes)
        if (analysis == None):
            return

        # TESTING
        block_lines = disassembler.get_fmt_block(analysis["addresses"], analysis["opcodes"], analysis["assembly"])
        block_line_length = (len(block_lines[0]))

        extra_info  = []
        extra_info += ansi_center(f"{Colors.BOLD}{Colors.GREEN}{self.source}{Colors.END}", block_line_length-4),
        extra_info += f"{Colors.BOLD}{Colors.BLUE}Architecture{Colors.END}: {self.arch}",
        extra_info += f"{Colors.BOLD}{Colors.BLUE}Alphanumeric{Colors.END}: {analysis['alphanumeric']}",
        extra_info += f"{Colors.BOLD}{Colors.BLUE}Size (bytes){Colors.END}: {len(self.raw_bytes)}",

        print(f"\n{block_lines[0]}")
        for i in range(len(extra_info)):
            print(f"| {ansi_ljust(extra_info[i], block_line_length-4, ' ')} |")
        
        for i in range(len(block_lines)):
            print(block_lines[i])
