'''

disassembler: Operations related to disassembling opcodes, future plans for ELF and PE binaries

'''

import binascii

from capstone import *
from sickle.common.lib.generic.colors import ansi_ljust

class Disassembler():

    ###
    # TODO: add description but need to document that self.analysis contains information related to analysis
    ###
    def __init__(self, architecture="x64"):
        self.target_arch = Disassembler.get_cs_arch_modes()[architecture]
        self.analysis = {}

    ###
    # get_cs_arch_modes: Returns the respective object used by Captsone
    ###
    def get_cs_arch_modes():
        try:
            architecture_mode = \
            {
                'x86'       : Cs(CS_ARCH_X86,   CS_MODE_32),
                'x64'       : Cs(CS_ARCH_X86,   CS_MODE_64),
                'arm'       : Cs(CS_ARCH_ARM,   CS_MODE_ARM),
            }
        except Exception as e:
            print(f"Failed to load capstone, error: {e}")
            exit(-1)

        return architecture_mode

    ###
    # get_linear_sweep: Disassemble bytecode from top->bottom. This is the most basic disassembly algorithm
    ###
    def get_linear_sweep(self, bytecode):
        if (type(bytecode) != bytes):
            print(f"Error get_linear_sweep() requires a \"bytes\" object, input: {bytecode}")
            return None

        self.analysis["addresses"] = []
        self.analysis["assembly"] = []
        self.analysis["opcodes"] = []

        try:
            # TODO: Make the addresses used more specific to architecture and filetype this is probably going to be updated once I create
            #       PE and ELF parsers for sickle.
            for i in self.target_arch.disasm(bytecode, 0x100000000):
                self.analysis["addresses"] += "%x" % i.address,
                self.analysis["opcodes"] += binascii.hexlify(i.bytes).decode('utf-8'),
                self.analysis["assembly"] += "%s %s" % (i.mnemonic, i.op_str),
        except CsError as e:
            print(f"Something went wrong during linear sweep: {e}")
            return None

        return self.analysis

    ###
    # get_alpha_check: Checks if bytecode is alphanumeric
    ###
    def get_alpha_check(self, bytecode):
        check = False
        for i in range(len(bytecode)):
            check = str.isascii(chr(bytecode[i]))
            if (check != True):
                break

        self.analysis["alphanumeric"] = check

    ###
    # get_fmt_block: Generates a block to view assembly
    ###
    def get_fmt_block(self, addresses, opcodes, assembly):
        generated_block = []
        longest_addr = 0
        longest_opcode = 0
        longest_asm = 0

        for i in range(len(addresses)):
            if (len(addresses[i]) > longest_addr):
                longest_addr = len(addresses[i])
            if (len(opcodes[i]) > longest_opcode):
                longest_opcode = len(opcodes[i])
            if (len(assembly[i]) > longest_asm):
                longest_asm = len(assembly[i])

        longest_asm += 2
        longest_addr += 2 
        longest_opcode += 2
        block_line_length = (longest_addr + longest_opcode + longest_asm)

        generated_block += (f"+-{'-' * block_line_length}-+"),

        for i in range(len(addresses)):
            generated_block += (f"| {ansi_ljust(addresses[i], longest_addr, ' ')}"
                  f"{ansi_ljust(opcodes[i], longest_opcode, ' ')}"
                  f"{ansi_ljust(assembly[i], longest_asm, ' ')} |"),

        generated_block += (f"+-{'-' * block_line_length}-+"),

        return generated_block

    ###
    # get_generic_bin_analysis: Generic bytecode analysis. Mainly meant to be used for shellcode stubs
    ###
    def get_generic_bin_analysis(self, shellcode):
        if (self.get_linear_sweep(shellcode) != None):
            self.get_alpha_check(shellcode)

        if (bool(self.analysis) != False):
            return self.analysis
        else:
            return None
