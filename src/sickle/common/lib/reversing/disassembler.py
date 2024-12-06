import sys
import binascii

from capstone import *
from sickle.common.lib.generic.colors import ansi_ljust

class Disassembler():
    """This class is responsible for all disassembly operations such as converting opcodes to
    assembly instructions.

    :param architecture: Optional, This is the architecture in which the opcodes are to be
        interpreted as.
    :type architecture: str
    """

    def __init__(self, architecture="x64"):
        
        self.target_arch = self.get_cs_target_arch(architecture)
        self.analysis = {}

    def get_cs_target_arch(self, arch):
        """Returns the Capstone object to be used for all disassembly operations going forward.
        
        :param arch: The Capstone object the caller will recieve which operates on the provided
            architecture.
        :type arch: str

        :return: Returns a Capstone object for disassembly
        :rtype: capstone.Cs
        """

        architectures = self.get_cs_arch_modes()
        if (arch not in architectures.keys()):
            sys.exit(f"Currently {arch} architecture is not supported / configured")

        return architectures[arch] 

    def get_cs_arch_modes(self=None):
        """Returns a dictionary containing the Capstone objects needed for their respective
        architectures.

        :return: Raw architectures objects in a dictionary
        :rtype: dict
        """

        try:
            architecture_mode = \
            {
                'x86'       : Cs(CS_ARCH_X86,   CS_MODE_32),
                'x64'       : Cs(CS_ARCH_X86,   CS_MODE_64),
                'aarch64'   : Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN),
            }
        except Exception as e:
            print(f"Failed to load capstone, error: {e}")
            exit(-1)

        return architecture_mode

    def get_linear_sweep(self, bytecode):
        """This function performs linear disassembly (top->bottom). Upon completion a dictionary containing
        addresses, assembly, and opcodes based on the provided bytecode.

        :param bytecode: Raw bytes object
        :type bytecode: bytes

        :return: A dictionary containing the results of the linear disassembly
        :rtype: dict
        """

        if (type(bytecode) != bytes):
            print(f"Error get_linear_sweep() requires a \"bytes\" object, input: {bytecode}")
            return None

        self.analysis["addresses"] = []
        self.analysis["assembly"] = []
        self.analysis["opcodes"] = []

        try:
            for i in self.target_arch.disasm(bytecode, 0x100000000):
                self.analysis["addresses"] += "%x" % i.address,
                self.analysis["opcodes"] += binascii.hexlify(i.bytes).decode('utf-8'),
                self.analysis["assembly"] += "%s %s" % (i.mnemonic, i.op_str),
        except CsError as e:
            print(f"Something went wrong during linear sweep: {e}")
            return None

        return self.analysis

    def get_alpha_check(self, bytecode):
        """Checks if bytes are alphanumeric.

        :return: If the bytecode is completely alphanumeric this function returns True
        :rtype: bool
        """

        check = False
        for i in range(len(bytecode)):
            check = str.isascii(chr(bytecode[i]))
            if (check != True):
                break

        self.analysis["alphanumeric"] = check

    def get_fmt_block(self, addresses, opcodes, assembly):
        """This function simply generates a box in which to put disassembly data. Think
        of this as a CLI version of a block in Ghidra or IDA. All parameters must have
        the same size in length, e.g addresses[10], opcodes[10], assembly[10]

        :param addresses: A list of addresses
        :type addresses: list

        :param opcodes: A list of opcodes
        :type opcodes: list

        :param assembly: A list of assembly instructions
        :type assembly: list

        :return: A list containing strings that make up a block with formatted disassembly data
        :rtype: list
        """

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

    def get_generic_bin_analysis(self, shellcode):
        """Generic bytecode analysis. This is mainly meant to be used for shellcode stubs. Upon
        completion a dictionary containing analysis data will be returned.

        :return: Currently returns if the shellcode is alphanumeric and a general disassembly
        :rtype: dict
        """

        if (self.get_linear_sweep(shellcode) != None):
            self.get_alpha_check(shellcode)

        if (bool(self.analysis) != False):
            return self.analysis
        else:
            return None
