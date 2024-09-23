import binascii

from keystone import *

class Assembler():
    """This class is responsible for all assembling operations such as converting instructions
    to their respective opcodes.

    :param architecture: Optional, This is the architecture in which the assembly language will be provided
    :type architecture: str
    """

    def __init__(self, architecture="x64"):
        
        self.target_arch = self.get_ks_target_arch(architecture)
        self.assembly_code = None
        self.analysis = {}

    def get_ks_target_arch(self, arch):
        """Returns the Keystone object to be used for all assembly operations going forward.
        
        :param arch: The architecture used during assembly operations
        :type arch: str

        :return: Returns a Keystone object for assembly
        :rtype: keystone.keystone.Ks
        """

        architectures = self.get_ks_arch_modes()
        if (arch not in architectures.keys()):
            sys.exit(f"Currently {arch} architecture is not supported / configured")

        return architectures[arch]

    def get_ks_arch_modes(self):
        """Returns a dictionary containing the Keystone objects needed for their
        respective architecture.

        :return: Raw architecture objects in a dictionary
        :rtype: dict
        """

        try:
            architecture_mode = \
            {
                'x86'       : Ks(KS_ARCH_X86,   KS_MODE_32),
                'x64'       : Ks(KS_ARCH_X86,   KS_MODE_64),
                'arm'       : Ks(KS_ARCH_ARM,   KS_MODE_ARM),
            }
        except Exception as e:
            print(f"Failed to load keystone, error: {e}")
            exit(-1)

        return architecture_mode

    def get_bytes_from_asm(self, asm_code):
        """Returns a byte array from assembly source code.

        :param asm_code: Assembly source code
        :type asm_code: str

        :return: Raw opcodes from assembly
        :rtype: bytes
        """

        asm_code = self.remove_comments_from_asm(asm_code)
        
        try:
            byte_list, count = self.target_arch.asm(asm_code)
            if (count == 0):
                print("Failed to generate bytes")
                return
        except Exception as e:
            print(f"Error: {e}")
            return

        raw_shellcode = bytes(byte_list)

        return raw_shellcode

    def remove_comments_from_asm(self, asm_code):
        """Returns a string with all assembly comments removed
        
        :param asm_code: Assembly source code with newlines
        :type asm_code: str

        :return: Original string with ASM comments removed
        :rtype: str
        """

        new_source = ""
        lines = asm_code.split('\n')
        for i in range(len(lines)):
            if (lines[i] != ''):
                comment = ';'
                clean_line = f"{lines[i].split(comment, 1)[0]}\n"
                if (clean_line.isspace() != True):
                    new_source += clean_line

        return new_source
