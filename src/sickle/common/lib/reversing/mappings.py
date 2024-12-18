import random

class Mappings():

    def __init__(self, architecture="x64"):
        self.arch = architecture

    def x64_map(self):

        x64_mapping = {
        # 64-bit | 32-bit | 16-bit | 8-bit High | 8-bit Low #
        # ------------------------------------------------- #
           'rax': { 'eax',   'ax',      'ah',       'al' },
           'rbx': { 'ebx',   'bx',      'bh',       'bl' },
           'rcx': { 'ecx',   'cx',      'ch',       'cl' },
           'rdx': { 'edx',   'dx',      'dh',       'dl' },
           'rsi': { 'esi',   'si',      None,       None },
           'rdi': { 'edi',   'di',      None,       None },
           'rbp': { 'ebp',   'bp',      None,       None },       
           'rsp': { 'esp',   'sp',      None,       None },
            'r8': { 'r8d',  'r8w',      None,      'r8b' },
            'r9': { 'r9d',  'r9w',      None,      'r9b' },
           'r10': {'r10d', 'r10w',      None,     'r10b' },
           'r11': {'r11d', 'r11w',      None,     'r11b' },
           'r12': {'r12d', 'r12w',      None,     'r12b' },
           'r13': {'r13d', 'r13w',      None,     'r13b' },
           'r14': {'r14d', 'r14w',      None,     'r14b' },
           'r15': {'r15d', 'r15w',      None,     'r15b' }
        }


        # Remove stack pointer and base pointer
        del x64_mapping['rsp']
        del x64_mapping['rbp']

        return x64_mapping

    def gen_regs(self, count, size):
        """Get x amount of registers of size y
        """
        
        generated_registers = []

        if (self.arch == 'x64'):
            if (size == 64):
                list_obj = list(self.x64_map().keys())

        for i in range(count):
            generated_registers += random.choice(list_obj),
            list_obj.remove(generated_registers[-1])

        return generated_registers
