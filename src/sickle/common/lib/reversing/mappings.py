import random

class Mappings():

    def __init__(self, architecture="x64"):
        self.arch = architecture

    def maps(self):
        """This function is responsible for returning the map respective to
        the target architecture. Right now, critical registers such as the
        base and stack pointer won't be included in the mapping.
        """

        # TODO: ARM32 MAPPING
        # Name   | Purpose/Usage
        # --------------------------
        # R0-R3  | General-purpose registers (used for function arguments and return values).
        # R4-R11 | General-purpose registers (callee-saved).
        # R12    | Intra-Procedure Call Scratch Register (IP or "scratch").
        # R13    | Stack Pointer (SP).
        # R14    | Link Register (LR) - stores the return address for function calls.
        # R15    | Program Counter (PC) - stores the address of the next instruction to execute.
        # --------------------------
        # CPSR   | Current Program Status Register - holds condition flags, interrupt status, and processor mode.
        # SPSR   | Saved Program Status Register (used in exception handling).

        aarch64_mapping = {
        # 64-bit | 32-bit #
        # --------------- #
            'x0':   'w0',  
            'x1':   'w1',  
            'x2':   'w2',  
            'x3':   'w3',  
            'x4':   'w4',  
            'x5':   'w5',  
            'x6':   'w6',  
            'x7':   'w7',  
            'x8':   'w8',  
            'x9':   'w9',  
           'x10':   'w10', 
           'x11':   'w11', 
           'x12':   'w12', 
           'x13':   'w13', 
           'x14':   'w14', 
           'x15':   'w15', 
           'x16':   'w16', 
           'x17':   'w17', 
           'x18':   'w18', 
           'x19':   'w19', 
           'x20':   'w20', 
           'x21':   'w21', 
           'x22':   'w22', 
           'x23':   'w23', 
           'x24':   'w24', 
           'x25':   'w25', 
           'x26':   'w26', 
           'x27':   'w27', 
           'x28':   'w28', 
           'x29':   'w29', # (Frame Pointer, FP)
           'x30':   'w30', # (Link Register, LR)
            'sp':    None, # (Stack Pointer)
        }

        # Remove frame pointer, link register, and stack pointer
        del aarch64_mapping['x29']
        del aarch64_mapping['x30']
        del aarch64_mapping['sp']

        x64_mapping = {
        # 64-bit | 32-bit | 16-bit | 8-bit High | 8-bit Low #
        # ------------------------------------------------- #
           'rax': [ 'eax',   'ax',      'ah',       'al' ],
           'rbx': [ 'ebx',   'bx',      'bh',       'bl' ],
           'rcx': [ 'ecx',   'cx',      'ch',       'cl' ],
           'rdx': [ 'edx',   'dx',      'dh',       'dl' ],
           'rsi': [ 'esi',   'si',      None,       None ],
           'rdi': [ 'edi',   'di',      None,       None ],
           'rbp': [ 'ebp',   'bp',      None,       None ], # Base Pointer 
           'rsp': [ 'esp',   'sp',      None,       None ], # Stack Pointer
            'r8': [ 'r8d',  'r8w',      None,      'r8b' ],
            'r9': [ 'r9d',  'r9w',      None,      'r9b' ],
           'r10': ['r10d', 'r10w',      None,     'r10b' ],
           'r11': ['r11d', 'r11w',      None,     'r11b' ],
           'r12': ['r12d', 'r12w',      None,     'r12b' ],
           'r13': ['r13d', 'r13w',      None,     'r13b' ],
           'r14': ['r14d', 'r14w',      None,     'r14b' ],
           'r15': ['r15d', 'r15w',      None,     'r15b' ]
        }

        # Remove stack pointer and base pointer
        del x64_mapping['rsp']
        del x64_mapping['rbp']

        # Return the respective mapping
        if (self.arch == "x64"):
            return x64_mapping
        elif (self.arch == "aarch64"):
            return aarch64_mapping
        else:
            return None

    def get_full_mapping(self):
        """Returns the caller full mapping for respective architecture
        """

        return self.maps()

    def gen_regs(self, count, size):
        """Get x amount of registers of size y
        """
        
        mapping = self.maps()
        generated_registers = []
        list_obj = []

        if (self.arch == 'x64'):

            if (size == 64):
                list_obj = list(self.maps().keys())
            elif (size == 32):
                for key, value in mapping.items():
                    list_obj += value[0],
            elif (size == 16):
                for key, value in mapping.items():
                    list_obj += value[1],
            elif (size == 8):
                for key, value in mapping.items():
                    if (value[3] != None):
                        list_obj += value[3],
            else:
                print("Requested invalid register size")
                exit(-1)

        for i in range(count):
            generated_registers += random.choice(list_obj),
            list_obj.remove(generated_registers[-1])

        return generated_registers
