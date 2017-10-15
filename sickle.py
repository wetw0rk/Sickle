#!/usr/bin/env python3
#
# MIT License
#
# Copyright (c) 2017 Milton Valencia
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Script name     : sickle.py
# Version         : 1.0
# Created date    : 10/14/2017
# Last update     : 10/14/2017
# Author          : wetw0rk
# Architecture	  : x86, and x86-x64
# Python version  : 3
# Designed OS     : Linux (preferably a penetration testing distro)
# Dependencies    : none besides objdump, and capstone
#

import os, sys, time, ctypes, codecs, argparse, binascii, subprocess

# capstone is only needed for disassembly
try:
    from capstone import *
except:
    print("Missing capstone, please install via:")
    print("apt-get install python3-pip")
    print("\tpip3 install capstone")
    print("\tcontinuing in 3 seconds")
    time.sleep(3)
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

def format_list():

    supported_formats = [
            "hex",
            "hex_space",
            "nasm",
            "c",
            "perl",
            "python",
            "python3",
            "bash",
            "csharp",
            "dword",
            "java",
            "num",
            "powershell",
            "ruby-array",
            "ruby",
            "raw",
    ]

    supported_architectures = [
            "all",
            "arm",
            "arm64",
            "mips",
            "ppc",
            "x86",
            "xcore",
    ]

    supported_modes = [
            "16",
            "32",
            "64",
            "13",
            "64",
            "arm",
            "big_endian",
            "little_endian",
            "micro",
            "thumb",
    ]

    supF = "\t"
    supA = "\t"
    supM = "\t"

    # dumpable languages currently supported
    print("Dump formats:")
    for i in range(len(supported_formats)):
        supF += "{:s}, ".format(supported_formats[i])
    print(supF[:len(supF)-2])

    # supported architectures
    print("Supported architectures:")
    for i in range(len(supported_architectures)):
        supA += "{:s}, ".format(supported_architectures[i])
    print(supA[:len(supA)-2])

    # supported modes
    print("Supported modes:")
    for i in range(len(supported_modes)):
        supM += "{:s}, ".format(supported_modes[i])
    print(supM[:len(supM)-2])

class colors():

    def __init__(self):
        pass

    # color output only for unix
    if os.name == 'posix':
        RED     = '\033[31m'
        BLUE    = '\033[94m'
        BOLD    = '\033[1m'
        END     = '\033[0m'
    else:
        RED     = ""
        BLUE    = ""
        BOLD    = ""
        END     = ""

class formatting():

    def __init__(self, byte_file, format_mode, badchars, variable):

        self.byte_file      = byte_file
        self.format_mode    = format_mode
        self.badchars       = badchars
        self.variable       = variable

    def character_analysis(self, num, op_str, results):

        op_line = []
        spotted = []

        if self.badchars != None:
            # split badchars if any
            sep_chars = self.badchars.split(",")

            for i in range(len(sep_chars)):
                if sep_chars[i] in op_str:
                    spotted += ("{:s}".format(sep_chars[i])),

        # here we begin to spot the badchars should we find one
        # we will replace it with a bold and red opcode, simply
        # making identification an ease

        indiv_byte = len(spotted)-1         # loop counter for bad characters

        # the tactical dumping begins here, aiding in spotting badchars
        splits = [op_str[x:x+num] for x in range(0,len(op_str),num)]
        for i in range(len(splits)):
            while indiv_byte > -1:
                if spotted[indiv_byte] in splits[i]:
                    highlight_byte = "{:s}{:s}{:s}{:s}".format(colors.BOLD, colors.RED, spotted[indiv_byte], colors.END)
                    splits[i] = splits[i].replace(spotted[indiv_byte], highlight_byte)
                indiv_byte -= 1
            indiv_byte = len(spotted)-1     # reset the loop counter

        for i in range(len(splits)):
            results += splits[i],

        return

    def tactical_dump(self):

        # are we reading from stdin?
        try:    
            with open(self.byte_file, "rb") as fd:
                fc = fd.read()
        except:
            fc = self.byte_file

        results = []
        op_str  = ""
        norm    = ""
        size    = len(fc)

        if self.format_mode != "raw":
            print("Payload size: {:d} bytes".format(size))

        if self.format_mode == "raw":
            sys.stdout.buffer.write(fc)

        # majority of dumps use this format
        for byte in bytearray(fc):
            norm += "\\x{:02x}".format(byte)

        if self.format_mode == 'c':
            num = 60
            self.character_analysis(num, norm, results)
            print("unsigned char {:s}[] = ".format(self.variable))
            for i in range(len(results)):
                if i == (len(results) -1):
                    print("\"{:s}\";".format(results[i]))
                else:
                    print("\"{:s}\"".format(results[i]))

        if self.format_mode == "python":
            num = 60
            self.character_analysis(num, norm, results)
            print('{:s} = ""'.format(self.variable))
            for i in range(len(results)):
                print("{:s} += \"{:s}\"".format(self.variable, results[i]))

        if self.format_mode == "python3":
            num = 60
            self.character_analysis(num, norm, results)
            print('{:s} = bytearray()'.format(self.variable))
            for i in range(len(results)):
                print("{:s} += b'{:s}'".format(self.variable, results[i]))

        if self.format_mode == "bash":
            num = 56
            self.character_analysis(num, norm, results)
            for i in range(len(results)):
                if i == (len(results) - 1):
                    print("$'{:s}'".format(results[i]))
                else:
                    print("$'{:s}'\\".format(results[i]))

        if self.format_mode == "ruby":
            num = 56
            self.character_analysis(num, norm, results)
            print("{:s} = ".format(self.variable))
            for i in range(len(results)):
                if i == (len(results) -1):
                    print("\"{:s}\"".format(results[i]))
                else:
                    print("\"{:s}\" +".format(results[i]))

        if self.format_mode == "perl":
            num = 60
            self.character_analysis(num, norm, results)
            print("my ${:s} =".format(self.variable))
            for i in range(len(results)):
                if i == (len(results) -1):
                    print("\"{:s}\";".format(results[i]))
                else:
                    print("\"{:s}\" .".format(results[i]))

        if self.format_mode == "hex_space":
            num = 8
            ops = ""
            for byte in bytearray(fc):
                op_str += "{:02x} ".format(byte)

            self.character_analysis(num, op_str, results)
            for i in range(len(results)):
                ops += results[i]

            print(ops)

        if self.format_mode == "hex":
            num = 8
            ops = ""
            for byte in bytearray(fc):
                op_str += "{:02x}".format(byte)

            self.character_analysis(num, op_str, results)
            for i in range(len(results)):
                ops += results[i]

            print(ops)

        if self.format_mode == "csharp":
            num = 75
            for byte in bytearray(fc):
                op_str += "0x{:02x},".format(byte)

            self.character_analysis(num, op_str, results)
            print("byte[] {:s} = new byte[{:d}] {:s}".format(self.variable, size, "{"))
            for i in range(len(results)):
                snip = len(results[i]) - 1
                if i == (len(results)-1):
                    print(results[i][:snip] + " };")
                else:
                    print(results[i])

        if self.format_mode == "dword":
            num = 94
            dwrd= ""
            dlst= []

            for byte in bytearray(fc):
                dwrd += "{:02x}".format(byte)

            # format the hex bytes into dword
            splits = [dwrd[x:x+8] for x in range(0,len(dwrd),8)]
            for i in range(len(splits)):
                s = splits[i]
                dlst += "0x" + "".join(map(str.__add__, s[-2::-2] ,s[-1::-2])),
            for i in range(int(len(dlst)/8+1)):
                op_str += ", ".join(dlst[i*8:(i+1)*8])

            # send it of for character character_analysis
            self.character_analysis(num, op_str, results)
            for i in range(len(results)):
                print(results[i])

        if self.format_mode == "nasm":
            num = 60

            for byte in bytearray(fc):
                op_str += "0x{:02x},".format(byte)

            self.character_analysis(num, op_str, results)

            for i in range(len(results)):
                snip = len(results[i]) - 1
                print("db " + results[i][:snip])

        if self.format_mode == "num":
            num = 84

            for byte in bytearray(fc):
                op_str += "0x{:02x}, ".format(byte)

            self.character_analysis(num, op_str, results)
            for i in range(len(results)):
                snip = len(results[i]) - 2
                if i == (len(results)-1):
                    print(results[i][:snip])
                else:
                    print(results[i])

        if self.format_mode == "powershell":
            num = 50

            for byte in bytearray(fc):
                op_str += "0x{:02x},".format(byte)

            self.character_analysis(num, op_str, results)
            for i in range(len(results)):
                snip = len(results[i]) - 1
                if i == 0:
                    print("[Byte[]] {:s} = {:s}".format(self.variable, results[i].replace(" ", ",")[:snip]))
                else:
                    print("${:s} += {:s}".format(self.variable, results[i].replace(" ", ",")[:snip]))

        if self.format_mode == "java":
            num = 104

            for byte in bytearray(fc):
                op_str += " (byte) 0x{:02x},".format(byte)

            self.character_analysis(num, op_str, results)
            print("byte {:s}[] = new byte[]".format(self.variable))
            print("{")
            for i in range(len(results)):
                print("\t" + results[i].lstrip(" "))
            print("};")

        if self.format_mode == "ruby-array":
            num = 60
            self.character_analysis(num, norm, results)
            for i in range(len(results)):
                if i == 0:
                    print('{:s} = "{:s}"'.format(self.variable, results[i]))
                else:
                    print('{:s} << "{:s}"'.format(self.variable, results[i]))

class reversing():

    def __init__(self, byte_file, compare, arch, mode):

        self.byte_file  = byte_file
        self.compare    = compare
        self.arch       = arch
        self.mode       = mode

    def compare_dump(self):
    
        done        = []
        examination = ""
        op_str      = ""
        cmp_str     = ""

        # open the bin-file to compare
        with open(self.compare, 'rb') as fd:
            fc = fd.read()
            for byte in bytearray(fc):
                cmp_str += "\\x{:02x}".format(byte)
        # open the original file
        with open(self.byte_file, 'rb') as fd:
            fc = fd.read()
            for byte in bytearray(fc):
                op_str += "\\x{:02x}".format(byte)

        checking_split = [op_str[x:x+4] for x in range(0,len(op_str),4)]
        original_split = [cmp_str[x:x+4] for x in range(0,len(cmp_str),4)]

        # format anything strange
        for i in range(len(original_split)):
            try:
                if checking_split[i] == original_split[i]:
                    examination += "{:s}{:s}{:s}".format(
                        colors.BLUE, original_split[i], colors.END
                    )

                else:
                    examination += "{:s}{:s}{:s}".format(
                        colors.RED, original_split[i], colors.END
                    )

            except IndexError:
                examination += "{:s}{:s}{:s}".format(colors.RED, original_split[i], colors.END)

        exam_split = [examination[x:x+130] for x in range(0,len(examination),130)]
        checking_split = [op_str[x:x+40] for x in range(0,len(op_str),40)]
        original_split = [cmp_str[x:x+40] for x in range(0,len(cmp_str),40)]

        print("+------------------------------------------+ +------------------------------------------+ +------------------------------------------+")
        print("|    (Differences In Red) Final Results    | |         Shellcode Being Examined         | |          Shellcode Being Dumped          |")
        print("+------------------------------------------+ +------------------------------------------+ +------------------------------------------+")
        for i in range(len(exam_split)):
            try:
                spaces = 13 - int(
                    len(exam_split[i])/10
                )
                if spaces < 13:
                    spaces = spaces * 3
                # ugly don't look
                if len(exam_split[i]) == 26:
                    spaces -= 1
                elif len(exam_split[i]) == 39:
                    spaces -= 2
                elif len(exam_split[i]) == 65:
                    spaces -= 1
                elif len(exam_split[i]) == 78:
                    spaces -= 2
                elif len(exam_split[i]) == 104:
                    spaces -= 1
                elif len(exam_split[i]) == 117:
                    spaces -= 2

                done += (
                        # examination splits
                        "| " +
                        "{:s}".format(exam_split[i]) +
                        " " * spaces +
                        " |" +
                        # original shellcode
                        " | " +
                        "{:s}".format(original_split[i]) +
                        " " * abs(len(original_split[i]) - 40) +
                        " |" +
                        # file we are dumping / checking
                        " | " +
                        "{:s}".format(checking_split[i]) +
                        " " * abs(len(checking_split[i]) - 40) +
                        " |"
                ),
            except IndexError:
                # if the dumped shellcode length is not == examined code
                # truncation has occured
                done += (
                        # examination splits
                        "| " +
                        "{:s}".format(exam_split[i]) +
                        " " * spaces +
                        " |" +
                        # original shellcode
                        " | " +
                        "{:s}".format(original_split[i]) +
                        " " * abs(len(original_split[i]) - 40) +
                        " |"
                ),

        for i in range(len(done)):
            print(done[i])

    def disassemble(self):

        completed_disassembly = []

        ARCH = {
                "all"   : CS_ARCH_ALL,
                "arm"   : CS_ARCH_ARM,
                "arm64" : CS_ARCH_ARM64,
                "mips"  : CS_ARCH_MIPS,
                "ppc"   : CS_ARCH_PPC,
                "x86"   : CS_ARCH_X86,
                "xcore" : CS_ARCH_XCORE
        }

        MODE = {
                "16"            : CS_MODE_16,
                "32"            : CS_MODE_32,
                "64"            : CS_MODE_64,
                "arm"           : CS_MODE_ARM,
                "big_endian"    : CS_MODE_BIG_ENDIAN,
                "little_endian" : CS_MODE_LITTLE_ENDIAN,
                "micro"         : CS_MODE_MICRO,
                "thumb"         : CS_MODE_THUMB

        }

        with open(self.byte_file, "rb") as fd:
            binCode = fd.read()

        try:
            mode = Cs(ARCH[self.arch], MODE[self.mode])
            for i in mode.disasm(binCode, 0x1000):
                completed_disassembly += ("0x%x: %s\t%s %s" % (
                    i.address,
                    binascii.hexlify(i.bytes).decode('utf-8'),
                    i.mnemonic,
                    i.op_str)
                ).expandtabs(25),

            for i in range(len(completed_disassembly)):
                print(completed_disassembly[i])

        except CsError as e:
            print("Something went wrong: {:s}".format(e))

def deployment(byte_file):

    # are we reading from stdin
    try:
        with open(byte_file, "rb") as fd:
            fc = fd.read()
    except:
        fc = byte_file

    # operating system shellcode execution is a bit different
    if os.name == 'posix':
        sc = ""
        print("Saving to shellcodetest.c")

        for byte in bytearray(fc):
            sc += "\\x{:02x}".format(byte)

        print("Shellcode length: {:d}".format(len(fc)))

        cmd = "gcc -fno-stack-protector -z execstack shellcodetest.c -o shellcodetest && ./shellcodetest"
        shellcodetest = "#include <stdio.h>\n"
        shellcodetest += "#include <string.h>\n\n"
        shellcodetest += "unsigned char code[]=\n"
        shellcodetest += '"' + sc + '"' + ";\n\n"
        shellcodetest += "int main()\n"
        shellcodetest += "{\n"
        shellcodetest += "\tint (*ret)() = (int(*)())code;\n"
        shellcodetest += "\tret();\n"
        shellcodetest += "}\n"

        file = open("shellcodetest.c", "w")
        file.write(shellcodetest)
        file.close()

        os.system(cmd)

    else:
        print("Shellcode length: {:d}".format(len(fc)))

        shellcode = bytearray(fc)

        ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                ctypes.c_int(len(shellcode)), ctypes.c_int(0x3000), ctypes.c_int(0x40))

        buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

        ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                buf, ctypes.c_int(len(shellcode)))

        ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                ctypes.c_int(0), ctypes.c_int(ptr), ctypes.c_int(0), ctypes.c_int(0), ctypes.pointer(ctypes.c_int(0)))

        ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))
                
    sys.exit()

def objdump2shellcode(dumpfile, format_mode, badchars, variable):

    no_junk = []
    no_addr = []
    opcodes = []
    instrut = []
    ops     = ""

    # detect if the file exists
    if os.path.isfile(dumpfile) is False:
        print("File non-existent!")
        sys.exit()

    # run objdump to disassemble the binary
    try:
        intel_dump = subprocess.Popen(['objdump', '-D', dumpfile, '-M', 'intel', '--insn-width=15'],
                stdout=subprocess.PIPE).communicate()[0]
    except:
        print("[-] error running command")
        sys.exit()

    # here we begin to clean the output accordingly; this was
    # once a function however after consideration, ideally we
    # we want to reuse the dumping class for stdin, etc
    newline_split = intel_dump.decode().split("\n")

    for i in range(len(newline_split)):
        # split up every line by a [tab] and remove address
        addr_splt = newline_split[i].split('\t')[1:3]
        # get rid of blank lines
        if len(addr_splt) > 0:
            no_addr += addr_splt
        else:
            pass

    # separate opcodes and instructions
    list_len = len(no_addr)
    for i in range(list_len):
        if (i & 1) == 1:
            instrut += no_addr[i],
        else:
            opcodes += no_addr[i],

    # cut off the junk and format (\xde\xad\xbe\xef)
    for i in range(len(opcodes)):
        no_junk  += opcodes[i].rstrip(" "),
    for i in range(len(opcodes)):
        opcodes[i] = opcodes[i].rstrip(" ")
    for i in range(len(opcodes)):
        ops += "\\x%s" % opcodes[i].replace(" ", "\\x")

    str_obj = bytes(ops, 'ascii')
    raw_ops = codecs.escape_decode(str_obj)[0]

    sendIT = formatting(raw_ops, format_mode, badchars, variable)
    sendIT.tactical_dump()

def main():

    # handle command line arguments
    parser = argparse.ArgumentParser(description="Sickle - a shellcode development tool")
    parser.add_argument("-r", "--read",help="Read byte array from the binary file")
    parser.add_argument("-s", "--stdin",help="read ops from stdin (EX: echo -ne \"\\xde\\xad\\xbe\\xef\" | sickle -s -f <format> -b '\\x00')", action="store_true")
    parser.add_argument("-obj","--objdump",help="binary to use for shellcode extraction (via objdump method)")
    parser.add_argument("-f", "--format",help="Output format (use --list for a list)")
    parser.add_argument("-b", "--badchar",help="Bad characters to avoid in shellcode")
    parser.add_argument("-v", "--varname",required=False, help="alternative variable name")
    parser.add_argument("-l", "--list",help="List all available formats and arguments", action="store_true")
    parser.add_argument("-e", "--examine",help="Examine a separate file containing original shellcode. Mainly used to see if shellcode was recreated successfully")
    parser.add_argument("-d", "--disassemble",help="disassemble the binary file", action="store_true")
    parser.add_argument("-a", "--arch",help="select architecture for disassembly")
    parser.add_argument("-m", "--mode",help="select mode for disassembly")
    parser.add_argument('-rs', "--run-shellcode",help="run the shellcode (on linux generates binary)", action="store_true")

    args = parser.parse_args()

    # assign arguments
    byte_file   = args.read
    badchars    = args.badchar
    compare     = args.examine
    disassemble = args.disassemble
    arch        = args.arch
    mode        = args.mode
    run         = args.run_shellcode
    dumpfile    = args.objdump

    # if a list is requested print it
    if args.list == True:
        format_list()
        sys.exit()

    # default variables if none given
    if args.varname == None:
        variable = "buf"
    else:
        variable = args.varname

    if args.format == None:
        format_mode = 'c'
    else:
        format_mode = args.format

    # if we are just extracting raw opcodes
    if byte_file:
        if run == True:
            deployment(byte_file)
        elif compare:
            # send the file to be compared
            compareIT = reversing(byte_file, compare, arch="", mode="")
            compareIT.compare_dump()
        elif disassemble == True:
            if arch == None or mode == None:
                print("Architecture or mode not selected, defaulting to x86")
                disassIT = reversing(byte_file, compare, arch="x86", mode="32")
                disassIT.disassemble()
            else:
                print("Disassembling in MODE:{:s} ARCH:{:s}".format(mode, arch))
                disassIT = reversing(byte_file, compare, arch, mode)
                disassIT.disassemble()
        else:
            # send the file to be dumped and formatted
            dumpIT = formatting(byte_file, format_mode, badchars, variable)
            dumpIT.tactical_dump()

    elif args.stdin == True:

        byte_file = sys.stdin.buffer.raw.read()

        if run == True:
            deployment(byte_file)
        else:
            readIT = formatting(byte_file, format_mode, badchars, variable)
            readIT.tactical_dump()

    elif dumpfile:
        objdump2shellcode(dumpfile, format_mode, badchars, variable)

    else:
        parser.print_help()

if __name__ == '__main__':
    main()
