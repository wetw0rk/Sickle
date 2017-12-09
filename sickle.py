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
# Version         : 1.3
# Created date    : 10/14/2017
# Last update     : 12/9/2017
# Author          : wetw0rk
# Architecture	  : x86, and x86-x64
# Python version  : 3
# Designed OS     : Linux (preferably a penetration testing distro)
#
# Description     : Sickle is a shellcode development tool, created
#                   to speed up the various steps for functioning
#                   shellcode.
#
# Dependencies (if capstone is not installed)
#   apt-get install python3-pip
#   pip3 install capstone
#

from ctypes import CDLL, c_char_p, c_void_p, memmove, cast, CFUNCTYPE
import os, sys, ctypes, codecs, argparse, binascii, subprocess

try:

    from capstone import *

except:

    # if capstone is installed under python2.7 path, import directly
    # if fails we are on a Windows OS
    try:

        import importlib.machinery
        path_var = "/usr/lib/python2.7/dist-packages/capstone/__init__.py"
        capstone = importlib.machinery.SourceFileLoader(
            'capstone', path_var
        ).load_module()
        from capstone import *

    except:

        pass

try:

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
except:

    print("Failed to load capstone, disassembly disabled")

def format_list(print_formats):

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

    supported_comments = [
            "c",
            "python",
            "perl",
            "ruby-array",
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

    if print_formats == True:
        supF = "\t"
        supC = "\t"
        supA = "\t"
        supM = "\t"

        # dumpable languages currently supported
        print("Dump formats:")
        for i in range(len(supported_formats)):
            supF += "{:s}, ".format(supported_formats[i])
        print(supF[:len(supF)-2])

        # comment supported dump
        print("Comment dump formats:")
        for i in range(len(supported_comments)):
            supC += "{:s}, ".format(supported_comments[i])
        print(supC[:len(supC)-2])

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
        exit(0)
    else:
        return supported_formats

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

    def __init__(self, byte_file, format_mode, badchars, variable, arch, mode):

        self.byte_file      = byte_file
        self.format_mode    = format_mode
        self.badchars       = badchars
        self.variable       = variable
        self.arch           = arch
        self.mode           = mode

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

    def informational_dump(self):
        opcode_string       = []
        instruction_line    = []
        hex_opcode_string   = []
        completed_conversion= []
        results             = []

        try:
            mode = Cs(ARCH[self.arch], MODE[self.mode])
        except:
            print("Architecture or Mode not supported")
            exit(1)
        try:
            with open(self.byte_file, "rb") as fd:
                binCode = fd.read()
        except:
            binCode = self.byte_file

        print("Payload size: {:d} bytes".format(len(binCode)))

        # seperate the instructions and opcode
        for i in mode.disasm(binCode, 0x1000):
            opcode_string += "{:s}".format(binascii.hexlify(i.bytes).decode('utf-8')),
            instruction_line += "{:s} {:s}".format(i.mnemonic, i.op_str),
        # hex-ify the opcode string
        for i in range(len(opcode_string)):
            line = opcode_string[i]
            hex_opcode_string += "\\x" + "\\x".join([line[i:i+2] for i in range(0, len(line), 2)]),
        # send it off for character analysis (at this point the results are in... the results)
        for i in range(len(hex_opcode_string)):
            self.character_analysis(66, hex_opcode_string[i], results)

        ID = colors.BOLD and colors.RED and colors.END

        # once we have all our conversions complete dump
        # it into the desired format. each differently..
        if self.format_mode == 'c':
            print("unsigned char {:s}[] = ".format(self.variable))
            for i in range(len(instruction_line)):
                if ID in results[i] and i != (len(instruction_line)-1):
                    completed_conversion += ("\"%s\"\t %s%s// %s%s" % (
                        hex_opcode_string[i],
                        colors.BOLD,
                        colors.RED,
                        instruction_line[i],
                        colors.END)
                    ).expandtabs(40),
                elif i == (len(instruction_line)-1) and ID in results[i]:
                    completed_conversion += ("\"%s\";\t %s%s// %s%s" % (
                        hex_opcode_string[i],
                        colors.BOLD,
                        colors.RED,
                        instruction_line[i],
                        colors.END)
                    ).expandtabs(40),
                elif i == (len(instruction_line)-1):
                    completed_conversion += ("\"%s\";\t // %s" % (
                        results[i],
                        instruction_line[i])
                    ).expandtabs(40),
                else:
                    completed_conversion += ("\"%s\"\t // %s" % (
                        results[i],
                        instruction_line[i])
                    ).expandtabs(40),

        if self.format_mode == "python":
            for i in range(len(instruction_line)):
                if ID in results[i]:
                    completed_conversion += ("\"%s\"\t %s%s# %s%s" % (
                        hex_opcode_string[i],
                        colors.BOLD,
                        colors.RED,
                        instruction_line[i],
                        colors.END)
                    ).expandtabs(40),
                else:
                    completed_conversion += ("\"%s\"\t # %s" % (
                        results[i],
                        instruction_line[i])
                    ).expandtabs(40),

        if self.format_mode == "ruby-array":
            print('%s = ""' % self.variable)
            for i in range(len(instruction_line)):
                if ID in results[i]:
                    completed_conversion += ("%s << \"%s\"\t %s%s# %s%s" % (
                        self.variable,
                        hex_opcode_string[i],
                        colors.BOLD,
                        colors.RED,
                        instruction_line[i],
                        colors.END)
                    ).expandtabs(40),
                else:
                    completed_conversion += ("%s << \"%s\"\t # %s" % (
                        self.variable,
                        results[i],
                        instruction_line[i])
                    ).expandtabs(40),

        if self.format_mode == "perl":
            for i in range(len(instruction_line)):
                if ID in results[i] and i != (len(instruction_line)-1):
                    completed_conversion += ("\"%s\".\t %s%s# %s%s" % (
                        hex_opcode_string[i],
                        colors.BOLD,
                        colors.RED,
                        instruction_line[i],
                        colors.END)
                    ).expandtabs(40),
                elif i == (len(instruction_line)-1) and ID in results[i]:
                    completed_conversion += ("\"%s\";\t %s%s# %s%s" % (
                        hex_opcode_string[i],
                        colors.BOLD,
                        colors.RED,
                        instruction_line[i],
                        colors.END)
                    ).expandtabs(40),
                elif i == (len(instruction_line)-1):
                    completed_conversion += ("\"%s\";\t # %s" % (
                        results[i],
                        instruction_line[i])
                    ).expandtabs(40),
                else:
                    completed_conversion += ("\"%s\".\t # %s" % (
                        results[i],
                        instruction_line[i])
                    ).expandtabs(40),

        for i in range(len(completed_conversion)):
            print(completed_conversion[i])

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

        # majority of dumps use this format
        try:
            for byte in bytearray(fc):
                norm += "\\x{:02x}".format(byte)
        except:
            print("Error dumping shellcode. Is file present?")
            exit(1);

        if self.format_mode != "raw":
            print("Payload size: {:d} bytes".format(size))

        if self.format_mode == "raw":
            sys.stdout.buffer.write(fc)

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
        try:
            with open(self.compare, 'rb') as fd:
                fc = fd.read()
                for byte in bytearray(fc):
                    cmp_str += "\\x{:02x}".format(byte)
        except:
            print("Error examining shellcode. Is file present?")
            exit(1);

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

        completed_disassembly   = []

        try:
            with open(self.byte_file, "rb") as fd:
                binCode = fd.read()
        except:
            binCode = self.byte_file

        try:
            try:
                mode = Cs(ARCH[self.arch], MODE[self.mode])
            except:
                print("Architecture or Mode not supported")
                exit(0);

            print("Disassembling shellcode in {:s}-{:s}".format(self.arch, self.mode))

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

        print("Shellcode length: {:d}".format(len(fc)))

        shellcode = bytes(fc)                       # convert shellcode into a bytes
        libc = CDLL('libc.so.6')                    # implement C functions (duh)
        sc = c_char_p(shellcode)                    # character pointer (NUL terminated)
        size = len(shellcode)                       # size of the shellcode executing
        addr = c_void_p(libc.valloc(size))          # allocate bytes and return pointer to allocated memory
        memmove(addr, sc, size)                     # copy bytes to allocated memory destination
        libc.mprotect(addr, size, 0x7)              # change access protections
        run = cast(addr, CFUNCTYPE(c_void_p))       # calling convention
        run()                                       # run the shellcode
    else:
        print("Shellcode length: {:d}".format(len(fc)))

        shellcode = bytearray(fc)

        # LPVOID WINAPI VirtualAlloc(
        #   __in_opt  LPVOID lpAddress,         // Address of the region to allocate. If this parameter is NULL, the system determines where to allocate the region.
        #   __in      SIZE_T dwSize,            // Size of the region in bytes. Here we put the size of the shellcode
        #   __in      DWORD flAllocationType,   // The type of memory allocation, flags 0x1000 (MEMCOMMIT) and 0x2000 (MEMRESERVE) to both reserve and commit memory
        #   __in      DWORD flProtect           // Enables RWX to the committed region of pages
        # );
        ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                ctypes.c_int(len(shellcode)), ctypes.c_int(0x3000), ctypes.c_int(0x40))
        # BOOL WINAPI VirtualLock(
        #   _In_ LPVOID lpAddress,  // A pointer to the base address of the region of pages to be locked
        #   _In_ SIZE_T dwSize      // The size of the region to be locked, in bytes.
        # );
        buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
        # VOID RtlMoveMemory(
        #   _Out_       VOID UNALIGNED *Destination,    // A pointer to the destination memory block to copy the bytes to.
        #   _In_  const VOID UNALIGNED *Source,         // A pointer to the source memory block to copy the bytes from.
        #   _In_        SIZE_T         Length           // The number of bytes to copy from the source to the destination.
        # );
        ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                buf, ctypes.c_int(len(shellcode)))
        # HANDLE WINAPI CreateThread(
        #   _In_opt_  LPSECURITY_ATTRIBUTES  lpThreadAttributes,    // If lpThreadAttributes is NULL, the thread gets a default security descriptor.
        #   _In_      SIZE_T                 dwStackSize,           // If this parameter is zero, the new thread uses the default size for the executable.
        #   _In_      LPTHREAD_START_ROUTINE lpStartAddress,        // A pointer to the application-defined function to be executed by the thread.
        #   _In_opt_  LPVOID                 lpParameter,           // optional (A pointer to a variable to be passed to the thread)
        #   _In_      DWORD                  dwCreationFlags,       // Run the thread immediately after creation.
        #   _Out_opt_ LPDWORD                lpThreadId             // NULL, so the thread identifier is not returned.
        # );
        ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                ctypes.c_int(0), ctypes.c_int(ptr), ctypes.c_int(0), ctypes.c_int(0), ctypes.pointer(ctypes.c_int(0)))
        # Waits until the specified object is in the signaled state or the time-out interval elapses
        ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))

    sys.exit()

def objdump2shellcode(dumpfile):
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

    return raw_ops

def main():

    # handle command line arguments
    parser = argparse.ArgumentParser(description="Sickle - a shellcode development tool")
    parser.add_argument("-r", "--read",help="read byte array from the binary file")
    parser.add_argument("-s", "--stdin",help="read ops from stdin (EX: echo -ne \"\\xde\\xad\\xbe\\xef\" | sickle -s -f <format> -b '\\x00')", action="store_true")
    parser.add_argument("-obj","--objdump",help="binary to use for shellcode extraction (via objdump method)")
    parser.add_argument("-f", "--format",help="output format (use --list for a list)")
    parser.add_argument("-b", "--badchar",help="bad characters to avoid in shellcode")
    parser.add_argument("-c", "--comment",  help="comments the shellcode output", action="store_true")
    parser.add_argument("-v", "--varname",required=False, help="alternative variable name")
    parser.add_argument("-l", "--list",help="list all available formats and arguments", action="store_true")
    parser.add_argument("-e", "--examine",help="examine a separate file containing original shellcode. mainly used to see if shellcode was recreated successfully")
    parser.add_argument("-d", "--disassemble",help="disassemble the binary file", action="store_true")
    parser.add_argument("-a", "--arch",help="select architecture for disassembly")
    parser.add_argument("-m", "--mode",help="select mode for disassembly")
    parser.add_argument('-rs', "--run-shellcode",help="run the shellcode (use at your own risk)", action="store_true")

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
    comment_code= args.comment

    # if a list is requested print it
    if args.list == True:
        grab_info = format_list(True)
    else:
        grab_info = format_list(False)

    # default variables if none given
    if args.varname == None:
        variable = "buf"
    else:
        variable = args.varname

    if args.format == None:
        format_mode = 'c'
    else:
        format_mode = args.format
        if format_mode not in grab_info:
            print("Currently %s format is not supported" % (format_mode))
            exit(0)

    # if we are just extracting raw opcodes
    if byte_file:
        if run == True:
            deployment(byte_file)
        elif compare:
            # send the file to be compared
            compareIT = reversing(byte_file, compare, arch="", mode="")
            compareIT.compare_dump()
        elif comment_code:
            if arch == None or mode == None:
                print("Architecture or mode not selected, defaulting to x86-32")
                commentIT = formatting(byte_file, format_mode, badchars, variable, arch="x86", mode="32")
                commentIT.informational_dump()
            else:
                commentIT = formatting(byte_file, format_mode, badchars, variable, arch, mode)
                commentIT.informational_dump()
        elif disassemble:
            if arch == None or mode == None:
                print("Architecture or mode not selected, defaulting to x86-32")
                disassIT = reversing(byte_file, compare, arch="x86", mode="32")
                disassIT.disassemble()
            else:
                disassIT = reversing(byte_file, compare, arch, mode)
                disassIT.disassemble()
        else:
            # send the file to be dumped and formatted
            dumpIT = formatting(byte_file, format_mode, badchars, variable, None, None)
            dumpIT.tactical_dump()
    # are we reading from STDIN?
    elif args.stdin == True:
        byte_file = sys.stdin.buffer.raw.read()
        if run == True:
            deployment(byte_file)
        elif comment_code:
            if arch == None or mode == None:
                print("Architecture or mode not selected, defaulting to x86-32")
                commentIT = formatting(byte_file, format_mode, badchars, variable, arch="x86", mode="32")
                commentIT.informational_dump()
            else:
                commentIT = formatting(byte_file, format_mode, badchars, variable, arch, mode)
                commentIT.informational_dump()
        elif disassemble:
            if arch == None or mode == None:
                print("Architecture or mode not selected, defaulting to x86-32")
                disassIT = reversing(byte_file, compare, arch="x86", mode="32")
                disassIT.disassemble()
            else:
                disassIT = reversing(byte_file, compare, arch, mode)
                disassIT.disassemble()
        else:
            readIT = formatting(byte_file, format_mode, badchars, variable, None, None)
            readIT.tactical_dump()
    # are we extracting opcodes from an existing binary?
    elif dumpfile:
        raw_ops = objdump2shellcode(dumpfile)
        if run == True:
            deployment(raw_ops)
        elif comment_code:
            if arch == None or mode == None:
                print("Architecture or mode not selected, defaulting to x86-32")
                commentIT = formatting(raw_ops, format_mode, badchars, variable, arch="x86", mode="32")
                commentIT.informational_dump()
            else:
                commentIT = formatting(raw_ops, format_mode, badchars, variable, arch, mode)
                commentIT.informational_dump()
        elif disassemble:
            if arch == None or mode == None:
                print("Architecture or mode not selected, defaulting to x86-32")
                disassIT = reversing(raw_ops, compare, arch="x86", mode="32")
                disassIT.disassemble()
            else:
                disassIT = reversing(raw_ops, compare, arch, mode)
                disassIT.disassemble()
        else:
            dumpIT = formatting(raw_ops, format_mode, badchars, variable, None, None)
            dumpIT.tactical_dump()

    else:
        parser.print_help()

if __name__ == '__main__':
    main()
