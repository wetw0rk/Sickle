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
# Version         : 1.5
# Created date    : 10/14/2017
# Last update     : 04/04/2019
# Author          : Milton Valencia (wetw0rk)
# Architecture    : x86, and x86-x64
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

from ctypes import CDLL, c_char_p, c_void_p, memmove, cast, CFUNCTYPE
import os, sys, time, ctypes, codecs, argparse, binascii, subprocess

try:
    from capstone import *

except:
    # if capstone is installed under python2.7 path, import directly
    # else fails we are on a Windows OS
    try:

        # don't look nasty direct import
        import importlib.machinery
        path_var = "/usr/lib/python2.7/dist-packages/capstone/__init__.py"
        capstone = importlib.machinery.SourceFileLoader(
            'capstone', path_var
        ).load_module()

        from capstone import *

    except:

        pass

try:

    architecture_mode = {
        'x86_32'    : Cs(CS_ARCH_X86,   CS_MODE_32),
        'x86_64'    : Cs(CS_ARCH_X86,   CS_MODE_64),
        'mips32'    : Cs(CS_ARCH_MIPS,  CS_MODE_32),
        'mips64'    : Cs(CS_ARCH_MIPS,  CS_MODE_64),
        'arm'       : Cs(CS_ARCH_ARM,   CS_MODE_ARM),
        'arm64'     : Cs(CS_ARCH_ARM64, CS_MODE_ARM),
        'arm_thumb' : Cs(CS_ARCH_ARM,   CS_MODE_THUMB)
    }

except:

    print("Failed to load capstone, disassembly disabled")

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
    "raw_shell"
]

supported_comments = [
    "c",
    "python",
    "perl",
    "ruby-array",
]

supported_architecture_modes = [
    'x86_32',
    'x86_64',
    'mips32',
    'mips64',
    'arm',
    'arm64',
    'arm_thumb'
]

class check_default_formats():
    def __init__(self, format_mode, comment_bool, arch):
        self.format_mode    = format_mode
        self.comment_bool   = comment_bool
        self.arch           = arch

    def check(self):
        if self.format_mode not in supported_formats:
            sys.exit("Currently %s format is not supported" % (self.format_mode))
        if self.comment_bool == True and self.format_mode not in supported_comments:
            sys.exit("Currently %s comment format is not supported" % (self.format_mode))
        if self.arch not in supported_architecture_modes:
            sys.exit("Currently %s architecture is not supported" % (self.arch))

        return

    def loop(self, arg):
        sup = "\t"
        for i in range(len(arg)):
            sup += "{:s}, ".format(arg[i])
        print(sup[:len(sup)-2])
        sup = ""

        return

    def print_info(self):
        print("Dump formats:")
        self.loop(supported_formats)

        print("Comment dump formats:")
        self.loop(supported_comments)

        print("Supported architectures modes:")
        self.loop(supported_architecture_modes)

        sys.exit(0)

class colors():
    def __init__(self):
        pass

    # color output only for unix
    if os.name == 'posix':
        RED     = '\033[31m'
        BLUE    = '\033[94m'
        BOLD    = '\033[1m'
        GRN     = '\033[92m'
        END     = '\033[0m'
    else:
        RED     = ""
        BLUE    = ""
        BOLD    = ""
        GRN     = ""
        END     = ""

class shellcode_manipulation():
    def __init__(self, binary_file, format_mode, badchars, variable, arch):
        self.binary_file    = binary_file
        self.format_mode    = format_mode
        self.badchars       = badchars
        self.variable       = variable
        self.arch           = arch

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

    def commented_dump(self):
        opcode_string       = []
        instruction_line    = []
        hex_opcode_string   = []
        completed_conversion= []
        results             = []

        mode = architecture_mode[self.arch]

        rbytes = read_in_bytes(self.binary_file, False)

        print("Payload size: {:d} bytes".format(rbytes[2]))

        # seperate the instructions and opcode
        for i in mode.disasm(rbytes[1], 0x1000):
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
                    ).expandtabs(44),
                elif i == (len(instruction_line)-1) and ID in results[i]:
                    completed_conversion += ("\"%s\";\t %s%s// %s%s" % (
                        hex_opcode_string[i],
                        colors.BOLD,
                        colors.RED,
                        instruction_line[i],
                        colors.END)
                    ).expandtabs(44),
                elif i == (len(instruction_line)-1):
                    completed_conversion += ("\"%s\";\t // %s" % (
                        results[i],
                        instruction_line[i])
                    ).expandtabs(44),
                else:
                    completed_conversion += ("\"%s\"\t // %s" % (
                        results[i],
                        instruction_line[i])
                    ).expandtabs(44),

        if self.format_mode == "python":
            print('%s = ""' % self.variable)
            for i in range(len(instruction_line)):
                if ID in results[i]:
                    completed_conversion += ("%s += \"%s\"\t %s%s# %s%s" % (
                        self.variable,
                        hex_opcode_string[i],
                        colors.BOLD,
                        colors.RED,
                        instruction_line[i],
                        colors.END)
                    ).expandtabs(40),
                else:
                    completed_conversion += ("%s += \"%s\"\t # %s" % (
                        self.variable,
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
            print('my $%s =' % self.variable)
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


    def standard_dump(self):
        rbytes = read_in_bytes(self.binary_file, False)
        fbytes = read_in_bytes(self.binary_file, True)

        results = []
        op_str  = ""

        if self.format_mode != "raw":
            print("Payload size: {:d} bytes".format(fbytes[2]))

        if self.format_mode == "raw":
            sys.stdout.buffer.write(rbytes[1])

        elif self.format_mode == 'c':
            self.character_analysis(60, fbytes[1], results)
            print("unsigned char {:s}[] = ".format(self.variable))
            for i in range(len(results)):
                if i == (len(results) -1):
                    print("\"{:s}\";".format(results[i]))
                else:
                    print("\"{:s}\"".format(results[i]))

        if self.format_mode == "python":
            self.character_analysis(60, fbytes[1], results)
            print('{:s} = ""'.format(self.variable))
            for i in range(len(results)):
                print("{:s} += \"{:s}\"".format(self.variable, results[i]))

        if self.format_mode == "raw_shell":
            ops = ""
            self.character_analysis(60, fbytes[1], results)
            for i in range(len(results)):
                ops += results[i]
            print(ops)

        if self.format_mode == "python3":
            self.character_analysis(60, fbytes[1], results)
            print('{:s} = bytearray()'.format(self.variable))
            for i in range(len(results)):
                print("{:s} += b'{:s}'".format(self.variable, results[i]))

        if self.format_mode == "bash":
            self.character_analysis(56, fbytes[1], results)
            for i in range(len(results)):
                if i == (len(results) - 1):
                    print("$'{:s}'".format(results[i]))
                else:
                    print("$'{:s}'\\".format(results[i]))

        if self.format_mode == "ruby":
            self.character_analysis(56, fbytes[1], results)
            print("{:s} = ".format(self.variable))
            for i in range(len(results)):
                if i == (len(results) -1):
                    print("\"{:s}\"".format(results[i]))
                else:
                    print("\"{:s}\" +".format(results[i]))

        if self.format_mode == "perl":
            self.character_analysis(60, fbytes[1], results)
            print("my ${:s} =".format(self.variable))
            for i in range(len(results)):
                if i == (len(results) -1):
                    print("\"{:s}\";".format(results[i]))
                else:
                    print("\"{:s}\" .".format(results[i]))

        if self.format_mode == "hex_space":
            ops = ""

            # setup bad chars properly
            try:
                split_badchar = self.badchars.split(',')
                for i in range(len(split_badchar)):
                    mod_badchars += "%s," % (split_badchar[i][2:])
                self.badchars = mod_badchars.rstrip(',')
            except:
                pass

            for byte in bytearray(rbytes[1]):
                op_str += "{:02x} ".format(byte)

            self.character_analysis(8, op_str, results)
            for i in range(len(results)):
                ops += results[i]

            print(ops)

        if self.format_mode == "hex":
            ops = ""

            # setup bad chars properly
            try:
                split_badchar = self.badchars.split(',')
                for i in range(len(split_badchar)):
                    mod_badchars += "%s," % (split_badchar[i][2:])
                self.badchars = mod_badchars.rstrip(',')
            except:
                pass

            for byte in bytearray(rbytes[1]):
                op_str += "{:02x}".format(byte)

            self.character_analysis(8, op_str, results)
            for i in range(len(results)):
                ops += results[i]

            print(ops)

        if self.format_mode == "csharp":
            # setup bad chars properly
            try:
                split_badchar = self.badchars.split(',')
                for i in range(len(split_badchar)):
                    mod_badchars += "0x%s," % (split_badchar[i][2:])
                self.badchars = mod_badchars.rstrip(',')
            except:
                pass

            for byte in bytearray(rbytes[1]):
                op_str += "0x{:02x},".format(byte)

            self.character_analysis(75, op_str, results)
            print("byte[] {:s} = new byte[{:d}] {:s}".format(self.variable, rbytes[2], "{"))
            for i in range(len(results)):
                snip = len(results[i]) - 1
                if i == (len(results)-1):
                    print(results[i][:snip] + " };")
                else:
                    print(results[i])

        if self.format_mode == "dword":
            dwrd= ""
            dlst= []

            # setup bad chars properly
            try:
                split_badchar = self.badchars.split(',')
                for i in range(len(split_badchar)):
                    mod_badchars += "%s," % (split_badchar[i][2:])
                self.badchars = mod_badchars.rstrip(',')
            except:
                pass

            for byte in bytearray(rbytes[1]):
                dwrd += "{:02x}".format(byte)

            # format the hex bytes into dword
            splits = [dwrd[x:x+8] for x in range(0,len(dwrd),8)]
            for i in range(len(splits)):
                s = splits[i]
                dlst += "0x" + "".join(map(str.__add__, s[-2::-2] ,s[-1::-2])),
            for i in range(int(len(dlst)/8+1)):
                op_str += ", ".join(dlst[i*8:(i+1)*8])

            # send it of for character character_analysis
            self.character_analysis(94, op_str, results)
            for i in range(len(results)):
                print(results[i])

        if self.format_mode == "nasm":
            # setup bad chars properly
            try:
                split_badchar = self.badchars.split(',')
                for i in range(len(split_badchar)):
                    mod_badchars += "0x%s," % (split_badchar[i][2:])
                self.badchars = mod_badchars.rstrip(',')
            except:
                pass

            for byte in bytearray(rbytes[1]):
                op_str += "0x{:02x},".format(byte)

            self.character_analysis(60, op_str, results)

            for i in range(len(results)):
                snip = len(results[i]) - 1
                print("db " + results[i][:snip])


        if self.format_mode == "num":
            # setup bad chars properly
            try:
                split_badchar = self.badchars.split(',')
                for i in range(len(split_badchar)):
                    mod_badchars += "0x%s," % (split_badchar[i][2:])
                self.badchars = mod_badchars.rstrip(',')
            except:
                pass

            for byte in bytearray(rbytes[1]):
                op_str += "0x{:02x}, ".format(byte)

            self.character_analysis(84, op_str, results)
            for i in range(len(results)):
                snip = len(results[i]) - 2
                if i == (len(results)-1):
                    print(results[i][:snip])
                else:
                    print(results[i])

        if self.format_mode == "powershell":
            # setup bad chars properly
            try:
                split_badchar = self.badchars.split(',')
                for i in range(len(split_badchar)):
                    mod_badchars += "0x%s," % (split_badchar[i][2:])
                self.badchars = mod_badchars.rstrip(',')
            except:
                pass

            for byte in bytearray(rbytes[1]):
                op_str += "0x{:02x},".format(byte)

            self.character_analysis(50, op_str, results)
            for i in range(len(results)):
                snip = len(results[i]) - 1
                if i == 0:
                    print("[Byte[]] ${:s} = {:s}".format(self.variable, results[i].replace(" ", ",")[:snip]))
                else:
                    print("${:s} += {:s}".format(self.variable, results[i].replace(" ", ",")[:snip]))

        if self.format_mode == "java":
            # setup bad chars properly
            try:
                split_badchar = self.badchars.split(',')
                for i in range(len(split_badchar)):
                    mod_badchars += "(byte) 0x%s," % (split_badchar[i][2:])
                self.badchars = mod_badchars.rstrip(',')
            except:
                pass

            for byte in bytearray(rbytes[1]):
                op_str += " (byte) 0x{:02x},".format(byte)

            self.character_analysis(104, op_str, results)
            print("byte {:s}[] = new byte[]".format(self.variable))
            print("{")
            for i in range(len(results)):
                print("\t" + results[i].lstrip(" "))
            print("};")

        if self.format_mode == "ruby-array":
            self.character_analysis(60, fbytes[1], results)
            for i in range(len(results)):
                if i == 0:
                    print('{:s} = "{:s}"'.format(self.variable, results[i]))
                else:
                    print('{:s} << "{:s}"'.format(self.variable, results[i]))

class reversing_shellcode():
    def __init__(self, binary_file, compare, arch):
        self.binary_file    = binary_file
        self.compare        = compare
        self.arch           = arch

    def disassemble_bytes(self, source_file, shellcode, sc_size):
        instruction = []
        address     = []
        opcode      = []

        mode = architecture_mode[self.arch]

        try:
            for i in mode.disasm(shellcode, 0x10000000):
                address     += "%x" % i.address,
                opcode      += binascii.hexlify(i.bytes).decode('utf-8'),
                instruction += "%s %s" % (i.mnemonic, i.op_str),
        except CsError as e:
            print("Something went wrong: {:s}".format(e))

        return address, opcode, instruction

    def check_alpha(self, shellcode):
        try:
            shellcode.decode('ascii')
            alpha = True
        except:
            alpha = False

        return alpha

    def disassemble_shellcode(self):
        rbytes = read_in_bytes(self.binary_file, False)
        completed_check = []

        sc_adr, sc_ops, sc_ins = self.disassemble_bytes(rbytes[0], rbytes[1], rbytes[2])

        alpha = self.check_alpha(rbytes[1])

        print("%s%s" % (colors.BOLD, colors.GRN)),
        print("[Bytearray information]".center(60)),
        print(colors.BLUE),
        print("Architecture\tAlphanumeric\tSize (bytes)\tSource{:s}".format(colors.END).expandtabs(15)),
        print("{:s}\t{}\t{:d}\t{:s}".format(self.arch, alpha, rbytes[2], rbytes[0]).expandtabs(15)),
        print("%s%s" % (colors.BOLD, colors.GRN)),
        print("[Shellcode disassembly]".center(60)),
        print(colors.BLUE),
        print("Address\tOpCodes\tAssembly{:s}".format(colors.END).expandtabs(22)),

        for i in range(len(sc_adr)):
            completed_check += ("%s\t%s\t%s" % (
                    sc_adr[i],
                    sc_ops[i],
                    sc_ins[i],
            )).expandtabs(22),

        for i in range(len(completed_check)):
            print(completed_check[i])

    def compare_shellcode(self):
        original = read_in_bytes(self.binary_file, False)
        modified = read_in_bytes(self.compare, False)

        og_addr, og_op, og_ins = self.disassemble_bytes(original[0], original[1], original[2])
        md_addr, md_op, md_ins = self.disassemble_bytes(modified[0], modified[1], modified[2])

        final_ops = []
        final_asm = []
        final_end = []
        final_ogc = []

        if len(og_addr) > len(md_addr):
            loopc = len(og_addr)
        else:
            loopc = len(md_addr)

        for i in range(loopc):
            # opcode manipulation
            try:
                if og_op[i] == md_op[i]:
                    final_ops += ("%s%s%s%s" % (colors.BOLD, colors.BLUE, md_op[i], colors.END)),
                else:
                    final_ops += ("%s%s%s%s" % (colors.BOLD, colors.RED, md_op[i], colors.END)),
            except IndexError:
                try:
                    final_ops += ("%s%s%s%s" % (colors.BOLD, colors.GRN, md_op[i], colors.END)),
                except:
                    pass
            # instruction manipulation
            try:
                if og_ins[i] == md_ins[i]:
                    final_asm += ("%s%s%s%s" % (colors.BOLD, colors.BLUE, og_ins[i], colors.END)),
                else:
                    final_asm += ("%s%s%s%s" % (colors.BOLD, colors.RED, md_ins[i], colors.END)),
            except IndexError:
                try:
                    final_asm += ("%s%s%s%s" % (colors.BOLD, colors.GRN, md_ins[i], colors.END)),
                except:
                    pass

        for i in range(len(final_asm)):
            final_end += ("%s\t%s" % (
            final_ops[i],
            final_asm[i],
        )).expandtabs(35),

        for i in range(len(og_addr)):
            final_ogc += ("%s\t%s" % (
            og_op[i],
            og_ins[i],
        )).expandtabs(22),

        alpha   = self.check_alpha(original[1])
        alpha2  = self.check_alpha(modified[1])

        print(colors.BOLD, colors.GRN)
        print("\t[Original information]\t\t[Modified information]".expandtabs(25))
        print(colors.BLUE)
        print("Architecture\tAlphanumeric\tSize (bytes)\tSource\tArchitecture\tAlphanumeric\tSize (bytes)\tSource{:s}".format(colors.END).expandtabs(15))
        print("{:s}\t{}\t{:d}\t{:s}\t{:s}\t{}\t{:d}\t{:s}".format(
            self.arch, alpha, original[2], original[0],
            self.arch, alpha2, modified[2], modified[0]
        ).expandtabs(15))
        print(colors.BOLD, colors.GRN)
        print("\t[Shellcode disassembly]\t\t[Shellcode disassembly]".expandtabs(25))
        print(colors.BLUE)
        print("OpCodes\t  Assembly\t\tOpCodes\t  Assembly{:s}".format(colors.END).expandtabs(20))

        if len(final_ogc) > len(final_end):
            loopc = len(final_ogc)
        else:
            loopc = len(final_end)

        for i in range(loopc):
            try:
                if len(final_ogc[i]) != 60:
                    num_spaces = 60 - len(final_ogc[i])
                    final_ogc[i] = final_ogc[i] + " " * num_spaces

                print("%s\t%s".expandtabs(0) % (final_ogc[i], final_end[i]))
            except:
                if len(final_ogc) > len(final_end):
                    print("%s".expandtabs(0) % (final_ogc[i]))
                else:
                    print("\t%s".expandtabs(60) % (final_end[i]))

def run_shellcode(shellcode):
    # Methods used are heavily inspired by the following:
    #   http://hacktracking.blogspot.com/2015/05/execute-shellcode-in-python.html
    #   http://www.debasish.in/2012/04/execute-shellcode-using-python.html

    sbytes = read_in_bytes(shellcode, False)

    print("Shellcode length: {:d}".format(sbytes[2]))

    if os.name == 'posix':

        shellcode = bytes(sbytes[1])                # convert shellcode into a bytes
        libc = CDLL('libc.so.6')                    # implement C functions (duh)
        sc = c_char_p(shellcode)                    # character pointer (NUL terminated)
        size = len(shellcode)                       # size of the shellcode executing
        addr = c_void_p(libc.valloc(size))          # allocate bytes and return pointer to allocated memory
        memmove(addr, sc, size)                     # copy bytes to allocated memory destination
        libc.mprotect(addr, size, 0x7)              # change access protections
        run = cast(addr, CFUNCTYPE(c_void_p))       # calling convention
        run()                                       # run the shellcode

    else:

        shellcode = bytearray(sbytes[1])

        # LPVOID WINAPI VirtualAlloc(
        #   __in_opt  LPVOID lpAddress,         // Address of the region to allocate. If this parameter is NULL, the system determines where to allocate the region.
        #   __in      SIZE_T dwSize,            // Size of the region in bytes. Here we put the size of the shellcode
        #   __in      DWORD flAllocationType,   // The type of memory allocation, flags 0x1000 (MEMCOMMIT) and 0x2000 (MEMRESERVE) to both reserve and commit memory
        #   __in      DWORD flProtect           // Enables RWX to the committed region of pages
        # );
        ptr = ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p
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
        ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_void_p(ptr),
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
                ctypes.c_int(0), ctypes.c_void_p(ptr), ctypes.c_int(0), ctypes.c_int(0), ctypes.pointer(ctypes.c_int(0)))
        # Waits until the specified object is in the signaled state or the time-out interval elapses
        ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))

    sys.exit()



def objdump2shellcode(dumpfile):
    no_junk = []
    no_addr = []
    opcodes = []
    instrut = []
    ops     = ""

    # run objdump to disassemble the binary
    try:
        intel_dump = subprocess.Popen(['objdump', '-D', dumpfile, '-M', 'intel', '--insn-width=15'],
                stdout=subprocess.PIPE).communicate()[0]
    except:
        print("Error running objdump command")
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

def read_in_bytes(binary_file, trigger):
    if trigger == True:
        fc = ""
        try:
            with open(binary_file, 'rb') as fd:
                fcr = fd.read()
                for byte in bytearray(fcr):
                    fc += "\\x{:02x}".format(byte)
            fn = binary_file
            fs = os.path.getsize(binary_file)
        except:
            fcr = binary_file
            for byte in bytearray(fcr):
                fc += "\\x{:02x}".format(byte)
            fn = "STDIN"
            fs = len(fcr)
    else:
        try:
            with open(binary_file, "rb") as fd:
                fc = fd.read()
            fn = binary_file
            fs = os.path.getsize(binary_file)
        except:
            fc = binary_file
            fn = "STDIN"
            fs = len(fc)

    data = [fn, fc, fs]

    return data

def main():
    # handle command line arguments
    parser = argparse.ArgumentParser(description="Sickle - Shellcode development tool")
    parser.add_argument("-r", "--read",help="read byte array from the binary file")
    parser.add_argument("-s", "--stdin",help="read ops from stdin (EX: echo -ne \"\\xde\\xad\\xbe\\xef\" | sickle -s -f <format> -b '\\x00')", action="store_true")
    parser.add_argument("-obj","--objdump",help="binary to use for shellcode extraction (via objdump method)")
    parser.add_argument("-a", "--arch",default="x86_32",type=str,help="select architecture for disassembly")
    parser.add_argument("-f", "--format",default='c',type=str,help="output format (use --list for a list)")
    parser.add_argument("-b", "--badchar",help="bad characters to avoid in shellcode")
    parser.add_argument("-c", "--comment",help="comments the shellcode output", action="store_true")
    parser.add_argument("-v", "--varname",default='buf',type=str,help="alternative variable name")
    parser.add_argument("-l", "--list",help="list all available formats and arguments", action="store_true")
    parser.add_argument("-e", "--examine",help="examine a separate file containing original shellcode. mainly used to see if shellcode was recreated successfully")
    parser.add_argument("-d", "--disassemble",help="disassemble the binary file", action="store_true")
    parser.add_argument('-rs', "--run-shellcode",help="run the shellcode (use at your own risk)", action="store_true")

    args = parser.parse_args()

    # assign arguments
    binary_file = args.read
    format_mode = args.format
    compare     = args.examine
    badchars    = args.badchar
    disassemble = args.disassemble
    variable    = args.varname
    obj_dumpfile= args.objdump
    comment_code= args.comment
    run         = args.run_shellcode
    arch        = args.arch

    def_check = check_default_formats(format_mode, comment_code, arch)

    if args.list == True:
        def_check.print_info()
    else:
        def_check.check()

    if args.stdin == False and binary_file or obj_dumpfile or compare:
        if obj_dumpfile:
            file2check = obj_dumpfile
        elif compare:
            if os.path.isfile(binary_file) is False:
                sys.exit("Error dumping shellcode. Is file present?")
            file2check = compare
        else:
            file2check = binary_file

        if os.path.isfile(file2check) is False:
            sys.exit("Error dumping shellcode. Is file present?")

    if args.stdin == True:
        binary_file = sys.stdin.buffer.raw.read()

    if obj_dumpfile:
        binary_file = objdump2shellcode(obj_dumpfile)
        flag = 1

    if binary_file:
        if run == True:
            run_shellcode(binary_file)
        elif disassemble or compare:
            dis = reversing_shellcode(binary_file, compare, arch)
            if disassemble:
                dis.disassemble_shellcode()
            elif compare:
                dis.compare_shellcode()
        else:
            dump_shellcode = shellcode_manipulation(binary_file, format_mode, badchars, variable, arch)
            if comment_code:
                dump_shellcode.commented_dump()
            else:
                dump_shellcode.standard_dump()
    else:
        parser.print_help()

main()
