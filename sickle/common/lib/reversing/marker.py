'''

marker: Functions and classes that perform highlighting should be placed here :)

'''

import os
import sys
import codecs
import binascii

from sickle.common.lib.generic.colors import Colors
from sickle.common.lib.generic.colors import ansi_ljust

###
# OpcodeAnalyser:
#   Generates a list of analyzed bytes with bad character highlighting.
###
class OpcodeAnalyser():

    def __init__(self, language_info, opcode_string, badchars, bytes_per_line):
        self.li       = language_info
        self.op_str   = opcode_string
        self.badchars = badchars
        self.bpl      = bytes_per_line

        self.num = 0

    def get_bytecode_analysis(self):
        op_line = []
        spotted = []
        results = []

        self.set_badchars()
        if (self.num == 0):
            self.set_num()

        if self.badchars != None:
            # split badchars if any
            sep_chars = self.badchars.split(",")
            for i in range(len(sep_chars)):
                if sep_chars[i] in self.op_str:
                    spotted += ("{:s}".format(sep_chars[i])),
 
  
        # here we begin to spot the badchars should we find one
        # we will replace it with a bold and red opcode, simply
        # making identification an ease
        indiv_byte = len(spotted)-1         # loop counter for bad characters
 
        # the tactical dumping begins here, aiding in spotting badchars
        splits = [self.op_str[x:x+self.num] for x in range(0,len(self.op_str),self.num)]
        for i in range(len(splits)):
            while indiv_byte > -1:
                if spotted[indiv_byte] in splits[i]:
                    highlight_byte = "{:s}{:s}{:s}{:s}".format(Colors.BOLD, Colors.RED, spotted[indiv_byte], Colors.END)
                    splits[i] = splits[i].replace(spotted[indiv_byte], highlight_byte)
                indiv_byte -= 1
            indiv_byte = len(spotted)-1
 
        for i in range(len(splits)):
            results += splits[i],

        return results

    def get_modified_bytes(self):
        byte_list = self.get_badchar_list()
        modified_bytes = ""

        for i in range(len(byte_list)):
            if (self.li["opcode escape"] != None):
                modified_bytes += f"{self.li['opcode escape']}{byte_list[i]},"
            else:
                modified_bytes += f"{byte_list[i]},"

        modified_bytes = modified_bytes.rstrip(',')

        return modified_bytes

    def get_badchar_list(self):
        hex_list = list(filter(None, self.badchars.split("\\x")))
        return hex_list

    def set_badchars(self):
        if (self.badchars != None):
            self.badchars = self.get_modified_bytes()
        return

    def set_num(self, num=0):
        if (num == 0):
            size_of_byte_str = 2

            num += self.bpl * size_of_byte_str
            num += self.bpl * len(self.li["opcode escape"])
            num += self.bpl * len(self.li["seperator"])

        self.num = num

        return

def analyze_bytes(language_info, escaped_opcodes, badchars, bytes_per_line):
    analyzer = OpcodeAnalyser(language_info, escaped_opcodes, badchars, bytes_per_line)
    return analyzer.get_bytecode_analysis()
