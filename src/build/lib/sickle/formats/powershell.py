from sickle.common.lib.reversing.marker import analyze_bytes

class FormatModule():

    author      = "wetw0rk"
    format_name = "powershell"
    description = "Format bytecode for Powershell"

    def __init__(self, raw_bytes, badchars, varname):
        
        self.raw_bytes = raw_bytes
        self.badchars = badchars
        self.varname = varname

        self.language_info = \
        {
            "single line comment": '#',
            "multi line comment": ["<#", "#>"],
            "opcode escape": "0x",
            "seperator": ",",
        }

    def get_language_information(self):
        
        return self.language_info

    def get_generated_lines(self, pinpoint=False, single_line=False):
        
        op_str = ""

        for byte in bytearray(self.raw_bytes):
            op_str += "0x{:02x},".format(byte)

        lines = []
        results = analyze_bytes(self.language_info, op_str, self.badchars, 10)
        for i in range(len(results)):
            snip = len(results[i]) - 1
            if ((i == 0) and (single_line != True)):
                lines += ("[Byte[]] ${:s} = {:s}".format(self.varname, results[i].replace(" ", ",")[:snip])),
            else:
                lines += ("${:s} += {:s}".format(self.varname, results[i].replace(" ", ",")[:snip])),

        return lines
