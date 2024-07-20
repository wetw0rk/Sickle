from sickle.common.lib.reversing.marker import analyze_bytes

class FormatModule():

    author      = "wetw0rk"
    format_name = "num"
    description = "Format bytecode in num format"

    def __init__(self, raw_bytes=None, badchars=None, varname=None):
        self.raw_bytes = raw_bytes
        self.badchars = badchars
        self.varname = varname

        self.language_info = \
        {
            "single line comment": None,
            "multi line comment": None,
            "opcode escape": " 0x",
            "seperator": ","
        }

    def get_language_information(self):
        return self.language_info

    def get_generated_lines(self, pinpoint=False, single_line=False):
        op_str = ""
        for byte in bytearray(self.raw_bytes):
            op_str += "0x{:02x}, ".format(byte)

        lines = []
        results = analyze_bytes(self.language_info, op_str, self.badchars, 14)
        for i in range(len(results)):
            snip = len(results[i]) - 2
            if i == (len(results)-1):
                lines += (results[i][:snip]),
            else:
                lines += (results[i]),

        return lines
