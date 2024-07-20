from sickle.common.lib.reversing.marker import analyze_bytes

class FormatModule():

    author      = "wetw0rk"
    format_name = "java"
    description = "Format bytecode for Java"

    def __init__(self, raw_bytes=None, badchars=None, varname=None):
        self.raw_bytes = raw_bytes
        self.badchars = badchars
        self.varname = varname

        self.language_info = \
        {
            "single line comment": '//',
            "multi line comment": ["/*", "*/"],
            "opcode escape": " (byte) 0x",
            "seperator": ",",
        }

    def get_language_information(self):
        return self.language_info

    def get_generated_lines(self, pinpoint=False, single_line=False):
        max_bytes_per_line = 8
        if (pinpoint == False):
            self.badchars = None
        
        if (single_line == True):
            max_bytes_per_line = 16

        op_str = ""
        for byte in bytearray(self.raw_bytes):
            op_str += " (byte) 0x{:02x},".format(byte)

        lines = []
        if (single_line != True):
            lines += f"byte {self.varname}[] = new byte[]",
            lines += "{"

        results = analyze_bytes(self.language_info, op_str, self.badchars, max_bytes_per_line)
        for i in range(len(results)):
            lines += results[i],
        
        if (single_line != True):
            lines += ("};"),

        return lines
