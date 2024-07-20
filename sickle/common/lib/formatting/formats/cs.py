from sickle.common.lib.reversing.marker import analyze_bytes

class FormatModule():

    author      = "wetw0rk"
    format_name = "cs"
    description = "Format bytecode for C#"

    def __init__(self, raw_bytes=None, badchars=None, varname=None):
        self.raw_bytes = raw_bytes
        self.badchars = badchars
        self.varname = varname

        self.language_info = \
        {
            "single line comment": '//',
            "mutli line comment": ["/*", "*/"],
            "opcode escape": "0x",
            "seperator": ","
        }
        
    def get_language_information(self):
        return self.language_info

    def get_generated_lines(self, pinpoint=False, single_line=False):
        if (pinpoint == False):
            self.badchars = None

        op_str = ""
        try:
            split_badchar = self.badchars.split(',')
            for i in range(len(split_badchar)):
                mod_badchars += "0x%s," % (split_badchar[i][2:])
                self.badchars = mod_badchars.rstrip(',')
        except:
            pass

        for byte in bytearray(self.raw_bytes):
            op_str += "0x{:02x},".format(byte)

        if (single_line != True):
            lines = ["byte[] {:s} = new byte[{:d}] {:s}".format(self.varname, len(self.raw_bytes), '{')]
        else:
            lines = []

        results = analyze_bytes(self.language_info, op_str, self.badchars, 15)
        for i in range(len(results)):
            snip = len(results[i]) - 1

            if ((i == (len(results)-1)) and single_line != True):
                lines += (results[i][:snip] + " };"),
            else:
                lines += (results[i]),

        return lines
