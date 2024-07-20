from sickle.common.lib.reversing.marker import analyze_bytes
from sickle.common.lib.generic.convert import from_raw_to_escaped

class FormatModule():

    author      = "wetw0rk"
    format_name = "python3"
    description = "Format bytecode for Python3"

    def __init__(self, raw_bytes, badchars, varname):
        self.raw_bytes = raw_bytes
        self.badchars = badchars
        self.varname = varname

        self.language_info = \
        {
            "single line comment": "#",
            "multi line comment": ["'''", "'''"],
            "opcode escape"       : "\\x",
            "seperator": ""
        }

    def get_language_information(self):
        return self.language_info

    def get_generated_lines(self, pinpoint=False, single_line=False):
        if (pinpoint == False):
            self.badchars = None

        lines = []
        escaped_bytes = from_raw_to_escaped(self.raw_bytes)
        results = analyze_bytes(self.language_info, escaped_bytes, self.badchars, 14)

        for i in range(len(results)):
            if ((i == 0) and (single_line != True)):
                lines += f'{self.varname} = bytearray()',
            lines += ("{:s} += b'{:s}'".format(self.varname, results[i])),

        return lines
