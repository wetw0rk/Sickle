from sickle.common.lib.reversing.marker import analyze_bytes
from sickle.common.lib.generic.convert import from_raw_to_escaped

class FormatModule():

    author      = "wetw0rk"
    format_name = "ruby"
    description = "Format bytecode for Ruby"

    def __init__(self, raw_bytes, badchars, varname):
        
        self.raw_bytes = raw_bytes
        self.badchars = badchars
        self.varname = varname

        self.language_info = \
        {
            "single line comment": "#",
            "multi line comment": ["=begin", "=end"],
            "opcode escape": "\\x",
            "seperator": ""
        }

    def get_language_information(self):
        
        return self.language_info

    def get_generated_lines(self, pinpoint=False, single_line=False):
        
        if (pinpoint == False):
            self.badchars = False

        escaped_bytes = from_raw_to_escaped(self.raw_bytes)
        results = analyze_bytes(self.language_info, escaped_bytes, self.badchars, 14)
        lines = []
        for i in range(len(results)):
            if ((i == 0) and single_line != True):
                lines += f'{self.varname} = ""',
            if ((i == (len(results) -1)) and (single_line != True)):
                lines += ("\"{:s}\"".format(results[i])),
            else:
                lines += ("\"{:s}\" +".format(results[i])),

        return lines
