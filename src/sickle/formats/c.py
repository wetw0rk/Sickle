from sickle.common.lib.reversing.marker import analyze_bytes
from sickle.common.lib.generic.convert import from_raw_to_escaped

class FormatModule():

    author           = "wetw0rk"
    format_name      = "c"
    description      = "Format bytecode for a C application"

    def __init__(self, raw_bytes=None, badchars=None, varname=None):
        
        self.raw_bytes = raw_bytes
        self.badchars = badchars
        self.varname = varname

        self.language_info = \
        {
            "single line comment": '//',
            "multi line comment": ["/*", "*/"],
            "opcode escape": "\\x",
            "seperator": "",
        }

    ###
    # get_language_information: Returns information on target language
    ###
    def get_language_information(self):
        
        return self.language_info

    ###
    # get_generated_lines:
    #   Generates bytecode lines to be injected into source code following rules of the target
    #   language. This is useful for when you want to inject shellcode into some source code.
    ###
    def get_generated_lines(self, pinpoint=False, single_line=False):
        
        backup_badchars = self.badchars
        if (pinpoint == False):
            self.badchars = None

        if (single_line != True):
            lines = ["unsigned char {:s}[] = ".format(self.varname)]
        else:
            lines = []

        escaped_bytes = from_raw_to_escaped(self.raw_bytes)
        results = analyze_bytes(self.language_info, escaped_bytes, self.badchars, 14)
        for i in range(len(results)):
            if ((i == (len(results) - 1)) and single_line != True):
                lines += "\"{:s}\";".format(results[i]),
            else:
                lines += "\"{:s}\"".format(results[i]),

        self.badchars = backup_badchars

        return lines
