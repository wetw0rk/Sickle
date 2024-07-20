from sickle.common.lib.reversing.marker import analyze_bytes
from sickle.common.lib.generic.convert import from_raw_to_escaped

class FormatModule():

    author      = "wetw0rk"
    format_name = "escaped"
    description = "Format bytecode for one-liner hex escape paste"

    def __init__(self, raw_bytes, badchars=None, varname=None):
        self.raw_bytes = raw_bytes
        self.badchars = badchars
        self.varname = varname

        self.language_info = \
        {
            "single line comment": None,
            "multi line comment": None,
            "opcode escape": "\\x",
            "seperator": ""
        }

    def get_language_information(self):
        return self.language_info

    def get_generated_lines(self, pinpoint=False, single_line=False):
        ops = ""
        escaped_bytes = from_raw_to_escaped(self.raw_bytes)
        results = analyze_bytes(self.language_info, escaped_bytes, self.badchars, len(self.raw_bytes))
        for i in range(len(results)):
            ops += results[i]
        return [ops]
