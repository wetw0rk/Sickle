import sys

from sickle.common.lib.reversing.marker import analyze_bytes

class FormatModule():

    author      = "Joseph McPeters (liquidsky)"
    format_name = "raw"
    description = "Format bytecode to be written to stdout in raw form"

    def __init__(self, raw_bytes, badchars, varname):
        self.raw_bytes = raw_bytes

        self.language_info = \
        {
            "single line comment": None,
            "multi line comment": None,
            "opcode escape": None,
            "seperator": None,
        }

    def get_language_information(self):
        return self.language_info

    def get_generated_lines(self, pinpoint=False, single_line=False):
        sys.stdout.buffer.write(self.raw_bytes)
        return None
