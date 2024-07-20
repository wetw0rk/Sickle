class FormatModule():

    author      = "wetw0rk"
    format_name = "uint8array"
    description = "Format bytecode for Javascript as a Uint8Array directly"

    def __init__(self, raw_bytes, badchars, varname):
        self.raw_bytes = raw_bytes
        self.badchars = badchars
        self.varname = varname

        self.language_info = \
        {
            "single line comment": None,
            "multi line comment": None,
            "opcode escape": None,
            "seperator":None,
        }

    def get_language_information(self):
        return self.language_info

    def get_generated_lines(self, pinpoint=False, single_line=False):
        op_str = "var %s = new Uint8Array([" % self.varname

        for byte in bytearray(self.raw_bytes):
            op_str += "%d, " % byte
        op_str = "%s]);" % op_str[:-2]

        return [op_str]
