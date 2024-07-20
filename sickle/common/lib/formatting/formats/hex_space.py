from sickle.common.lib.reversing.marker import OpcodeAnalyser

class FormatModule():

    author      = "wetw0rk"
    format_name = "hex_space",
    description = "Format bytecode in hex, seperated by a space"

    def __init__(self, raw_bytes=None, badchars=None, varname=None):
        self.raw_bytes = raw_bytes
        self.badchars = badchars
        self.varname = varname

        self.language_info = \
        {
            "single line comment" : None,
            "multi line comment": None,
            "opcode escape": None,
            "seperator": None
        }

    def get_language_information(self):
        return self.language_info

    def get_generated_lines(self, pinpoint=False, single_line=False):
        op_str = ""
        ops = ""

        for byte in bytearray(self.raw_bytes):
            op_str += "{:02x} ".format(byte)

        custom_analyser = OpcodeAnalyser(self.language_info,
                                         op_str,
                                         self.badchars,
                                         0)
        custom_analyser.set_num(8)

        results = custom_analyser.get_bytecode_analysis()

        for i in range(len(results)):
            ops += results[i]

        return [ops]
