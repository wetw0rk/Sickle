from sickle.common.lib.reversing.marker import OpcodeAnalyser

class FormatModule():

    author      = "wetw0rk"
    format_name = "dword",
    description = "Format bytecode in dword"

    def __init__(self, raw_bytes=None, badchars=None, varname=None):
        self.raw_bytes = raw_bytes
        self.badchars = badchars
        self.varname = varname

        self.language_info = \
        {
            "single line comment": None,
            "multi line comment": None,
            "opcode escape": None,
            "seperator": None
        }

    def get_language_information(self):
        return self.language_info

    def get_generated_lines(self, pinpoint=False, single_line=False):
        op_str = ""
        dwrd = ""
        dlst = []
        lines = []

        for byte in bytearray(self.raw_bytes):
            dwrd += "{:02x}".format(byte)

        # Format the hex bytes into dword
        splits = [dwrd[x:x+8] for x in range(0,len(dwrd),8)]
        for i in range(len(splits)):
            s = splits[i]
            dlst += "0x" + "".join(map(str.__add__, s[-2::-2] ,s[-1::-2])),
        for i in range(int(len(dlst)/8+1)):
            op_str += ", ".join(dlst[i*8:(i+1)*8])

        # Since this is a format rather than following a "language" rule we
        # need to manually set the OpcodeAnalyser class object ourselves.
        custom_analyser = OpcodeAnalyser(self.language_info,
                                         op_str,
                                         self.badchars,
                                         0)
        custom_analyser.set_num(94)


        # Send it off to analysis
        results = custom_analyser.get_bytecode_analysis()
        for i in range(len(results)):
            lines += results[i],

        return lines
