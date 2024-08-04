from sickle.common.lib.reversing.marker import OpcodeAnalyser

class FormatModule():

    author      = "wetw0rk"
    format_name = "javascript"
    description = "Format bytecode for Javascript (Blob to send via XHR)"

    def __init__(self, raw_bytes=None, badchars=None, varname=None):
        
        self.raw_bytes = raw_bytes
        self.badchars = badchars
        self.varname = varname

        self.language_info = \
        {
            "single line comment": '//',
            "multi line comment": ["/*", "*/"],
            "opcode escape": None,
            "seperator": None,
        }

    def get_language_information(self):
        
        return self.language_info

    def get_generated_lines(self, pinpoint=False, single_line=False):
        
        op_str = ""
        ops = ""

        for byte in bytearray(self.raw_bytes):
            op_str += "{:02x}".format(byte)

        custom_analyser = OpcodeAnalyser(self.language_info,
                                         op_str,
                                         self.badchars,
                                         0)

        custom_analyser.set_num(60)

        results = custom_analyser.get_bytecode_analysis()
        lines  = [f'var {self.varname} = "";']
        lines += f"var bytes = [];",
        for i in range(len(results)):
            lines += ('%s += \"%s\";' % (self.varname, results[i])),

        lines += (""),
        lines += ("/* blob: contains the final payload in proper format */"),
        lines += ("for (var i = 0, len = %s.length; i < len; i+=2)" % (self.varname)),
        lines += ("{"),
        lines += ("  bytes.push(parseInt(%s.substr(i,2),16));" % self.varname),
        lines += ("}"),
        lines += ("var fp = new Uint8Array(bytes);\n"),

        lines += ("var blob = new Blob([fp])"),

        return lines
