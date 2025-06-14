from sickle.common.lib.generic.colors import Colors
from sickle.common.lib.generic.colors import ansi_ljust

class OpcodeAnalyser():
    """This class is responsible for analyzing bytes or opcodes. Mainly this is used
    for bad character highlighting.

    :param language_info: Dictionary containing information on the language we are
        analyzing. This is due to different languages have different byte formats.
    :type languages: dict

    :param opcode_string: This is a string that has been formatted and needs to be
        analyzed.
    :type opcode_string: str

    :param badchars: This is a string of bad characters it should be provided in a
        string without stop, e.g '\x41\x41\x41'
    :type badchars: str

    :param bytes_per_line: The number of bytes per line
    :type bytes_per_line: int
    """

    def __init__(self, language_info, opcode_string, badchars, bytes_per_line):
        
        self.li       = language_info
        self.op_str   = opcode_string
        self.badchars = badchars
        self.bpl      = bytes_per_line

        self.num = 0

    def get_bytecode_analysis(self):
        """This function is responsible for highlighting the bad characters discovered
        within the user provided opcode string.

        :return: List object containing the results of the analysis.
        :rtype: list
        """

        op_line = []
        spotted = []
        results = []

        self.set_badchars()
        if (self.num == 0):
            self.set_num()

        if self.badchars != None:
            # split badchars if any
            sep_chars = self.badchars.split(",")
            for i in range(len(sep_chars)):
                if sep_chars[i] in self.op_str:
                    spotted += ("{:s}".format(sep_chars[i])),
 
  
        # here we begin to spot the badchars should we find one
        # we will replace it with a bold and red opcode, simply
        # making identification an ease
        indiv_byte = len(spotted)-1         # loop counter for bad characters
 
        # the tactical dumping begins here, aiding in spotting badchars
        splits = [self.op_str[x:x+self.num] for x in range(0,len(self.op_str),self.num)]
        for i in range(len(splits)):
            while indiv_byte > -1:
                if spotted[indiv_byte] in splits[i]:
                    highlight_byte = "{:s}{:s}{:s}{:s}".format(Colors.BOLD, Colors.RED, spotted[indiv_byte], Colors.END)
                    splits[i] = splits[i].replace(spotted[indiv_byte], highlight_byte)
                indiv_byte -= 1
            indiv_byte = len(spotted)-1
 
        for i in range(len(splits)):
            results += splits[i],

        return results

    def get_modified_bytes(self):
        """This function is responsible for parsing the bad characters and converting them
        to a format that can be used for highlighting. This means converting '\x41\x41' to
        '0x41,0x41' and so on.

        :return: A format that can be interpreted by the class during its current
            operation.
        :rtype: str
        """

        byte_list = self.get_badchar_list()
        modified_bytes = ""

        for i in range(len(byte_list)):
            if (self.li["opcode escape"] != None):
                modified_bytes += f"{self.li['opcode escape']}{byte_list[i]},"
            else:
                modified_bytes += f"{byte_list[i]},"

        modified_bytes = modified_bytes.rstrip(',')

        return modified_bytes

    def get_badchar_list(self):
        """Generates a list of hex opcodes to be converted later on by get_modified_bytes().

        :return: A list of hex opcodes
        :rtype: list[str]
        """

        hex_list = list(filter(None, self.badchars.split("\\x")))
        return hex_list

    def set_badchars(self):
        """This function is responsible for determining whether or not we need to format any
        bad characters.

        :return: None
        :rtype: None
        """

        if (self.badchars != None):
            self.badchars = self.get_modified_bytes()
        return

    def set_num(self, num=0):
        """This function is responsible for setting the num member. This number is used to
        highlight the bad characters. Think of this as the number of actual bytes within a
        string NOT the bytes. For example, 0x40 is 4 bytes.

        :return: None
        :rtype: None
        """

        if (num == 0):
            size_of_byte_str = 2

            num += self.bpl * size_of_byte_str
            num += self.bpl * len(self.li["opcode escape"])
            num += self.bpl * len(self.li["seperator"])

        self.num = num

        return

def analyze_bytes(language_info, escaped_opcodes, badchars, bytes_per_line):
    """This is a generic function used by many formats to analyze bytes using the OpcodeAnalyser
    class.

    :param language_info: Dictionary containing information on the language we are
        analyzing. This is due to different languages have different byte formats.
    :type languages: dict

    :param opcode_string: This is a string that has been formatted and needs to be
        analyzed.
    :type opcode_string: str

    :param badchars: This is a string of bad characters it should be provided in a
        string without stop, e.g '\x41\x41\x41'
    :type badchars: str

    :param bytes_per_line: The number of bytes per line
    :type bytes_per_line: int

    :return: A list containing the formatted strings with highlighting added
    "return: list[str]
    """

    analyzer = OpcodeAnalyser(language_info, escaped_opcodes, badchars, bytes_per_line)
    return analyzer.get_bytecode_analysis()
