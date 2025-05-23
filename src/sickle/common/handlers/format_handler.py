from sickle.common.lib.generic.mparser import get_module_list
from sickle.common.lib.generic.mparser import check_module_support

class FormatHandler():
    """This class is responsible for calling the appropriate format module. All formatting
    should pass through this class

    :param fmt: The language format to use for bytecode returned
    :type fmt: str

    :param raw_bytes: The bytes to be formatted
    :type raw_bytes: bytes

    :param badchars: Bad characters to be highlighted
    :type badchars: str

    :param varname: The variable name used for formatting output
    :type varname: str
    """

    def __init__(self, fmt, raw_bytes, badchars, varname):
        
        self.raw_bytes = raw_bytes
        self.badchars = badchars
        self.varname = varname
        self.fmt = fmt
        self.fmt_mod = None

    def get_language_formatter(self):
        """Returns a language format module object

        :return: Format module
        :rtype: FormatModule class
        """

        format_module = check_module_support("formats", self.fmt)
        if (format_module == None):
            return None

        language_formatter = format_module.FormatModule(self.raw_bytes, self.badchars, self.varname)
        return language_formatter

    def print_formats():
        """Prints all currently supported formats along with a short desciption
        """
       
        # TODO: Account for terminal size if possible I'll need to look into it but not important for now

        formats = get_module_list("formats")
        parsed_formats = []

        max_format_len = 0x0D
        max_info_len = 0x00
        
        for i in range(len(formats)):
            format_module = check_module_support("formats", formats[i])
            format_len = len(formats[i])
            info_len = len(format_module.FormatModule.description)

            if format_len > max_format_len:
                max_format_len = format_len

            if info_len > max_info_len:
                max_info_len = info_len

            parsed_formats.append([formats[i], format_module.FormatModule.description])

            #print(f"  {formats[i]:<20}{format_module.FormatModule.description}")

        print(f"\n  {'Format':<{max_format_len}} {'Description'}")
        print(f"  {'-':-<{max_format_len}} {'-':-<{max_info_len}}")
        for i in range(len(parsed_formats)):
            name = parsed_formats[i][0]
            info = parsed_formats[i][1]
            print(f"  {name:<{max_format_len}} {info:<{max_info_len}}")
