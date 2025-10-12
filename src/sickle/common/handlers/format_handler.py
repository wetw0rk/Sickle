from sickle.common.lib.generic import modparser

class FormatHandler():
    """This class is responsible for calling the appropriate format module. All
    formatting should pass through this class

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

        format_module = modparser.check_module_support("formats", self.fmt)
        if (format_module == None):
            return None

        language_formatter = format_module.FormatModule(self.raw_bytes, self.badchars, self.varname)
        return language_formatter

    def print_formats():
        """Prints all currently supported formats along with a short desciption
        """
        
        # Obtain the list of formats and their respective desciptions
        formats = modparser.get_module_list("formats")
        descriptions = [modparser.check_module_support("formats", fmt).FormatModule.description
                        for fmt in formats]

        # Obtain the largest format and format description string then calculate its
        # length.
        max_format_len = len(max(formats, key=len))
        if (max_format_len < 0x0D):
            max_format_len = 0x0D

        max_info_len = len(max(descriptions, key=len))

        # Output the results        
        print(f"\n  {'Format':<{max_format_len}} {'Description'}")
        print(f"  {'------':<{max_format_len}} {'-----------'}")
        for fmt, info in zip(formats, descriptions):
            space_used = max_format_len + 4
            out_list = modparser.get_truncated_list(f"{info}", space_used)
            for i in range(len(out_list)):
                if i != 0:
                    print(f"  {' ' * max_format_len} {out_list[i]}")
                else:
                    print(f"  {fmt:<{max_format_len}} {out_list[i]}")
