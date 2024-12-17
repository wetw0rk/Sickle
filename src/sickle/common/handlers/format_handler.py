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
        
        formats = get_module_list("formats")
        print(f"\n  {'Format':<20}{'Description'}")
        print(f"  {'------':<20}{'-----------'}")
        for i in range(len(formats)):
            format_module = check_module_support("formats", formats[i])
            print(f"  {formats[i]:<20}{format_module.FormatModule.description}")
