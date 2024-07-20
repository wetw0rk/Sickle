'''

fmt: Operations related to formatting bytecode

'''


from .formats import *

class Format():

    def __init__(self, fmt, raw_bytes, badchars, varname):
        self.raw_bytes = raw_bytes
        self.badchars = badchars
        self.varname = varname
        self.fmt = fmt

    def get_language_formatter(self):
        language_formatter = eval(self.fmt).FormatModule(self.raw_bytes, self.badchars, self.varname)
        return language_formatter
