import sys

from sickle.common.handlers.format_handler import FormatHandler

class Module():

    name = "Format"

    module = "format"

    example_run = f"{sys.argv[0]} -r shellcode -f c"

    platform = "N/A"

    arch = "N/A"

    ring = "N/A"

    author = ["wetw0rk"]

    tested_platforms = ["N/A"]

    summary = "Converts bytecode into a respective format (activated anytime '-f' is used)"

    description = ("Formats bytecode into a format for a target language")

    arguments = None

    def __init__(self, arg_object):
        
        self.raw_bytes = arg_object["raw bytes"]
        self.badchars = arg_object["bad characters"]
        self.varname = arg_object["variable name"]
        self.format  = arg_object["format"]

    def do_thing(self):
        
        if (self.raw_bytes == None):
            return

        formatter = FormatHandler(self.format, self.raw_bytes, self.badchars, self.varname) 
        language_formatter = formatter.get_language_formatter()

        language_info = language_formatter.get_language_information()
        comment = language_info["single line comment"]

        if (comment != None):
            sys.stderr.write(f"{comment} {' '.join(sys.argv)}\n")
            sys.stderr.write(f"{comment} size: {len(self.raw_bytes)} bytes\n")

        lines = language_formatter.get_generated_lines(True, False)
        if (lines != None):
            for i in range(len(lines)):
                print(lines[i])

        return
