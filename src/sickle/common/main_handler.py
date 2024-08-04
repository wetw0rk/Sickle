import os
import sys

from sickle.common.handlers.format_handler import FormatHandler
from sickle.common.handlers.module_handler import ModuleHandler

from sickle.common.lib.generic.mparser import print_module_info
from sickle.common.lib.generic.extract import read_bytes_from_file

class Handle():
    """This class should be looked at as the coordinator of the framework. Execution
    flow is generally directed from here.

    param arg_parser: The arguments passed to sickle via the command line
    type arg_parser: argparse.ArgumentParser
    """

    def __init__(self, arg_parser):

        args = arg_parser.parse_args()

        self.arg_parser = arg_parser      # parser object used for help output
        self.binfile    = args.read       # read from binary file
        self.module     = args.module     # module to use on binfile
        self.list       = args.list       # list all formats / archs
        self.info       = args.info       # detailed info for module

        self.module_args = {}
        self.module_args["format"] = args.format
        self.module_args["architecture"] = args.arch
        self.module_args["variable name"] = args.varname
        self.module_args["bad characters"] = args.badchars
        self.module_args["positional arguments"] = args.pargs

    def print_supported(self):
        """Print support information for all currently supported modules and overall operations
        supported by sickle.
        """

        ModuleHandler.print_modules()
        FormatHandler.print_formats()
        
        exit(0)

    def handle_args(self):
        """Parse the user arguments and overall direct execution for sickle.
        """

        if self.list == True:
            self.print_supported()

        if self.info == True:
            if (self.module != "format"):
                print_module_info("modules", self.module)
            else:
                sys.exit(f"What do you want information for?")

        # Here we define where we will be reading bytecode from. If we end up reading from STDIN,
        # we go ahead and read the buffer directly.
        read_source = None
        if self.binfile:
            if (self.binfile == '-'):
                read_source = "stdin"
                self.binfile = sys.stdin.buffer.raw.read()
            else:
                read_source = self.binfile
                if os.path.isfile(self.binfile) is False:
                    sys.exit("Error dumping bytecode. Is file present?")
        
        self.module_args["source"] = read_source

        # This is where we actually read the bytecode / binary data and assign it to the module_args
        # dictionary.
        if self.binfile:
            read_bytes = read_bytes_from_file(self.binfile)
        else:
            read_bytes = None

        self.module_args["raw bytes"] = read_bytes
        if (read_bytes != None):
            self.module_args["num bytes"] = len(read_bytes)
        else:
            self.module_args["num bytes"] = None

        # If the format module is called (default module) we expect it to have a read_source
        if (self.module == "format" and read_source == None):
            self.arg_parser.print_help()

        module = ModuleHandler(self.module, self.module_args)
        module.execute_module()
