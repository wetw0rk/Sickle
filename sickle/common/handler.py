'''

handler: consider this the body, execution flow is generally directed here

'''

import os
import sys

from sickle.modules import *
from sickle.common.lib.formatting.formats import *

from sickle.common.lib.generic.extract import read_bytes_from_file
from sickle.common.lib.reversing.disassembler import Disassembler

class handle():

    def __init__(self, arg_parser):
        args = arg_parser.parse_args()

        self.arg_parser = arg_parser      # parser object used for help output
        self.binfile    = args.read       # read from binary file
        self.module     = args.module     # module to use on binfile
        self.list       = args.list       # list all formats / archs
        self.info       = args.info       # detailed info for module or payload

        # Setup arguments that are meant to be passed into a given module.. Please if you edit this
        # leave it in an order it looks nice or my OCD will go CRAZY xD
        self.module_args = {}
        self.module_args["format"] = args.format
        self.module_args["architecture"] = args.arch
        self.module_args["variable name"] = args.varname
        self.module_args["bad characters"] = args.badchars
        self.module_args["positional arguments"] = args.pargs
        
        # Variables not passed into modules but generated for other functions
        root_dir     = os.path.abspath(os.path.join(os.path.dirname( __file__ ), '..'))
        self.formats = self.get_modules("%s/common/lib/formatting/formats" % root_dir)
        self.modules = self.get_modules("%s/modules/" % root_dir)
        self.archs   = self.get_archs()

    ###
    # print_module_info:
    #   Obtain general information on a given module and exit. Consider this the "man" page parser to every
    #   module within sickle. This only applies to modules
    ###
    def print_module_info(self, module_name):
        print("\nUsage information for %s module\n" % (module_name))
        m = eval(module_name)

        ###
        # The description of the module overall
        ###
        print("\nDescription:\n")
        print(f"  {m.Module.description}\n")       

        ###
        # Information on each argument for a given module and what it does
        ###
        print("Argument Information:\n")

        mod_args = m.Module.arguments
        if (mod_args != None):
            print(f"  {'Argument Name':<20} {'Argument Description':<50} {'Optional'}")
            print(f"  {'-------------':<20} {'--------------------':<50} {'--------'}")
            
            for arg_name, _ in mod_args.items():
                optional = mod_args[arg_name]["optional"]
                description = mod_args[arg_name]["description"]
                print(f"  {arg_name:<20} {description:<50} {optional}")
            print("")

            print(f"Argument Options:\n")
            print(f"  {arg_name:<20} {'Option Description'}")
            print(f"  {('-' * (len(arg_name))):<20} {'------------------'}")
            supported_options = mod_args[arg_name]["options"]
            for opt, opt_desc in supported_options.items():
                print(f"  {opt:<20} {opt_desc}")
            print("")
        else:
            print(f"  The {module_name} module does not require arguments\n")

        print("Example:\n")
        print(f"   {m.Module.example_run}\n")

        exit(0)

    ###
    # get_modules: Obtain all modules in a given directory
    ###
    def get_modules(self, directory):
        _modules = os.listdir(directory)
        mod_list = []
        for i in range(len(_modules)):
            if "deps.py" in _modules[i] or ".pyc" in _modules[i] or "__" in _modules[i]:
                pass
            else:
                mod_list += _modules[i][:-3],

        return mod_list

    ###
    # get_archs: Gather all current supported architectures
    ###
    def get_archs(self):
        archs = []
        arch = Disassembler.get_cs_arch_modes()
        for k, v in arch.items():
            archs += k,
        return archs

    ###
    # print_supported: Pretty self explanitory, print supported modules, formats, and architectures
    ###
    def print_supported(self):

        module = []
        archs = []
   
        print(f"\n  {'Modules':<20}{'Description'}")
        print(f"  {'-------':<20}{'-----------'}") 
        for i in range(len(self.modules)):
            hook = eval(self.modules[i])
            module += f"  {hook.Module.module_name:<20}{hook.Module.description}",
        for i in range(len(module)):
            print(module[i])

        print(f"\n  {'Formats':<20}{'Description'}")
        print(f"  {'-------':<20}{'-----------'}")
        for i in range(len(self.formats)):
            format_module = eval(self.formats[i])
            print(f"  {self.formats[i]:<20}{format_module.FormatModule.description}")

        print(f"\n  Architectures")
        print(f"  -------------")
        archs = self.get_archs()
        for i in range(len(archs)):
            print(f"  {archs[i]}")

        exit(0)

    ###
    # check_args: Verify module, format, for architecture is supported
    ###
    def check_args(self):

        if self.module_args["format"] not in self.formats:
            sys.exit("Currently %s format is not supported" % (self.module_args["format"]))
        if self.module not in self.modules and self.module != None:
            sys.exit("Currently %s module is not supported" % (self.module))
        if self.module_args["architecture"] not in self.archs:
            sys.exit("Currently %s architecture is not supported" % (self.arch))

    def handle_args(self):

        self.check_args()

        if self.list == True:
            self.print_supported()
        elif self.info == True:
            self.print_module_info(self.module)

        if self.binfile:
            if self.binfile == '-':
                self.module_args["source"] = "stdin"
                self.binfile = sys.stdin.buffer.raw.read()
            else:
                self.module_args["source"] = self.binfile
                if os.path.isfile(self.binfile) is False:
                    sys.exit("Error dumping bytecode. Is file present?")

        # Set the raw/escaped objects, since most modules use them. If there is no input file it does
        # not mean the module won't expect the objects in the dictionary. For this reason we go ahead
        # and set them to NULL (None).
        if self.binfile:
            self.module_args["raw bytes"] = read_bytes_from_file(self.binfile)
            self.module_args["num bytes"] = len(self.module_args["raw bytes"])
        else:
            self.module_args["source"] = "NONE"
            self.module_args["raw bytes"] = None # NEW
            self.module_args["num bytes"] = None # New

        if self.module and self.binfile:
            module = eval(self.module).Module(self.module_args)
            module.do_thing()
        elif self.module != "format" and eval(self.module).Module.arguments == None:
            module = eval(self.module).Module(self.module_args)
            module.do_thing()
        else:
            self.arg_parser.print_help()
            exit(-1)
