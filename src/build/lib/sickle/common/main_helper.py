import argparse

def parser():
    """This function is responsible for parsing the user provided arguments via the argparse
    library. Upon completion the object containing said arguments is returned.
    
    return: Parsed arguments
    rtype: argparse.ArgumentParser
    """

    formatter = lambda prog: argparse.HelpFormatter(prog, max_help_position=52)
    parser = argparse.ArgumentParser(description="Sickle - Payload development framework",
                                     formatter_class=formatter,
                                     add_help=False)

    parser.add_argument("pargs", nargs="*", help=argparse.SUPPRESS)
    parser.add_argument("-h", "--help", action='help', default=argparse.SUPPRESS, help="Show this help message and exit")
    parser.add_argument("-r", "--read", help="Read bytes from binary file (use - for stdin)")
    parser.add_argument("-p", "--payload", help="Shellcode to use")
    parser.add_argument("-f", "--format", default='c', type=str, help="Output format (--list for more info)")
    parser.add_argument("-m", "--module", default="format", help="Development module")
    parser.add_argument("-a", "--arch", default="x64", type=str, help="Select architecture for disassembly")
    parser.add_argument("-b", "--badchars", help="Bad characters to avoid in shellcode")
    parser.add_argument("-v", "--varname",  default='buf', type=str, help="Alternative variable name")
    parser.add_argument("-i", "--info", help="Print detailed info for module or payload", action="store_true")
    parser.add_argument("-l", "--list", help="List available formats, payloads, or modules",  action="store_true")

    return parser
