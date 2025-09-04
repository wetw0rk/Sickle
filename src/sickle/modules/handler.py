import os
import sys
import ctypes

from ctypes import CDLL, c_char_p, c_void_p, memmove, cast, CFUNCTYPE

class Module():

    name = "TODO"

    module = "handler"

    example_run = f"{sys.argv[0]} -m {module} -r shellcode"

    platform = "Multi"

    arch = "Multi"

    ring = 3

    author = ["wetw0rk"]

    tested_platforms = ["Linux", "Windows"]

    summary = "TODO"

    description = ("TODO")

    arguments = None

    def __init__(self, arg_object):
        
        self.shellcode = arg_object["raw bytes"]

    def do_thing(self):
       print("TODO")

#    def tty_handler(self):


