import os
import sys
import time
import socketserver

from sickle.common.lib.generic import modparser

time_start = time.time()

class SimpleTTYHandler(socketserver.StreamRequestHandler):

    def handle(self):

        log_print(f"Received connection from {self.client_address[0]}\n")

        while True:
            self.request.settimeout(0.1)

            response = b""
            while True:
                try:
                    data = self.request.recv(4096)
                except:
                    break

                response += data

            self.request.settimeout(30)

            shell_prompt = response.decode('latin-1')

            self.request.sendall(input(shell_prompt).encode('latin-1') + b'\n')

class Module():

    name = "Payload Session Handler"

    module = "handler"

    example_run = f"{sys.argv[0]} -m {module}"

    platform = "Multi"

    arch = "Multi"

    ring = 3

    author = ["wetw0rk"]

    tested_platforms = ["Linux", "Windows"]

    summary = ""

    description = ("")

    arguments = {}

    arguments["HANDLER"] = {}
    arguments["HANDLER"]["optional"] = "no"
    arguments["HANDLER"]["description"] = "Handler for incoming connections"
    arguments["HANDLER"]["options"] = { "tty": "Simple TTY handler similiar to netcat for capturing a shell" }

    arguments["SRVHOST"] = {}
    arguments["SRVHOST"]["optional"] = "yes"
    arguments["SRVHOST"]["description"] = "IP to bind handler to"
    
    arguments["SRVPORT"] = {}
    arguments["SRVPORT"]["optional"] = "yes"
    arguments["SRVPORT"]["description"] = "Port to bind handler to"

    def __init__(self, arg_object):
       
        self.arg_list  = arg_object["positional arguments"]
        self.shellcode = arg_object["raw bytes"]

        self.set_args()

    def set_args(self):

        argv_dict = modparser.argument_check(Module.arguments, self.arg_list)
        if (argv_dict == None):
            exit(-1)

        self.handler = argv_dict["HANDLER"]

        if "SRVHOST" not in argv_dict.keys():
            self.srvhost = "0.0.0.0"
        else:
            self.srvhost = argv_dict["SRVHOST"]

        if "SRVPORT" not in argv_dict.keys():
            self.srvport = 4242
        else:
            self.srvport = argv_dict["SRVPORT"]

    def do_thing(self):
        if self.handler == "tty":
            self.start_tty_handler()
        else:
            print(f"{self.handler} is not a valid handler")
            exit(-1)

    def start_tty_handler(self):

        self.start = time.time()
        with socketserver.TCPServer(("0.0.0.0", 4242), SimpleTTYHandler) as handler:
            log_print(f"SimpleTTYHandler started on {self.srvhost}:{self.srvport}")
            handler.serve_forever()

def log_print(msg):
        
    elapsed = time.time() - time_start
    print(f"[{elapsed:8.6f}] {msg}")
    
    return
