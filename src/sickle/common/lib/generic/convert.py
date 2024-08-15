import struct
import socket
import binascii

def from_hex_to_raw(line):
    """This function is responsible for converting a hex string into raw bytes.

    :param line: A string containing hex opcodes, e.g '414141'
    :type line: str

    :return: Raw bytecode from a user provided hex string
    :rtype: bytes
    """

    return binascii.unhexlify(line)

def from_hex_to_escape(line, opcode_escape):
    """This functions returns a string of bytes escaped via the user provided hex string.

    :param line: A single string containing hex opcodes, e.g '414141'
    :type line: str

    :param opcode_escape: The escape sequence for each opcode in the hex string, e.g '0x'
    :type opcode_escape: str

    :return: A string containing escaped bytes, e.g from '41' to '0x41'
    :rtype: str
    """

    fmt_str = ""
    for i in range(0, len(line), 2):
        if (opcode_escape != None):
            fmt_str += opcode_escape
        fmt_str += line[i:i+2]

    return fmt_str

def from_raw_to_escaped(raw_bytes):
    """This function will convert raw bytes into a fixed escaped format. This was
    created as this is a common format.

    :param raw_bytes: Raw bytes object
    :type raw_bytes: bytes

    :return: A string containing escaped bytes, e.g b'\xff\xff' -> "\\xff\\xff"
    :rtype: str
    """

    escaped_bytes = ""
    for i in range(len(raw_bytes)):
        escaped_bytes += "\\x{:02x}".format(raw_bytes[i])
    return escaped_bytes

def ip_str_to_inet_addr(ip):
    return struct.unpack('<L', (socket.inet_aton(ip)))[0]

def port_str_to_htons(port):
    return socket.htons(int(port))
