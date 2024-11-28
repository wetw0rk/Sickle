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

def from_str_to_win_hash(function_name):
    """ This function will convert a string into the proper hash format used by most
    Windows shellcode(s) when attempting to search for a function.

    :param function_name: The name of the function to convert into a hash
    :type function_name: str
    """
    
    bits = 32
    count = 0xD
    int_hash = 0x00
    mask = 0xFFFFFFFF
    for i in range(len(function_name)):
        int_hash += ord(function_name[i]) & mask
        if (i < len(function_name)-1):
            int_hash = ((int_hash >> count) | (int_hash << (bits - count))) & mask # ROR
    hashed = hex(int_hash)

    return hashed
