import math
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

def from_str_to_xwords(string, regs_limit=0x08):
    """This function will get a string and return the number of qwords, dwords,
    words, and bytes needed to create said string. Each X-WORD will be formatted
    in big endain. This is used by shellcode stubs that need to push the string
    onto the stack or simply store it within registers. By default the
    regs_limit is set to a QWORD (8 bytes) however if the architecture only
    allows X bytes the regs_limit can be adjusted for X bytes. For example in
    x86 it would be set to four and the max returned would be a DWORD (4 bytes).

    :param string: The string to be converted into mutliple "xwords"
    :type string: str

    :param regs_limit: The MAX register size used by the architecture
    :type regs_limit: int

    :return: A dictionary containing Xwords that can be stored in registers
    :rtype: dict
    """

    len_of_str = len(string)
    written = len_of_str

    # Here we instantiate the max X-WORD that will be returned. By default
    # this is set to a QWORD. 
    count = {}
    sizes = {}
    lists = {}

    if regs_limit >= 0x08:
        count["QWORDS"] = 0x00
        sizes["QWORD_SIZE"] = 0x08
        lists["QWORD_LIST"] = []
    if regs_limit >= 0x04:
        count["DWORDS"] = 0x00
        sizes["DWORD_SIZE"] = 0x04
        lists["DWORD_LIST"] = []
    if regs_limit >= 0x02:
        count["WORDS"] = 0x00
        sizes["WORD_SIZE"] = 0x02
        lists["WORD_LIST"] = []
    if regs_limit >= 0x01:
        count["BYTES"] = 0x00
        sizes["BYTE_SIZE"] = 0x01
        lists["BYTE_LIST"] = []


    # Calculate the amount of each X-WORD needed to make the string. For example,
    # if a string is 11 bytes we would need 1 QWORD, 1 WORD and 1 BYTES. This is
    # then written to the count dictionary.
    for (count_type), (size_type) in zip(count.keys(), sizes.keys()):
        if (written != 0):
            count[count_type] = math.floor(written/sizes[size_type])
            written -= (count[count_type] * sizes[size_type])


    # Obtain the total number of bytes that will be written using the generated
    # X-WORDS.
    total_written = 0x00

    if regs_limit >= 0x08:
        total_written += (count["QWORDS"] * sizes["QWORD_SIZE"])
    if regs_limit >= 0x04:
        total_written += (count["DWORDS"] * sizes["DWORD_SIZE"])
    if regs_limit >= 0x02:
        total_written += (count["WORDS"] * sizes["WORD_SIZE"])
    if regs_limit >= 0x01:
        total_written += (count["BYTES"] * sizes["BYTE_SIZE"])
        
    # If our X-WORDS do not add up to the length of the string something went
    # wrong and we must exit since the shellcode will fail to create the string
    # needed.
    if (total_written != len_of_str):
        print(f"Failed to generate xword encoded format for {string}")
        exit(-1)

    # If everything went well a dictionary will be generated containing X-WORDS,
    # Example below:
    #
    # { 'DWORD_LIST': [1467167327, 858926692],
    #   'WORD_LIST': [27756], 'BYTE_LIST': [] }
    #
    tmp_str_name = string
    for count_type, size_type, list_type in zip(count.keys(), sizes.keys(), lists.keys()):
        for i in range(count[count_type]):
            byte_format = bytes(tmp_str_name[:sizes[size_type]], 'latin-1')
            big_int = int.from_bytes(byte_format, 'big')

            lists[list_type] += big_int,
            tmp_str_name = tmp_str_name[sizes[size_type]:]

    return lists
