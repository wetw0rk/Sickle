'''

convert: Anything regarding conversion should be placed here

'''

import binascii

###
# hex_to_raw: Convert hex to raw bytes ("414141" -> b'\x41\x41\x41')
###
def from_hex_to_raw(line):
    return binascii.unhexlify(line)

###
# from_hex_to_escape: Convert hex to escape sequence ("414141" - > "\\x41\\x41\\x41")
###
def from_hex_to_escape(line, opcode_escape):
    fmt_str = ""
    for i in range(0, len(line), 2):
        if (opcode_escape != None):
            fmt_str += opcode_escape
        fmt_str += line[i:i+2]

    return fmt_str

###
# create_escaped_from_bytes: Convert raw bytes to escaped format (b'\xff\xfe' -> "\\xff\\xfe") 
###
def from_raw_to_escaped(raw_bytes):
    escaped_bytes = ""
    for i in range(len(raw_bytes)):
        escaped_bytes += "\\x{:02x}".format(raw_bytes[i])
    return escaped_bytes
