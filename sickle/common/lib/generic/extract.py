'''

extract: Functions related to extraction of bytes should go here

'''

import os
import sys

###
# read_bytes_from_file: Read bytes from a file, if we are reading from STDIN do no read - simply return.
###
def read_bytes_from_file(filename):
    if (isinstance(filename, bytes)):
        return filename

    try:
        with (open(filename, "rb") as fd):
            all_bytes = fd.read()
        fd.close()
    except Exception as e:
        print(f"Error: {e}")
        return None

    return all_bytes
