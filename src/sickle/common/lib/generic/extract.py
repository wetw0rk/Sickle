import os
import sys

def read_bytes_from_file(filename):
    """This function is responsible for reading bytes from any file.

    :param filename: The file we are attempting to read from
    :type filename: str

    :return: Raw bytecode
    :rtype: bytes
    """

    # Check if the object is bytes, we do this incase the user has read from stdin
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
