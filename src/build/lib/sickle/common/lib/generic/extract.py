# TODO: Consider renaming to read_from_file since this can be used by modules as well
def read_bytes_from_file(filename, mode="rb"):
    """This function is responsible for reading bytes from any file.

    :param filename: The file we are attempting to read from
    :type filename: str

    :param mode: The type of read operation we're going to be performing (e.g r, rb)
    "type mode: str

    :return: Raw bytecode
    :rtype: bytes
    """

    # Check if the object is bytes, we do this incase the user has read from stdin
    if (isinstance(filename, bytes)):
        return filename

    try:
        with open(filename, mode) as fd:
            all_bytes = fd.read()
        fd.close()
    except Exception as e:
        print(f"Error: {e}")
        return None

    return all_bytes
