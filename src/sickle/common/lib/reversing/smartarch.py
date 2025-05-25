import ctypes

USE_64BIT = True

def PTR():
    """Returns a ctypes pointer object depending on the architecture being used by
    the current shellcode stub.

    :return: ctypes class representitive of the pointer size for its respective
        architecture.
    :rtype: ctypes class
    """

    if USE_64BIT == True:
        return ctypes.c_uint64
    else:
        return ctypes.c_uint32

def set_arch(arch):
    """Sets the USE_64BIT global variable to True. This is necessary to ensure that
    structure offsets are generated based on the target architecture.

    :param arch: The name of the payload (contains arch in name)
    :type arch: str

    :return: Nothing it sets the global variable
    :rtype: None
    """

    global USE_64BIT

    if ("64" in arch):
        USE_64BIT = True
    else:
        USE_64BIT = False

    return
