import ctypes

USE_64BIT = True

def PTR():
    """Returns a ctypes pointer object depending on the architecture being used by
    the current shellcode stub.
    """

    if USE_64BIT == True:
        return ctypes.c_uint64
    else:
        return ctypes.c_uint32

def set_arch(arch):
    """Sets the USE_64BIT global variable to True. This is necessary to ensure that
    structure offsets are generated based on the target architecture.
    """

    global USE_64BIT

    if ("64" in arch):
        USE_64BIT = True
    else:
        USE_64BIT = False

    return True
