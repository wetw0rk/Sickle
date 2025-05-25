import ctypes

using_64bit = True
arch_used   = None


def get_ptr():
    """Returns a ctypes pointer object depending on the architecture being used by
    the current shellcode stub.

    :return: ctypes class representitive of the pointer size for its respective
        architecture.
    :rtype: ctypes class
    """

    if using_64bit == True:
        return ctypes.c_uint64
    else:
        return ctypes.c_uint32

def set_arch(payload):
    """Sets the USE_64BIT global variable to True. This is necessary to ensure that
    structure offsets are generated based on the target architecture.

    :param payload: The name of the payload (contains arch in name)
    :type payload: str

    :return: Nothing it sets the global variable
    :rtype: None
    """

    global arch_used
    global using_64bit

    # All payloads in Sickle follow the same format so we can assume that index 2
    # will always contain the architecture. Since in the future other
    # architectures may have special needs in builder.py the arch used will also
    # be saved in a global variable.
    arch_used = payload.split('/')[1]

    if ("64" in arch_used):
        using_64bit = True
    else:
        using_64bit = False

    return
