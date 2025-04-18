import ctypes

STARTF_USESTDHANDLES = 0x00000100

class _STARTUPINFOA(ctypes.Structure):
    _fields_ = [
        ("cb",              ctypes.c_int32),
        ("lpReserved",      ctypes.c_void_p),
        ("lpDesktop",       ctypes.c_void_p),
        ("lpTitle",         ctypes.c_void_p),
        ("dwX",             ctypes.c_int32),
        ("dwY",             ctypes.c_int32),
        ("dwXSize",         ctypes.c_int32),
        ("dwYSize",         ctypes.c_int32),
        ("dwXCountChars",   ctypes.c_int32),
        ("dwYCountChars",   ctypes.c_int32),
        ("dwFillAttribute", ctypes.c_int32),
        ("dwFlags",         ctypes.c_int32),
        ("wShowWindow",     ctypes.c_int16),
        ("cbReserved2",     ctypes.c_int16),
        ("lpReserved2",     ctypes.POINTER(ctypes.c_byte)),
        ("hStdInput",       ctypes.c_void_p),
        ("hStdOutput",      ctypes.c_void_p),
        ("hStdError",       ctypes.c_void_p),
    ]
