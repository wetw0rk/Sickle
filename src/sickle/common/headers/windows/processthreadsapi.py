import ctypes

from sickle.common.lib.reversing.smartarch import PTR

STARTF_USESTDHANDLES = 0x00000100

class _STARTUPINFOA(ctypes.Structure):
    _fields_ = [
        ("cb",              ctypes.c_int32),
        ("lpReserved",      PTR()),
        ("lpDesktop",       PTR()),
        ("lpTitle",         PTR()),
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
        ("lpReserved2",     PTR()),
        ("hStdInput",       PTR()),
        ("hStdOutput",      PTR()),
        ("hStdError",       PTR()),
    ]
