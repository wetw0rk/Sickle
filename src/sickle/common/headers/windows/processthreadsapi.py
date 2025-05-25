from ctypes import c_int16
from ctypes import c_int32
from ctypes import Structure

from sickle.common.lib.reversing.smartarch import get_ptr

STARTF_USESTDHANDLES = 0x00000100

class _PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess",    get_ptr()),
        ("hThread",     get_ptr()),
        ("dwProcessId", c_int32),
        ("dwThreadId",  c_int32),
    ]

class _STARTUPINFOA(Structure):
    _fields_ = [
        ("cb",              c_int32),
        ("lpReserved",      get_ptr()),
        ("lpDesktop",       get_ptr()),
        ("lpTitle",         get_ptr()),
        ("dwX",             c_int32),
        ("dwY",             c_int32),
        ("dwXSize",         c_int32),
        ("dwYSize",         c_int32),
        ("dwXCountChars",   c_int32),
        ("dwYCountChars",   c_int32),
        ("dwFillAttribute", c_int32),
        ("dwFlags",         c_int32),
        ("wShowWindow",     c_int16),
        ("cbReserved2",     c_int16),
        ("lpReserved2",     get_ptr()),
        ("hStdInput",       get_ptr()),
        ("hStdOutput",      get_ptr()),
        ("hStdError",       get_ptr()),
    ]


