from ctypes import c_int16
from ctypes import c_int32
from ctypes import Structure

from sickle.common.lib.reversing.smartarch import PTR

STARTF_USESTDHANDLES = 0x00000100

class _PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess",    PTR()),
        ("hThread",     PTR()),
        ("dwProcessId", c_int32),
        ("dwThreadId",  c_int32),
    ]

class _STARTUPINFOA(Structure):
    _fields_ = [
        ("cb",              c_int32),
        ("lpReserved",      PTR()),
        ("lpDesktop",       PTR()),
        ("lpTitle",         PTR()),
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
        ("lpReserved2",     PTR()),
        ("hStdInput",       PTR()),
        ("hStdOutput",      PTR()),
        ("hStdError",       PTR()),
    ]


