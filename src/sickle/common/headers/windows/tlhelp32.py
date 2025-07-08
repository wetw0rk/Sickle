import ctypes

from .windef import MAX_PATH

from sickle.common.lib.reversing.smartarch import get_ptr

# CreateToolhelp32Snapshot

TH32CS_SNAPHEAPLIST = 0x00000001
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPTHREAD = 0x00000004
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPALL = (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE)
TH32CS_INHERIT = 0x80000000

# TODO: finish

class _PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",               ctypes.c_int32),              # DWORD
        ("cntUsage",             ctypes.c_int32),              # DWORD
        ("th32ProcessID",        ctypes.c_int32),              # DWORD
        ("th32DefaultHeapID",    get_ptr()),                   # ULONG_PTR
        ("th32ModuleID",         ctypes.c_int32),              # DWORD
        ("cntThreads",           ctypes.c_int32),              # DWORD
        ("th32ParentProcessID",  ctypes.c_int32),              # DWORD
        ("pcPriClassBase",       ctypes.c_int32),              # LONG
        ("dwFlags",              ctypes.c_int32),              # DWORD
        ("szExeFile",            ctypes.c_ubyte * MAX_PATH),   # char[MAX_PATH]
    ]
