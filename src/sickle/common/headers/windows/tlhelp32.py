##
# References:
#
#   https://github.com/wine-mirror/wine/blob/1d1e5fb3e51b2acb0143e86c16463dfed1bc90aa/include/tlhelp32.h
#
##

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

# thread entry list as created by CreateToolHelp32Snapshot

class _THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",              ctypes.c_uint32), # DWORD
        ("cntUsage",            ctypes.c_uint32), # DWORD
        ("th32ThreadID",        ctypes.c_uint32), # DWORD
        ("th32OwnerProcessID",  ctypes.c_uint32), # DWORD
        ("tpBasePri",           ctypes.c_int32),  # LONG 
        ("tpDeltaPri",          ctypes.c_int32),  # LONG 
        ("dwFlags",             ctypes.c_uint32)  # DWORD 
    ]

class _PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",               ctypes.c_uint32),             # DWORD
        ("cntUsage",             ctypes.c_uint32),             # DWORD
        ("th32ProcessID",        ctypes.c_uint32),             # DWORD
        ("th32DefaultHeapID",    get_ptr()),                   # ULONG_PTR
        ("th32ModuleID",         ctypes.c_uint32),             # DWORD
        ("cntThreads",           ctypes.c_uint32),             # DWORD
        ("th32ParentProcessID",  ctypes.c_uint32),             # DWORD
        ("pcPriClassBase",       ctypes.c_int32),              # LONG
        ("dwFlags",              ctypes.c_uint32),             # DWORD
        ("szExeFile",            ctypes.c_ubyte * MAX_PATH),   # char[MAX_PATH]
    ]

class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize",                        ctypes.c_uint32),           # DWORD
        ("cntUsage",                      ctypes.c_uint32),           # DWORD
        ("th32ProcessID",                 ctypes.c_uint32),           # DWORD
        ("th32DefaultHeapID",             get_ptr()),                 # ULONG_PTR 
        ("th32ModuleID",                  ctypes.c_uint32),           # DWORD
        ("cntThreads",                    ctypes.c_uint32),           # DWORD
        ("th32ParentProcessID",           ctypes.c_uint32),           # DWORD
        ("pcPriClassBase",                ctypes.c_int32),            # LONG
        ("dwFlags",                       ctypes.c_uint32),           # DWORD
        ("szExeFile",                     ctypes.c_wchar * MAX_PATH), # WCHAR[MAX_PATH]
    ]

# Module entry list created by CreateToolHelp32Snapshot

MAX_MODULE_NAME32 = 255

class _MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",       ctypes.c_uint32),                         # DWORD
        ("th32ModuleID", ctypes.c_uint32),                         # DWORD
        ("th32ProcessID",ctypes.c_uint32),                         # DWORD
        ("GlblcntUsage", ctypes.c_uint32),                         # DWORD
        ("ProccntUsage", ctypes.c_uint32),                         # DWORD
        ("modBaseAddr",  get_ptr()),                               # BYTE * 
        ("modBaseSize",  ctypes.c_uint32),                         # DWORD
        ("hModule",      get_ptr()),                               # HMODULE
        ("szModule",     ctypes.c_char * (MAX_MODULE_NAME32 + 1)), # char[MAX_MODULE_NAME32 + 1]
        ("szExePath",    ctypes.c_char * MAX_PATH),                # char[MAX_PATH]
    ]

class _MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize",       ctypes.c_uint32),                          # DWORD
        ("th32ModuleID", ctypes.c_uint32),                          # DWORD
        ("th32ProcessID",ctypes.c_uint32),                          # DWORD
        ("GlblcntUsage", ctypes.c_uint32),                          # DWORD
        ("ProccntUsage", ctypes.c_uint32),                          # DWORD
        ("modBaseAddr",  get_ptr()),                                # BYTE * 
        ("modBaseSize",  ctypes.c_uint32),                          # DWORD
        ("hModule",      get_ptr()),                                # HMODULE
        ("szModule",     ctypes.c_wchar * (MAX_MODULE_NAME32 + 1)), # WCHAR[MAX_MODULE_NAME32 + 1]
        ("szExePath",    ctypes.c_wchar * MAX_PATH),                # WCHAR[MAX_PATH]
    ]

class _HEAPLIST32(ctypes.Structure):
    _fields_ = [
        ("dwSize",        ctypes.c_size_t), # SIZE_T 
        ("th32ProcessID", ctypes.c_uint32), # DWORD
        ("th32HeapID",    get_ptr()),       # ULONG_PTR
        ("dwFlags",       ctypes.c_uint32), # DWORD
    ]

HF32_DEFAULT = 1
HF32_SHARED  = 2

class _HEAPENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",ctypes.c_size_t),        # SIZE_T 
        ("hHandle",get_ptr()),             # HANDLE 
        ("dwAddress",    get_ptr()),       # ULONG_PTR
        ("dwBlockSize",ctypes.c_size_t),   # SIZE_T 
        ("dwFlags",ctypes.c_uint32),       # DWORD
        ("dwLockCount",ctypes.c_uint32),   # DWORD
        ("dwResvd",ctypes.c_uint32),       # DWORD
        ("th32ProcessID",ctypes.c_uint32), # DWORD
        ("th32HeapID",    get_ptr()),      # ULONG_PTR
    ]
