##
# References:
#
#   https://github.com/wine-mirror/wine/blob/1d1e5fb3e51b2acb0143e86c16463dfed1bc90aa/include/processthreadsapi.h
#   https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
#   https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information
#
##

import enum
import ctypes

from sickle.common.lib.reversing.smartarch import get_ptr

STARTF_USESTDHANDLES = 0x00000100

class _THREAD_INFORMATION_CLASS(enum.IntEnum):
    ThreadMemoryPriority = 0
    ThreadAbsoluteCpuPriority = 1
    ThreadDynamicCodePolicy = 2
    ThreadPowerThrottling = 3
    ThreadInformationClassMax = 4

class _MEMORY_PRIORITY_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("MemoryPriority", ctypes.c_uint32), # ULONG
    ]

class _THREAD_POWER_THROTTLING_STATE(ctypes.Structure):
    _fields_ = [
        ("Version",     ctypes.c_uint32), # ULONG
        ("ControlMask", ctypes.c_uint32), # ULONG
        ("StateMask",   ctypes.c_uint32), # ULONG
    ]

class _QUEUE_USER_APC_FLAGS(enum.IntEnum):
    QUEUE_USER_APC_FLAGS_NONE = 1
    QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC = 0x00000001
    QUEUE_USER_APC_CALLBACK_DATA_CONTEXT = 0x00010000

class _APC_CALLBACK_DATA(ctypes.Structure):
    _fields_ = [
        ("Parameter",     get_ptr()), # ULONG_PTR 
        ("ContextRecord", get_ptr()), # CONTEXT *
        ("Reserved0",     get_ptr()), # ULONG_PTR
        ("Reserved1",     get_ptr()), # ULONG_PTR
    ]

class _PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess",    get_ptr()),       # HANDLE
        ("hThread",     get_ptr()),       # HANDLE
        ("dwProcessId", ctypes.c_uint32), # DWORD
        ("dwThreadId",  ctypes.c_uint32), # DWORD
    ]

class _STARTUPINFOA(ctypes.Structure):
    _fields_ = [
        ("cb",              ctypes.c_uint32), # DWORD
        ("lpReserved",      get_ptr()),       # LPSTR
        ("lpDesktop",       get_ptr()),       # LPSTR
        ("lpTitle",         get_ptr()),       # LPSTR
        ("dwX",             ctypes.c_uint32), # DWORD
        ("dwY",             ctypes.c_uint32), # DWORD
        ("dwXSize",         ctypes.c_uint32), # DWORD
        ("dwYSize",         ctypes.c_uint32), # DWORD
        ("dwXCountChars",   ctypes.c_uint32), # DWORD
        ("dwYCountChars",   ctypes.c_uint32), # DWORD
        ("dwFillAttribute", ctypes.c_uint32), # DWORD
        ("dwFlags",         ctypes.c_uint32), # DWORD
        ("wShowWindow",     ctypes.c_int16),  # WORD
        ("cbReserved2",     ctypes.c_int16),  # WORD
        ("lpReserved2",     get_ptr()),       # LPBYTE
        ("hStdInput",       get_ptr()),       # HANDLE
        ("hStdOutput",      get_ptr()),       # HANDLE
        ("hStdError",       get_ptr()),       # HANDLE
    ]
