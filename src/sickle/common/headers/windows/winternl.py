import ctypes

from .ntdef import _LIST_ENTRY
from .ntdef import _UNICODE_STRING
from .ntdef import _RTL_BALANCED_NODE

from .winnt import _LARGE_INTEGER

from sickle.common.lib.reversing.smartarch import PTR

class _PEB(ctypes.Structure):
    _fields_ = [
        ("Reserved1",               ctypes.c_byte * 2),   # BYTE[2] 
        ("BeingDebugged",           ctypes.c_byte),       # BYTE
        ("Reserved2",               ctypes.c_byte * 1),   # BYTE[1]
        ("Reserved3",               PTR() * 2),           # PVOID[2] 
        ("Ldr",                     PTR()),               # PPEB_LDR_DATA
        ("ProcessParameters",       PTR()),               # PRTL_USER_PROCESS_PARAMETERS
        ("Reserved4",               PTR() * 3),           # PVOID[3]
        ("AtlThunkSListPtr",        PTR()),               # PVOID
        ("Reserved5",               PTR()),               # PVOID
        ("Reserved6",               ctypes.c_uint32),     # ULONG
        ("Reserved7",               PTR()),               # PVOID
        ("Reserved8",               ctypes.c_uint32),     # ULONG
        ("AtlThunkSListPtr32",      ctypes.c_uint32),     # ULONG
        ("Reserved9",               PTR() * 45),          # PVOID[45]
        ("Reserved10",              ctypes.c_byte * 96),  # BYTE[96]
        ("PostProcessInitRoutine",  PTR()),               # PPS_POST_PROCESS_INIT_ROUTINE 
        ("Reserved11",              ctypes.c_byte * 128), # BYTE[128]
        ("Reserved12",              PTR() * 1),           # PVOID[1]
        ("SessionId",               ctypes.c_uint32),     # ULONG
    ]

class _PEB_LDR_DATA(ctypes.Structure):
    _fields_ = [
        ("Length",                          ctypes.c_uint32), # ULONG
        ("Initialized",                     ctypes.c_ubyte),  # UCHAR
        ("SsHandle",                        PTR()),           # VOID*
        ("InLoadOrderModuleList",           _LIST_ENTRY),     # struct _LIST_ENTRY
        ("InMemoryOrderModuleList",         _LIST_ENTRY),     # struct _LIST_ENTRY
        ("InInitializationOrderModuleList", _LIST_ENTRY),     # struct _LIST_ENTRY
        ("EntryInProgress",                 PTR()),           # VOID*
        ("ShutdownInProgress",              ctypes.c_ubyte),  # UCHAR
        ("ShutdownThreadId",                PTR()),           # VOID*
    ]

class _LDR_DLL_LOAD_REASON(ctypes.c_int):
    LoadReasonStaticDependency           = 0
    LoadReasonStaticForwarderDependency  = 1
    LoadReasonDynamicForwarderDependency = 2
    LoadReasonDelayloadDependency        = 3
    LoadReasonDynamicLoad                = 4
    LoadReasonAsImageLoad                = 5
    LoadReasonAsDataLoad                 = 6
    LoadReasonUnknown                    = -1

class _LDR_DATA_TABLE_ENTRY(ctypes.Structure):
    _fields_ = [
        ("InLoadOrderLinks",            _LIST_ENTRY),          # struct _LIST_ENTRY
        ("InMemoryOrderLinks",          _LIST_ENTRY),          # struct _LIST_ENTRY
        ("InInitializationOrderLinks",  _LIST_ENTRY),          # struct _LIST_ENTRY
        ("DllBase",                     PTR()),                # VOID*
        ("EntryPoint",                  PTR()),                # VOID*
        ("SizeOfImage",                 ctypes.c_uint32),      # ULONG
        ("FullDllName",                 _UNICODE_STRING),      # UNICODE_STRING
        ("BaseDllName",                 _UNICODE_STRING),      # UNICODE_STRING
        ("Flags",                       ctypes.c_uint32),      # ULONG
        ("LoadCount",                   ctypes.c_int16),       # SHORT
        ("TlsIndex",                    ctypes.c_int16),       # SHORT
        ("HashLinks",                   _LIST_ENTRY),          # struct _LIST_ENTRY
        ("TimeDateStamp",               ctypes.c_uint32),      # ULONG
        ("ActivationContext",           PTR()),                # HANDLE
        ("Lock",                        PTR()),                # VOID*
        ("DdagNode",                    PTR()),                # LDR_DDAG_NODE*
        ("NodeModuleLink",              _LIST_ENTRY),          # LIST_ENTRY
        ("LoadContext",                 PTR()),                # struct _LDRP_LOAD_CONTEXT *
        ("ParentDllBase",               PTR()),                # VOID*
        ("SwitchBackContext",           PTR()),                # VOID*
        ("BaseAddressIndexNode",        _RTL_BALANCED_NODE),   # RTL_BALANCED_NODE
        ("MappingInfoIndexNode",        _RTL_BALANCED_NODE),   # RTL_BALANCED_NODE
        ("OriginalBase",                PTR()),                # ULONG_PTR
        ("LoadTime",                    _LARGE_INTEGER),       # LARGE_INTEGER
        ("BaseNameHashValue",           ctypes.c_uint32),      # ULONG
        ("LoadReason",                  _LDR_DLL_LOAD_REASON), # LDR_DLL_LOAD_REASON
        ("ImplicitPathOptions",         ctypes.c_uint32),      # ULONG
        ("ReferenceCount",              ctypes.c_uint32),      # ULONG
    ]
