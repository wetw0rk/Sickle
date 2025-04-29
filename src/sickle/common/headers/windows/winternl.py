import ctypes

from .ntdef import _LIST_ENTRY
from .ntdef import _UNICODE_STRING
from .ntdef import _RTL_BALANCED_NODE

from .winnt import _LARGE_INTEGER

from sickle.common.lib.reversing.smartarch import PTR

class _PEB(ctypes.Structure):

    _fields_ = [
        ("InheritedAddressSpace",           ctypes.c_bool),     # BOOLEAN
        ("ReadImageFileExecOptions",        ctypes.c_bool),     # BOOLEAN
        ("BeingDebugged",                   ctypes.c_bool),     # BOOLEAN
        ("BitField",                        ctypes.c_ubyte),    # UCHAR (technically this is a union)
        ("Mutant",                          PTR()),             # HANDLE
        ("ImageBaseAddress",                PTR()),             # HMODULE
        ("Ldr",                             PTR()),             # PPEB_LDR_DATA
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
