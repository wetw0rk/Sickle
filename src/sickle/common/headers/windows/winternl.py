import ctypes

from .ntdef import _LIST_ENTRY
from .ntdef import _UNICODE_STRING
from .ntdef import _RTL_BALANCED_NODE

from .winnt import _LARGE_INTEGER
from .winnt import _ULARGE_INTEGER

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
        ("ProcessParameters",               PTR()),             # RTL_USER_PROCESS_PARAMETERS *
        ("SubSystemData",                   PTR()),             # PVOID
        ("ProcessHeap",                     PTR()),             # HANDLE
        ("FastPebLock",                     PTR()),             # PRTL_CRITICAL_SECTION
        ("AtlThunkSListPtr",                PTR()),             # PVOID
        ("IFEOKey",                         PTR()),             # PVOID
        ("CrossProcessFlags",               ctypes.c_uint32),   # ULONG (technically this is a union)
        ("Padding1",                        ctypes.c_ubyte * 4), # UCHAR[4]
        ("KernelCallbackTable",             PTR()),             # KERNEL_CALLBACK_PROC *
        ("Reserved",                        ctypes.c_uint32),   # ULONG
        ("AtlThunkSListPtr32",              ctypes.c_uint32),   # ULONG
        ("ApiSetMap",                       PTR()),             # PVOID
        ("TlsExpansionCounter",             ctypes.c_uint32),   # ULONG
        ("TlsBitmap",                       PTR()),             # PRTL_BITMAP
        ("TlsBitmapBits",                   ctypes.c_uint32 * 2), # ULONG [2]
        ("ReadOnlySharedMemoryBase",        PTR()),             # PVOID
        ("SharedData",                      PTR()),             # PVOID
        ("ReadOnlyStaticServerData",        PTR()),             # PVOID*
        ("AnsiCodePageData",                PTR()),             # PVOID
        ("OemCodePageData",                 PTR()),             # PVOID
        ("UnicodeCaseTableData",            PTR()),             # PVOID
        ("NumberOfProcessors",              ctypes.c_uint32),   # ULONG
        ("NtGlobalFlag",                    ctypes.c_uint32),   # ULONG
        ("CriticalSectionTimeout",          _LARGE_INTEGER),    # LARGE_INTEGER
        ("HeapSegmentReserve",              PTR()),             # SIZE_T
        ("HeapSegmentCommit",               PTR()),             # SIZE_T
        ("HeapDeCommitTotalFreeThreshold",  PTR()),             # SIZE_T
        ("HeapDeCommitFreeBlockThreshold",  PTR()),             # SIZE_T
        ("NumberOfHeaps",                   ctypes.c_uint32),   # ULONG
        ("MaximumNumberOfHeaps",            ctypes.c_uint32),   # ULONG
        ("ProcessHeaps",                    PTR()),             # PVOID
        ("GdiSharedHandleTable",            PTR()),             # PVOID
        ("ProcessStarterHelper",            PTR()),             # PVOID
        ("GdiDCAttributeList",              PTR()),             # PVOID
        ("LoaderLock",                      PTR()),             # PVOID
        ("OSMajorVersion",                  ctypes.c_uint32),   # ULONG
        ("OSMinorVersion",                  ctypes.c_uint32),   # ULONG
        ("OSBuildNumber",                   ctypes.c_uint32),   # ULONG
        ("OSPlatformId",                    ctypes.c_uint32),   # ULONG
        ("ImageSubSystem",                  ctypes.c_uint32),   # ULONG
        ("ImageSubSystemMajorVersion",      ctypes.c_uint32),   # ULONG
        ("ImageSubSystemMinorVersion",      ctypes.c_uint32),   # ULONG
        ("ActiveProcessAffinityMask",       PTR()),             # KAFFINITY
    ]

    if (ctypes.sizeof(PTR()) == 0x08):
        _fields_.append(("GdiHandleBuffer[60]", ctypes.c_uint32 * 60)), # ULONG
    else:
        _fields_.append(("GdiHandleBuffer", ctypes.c_uint32 * 34)), # ULONG

    _fields_ += [
        ("PostProcessInitRoutine",                  PTR()),                 # PVOID
        ("TlsExpansionBitmap",                      PTR()),                 # PRTL_BITMAP
        ("TlsExpansionBitmapBits",                  ctypes.c_uint32 * 32),  # ULONG [32]
        ("SessionId",                               ctypes.c_uint32),       # ULONG
        ("AppCompatFlags",                          _ULARGE_INTEGER),       # ULARGE_INTEGER
        ("AppCompatFlagsUser",                      _ULARGE_INTEGER),       # ULARGE_INTEGER
        ("ShimData",                                PTR()),                 # PVOID
        ("AppCompatInfo",                           PTR()),                 # PVOID
        ("CSDVersion",                              _UNICODE_STRING),       # UNICODE_STRING
        ("ActivationContextData",                   PTR()),                 # PVOID
        ("ProcessAssemblyStorageMap",               PTR()),                 # PVOID
        ("SystemDefaultActivationData",             PTR()),                 # PVOID
        ("SystemAssemblyStorageMap",                PTR()),                 # PVOID
        ("MinimumStackCommit",                      PTR()),                 # SIZE_T
        ("FlsCallback",                             PTR()),                 # PVOID
        ("FlsListHead",                             _LIST_ENTRY),           # LIST_ENTRY
        ("TracingFlags",                            PTR()),                 # (technically a union)
        ("FlsBitmapBits",                           ctypes.c_uint32 * 4),   # ULONG [4]
        ("FlsHighIndex",                            ctypes.c_uint32),       # ULONG
        ("WerRegistrationData",                     PTR()),                 # PVOID
        ("WerShipAssertPtr",                        PTR()),                 # PVOID
        ("EcCodeBitMap",                            PTR()),                 # PVOID
        ("pImageHeaderHash",                        PTR()),                 # PVOID
        ("TracingFlags2",                           ctypes.c_uint32),       # (technically a union)
        ("Padding6",                                ctypes.c_ubyte * 4),    # UCHAR [4]
        ("CsrServerReadOnlySharedMemoryBase",       ctypes.c_uint64),       # ULONGLONG
        ("TppWorkerpListLock",                      ctypes.c_uint64),       # ULONGLONG
        ("TppWorkerpList",                          _LIST_ENTRY),           # LIST_ENTRY
        ("WaitOnAddressHashTable",                  PTR() * 128),           # PVOID [128]
        ("TelemetryCoverageHeader",                 PTR()),                 # PVOID
        ("CloudFileFlags",                          ctypes.c_uint32),       # ULONG
        ("CloudFileDiagFlags",                      ctypes.c_uint32),       # ULONG
        ("PlaceholderCompatibilityMode",            ctypes.c_ubyte),        # CHAR
        ("PlaceholderCompatibilityModeReserved",    ctypes.c_ubyte),        # CHAR
        ("LeapSecondData",                          PTR()),                 # PVOID
        ("LeapSecondFlags",                         ctypes.c_uint32),       # ULONG
        ("NtGlobalFlag2",                           ctypes.c_uint32),       # ULONG
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
