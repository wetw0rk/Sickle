import ctypes

from .ntdef import _LIST_ENTRY
from .ntdef import _UNICODE_STRING
from .ntdef import _RTL_BALANCED_NODE

from .winnt import _LARGE_INTEGER
from .winnt import _ULARGE_INTEGER

from sickle.common.lib.reversing.smartarch import get_ptr

class _PEB(ctypes.Structure):

    _fields_ = [
        ("InheritedAddressSpace",           ctypes.c_bool),     # BOOLEAN
        ("ReadImageFileExecOptions",        ctypes.c_bool),     # BOOLEAN
        ("BeingDebugged",                   ctypes.c_bool),     # BOOLEAN
        ("BitField",                        ctypes.c_ubyte),    # UCHAR (technically this is a union)
        ("Mutant",                          get_ptr()),             # HANDLE
        ("ImageBaseAddress",                get_ptr()),             # HMODULE
        ("Ldr",                             get_ptr()),             # PPEB_LDR_DATA
        ("ProcessParameters",               get_ptr()),             # RTL_USER_PROCESS_PARAMETERS *
        ("SubSystemData",                   get_ptr()),             # PVOID
        ("ProcessHeap",                     get_ptr()),             # HANDLE
        ("FastPebLock",                     get_ptr()),             # PRTL_CRITICAL_SECTION
        ("AtlThunkSListPtr",                get_ptr()),             # PVOID
        ("IFEOKey",                         get_ptr()),             # PVOID
        ("CrossProcessFlags",               ctypes.c_uint32),   # ULONG (technically this is a union)
        ("Padding1",                        ctypes.c_ubyte * 4), # UCHAR[4]
        ("KernelCallbackTable",             get_ptr()),             # KERNEL_CALLBACK_PROC *
        ("Reserved",                        ctypes.c_uint32),   # ULONG
        ("AtlThunkSListPtr32",              ctypes.c_uint32),   # ULONG
        ("ApiSetMap",                       get_ptr()),             # PVOID
        ("TlsExpansionCounter",             ctypes.c_uint32),   # ULONG
        ("TlsBitmap",                       get_ptr()),             # PRTL_BITMAP
        ("TlsBitmapBits",                   ctypes.c_uint32 * 2), # ULONG [2]
        ("ReadOnlySharedMemoryBase",        get_ptr()),             # PVOID
        ("SharedData",                      get_ptr()),             # PVOID
        ("ReadOnlyStaticServerData",        get_ptr()),             # PVOID*
        ("AnsiCodePageData",                get_ptr()),             # PVOID
        ("OemCodePageData",                 get_ptr()),             # PVOID
        ("UnicodeCaseTableData",            get_ptr()),             # PVOID
        ("NumberOfProcessors",              ctypes.c_uint32),   # ULONG
        ("NtGlobalFlag",                    ctypes.c_uint32),   # ULONG
        ("CriticalSectionTimeout",          _LARGE_INTEGER),    # LARGE_INTEGER
        ("HeapSegmentReserve",              get_ptr()),             # SIZE_T
        ("HeapSegmentCommit",               get_ptr()),             # SIZE_T
        ("HeapDeCommitTotalFreeThreshold",  get_ptr()),             # SIZE_T
        ("HeapDeCommitFreeBlockThreshold",  get_ptr()),             # SIZE_T
        ("NumberOfHeaps",                   ctypes.c_uint32),   # ULONG
        ("MaximumNumberOfHeaps",            ctypes.c_uint32),   # ULONG
        ("ProcessHeaps",                    get_ptr()),             # PVOID
        ("GdiSharedHandleTable",            get_ptr()),             # PVOID
        ("ProcessStarterHelper",            get_ptr()),             # PVOID
        ("GdiDCAttributeList",              get_ptr()),             # PVOID
        ("LoaderLock",                      get_ptr()),             # PVOID
        ("OSMajorVersion",                  ctypes.c_uint32),   # ULONG
        ("OSMinorVersion",                  ctypes.c_uint32),   # ULONG
        ("OSBuildNumber",                   ctypes.c_uint32),   # ULONG
        ("OSPlatformId",                    ctypes.c_uint32),   # ULONG
        ("ImageSubSystem",                  ctypes.c_uint32),   # ULONG
        ("ImageSubSystemMajorVersion",      ctypes.c_uint32),   # ULONG
        ("ImageSubSystemMinorVersion",      ctypes.c_uint32),   # ULONG
        ("ActiveProcessAffinityMask",       get_ptr()),             # KAFFINITY
    ]

    if (ctypes.sizeof(get_ptr()) == 0x08):
        _fields_.append(("GdiHandleBuffer[60]", ctypes.c_uint32 * 60)), # ULONG
    else:
        _fields_.append(("GdiHandleBuffer", ctypes.c_uint32 * 34)), # ULONG

    _fields_ += [
        ("PostProcessInitRoutine",                  get_ptr()),                 # PVOID
        ("TlsExpansionBitmap",                      get_ptr()),                 # PRTL_BITMAP
        ("TlsExpansionBitmapBits",                  ctypes.c_uint32 * 32),  # ULONG [32]
        ("SessionId",                               ctypes.c_uint32),       # ULONG
        ("AppCompatFlags",                          _ULARGE_INTEGER),       # ULARGE_INTEGER
        ("AppCompatFlagsUser",                      _ULARGE_INTEGER),       # ULARGE_INTEGER
        ("ShimData",                                get_ptr()),                 # PVOID
        ("AppCompatInfo",                           get_ptr()),                 # PVOID
        ("CSDVersion",                              _UNICODE_STRING),       # UNICODE_STRING
        ("ActivationContextData",                   get_ptr()),                 # PVOID
        ("ProcessAssemblyStorageMap",               get_ptr()),                 # PVOID
        ("SystemDefaultActivationData",             get_ptr()),                 # PVOID
        ("SystemAssemblyStorageMap",                get_ptr()),                 # PVOID
        ("MinimumStackCommit",                      get_ptr()),                 # SIZE_T
        ("FlsCallback",                             get_ptr()),                 # PVOID
        ("FlsListHead",                             _LIST_ENTRY),           # LIST_ENTRY
        ("TracingFlags",                            get_ptr()),                 # (technically a union)
        ("FlsBitmapBits",                           ctypes.c_uint32 * 4),   # ULONG [4]
        ("FlsHighIndex",                            ctypes.c_uint32),       # ULONG
        ("WerRegistrationData",                     get_ptr()),                 # PVOID
        ("WerShipAssertPtr",                        get_ptr()),                 # PVOID
        ("EcCodeBitMap",                            get_ptr()),                 # PVOID
        ("pImageHeaderHash",                        get_ptr()),                 # PVOID
        ("TracingFlags2",                           ctypes.c_uint32),       # (technically a union)
        ("Padding6",                                ctypes.c_ubyte * 4),    # UCHAR [4]
        ("CsrServerReadOnlySharedMemoryBase",       ctypes.c_uint64),       # ULONGLONG
        ("TppWorkerpListLock",                      ctypes.c_uint64),       # ULONGLONG
        ("TppWorkerpList",                          _LIST_ENTRY),           # LIST_ENTRY
        ("WaitOnAddressHashTable",                  get_ptr() * 128),           # PVOID [128]
        ("TelemetryCoverageHeader",                 get_ptr()),                 # PVOID
        ("CloudFileFlags",                          ctypes.c_uint32),       # ULONG
        ("CloudFileDiagFlags",                      ctypes.c_uint32),       # ULONG
        ("PlaceholderCompatibilityMode",            ctypes.c_ubyte),        # CHAR
        ("PlaceholderCompatibilityModeReserved",    ctypes.c_ubyte),        # CHAR
        ("LeapSecondData",                          get_ptr()),                 # PVOID
        ("LeapSecondFlags",                         ctypes.c_uint32),       # ULONG
        ("NtGlobalFlag2",                           ctypes.c_uint32),       # ULONG
    ]

class _PEB_LDR_DATA(ctypes.Structure):
    _fields_ = [
        ("Length",                          ctypes.c_uint32), # ULONG
        ("Initialized",                     ctypes.c_ubyte),  # UCHAR
        ("SsHandle",                        get_ptr()),           # VOID*
        ("InLoadOrderModuleList",           _LIST_ENTRY),     # struct _LIST_ENTRY
        ("InMemoryOrderModuleList",         _LIST_ENTRY),     # struct _LIST_ENTRY
        ("InInitializationOrderModuleList", _LIST_ENTRY),     # struct _LIST_ENTRY
        ("EntryInProgress",                 get_ptr()),           # VOID*
        ("ShutdownInProgress",              ctypes.c_ubyte),  # UCHAR
        ("ShutdownThreadId",                get_ptr()),           # VOID*
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
        ("DllBase",                     get_ptr()),                # VOID*
        ("EntryPoint",                  get_ptr()),                # VOID*
        ("SizeOfImage",                 ctypes.c_uint32),      # ULONG
        ("FullDllName",                 _UNICODE_STRING),      # UNICODE_STRING
        ("BaseDllName",                 _UNICODE_STRING),      # UNICODE_STRING
        ("Flags",                       ctypes.c_uint32),      # ULONG
        ("LoadCount",                   ctypes.c_int16),       # SHORT
        ("TlsIndex",                    ctypes.c_int16),       # SHORT
        ("HashLinks",                   _LIST_ENTRY),          # struct _LIST_ENTRY
        ("TimeDateStamp",               ctypes.c_uint32),      # ULONG
        ("ActivationContext",           get_ptr()),                # HANDLE
        ("Lock",                        get_ptr()),                # VOID*
        ("DdagNode",                    get_ptr()),                # LDR_DDAG_NODE*
        ("NodeModuleLink",              _LIST_ENTRY),          # LIST_ENTRY
        ("LoadContext",                 get_ptr()),                # struct _LDRP_LOAD_CONTEXT *
        ("ParentDllBase",               get_ptr()),                # VOID*
        ("SwitchBackContext",           get_ptr()),                # VOID*
        ("BaseAddressIndexNode",        _RTL_BALANCED_NODE),   # RTL_BALANCED_NODE
        ("MappingInfoIndexNode",        _RTL_BALANCED_NODE),   # RTL_BALANCED_NODE
        ("OriginalBase",                get_ptr()),                # ULONG_PTR
        ("LoadTime",                    _LARGE_INTEGER),       # LARGE_INTEGER
        ("BaseNameHashValue",           ctypes.c_uint32),      # ULONG
        ("LoadReason",                  _LDR_DLL_LOAD_REASON), # LDR_DLL_LOAD_REASON
        ("ImplicitPathOptions",         ctypes.c_uint32),      # ULONG
        ("ReferenceCount",              ctypes.c_uint32),      # ULONG
    ]
