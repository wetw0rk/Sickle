##
# References:
# 
#   https://github.com/wine-mirror/wine/blob/4a7d6576f0a8507097e3894a579061b568db6ac6/include/ntdef.h
#   https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_unicode_string
#   https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-list_entry
#   https://www.vergiliusproject.com/
#
##

import enum
import ctypes

from sickle.common.lib.reversing.smartarch import get_ptr

class _EVENT_TYPE(enum.IntEnum):
    NotificationEvent = 0
    SynchronizationEvent = 1

class _TIMER_TYPE(enum.IntEnum):
    NotificationTimer = 0
    SynchronizationTimer = 1

class _WAIT_TYPE(enum.IntEnum):
    WaitAll = 0
    WaitAny = 1
    WaitNotification = 2

class _RTL_BALANCED_NODE(ctypes.Structure):
    class _CHILDREN_UNION(ctypes.Union):
        class _DUMMYSTRUCTNAME(ctypes.Structure):
            _fields_ = [
                ("Left", get_ptr()),  # struct _RTL_BALANCED_NODE *Left
                ("Right", get_ptr()), # struct _RTL_BALANCED_NODE *Right
            ]
        _fields_ = [
            ("Children", get_ptr() * 2),           # struct _RTL_BALANCED_NODE *Children[2]
            ("DUMMYSTRUCTNAME", _DUMMYSTRUCTNAME),
        ]

    class _BALANCE_UNION(ctypes.Union):
        _fields_ = [
            ("ParentValue", ctypes.c_size_t), # ULONGLONG ParentValue
            ("_bitfield", ctypes.c_ubyte),    # struct { UCHAR Red:1; UCHAR Balance:2; }
        ]

    _anonymous_ = ("DUMMYUNIONNAME", "DUMMYUNIONNAME2")
    _fields_ = [
        ("DUMMYUNIONNAME", _CHILDREN_UNION),
        ("DUMMYUNIONNAME2", _BALANCE_UNION),
    ]

class _RTL_RB_TREE(ctypes.Structure):
    _fields_ = [
        ("root", get_ptr()), # RTL_BALANCED_NODE *root
        ("min", get_ptr()),  # RTL_BALANCED_NODE *min
    ]

class _LIST_ENTRY(ctypes.Structure):
    _fields_ = [
        ("Flink", get_ptr()), # struct _LIST_ENTRY* Flink
        ("Blink", get_ptr()), # struct _LIST_ENTRY* Blink
    ]

class _UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length",          ctypes.c_uint16), # USHORT
        ("MaximumLength",   ctypes.c_uint16), # USHORT
        ("Buffer",          get_ptr()),       # PWSTR
    ]
