##
# References:
#   https://github.com/wine-mirror/wine/blob/1d1e5fb3e51b2acb0143e86c16463dfed1bc90aa/include/windef.h
#
##

import enum
import ctypes

MAX_PATH = 260

# The SIZE structure
class _SIZE(ctypes.Structure):
    _fields_ = [
        ("cx", ctypes.c_int32), # LONG
        ("cy", ctypes.c_int32), # LONG
    ]

# The POINT structure
class _POINT(ctypes.Structure):
    _fields_ = [
        ("x", ctypes.c_int32), # LONG
        ("y", ctypes.c_int32), # LONG
    ]

class _POINTL(ctypes.Structure):
    _fields_ = [
        ("x", ctypes.c_int32), # LONG
        ("y", ctypes.c_int32), # LONG
    ]

# The POINTS structure

class _POINTS(ctypes.Structure):
    _fields_ = [
        ("x", ctypes.c_int16), # SHORT
        ("y", ctypes.c_int16), # SHORT
    ]

# The RECT structure
class _RECT(ctypes.Structure):
    _fields_ = [
        ("left",   ctypes.c_int32), # LONG
        ("top",    ctypes.c_int32), # LONG
        ("right",  ctypes.c_int32), # LONG
        ("bottom", ctypes.c_int32), # LONG
    ]

class _RECTL(ctypes.Structure):
    _fields_ = [
        "left",     ctypes.c_int32), # LONG
        "top",      ctypes.c_int32), # LONG
        "right",    ctypes.c_int32), # LONG
        "bottom",   ctypes.c_int32), # LONG
    ]

class _APP_LOCAL_DEVICE_ID(ctypes.Structure):
    _fields_ = [
        ("value", ctypes.c_byte * 32), # BYTE[32]
    ]

# DPI awareness
class _DPI_AWARENESS(enum.IntEnum):
    DPI_AWARENESS_INVALID = -1
    DPI_AWARENESS_UNAWARE = 0
    DPI_AWARENESS_SYSTEM_AWARE = 1
    DPI_AWARENESS_PER_MONITOR_AWARE = 2

class _DPI_HOSTING_BEHAVIOR(enum.IntEnum):
  DPI_HOSTING_BEHAVIOR_INVALID = -1
  DPI_HOSTING_BEHAVIOR_DEFAULT = 0
  DPI_HOSTING_BEHAVIOR_MIXED = 1
