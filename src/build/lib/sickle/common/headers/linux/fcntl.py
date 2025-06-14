# Values for the second argument to access.
# These may be OR'd together.
R_OK = 4 # Test for read permission.
W_OK = 2 # Test for write permission.
X_OK = 1 # Test for execute permission.
F_OK = 0 # Test for existence.

# XPG wants the following symbols.
SEEK_SET = 0 # Seek from beginning of file.
SEEK_CUR = 1 # Seek from current position.
SEEK_END = 2 # Seek from end of file.

# The constants AT_REMOVEDIR and AT_EACCESS have the same value.  AT_EACCESS
# is meaningful only to faccessat, while AT_REMOVEDIR is meaningful only to
# unlinkat.  The two functions do completely different things and therefore,
# the flags can be allowed to overlap.  For example, passing AT_REMOVEDIR to
# faccessat would be undefined behavior and thus treating it equivalent to
# AT_EACCESS is valid undefined behavior.

AT_FDCWD = -100 # Special value used to indicate
                # the *at functions should use the
                # current working directory.

AT_SYMLINK_NOFOLLOW = 0x100 # Do not follow symbolic links.

AT_REMOVEDIR = 0x200 # Remove directory instead of
                     # unlinking file.

AT_SYMLINK_FOLLOW = 0x400 # Follow symbolic links.

AT_NO_AUTOMOUNT = 0x800 # Suppress terminal automount
                        # traversal.

AT_EMPTY_PATH = 0x1000 # Allow empty relative pathname.
AT_STATX_SYNC_TYPE = 0x6000
AT_STATX_SYNC_AS_STAT = 0x0000
AT_STATX_FORCE_SYNC = 0x2000
AT_STATX_DONT_SYNC = 0x4000
AT_RECURSIVE = 0x8000 # Apply to the entire subtree.

AT_EACCESS = 0x200 # Test access permitted for
                   # effective IDs, not real IDs.

