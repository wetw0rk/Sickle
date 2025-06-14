# Flags for mremap.
MREMAP_MAYMOVE    = 1
MREMAP_FIXED      = 2
MREMAP_DONTUNMAP  = 4

# Flags for memfd_create.
MFD_CLOEXEC       = 1
MFD_ALLOW_SEALING = 2
MFD_HUGETLB       = 4
MFD_NOEXEC_SEAL   = 8
MFD_EXEC          = 0x10

# Flags for mlock2.
MLOCK_ONFAULT     = 1

# Access restrictions for pkey_alloc.
PKEY_DISABLE_ACCESS = 0x1
PKEY_DISABLE_WRITE  = 0x2
