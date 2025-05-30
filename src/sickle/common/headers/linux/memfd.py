# flags for memfd_create(2) (unsigned int)
MFD_CLOEXEC       = 0x0001
MFD_ALLOW_SEALING = 0x0002
MFD_HUGETLB       = 0x0004

# not executable and sealed to prevent changing to executable.
MFD_NOEXEC_SEAL   = 0x0008

# executable
MFD_EXEC          = 0x0010

