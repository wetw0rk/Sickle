PROT_READ       = 0x1     # Page can be read.
PROT_WRITE      = 0x2     # Page can be written.
PROT_EXEC       = 0x4     # Page can be executed.
PROT_NONE       = 0x0     # Page can not be accessed.

PROT_GROWSDOWN  = 0x01000000  # Extend change to start of
                              # growsdown vma (mprotect only).

PROT_GROWSUP    = 0x02000000  # Extend change to start of
                              # growsup vma (mprotect only).

# Sharing types (must choose one and only one of these).
MAP_SHARED  = 0x01 # Share changes.
MAP_PRIVATE = 0x02 # Changes are private.

MAP_SHARED_VALIDATE = 0x03 # Share changes and validate
                           # extension flags.

MAP_DROPPABLE = 0x08 # Zero memory under memory pressure.
MAP_TYPE      = 0x0f # Mask for type of mapping.

# Other flags.
MAP_FIXED       = 0x10 # Interpret addr exactly.
MAP_FILE        = 0
MAP_ANONYMOUS   = 0x20 # Don't use a file.
