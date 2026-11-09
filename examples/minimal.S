# A freestanding entry with no dependency on an unspecified OS syscall ABI.
# Replace the pause loop with your OS startup/exit implementation for real apps.
.global _start
.text
_start:
    mov value(%rip), %eax
    add zero_area(%rip), %eax
1:
    pause
    jmp 1b

.data
value:
    .long 42

.bss
.balign 16
zero_area:
    .skip 8192

.section .note.GNU-stack,"",@progbits
