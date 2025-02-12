section .text
    global _start

_start:
    xor rax, rax         ; Limpia rax
    push rax             ; NULL terminator
    mov rdi, 0x68732f6e69622f2f ; "//bin/sh" en hexadecimal
    push rdi
    mov rdi, rsp         ; Apunta rdi a "/bin//sh"
    xor rsi, rsi         ; argv = NULL
    xor rdx, rdx         ; envp = NULL
    mov rax, 59          ; syscall execve (59 en 64 bits)
    syscall              ; Llamada al kernel
