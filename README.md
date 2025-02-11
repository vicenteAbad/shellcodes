# Shellcodes

## 1. ¿Qué es un Shellcode?
Un **shellcode** es un fragmento de código en lenguaje ensamblador diseñado para ejecutarse dentro de un proceso objetivo. 
Se usa comúnmente en **exploits** para tomar el control de un sistema vulnerable.

Los shellcodes pueden ejecutarse en memoria sin necesidad de archivos, lo que los hace ideales para ataques como **buffer overflows** o **inyecciones de código**.

## 2. Tipos de Shellcodes
Existen diferentes tipos de shellcodes según el contexto de ataque:

- **Shellcodes de usuario**: Se ejecutan dentro de procesos de usuario sin privilegios elevados.
- **Shellcodes de kernel**: Se ejecutan en el espacio de kernel, lo que permite un control total del sistema.
- **Shellcodes conectados a red**:
  - **Reverse shell**: Se conecta a un servidor remoto y permite al atacante tomar el control.
  - **Bind shell**: Abre un puerto en la máquina víctima para que el atacante se conecte.

## 3. Características de un Buen Shellcode
Un shellcode efectivo debe cumplir con los siguientes criterios:

- **Pequeño**: Minimiza el tamaño para encajar en buffers pequeños.
- **Autocontenido**: No depende de librerías externas.
- **Evasivo**: Evita caracteres nulos (`\x00`) y detección por antivirus.
- **Portable**: Funciona en múltiples versiones del sistema operativo objetivo.

## 4. Creación de un Shellcode
Para crear un shellcode, se usa ensamblador y luego se convierte en una cadena de bytes. Por ejemplo, un shellcode en **x86 Linux** para ejecutar `/bin/sh`:

```assembly
section .text
    global _start

_start:
    xor eax, eax         ; Limpia eax
    push eax             ; NULL terminator
    push 0x68732f2f      ; "//sh"
    push 0x6e69622f      ; "/bin"
    mov ebx, esp         ; Apunta ebx a "/bin//sh"
    xor ecx, ecx         ; argv = NULL
    xor edx, edx         ; envp = NULL
    mov al, 0xb          ; syscall execve
    int 0x80             ; Llamada al kernel

