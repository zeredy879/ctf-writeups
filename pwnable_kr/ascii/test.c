#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

int main()
{
    void *code = mmap((void *)0x80000000, 0x1000, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code != (void *)0x80000000)
    {
        puts("mmap error!");
        exit(0);
    }
    read(0, code, 0x1000);
    (*(int (*)())code)();
}