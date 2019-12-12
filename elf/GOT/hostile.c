#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>

//恶意代码
#define _write(fd, buf, size)              \
({                                         \
    long __ret;                            \
                                           \
    __asm__ volatile                       \
    (                                      \
        "int $0x80"                        \
        : "=a"(__ret)                      \
        : "0" (__NR_write), "b" (fd),      \
          "c" (buf), "d" (size)            \
    );                                     \
                                           \
    __ret;                                 \
})

void evilprnt()
{
    __asm__ volatile
    (
        "pusha"
    );


    char buf[8];
    buf[0] = 'h'; 
    buf[1] = 'o';
    buf[2] = 'o';
    buf[3] = 'k';
    buf[4] = 'e';
    buf[5] = 'd';
    buf[6] = '\n';
    buf[7] = '\0';
    
    
    _write(STDIN_FILENO, buf, sizeof(buf));

    
    __asm__ volatile
    (
        "popa"
    );
    
    __asm__ volatile
    (
        "addl $0x10, %esp       \n\t"
        "pop %ebx               \n\t"
        "pop %ebp               \n\t"
        "movl $0xaabbccdd, %eax \n\t"
        "jmp  *%eax             \n\t"
    );

    //tag用来标记line 54处的地址
    __asm__ volatile
    (
        ".byte 0xbe, 0xba, 0xfe, 0xca \n\t"
    );
}
