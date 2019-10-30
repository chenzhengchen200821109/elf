//使用汇编语言所能创建的最简单的程序(链接标准库)
//gcc -Wall tiny.S, 大小为15368字节
//gcc -Wall -s tiny.S, 大小为13768字节, 去除了.symtab和.strtab节

.global main
.section .text
main:
    movl $42, %eax
    ret
