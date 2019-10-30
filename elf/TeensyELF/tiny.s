//使用汇编语言所能创建的最简单的程序(不要链接标准库)
//as -o tiny.o tiny.s && ld -o a.out tiny.o, 大小为4464字节
//  有.text, .symtab, .strtab, .shstrtab四个节区。
//strip a.out, 大小为4248字节, 有.text, .shstrtab二个节区。

.global _start
.section .text
_start:
    movl $1, %eax
    movl $42, %ebx
    int $0x80
