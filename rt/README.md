# 在main函数执行之前发生什么？
我们可以先看一张流程图:
!(https://raw.githubusercontent.com/chenzhengchen200821109/elf/master/rt/rt0.png)
NOTE:gcc 4.7以下版本下才有__do_global_ctors_aux，而4.7及以上版本  
已经使用__init_array_start替代
## 1. _start函数 
```
 080482f0 <_start>:
  80482f0:   31 ed                   xor    %ebp,%ebp
  80482f2:   5e                      pop    %esi
  80482f3:   89 e1                   mov    %esp,%ecx
  80482f5:   83 e4 f0                and    $0xfffffff0,%esp
  80482f8:   50                      push   %eax
  80482f9:   54                      push   %esp
  80482fa:   52                      push   %edx
  80482fb:   68 70 84 04 08          push   $0x8048470
  8048300:   68 00 84 04 08          push   $0x8048400
  8048305:   51                      push   %ecx
  8048306:   56                      push   %esi
  8048307:   68 ed 83 04 08          push   $0x80483ed
  804830c:   e8 cf ff ff ff          call   80482e0 <__libc_start_main@plt>
  8048311:   f4                      hlt
  8048312:   66 90                   xchg   %ax,%ax
  8048314:   66 90                   xchg   %ax,%ax
  8048316:   66 90                   xchg   %ax,%ax
  8048318:   66 90                   xchg   %ax,%ax
  804831a:   66 90                   xchg   %ax,%ax
  804831c:   66 90                   xchg   %ax,%ax
  804831e:   66 90                   xchg   %ax,%ax
```
1.初始化寄存器%ebp，这是由ABI所规定的。
2.由于在_start之前，OS将argc，argv及envp入栈，因此寄存器%esi保存argc。
3.同理，寄存器%ecx保存argv。此时%esp指向argv。
4.使%esp保持16字节对齐。
5.接下来为调用__libc_start_main作准备。

## 2. __libc_start_main函数
首先看一下__libc_start_main函数的原型。
```
int __libc_start_main( int (*main)(int, char**, char**),
                       int argc, char ** ubp_av,
                       void (*init)(void),
                       void (*finit)(void),
                       void (*rtld_fini)(void),
                       void (*stack_end));
```
value | __libc_start_main arg | 含义
----- | --------------------- | ----
%eax | 占位 | 维持栈平衡
%esp | void（*stack_end) | Our aligned stack pointer.
%edx | void (*rtld_fini)(void) | Destructor of dynamic linker from loader passed in %edx(_dl_fini函数). 
0x8048570 | void (*fini)(void) | __libc_csu_fini - Destructor of this program.
0x8048400 | void (*init)(void) | __libc_csu_init, Constructor of this program.
%ecx | char** ubp_av | argv off of the stack.
%esi | argc | argc off of the stack.
0x80483ed | int (*main)(int, char**, char**) | main of our program called by __libc_start_main.

经过动态连接器(dynamic linker)解析后确定的__libc_start_main函数最终地址。此函数主要作用为:
(1)安全审查
(2)设置线程
(3)调用at_exit注册fini和rtld_fini函数
```
/* Register the destructor of the program, if any.  */
  if (fini)
    __cxa_atexit ((void (*) (void *)) fini, NULL, NULL);
```
```
/* Register the destructor of the dynamic linker if there is any.  */
  if (__builtin_expect (rtld_fini != NULL, 1))
    __cxa_atexit ((void (*) (void *)) rtld_fini, NULL, NULL);
```
(4)调用init函数
```
if (init)
    (*init) (argc, argv, __environ MAIN_AUXVEC_PARAM);
```
实际上是调用__libc_csu_init函数。
```
void
__libc_csu_init (int argc, char **argv, char **envp)
{
  /* For dynamically linked executables the preinit array is executed by
     the dynamic linker (before initializing any shared object).  */

#ifndef LIBC_NONSHARED
  /* For static executables, preinit happens right before init.  */
  {
    const size_t size = __preinit_array_end - __preinit_array_start;
    size_t i;
    for (i = 0; i < size; i++)
      (*__preinit_array_start [i]) (argc, argv, envp);
  }
#endif

#ifndef NO_INITFINI
  _init ();
#endif

  const size_t size = __init_array_end - __init_array_start;
  for (size_t i = 0; i < size; i++)
      (*__init_array_start [i]) (argc, argv, envp);
}
```
其中**_init()函数由编译器gcc定义**。
```
08049000 <_init>:
 8049000:	53                   	push   %ebx
 8049001:	83 ec 08             	sub    $0x8,%esp
 8049004:	e8 87 00 00 00       	call   8049090 <__x86.get_pc_thunk.bx>
 8049009:	81 c3 f7 2f 00 00    	add    $0x2ff7,%ebx
 804900f:	8b 83 fc ff ff ff    	mov    -0x4(%ebx),%eax
 8049015:	85 c0                	test   %eax,%eax
 8049017:	74 05                	je     804901e <_init+0x1e>
 8049019:	e8 32 00 00 00       	call   8049050 <__gmon_start__@plt>
 804901e:	83 c4 08             	add    $0x8,%esp
 8049021:	5b                   	pop    %ebx
 8049022:	c3                   	ret    

```
__gmon_start()函数用来profiling。  
现在我们来看看C++中全局对象的构造。由以下代码完成。
```
  const size_t size = __init_array_end - __init_array_start;
  for (size_t i = 0; i < size; i++)
      (*__init_array_start [i]) (argc, argv, envp);
```
其中__init_array_end和__init_array_start由linker提供。
(5)调用main函数
```
/* Run the program.  */
      result = main (argc, argv, __environ MAIN_AUXVEC_PARAM);
```
(6)调用exit函数
```
exit (result);
```

## 总结
一个程序的正常运行是编译器，标准库及操作系统共同作用的结果。
