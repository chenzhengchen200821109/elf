# The PLT  

The Procedure Linkage Table is a table in which the various entries are made up of code blocks.   
It's the principal component which allows the dynamic linker to resolve external functions.   
Here's an example: suppose that you write a program which references a function defined inside a library:  
```
int main()
{
    int res = external_function(3,4);
    return 0;
}
```
Of course, to invoke the function, you need to know its absolute address, being an external one.   
The absolute address cannot be hardcoded by the linker, because usually libraries are loaded at   
different base addresses, so absolute addresses have no meaning for them. This situation is overcome   
by the use of the PLT, so when you call an external function, the following code is generated:
```
push 0x04
push 0x03
call external_function@plt
add esp, 8
```
[,..]  

; this is a PLT entry  
external_function@plt (address 0xXXXXXX00):  
  ; reloc_address is just a memory location  
  external_function@plt+0x00: jmp dword ptr [reloc_address]  
  ; reloc_offset is a byte offset (not an index) into the relocation table  
  external_function@plt+0x06: push reloc_offset  
  ; resolve_function is a function that will resolve the external symbol  
  external_function@plt+0x0B: jmp resolve_function  
  
; this is what you find at reloc_address, data is displayed using dwords  
reloc_address: XXXXXX06 ........  

What's happening here is that when the program reaches "call", it will transfer execution   
to a PLT entry. The first instruction executed then is a "jmp", which will transfer execution   
to the value contained in the location "reloc_address", which, as you can see, is the address   
of the instruction following the first "jmp" in the PLT entry. So, back again in the PLT,   
a byte offset is PUSHed into the stack, and then execution is transferred to a function which,   
taking out of the stack the last value pushed, will resolve the external symbol. By now, you   
might think that this procedure is painfully slow, with all those cache-killing jumps. But, 
let's go one step ahead and look at what's happening after the external symbol has been resolved:  
```
push 0x04
push 0x03
call external_function@plt
add esp, 8
```
[...]

external_function@plt:
    external_function@plt+0x00:  jmp dword ptr [reloc_address]
    external_function@plt+0x06:  push reloc_index
    external_function@plt+0x0B:  jmp  resolve_function
    
reloc_address: BFF31337 ........

Something has changed, hasn't it? After the external symbol has been resolved, the memory location  
addressed by "reloc_address" will not contain the address of the instruction following the first jmp,   
but will contain the actual entry point to the external function, so all the jmp-crazyness will be   
done only the first time. If you did not understand something, then read the manual carefully. The PLT   
is the most important thing in this two-part article, and the next part will deal much more with it,   
so be sure to know how it works. Anyway, by the end of this part, there will be a practical example   
using GDB on how the PLT works.
