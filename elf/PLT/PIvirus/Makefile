#CC= gcc
#CFLAGS= -nostdlib -nostartfiles -fPIC -fomit-frame-pointer
#ASM= nasm
#ASMFLAGS= -f elf64
#
#all: hostile pivirus
#
#hostile: hostile.s 
#	$(ASM) $(ASMFLAGS) -o hostile.o hostile.s
#
#pivirus: pivirus.c
#	$(CC) pivirus.c hostile.o $(CFLAGS) -o pivirus

all: plt

plt: plt.c 
	gcc -std=c99 plt.c -o plt -nostdlib

host: host.c
	gcc host.c -o host

clean:
	rm *.o
