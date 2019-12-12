got.bin: got.c
	gcc -std=c99 -g -o got.bin got.c

victim.bin: victim.c
	gcc -o victim.bin victim.c

hostile.so: hostile.c
	gcc83 -fPIC  -c hostile.c -nostdlib -o hostile.o
	ld -shared -o hostile.so hostile.o

build: got.bin victim.bin hostile.so

run_victim: build
	./victim.bin

run_infector: build
	sudo ./got.bin `pidof victim.bin` printf hostile.so

run_debug: build
	gdb got.bin

clean:
	rm -rf *.o *.bin *.so
