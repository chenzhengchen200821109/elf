#
#

all: plt host 

plt: plt.c
	gcc -g -std=c99 -o plt plt.c -nostdlib

host: host.c
	gcc -o host host.c

clean:
	rm -rf plt a.out host 
