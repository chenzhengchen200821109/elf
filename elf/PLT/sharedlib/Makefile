
#Compile and link it:

# gcc -fPIC -c libdummy.c
# --------------------------------------------------------------------------------
# ld -shared -soname libdummy.so.1 -o libdummy.so.1.0 -lc libdummy.o
# ld options explanation:
# 	-soname: When creating an ELF shared object, set the internal DT_SONAME
#            field to the specified name.  When an executable is linked with a
#            shared object which has a DT_SONAME field, then when the executable
#            is run the dynamic linker will attempt to load the shared object
#            specified by the DT_SONAME field rather than the using the file
#            name given to the linker.
#  	-o: output
#   -lc: link with libc.a (use `locate libc.a` to be sure that this library has been installed properly)
# ---------------------------------------------------------------------------------
# Now, let's update the cache with "ldconfig" (if you move the library to 
# /usr/lib or any other system path, you might remove the "-n ." parameter):
# ldconfig -v -n .
# ldconfig option explanation:
# 	-v: verbose mode
# 	-n: only process directories specified on the command line. Don't process the 
# 	    trusted directories (/lib and /usr/lib) nor those specified in /etc/ld.so.conf. 
# ---------------------------------------------------------------------------------
# and create the symbolic link needed by the linker, so we can link with "-ldummy":
# ln -sf libdummy.so.1 libdummy.so
#
# Don't forget to try to to see if everything worked (if you did not move libdummy.so.1.0 to /usr/lib, 
# you should set LD_LIBRARY_PATH: "export LD_LIBRARY_PATH=.:$LD_LIBRARY_PATH").

all: libdummy dummyelf

libdummy:
	gcc -fPIC -c libdummy.c 
	ld -shared -soname libdummy.so.1 -o libdummy.so.1.0 libdummy.o -L/usr/lib/i386-linux-gnu -lc
	ldconfig -v -n .
	ln -sf libdummy.so.1 libdummy.so   

dummyelf:
	gcc -o dummyelf dummyelf.c -L. -ldummy 
   
clean:
	rm -rf libdummy.o libdummy.so libdummy.so.1 libdummy.so.1.0
