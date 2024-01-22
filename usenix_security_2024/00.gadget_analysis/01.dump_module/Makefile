obj-m += dump.o

all:
	# Normal
	make CC=clang LD=ld.lld -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	# KCFI
	#make CC=clang LD=ld.lld -C /lib/modules/6.1.27/build M=$(PWD) modules
	# FineIBT
	#make CC=clang LD=ld.lld -C /lib/modules/6.2.8/build M=$(PWD) modules
	gcc -o main main.c
clean:
	# Normal
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	# KCFI
	#make -C /lib/modules/6.1.27/build M=$(PWD) clean
	# FineIBT
	#make -C /lib/modules/6.2.8/build M=$(PWD) clean
	rm -f *.o
	rm -f dump.ko
	rm -f main
