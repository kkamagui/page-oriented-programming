obj-m += cve_driver.o

all:
	make CC=clang LD=ld.lld -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f *.o
	rm -f *.ko
