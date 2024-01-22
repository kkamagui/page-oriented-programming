#
# Makefile for Shadow-box module.
#
CONFIG_MODULE_SIG=n

obj-m = shadow_box.o 
#shadow_box-objs := mmu.o iommu.o shadow_watcher.o light_box.o asm.o 
shadow_box-objs := mmu.o shadow_watcher.o light_box.o asm.o 

KVERSION = $(shell uname -r)
# Disable function reorder
#ccflags-y := -fno-toplevel-reorder
#ccflags-y := -fcf-protection=branch

%.o: %.asm
	nasm -f elf64 -o $@ $^
	touch $(PWD)/.asm.o.cmd

all: 
	echo $(PWD)
	make CC=clang LD=ld.lld -C /lib/modules/$(KVERSION)/build M=$(PWD) modules 

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
