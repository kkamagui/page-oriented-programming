### Extract the data/vmlinux.text\_rodata file from the vmlinux file using the below command. 
```bash
objcopy -I elf64-little -j .text -j .rodata -O binary vmlinux vmlinux\_text\_rodata.bin
```
