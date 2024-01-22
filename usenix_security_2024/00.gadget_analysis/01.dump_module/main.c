/**
 *                   Page-Oriented Programming (POP)
 *                   -------------------------------
 *
 *                   Copyright (C) 2023 Seunghun Han
 *                 at the Affiliated Institute of ETRI
 * Project link: https://github.com/kkamagui/page-oriented-programming 
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>

// IOCTL for dump kernel memory
#define CFI_IOCTL_DUMP 0x101

/**
 * Main
 */
int main(int argc, char** argv)
{
    int fd_driver, fd_dump;
	unsigned long i = 0;
	int fail = 0;
	int ret = 0;
	unsigned char buffer[0x1000];

	printf("Open driver ...\n");

	fd_driver = open("/dev/dump", O_RDONLY);
	fd_dump = open("vmlinux_dump.bin", O_WRONLY | O_CREAT);

	while(1)
	{
		printf("[0x%08X] dump...\n", i);	
		ret = ioctl(fd_driver, CFI_IOCTL_DUMP, buffer);
		if (ret != 0)
		{
			break;
		}
		write(fd_dump, buffer, 0x1000);
		i += 0x1000;
	}

	close(fd_driver);
	close(fd_dump);

	return 0;
}
