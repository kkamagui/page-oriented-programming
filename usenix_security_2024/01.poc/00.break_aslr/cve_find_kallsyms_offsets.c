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
#include <fcntl.h>
#include <unistd.h>

/**
 *	Find the kallsyms offset from the vmlinux file.
 */
int find_kallsyms_offsets(void)
{
	int fd;
	int buffer[1024];
	int found = 0;
	int count = 0;
	int prev_value = 0;
	int read_size = 0;
	int i;
	int offset = 0;
	int detected = 0;
	int detected_offset = 0;

	fd = open("data/vmlinux.text_rodata", O_RDONLY);
	if (fd == -1)
	{
		printf("data/vmlinux.text_rodata is not found.\n");
	}

	while (read_size = read(fd, buffer, sizeof(buffer)))
	{
		for (i = 0 ; i < (read_size / 4) ; i++)
		{
			if (abs(buffer[i]) > prev_value)
			{
				//printf("count %d, prev %d, cur %d\n", count, prev_value, abs(buffer[i]));
				prev_value = abs(buffer[i]);
				detected = 1;
				if (detected_offset == 0)
				{
					detected_offset = offset;
				}
				count++;
			}
			else
			{
				prev_value = 0;
				detected_offset = 0;
				detected = 0;
				count = 0;
			}
			
			if (count > 256) 
			{
				found = 1;
				break;
			}

			offset += 4;
		}

		if (found == 1)
		{
			break;
		}
	}

	if (found == 0)
	{
		printf("kallsyms_offset is not detected.\n");
	}
	else
	{
		printf("kallsyms_offset is at 0x%016lX, maybe 0x%016lX is the start point.\n", detected_offset, detected_offset - 8);
	}

	close(fd);

	return detected_offset - 8;
}

/**
 * 	Dump symbol names from the /proc/kallsyms file and match them with kallsyms offsets.
 */
int dump_kallsyms_with_offset(int kallsyms_offset)
{
	int fd;
	int buffer[1024];
	int read_size;
	FILE *fp;
	size_t len = 0;
	char* line_buffer;
	int i;
	//unsigned long base_addr = 0xFFFFFFFF81000000;
	unsigned long base_addr = 0;

	fp = fopen("/proc/kallsyms", "r");
	if (fp == NULL)
	{
		return -1;
	}

	fd = open("data/vmlinux.text_rodata", O_RDONLY);
	if (fd == -1)
	{
		printf("data/vmlinux.text_rodata is not found\n");
		return -1;
	}

	if (lseek(fd, kallsyms_offset, SEEK_SET) == -1)
	{
		printf("lseek fail\n");
		return -1;
	}

	while (read_size = read(fd, buffer, sizeof(buffer)))
	{
		for (i = 0 ; i < (read_size / 4) ; i++)
		{
			if (buffer[i] < 0)
			{
				printf(" %016lX ", base_addr -buffer[i] - 1);
			}
			else
			{
				printf(" %016lX ", base_addr + buffer[i]);
			}

			if (getline(&line_buffer, &len, fp) == -1)
			{
				return 0;
			}

			printf(line_buffer);
		}
	}
	fclose(fp);
	close(fd);
}

int main(int argc, char* argv[])
{
	int kallsyms_offset;

	kallsyms_offset = find_kallsyms_offsets();
	dump_kallsyms_with_offset(kallsyms_offset);

	return 0;
}
