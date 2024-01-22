/**
 *                   Page-Oriented Programming (POP)
 *                   -------------------------------
 *
 *                   Copyright (C) 2023 Seunghun Han
 *                 at the Affiliated Institute of ETRI
 * Project link: https://github.com/kkamagui/page-oriented-programming 
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <linux/cred.h>
#include <linux/hugetlb.h>
#include <asm/io.h>
#include <asm/page_64.h>
#include <asm/tlbflush.h>
#include <asm/fsgsbase.h>
#include <linux/delay.h>

int in_use = 0;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("root");
MODULE_VERSION("1.0");
MODULE_DESCRIPTION("CFI");

// Function define
#define CFI_IOCTL_DUMP				0x101

/**
 *	Open handler
 */
static int dump_open(struct inode *inode, struct file *file)
{
    if(in_use)
    {
        return -EBUSY;
    }

    in_use++;
    printk(KERN_INFO "Dump Open\n");

    return 0;
}

/**
 *	Close handler
 */    
static int dump_release(struct inode *inode, struct file *file)
{
    in_use--;
    printk(KERN_INFO "Dump driver ends...\n");

    return 0;
}

/**
 * 	IOCTL handler
 */
static long dump_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
#define KERN_START 	0xffffffff81000000
// KCFI 6.1.27 ubuntu
//#define KERN_END 	0xffffffff8220224f
// KCFI 6.1.27 default
//#define KERN_END 	0xffffffff8220330f
// FINE_IBT 6.2.8 ubuntu
//#define KERN_END 	0xffffffff82400000
// FINE_IBT 6.2.8 default
#define KERN_END 	0xffffffff82200000

    int retval = 0;
	static unsigned long cur = KERN_START;
    
	printk(KERN_INFO "dump: IOCTRL cmd %d, arg %lX\n", cmd, arg);

	switch(cmd)
	{
		case CFI_IOCTL_DUMP:
			if (cur < KERN_END)
			{
				printk(KERN_INFO "dump: address %08lX\n", cur);
				retval = copy_to_user((void __user*) arg, (unsigned long*)cur, 0x1000);
				cur += 0x1000;
			}
			else
			{
				retval = -1;
			}
			break;
	}

    return retval;
}

/**
 * 	Read handler.
 */
static ssize_t dump_read(struct file *filp, char *buffer, size_t length, loff_t *offset)
{
    printk (KERN_INFO "CFI Read~!!.\n");
    return 0;
}

/**
 * 	Write handler.
 */
static ssize_t dump_write(struct file *filp, const char *buff, size_t len, loff_t *off)
{
    printk (KERN_INFO "CFI Write~!!.\n");
    return -EINVAL;
}

/**
 *  File operation structure for /dev/dump.
 */
static const struct file_operations cfi_fops = \
{
    .owner = THIS_MODULE,
    .open = &dump_open,
    .read = &dump_read,
    .write = &dump_write,
    .release = &dump_release,
    .unlocked_ioctl = (void*) &dump_ioctl,
    .compat_ioctl = (void*) &dump_ioctl
};

/**
 *  Device structure for the /dev/dump file.
 */
static struct miscdevice my_device = \
{
    MISC_DYNAMIC_MINOR,
    "dump",
    &cfi_fops
};

/**
 * Initialize.
 */
static int __init dump_init(void)
{
    int retval;
    printk(KERN_INFO "Dump driver starts...\n");    
    retval = misc_register(&my_device);

    return retval;
}

/**
 *	Finalize.
 */
static void __exit dump_exit(void)
{   
    printk(KERN_INFO "Dump driver ends...\n");
    misc_deregister(&my_device);
}

module_init(dump_init);
module_exit(dump_exit); 
