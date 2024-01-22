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

// Module information
MODULE_LICENSE("GPL");
MODULE_AUTHOR("root");
MODULE_VERSION("1.0");
MODULE_DESCRIPTION("Lost Control Driver");

// ======================================================
// Porting CVE-2013-2595

#define MSM_MEM_MMAP		0

// Port to 64bit
struct msm_mem_map_info {
	//uint32_t cookie;
	//uint32_t length;
	//uint32_t mem_type;
	uint64_t cookie;
	uint64_t length;
	uint64_t mem_type;
};

struct msm_cam_config_dev {
	//struct cdev config_cdev;
	//struct v4l2_queue_util config_stat_event_queue;
	//int use_count;
	/*struct msm_isp_ops* isp_subdev;*/
	//struct msm_cam_media_controller *p_mctl;
	struct msm_mem_map_info mem_map;
};

struct msm_cam_config_dev g_config_cam;
// ======================================================

// Function defines and variables
unsigned long cve_vaddr_to_paddr(struct mm_struct* mm, unsigned long vaddr);
int cve_exploit_vulnerability(void);
int cve_prepare_exploit(void);
void cve_prepare_tlb_flush(void);
unsigned long gs_base = 0x00;
void cve_disable_calls_in_commit_creds(void);

typedef struct page_modification
{
	unsigned long src_addr; 	// Address of source function
	unsigned long dst_addr;		// Address of destination function
	unsigned long bak_addr;		// Backup physical address of destination function
} PAGE_MOD;

PAGE_MOD page_mod_list[] =
{
	// Source, Target, Backup
	// ffff88846f600000, 31b40
	{0x31b40, 0x3bbb40, 0}, 	// Move: gs_base + pcpu_hot -> pcpu_hot <+ 0x38a000>
	{0xffffffff811253b0, 0xffffffff814af3b0, 0}, 	// Move: commit_creds() -> commit_creds() <+ 0x38a000>
	{0xffffffff846178a8, 0xffffffff849a18a8, 0},	// Move: suid_dumpable -> suid_dumpable variable <+ 0x38a000>
	{0xffffffff81a23c60, 0xffffffff81806c60, 0},	// Replace with nop: NOP gadget -> set_dumpable() <+ 0x38a000> 
	{0xffffffff811296c0, 0xffffffff814b36c0, 0},	// Move: inc_rlimit_ucounts() and del_rlimit_ucounts() -> inc_rlimit_ucounts() <+ 0x38a000> 
	{0xffffffff8164fba0, 0xffffffff819d9ba0, 0},	// Move: key_fsuid_changed() and key_fsgid_changed() -> key_fsuid_changed() and key_fsgid_changed() <+ 0x38a000>
	{0xffffffff81428ed0, 0xffffffff81e4bed0, 0},	// Replace with nop: NOP gadget -> proc_id_connector <+ 0x38a000>
	{0xffffffff82056a80, 0xffffffff81536a80, 0},	// Replace with nop: NOP gadget -> call_rcu <+ 0x38a000>
};

// Function pointer for debugging
typedef void* (*f_text_poke) (void *addr, const void *opcode, size_t len);
f_text_poke new_text_poke = (f_text_poke) 0x0;

struct cred* new_cred;
struct mm_struct* mm;
pgd_t* old_pgd;
int g_alloc_index = 0;
int in_use = 0;

// For debugging
#define GET_FREE_PAGE_DEBUG 		0
#define FLUSH_FORCE_DEBUG			0

// 16GB target
//#define RAM_SIZE					((unsigned long)14 * 1024 * 1024 * 1024)
#define RAM_SIZE					((unsigned long)16 * 1024 * 1024 * 1024)
// 8GB target(HP EliteDesk)
//#define RAM_SIZE					((unsigned long)8 * 1024 * 1024 * 1024)

#define POP_INFO 					KERN_INFO "POP: " 

#define MSM_CAM_IOCTL_MAGIC 'm'
#define MSM_CAM_IOCTL_SET_MEM_MAP_INFO			\
	_IOR(MSM_CAM_IOCTL_MAGIC, 41, struct msm_mem_map_info *)


/**
 *	Reset free page.
 */
void cve_reset_free_page(void)
{
	g_alloc_index = 0;
}

/**
 *	Get free page.
 *		get pages from the end of the RAM.
 */
void* cve_get_free_page(void)
{
	unsigned long addr;

#if GET_FREE_PAGE_DEBUG
	addr = (unsigned long)__get_free_page(GFP_KERNEL | __GFP_ZERO);
#else
	addr = page_offset_base + ((RAM_SIZE / PAGE_SIZE) - 0x1000) - (g_alloc_index * PAGE_SIZE);
	g_alloc_index++;
#endif
	printk(POP_INFO"   [*] cve_get_free_page: VA: %016lx, PA: %016lx is allocated\n", addr, virt_to_phys((void*)addr));
	return (void*) addr;
}

/**
 *	Handler for opening the /dev/cve_config0 file.
 */
static int cve_open(struct inode *inode, struct file *file)
{
    if(in_use)
    {
        return -EBUSY;
    }

    in_use++;
    printk(POP_INFO "Open function is called.\n");

    return 0;
}

/**
 *	Handler for closing the /dev/cve_config0 file.
 */    
static int cve_release(struct inode *inode, struct file *file)
{
    in_use--;
    printk(POP_INFO "Close function is called.\n");

    return 0;
}

/**
 *	Handler for I/O controls of the /dev/cve_config0 file.
 */
static long cve_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int retval = 0;
	uint64_t* p = 0;
	int i;

    printk(POP_INFO "IOCTRL cmd %d, arg %lx\n", cmd, arg);

	switch(cmd)
	{
		// Porting CVE-2013-2595
		case MSM_CAM_IOCTL_SET_MEM_MAP_INFO:
			printk(POP_INFO "MSM_CAM_IOCTL_SET_MEM_MAP_INFO is called.\n");

			// Porting CVE-2013-2595
			//if (copy_from_user(&config_cam->mem_map, (void __user *)arg, sizeof(struct_msm_mem_map_info)))
			if (copy_from_user(&(g_config_cam.mem_map), (void __user *)arg, sizeof(struct msm_mem_map_info)))
				retval = -EINVAL;

			break;
	}

    return retval;
}

/**
 *	Handler for reading the /dev/cve_config0 file.
 */
static ssize_t cve_read(struct file *filp, char *buffer, size_t length, loff_t *offset)
{
    printk (POP_INFO "Read function is called.\n");
    return 0;
}

/**
 *	Handler for writing the /dev/cve_config0 file.
 */
static ssize_t cve_write(struct file *filp, const char *buff, size_t len, loff_t *off)
{
    printk (POP_INFO "Writing function is called\n");
    return -EINVAL;
}

/**
 *	Porting CVE-2013-2595.
 */
static int msm_mmap_config(struct file *fp, struct vm_area_struct *vma)
{
	// Porting CVE-2013-2595
	//struct msm_cam_config_dev *config_cam = fp->private_data;
	struct msm_cam_config_dev *config_cam = &g_config_cam;
	int rc = 0;
	int phyaddr;
	int retval;
	unsigned long size;

	printk(POP_INFO "%s is called!!", __func__);
	printk(POP_INFO "%s: phy_addr=0x%lx", __func__, config_cam->mem_map.cookie);
	phyaddr = (int)config_cam->mem_map.cookie;
	if (!phyaddr) {
		pr_err("%s: no physical memory to map", __func__);
		return -EFAULT;
	}

	memset(&config_cam->mem_map, 0,
		sizeof(struct msm_mem_map_info));

	size = vma->vm_end - vma->vm_start;
	printk(POP_INFO "%s: vm_start %lx, vm_end %lx, size %lx", 
			__func__, vma->vm_start, vma->vm_end, size);
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	retval = remap_pfn_range(vma, vma->vm_start,
					phyaddr >> PAGE_SHIFT,
					size, vma->vm_page_prot);
	if (retval) {
		pr_err("%s: remap failed, rc = %d",
					__func__, retval);
		rc = -ENOMEM;
		goto end;
	}

	printk(POP_INFO "%s: phy_addr=0x%x: %08lx-%08lx, pgoff %08lx\n",
			__func__, (uint32_t)phyaddr,
			vma->vm_start, vma->vm_end, vma->vm_pgoff);
end:
	return rc;
}

/**
 *  File operation structure to register /dev/cve_config0.
 */
static const struct file_operations cve_fops = \
{
    .owner = THIS_MODULE,
    .open = &cve_open,
    .read = &cve_read,
    .write = &cve_write,
    .release = &cve_release,
    .unlocked_ioctl = (void*) &cve_ioctl,
    .compat_ioctl = (void*) &cve_ioctl,
	// Porting CVE-2013-2595
	.mmap = msm_mmap_config
};

/**
 *  Device structure to register /dev/cve_config0.
 */
static struct miscdevice my_device = \
{
    MISC_DYNAMIC_MINOR,
    "cve_config0",
    &cve_fops
};

/**
 * 	Start function of this driver.
 */
static int __init cve_init(void)
{
	struct cred* init_cred;
	unsigned long text_start = 0xffffffff81000000;
	//unsigned long data_end = text_start + 0x2378640; // <== until the end of .data section

	printk(POP_INFO "\n\n\n");
    printk(POP_INFO "CVE-2013-2595 driver starts.\n");
    int retval;

    retval = misc_register(&my_device);

	// Get gs_base from __per_cpu_offset.
	gs_base = __per_cpu_offset[0];

	printk(POP_INFO"   [*] PG5 enabled: %d, PGDR_SHIFT: %d\n", pgtable_l5_enabled(), pgdir_shift);
	printk(POP_INFO"   [*] dynamic physical_mask %016lX\n", physical_mask);
	printk(POP_INFO"   [*] GS_Base of CPU 0: %08lx\n", __per_cpu_offset[0]);
	init_cred = (struct cred*)init_task.real_cred;
	printk(POP_INFO"   [*] Init task: %016lx, cred: %016lx, uid: %d, euid: %d\n", 
		&init_task, init_cred, init_cred->uid, init_cred->euid);
	printk(POP_INFO"   [*] current_real_cred: %016lx, non_rcu: %d\n", 
		current->real_cred, current->real_cred->non_rcu);
	printk(POP_INFO"   [*] Direct mapping area: %016lx\n", page_offset_base);
	printk(POP_INFO"   [*] physical addr of _text: %016lx\n", virt_to_phys((void*)text_start));

	//printk(POP_INFO"   [*] Dump_text:");
	//print_hex_dump(KERN_INFO, "", DUMP_PREFIX_OFFSET, 16, 1, (void *)text_start, 32, 1);

#if 0
	// This means that kernel text and data have sequential physical pages.
	printk(POP_INFO"   [*] Check Physical pages... from start of the text to the end of the data\n");
	for(i = text_start ; i <= data_end ; i += 1000)
	{
		cur = virt_to_phys((void*)i);
		if ((prev == 0) && (cur != 0))
		{
			prev = cur;
			printk(POP_INFO" %016lX is %016lX\n", i, cur);
		}

		if ((cur - prev) > 0x1000)
		{
			printk(POP_INFO" %016lX is %016lX, %016lX is %016lX\n",
					i - 0x1000, prev, i, cur);
		}
		prev = cur;
	}
	printk(POP_INFO" %016lX is %016lX\n", i, cur);

	printk(POP_INFO"===================================\n");
	printk(POP_INFO"Check offset\n");
	printk(POP_INFO"tasks offset in task struct: %d, real_cred offset in task struct: %d, comm offset in task struct: %d\n", 
			offsetof(struct task_struct, tasks), offsetof(struct task_struct, real_cred), offsetof(struct task_struct, comm));
	printk(POP_INFO"mm offset in task struct: %d, pgd offset in mm struct: %d\n", 
			offsetof(struct task_struct, mm), offsetof(struct mm_struct, pgd));
	printk(POP_INFO"thread_keyring offset in cred struct: %d\n", offsetof(struct cred, thread_keyring));

	printk(POP_INFO"Check task structure\n");
	printk(POP_INFO"Init task %016lX, mm %016lX, tasks->next %016lX", &init_task, init_task.mm, init_task.tasks.next);
	printk(POP_INFO"===================================\n");
	
	for (p = next_task(&init_task) ; p!= &init_task ; p = next_task(p))
	{
		if (p->mm != NULL)
		{
			printk(POP_INFO"task %016lX, pgd %016lX (%016lX)", p, p->mm->pgd, (unsigned long)virt_to_phys(p->mm->pgd));
		}
		else
		{
			printk(POP_INFO"task %016lX, pgd NULL", p);
		}

		if ((((unsigned long)p) & 0xFFFFFFFFF) != ((unsigned long)virt_to_phys(p)))
		{
			printk(POP_INFO"%016lX %016lX %s\n", p, virt_to_phys(p), p->comm);
		}
	}
#endif

#if FLUSH_FORCE_DEBUG
	__flush_tlb_all();
#endif

    return 0;
}

/**
 * 	Exit function of this driver.
 */
static void __exit cve_exit(void)
{   
    printk(POP_INFO "CVE-2013-2595 driver ends.\n");    
    misc_deregister(&my_device);
}

module_init(cve_init);
module_exit(cve_exit); 
