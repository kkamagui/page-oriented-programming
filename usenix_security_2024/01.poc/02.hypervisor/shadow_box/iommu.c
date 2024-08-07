/*
 *                          Shadow-Box
 *                         ------------
 *      Lightweight Hypervisor-Based Kernel Protector
 *
 *               Copyright (C) 2017 Seunghun Han
 */

/*
 * This software has GPL v2 license. See the GPL_LICENSE file.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/dmar.h>
//#include <linux/intel-iommu.h>
#include <linux/iommu.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/reboot.h>
#include <linux/smp.h>
#include <linux/version.h>
#include <asm/tlbflush.h>
#include <asm/io.h>
#include "shadow_box.h"
#include "mmu.h"
#include "iommu.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
#include <linux/vmalloc.h>
#endif

/*
 * Variables.
 */
struct sb_iommu_info g_iommu_info = {0, };
u32 g_entry_level = ENTRY_4LEVEL_PTE;

/*
 * Static functions.
 */
static void sb_wait_dmar_operation(u8* reg_remap_addr, int flag);
static int sb_need_intel_i915_workaround(void);
static int sb_is_intel_graphics_in(struct acpi_dmar_hardware_unit* drhd);
static acpi_status sb_get_acpi_dmar_table_header(struct acpi_table_dmar** dmar_ptr);
static int sb_alloc_iommu_pages_internal(u64 *array, int count);
static void sb_free_iommu_pages_internal(u64 *array, int count);

#if SHADOWBOX_USE_IOMMU_DEBUG
/*
 * Parse PTE.
 */
static void sb_parse_iommu_pte(u64 pte_addr)
{
	u8* remap_addr;
	u64 entry;
	int i;
	bool ioremap = true;

	remap_addr = (u8*)ioremap_uc(pte_addr & MASK_PAGEADDR, VTD_PAGE_SIZE);
	if (remap_addr == NULL)
	{
		ioremap = false;
		remap_addr = (u8*)phys_to_virt(pte_addr & MASK_PAGEADDR);
	}

	sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "                    [*] PTE value\n");

	for (i = 0 ; i < IOMMU_PAGE_ENT_COUNT ; i++)
	{
		entry = *(u64*)(remap_addr + i * 8);
		if (entry != 0)
		{
			sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "                    [*] %d "
				"Addr %016lX\n", i, entry);
		}
	}

	if (ioremap == true)
	{
		iounmap(remap_addr);
	}
}

/*
 * Parse PDE.
 */
static void sb_parse_iommu_pde(u64 pte_addr)
{
	u8* remap_addr;
	u64 entry;
	int i;
	bool ioremap = true;

	remap_addr = (u8*)ioremap_uc(pte_addr & MASK_PAGEADDR, VTD_PAGE_SIZE);
	if (remap_addr == NULL)
	{
		ioremap = false;
		remap_addr = (u8*)phys_to_virt(pte_addr & MASK_PAGEADDR);
	}

	sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "                [*] PDE value\n");

	for (i = 0 ; i < IOMMU_PAGE_ENT_COUNT ; i++)
	{
		entry = *(u64*)(remap_addr + i * 8);
		if (entry != 0)
		{
			sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "                [*] %d Addr "
				"%016lX\n", i, entry);

			if ((entry & PS_BIT) == 0)
			{
				sb_parse_iommu_pte(entry);

				/* Delay to prevent ring buffer overflow. */
				msleep_interruptible(50);
			}
		}
	}

	if (ioremap == true)
	{
		iounmap(remap_addr);
	}
}

/*
 * Parse PDPEPD.
 */
static void sb_parse_iommu_pdpepd(u64 pte_addr)
{
	u8* remap_addr;
	u64 entry;
	int i;
	bool ioremap = true;

	remap_addr = (u8*)ioremap_uc(pte_addr & MASK_PAGEADDR, VTD_PAGE_SIZE);
	if (remap_addr == NULL)
	{
		ioremap = false;
		remap_addr = (u8*)phys_to_virt(pte_addr & MASK_PAGEADDR);
	}

	sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "            [*] PDPEPD value\n");

	for (i = 0 ; i < IOMMU_PAGE_ENT_COUNT ; i++)
	{
		entry = *(u64*)(remap_addr + i * 8);
		if (entry != 0)
		{
			sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "            [*] %d Addr "
				"%016lX\n", i, (u64)entry);

			if ((entry & PS_BIT) == 0)
			{
				sb_parse_iommu_pde(entry);
			}
		}
	}

	if (ioremap == true)
	{
		iounmap(remap_addr);
	}
}

/*
 * Parse PML4.
 */
static void sb_parse_iommu_pml4(u64 pte_addr)
{
	u8* remap_addr;
	u64 entry;
	int i;
	bool ioremap = true;

	remap_addr = (u8*)ioremap_uc(pte_addr & MASK_PAGEADDR, VTD_PAGE_SIZE);
	if (remap_addr == NULL)
	{
		ioremap = false;
		remap_addr = (u8*)phys_to_virt(pte_addr & MASK_PAGEADDR);
	}

	sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "            [*] PML4 value\n");

	for (i = 0 ; i < IOMMU_PAGE_ENT_COUNT ; i++)
	{
		entry = *(u64*)(remap_addr + i * 8);
		if (entry != 0)
		{
			sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "            [*] %d Addr "
				"%016lX\n", i, (u64)entry);

			if ((entry & PS_BIT) == 0)
			{
				sb_parse_iommu_pdpepd(entry);
			}
		}
	}

	if (ioremap == true)
	{
		iounmap(remap_addr);
	}
}

/*
 * Parse context entry.
 */
static void sb_parse_iommu_context_entry(u64 context_addr)
{
	struct sb_context_entry* context;
	int i;
	u8* remap_addr;

	remap_addr = (u8*)phys_to_virt(context_addr & MASK_PAGEADDR);
	if (remap_addr == NULL)
	{
		sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "IO Remap Error %016lX\n",
			(u64)context_addr);
		return ;
	}

	for (i = 0 ; i < 256 ; i++)
	{
		context = (struct sb_context_entry*) (remap_addr + i * sizeof(
				struct sb_context_entry));
		if (context == NULL)
		{
			sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "        [*] %d Entry is null\n",
				i);
		}
		else
		{
			if (context->lo == 0)
			{
				continue;
			}

			sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "        [*] %d Addr %016lX\n",
				i, (u64)context->lo);
			sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "        [*] %d Addr %016lX\n",
				i, (u64)context->hi);

			sb_parse_iommu_pml4(context->lo);
		}
	}
}


/*
 * Parse root entry.
 */
static void sb_parse_iommu_root_entry(u64 root_table_addr)
{
	struct sb_root_entry* root;
	u8* remap_addr;
	int i;

	sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "Show Root Entry\n");
	remap_addr = (u8*)phys_to_virt(root_table_addr & MASK_PAGEADDR);
	if (remap_addr == NULL)
	{
		sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "IO Remap Error %016lX\n",
			root_table_addr);
		return ;
	}

	/* Root Entry. */
	for (i = 0 ; i < 256 ; i++)
	{
		root = (struct sb_root_entry*)(remap_addr + i * sizeof(struct sb_root_entry));
		if (root == NULL)
		{
			sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "    [*] %d Entry is null\n",
				i);
		}
		else
		{
			if (root->val == 0)
			{
				continue;
			}

			sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "    [*] %d Addr %016lX\n", i,
				(u64)root->val);
			sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "    [*] %d Addr %016lX\n", i,
				(u64)root->rsvd1);
			sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "        [*] Show Context Entry\n");

			sb_parse_iommu_context_entry(root->val);
		}
	}
}
#endif


/*
 * Wait until the operation is finished.
 */
static void sb_wait_dmar_operation(u8* reg_remap_addr, int flag)
{
	u32 sts;
	cycles_t init_time = get_cycles();

	while (1)
	{
		sts = readl(reg_remap_addr);
		if (sts & flag)
		{
			break;
		}

		if (DMAR_OPERATION_TIMEOUT < (get_cycles() - init_time))
		{
			break;
		}

		cpu_relax();
	}
}

/*
 * Activate IOMMU.
 */
static void sb_enable_iommu(u8* reg_remap_addr)
{
	u32 flags;
	unsigned long irqs;

	preempt_disable();
	local_irq_save(irqs);

	flags = readl(reg_remap_addr + DMAR_GSTS_REG);
	writel(flags | DMA_GCMD_QIE, reg_remap_addr + DMAR_GCMD_REG);
	sb_wait_dmar_operation(reg_remap_addr + DMAR_GSTS_REG, DMA_GSTS_QIES);

	writel(flags | DMA_GCMD_TE, reg_remap_addr + DMAR_GCMD_REG);
	sb_wait_dmar_operation(reg_remap_addr + DMAR_GSTS_REG, DMA_GSTS_TES);

	local_irq_restore(irqs);
	preempt_enable();
}

/*
 * Deactivate IOMMU.
 */
void sb_disable_iommu(u8* reg_remap_addr)
{
	u32 flags;
	unsigned long irqs;

	preempt_disable();
	local_irq_save(irqs);

	flags = readl(reg_remap_addr + DMAR_GSTS_REG);
	writel(flags & ~DMA_GCMD_TE, reg_remap_addr + DMAR_GCMD_REG);

	/* Just wait until timeout. */
	sb_wait_dmar_operation(reg_remap_addr + DMAR_GSTS_REG, 0);

	local_irq_restore(irqs);
	preempt_enable();
}


/*
 * Register new root entry to IOMMU.
 */
static void sb_set_iommu_root_entry_register(u8* reg_remap_addr, u64 addr)
{
	u32 flags;
	unsigned long irqs;

	preempt_disable();
	local_irq_save(irqs);

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "Root Entry Addr %016lX\n", addr);
	flags = readl(reg_remap_addr + DMAR_GSTS_REG);
   	dmar_writeq(reg_remap_addr + DMAR_RTADDR_REG, addr);

   	writel(flags | DMA_GCMD_SRTP, reg_remap_addr + DMAR_GCMD_REG);
	sb_wait_dmar_operation(reg_remap_addr + DMAR_GSTS_REG, DMA_GSTS_RTPS);

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "Root Entry Addr %016lX\n",
		dmar_readq(reg_remap_addr + DMAR_RTADDR_REG));

	local_irq_restore(irqs);
	preempt_enable();
}

/*
 * Get logical address of DMAR page table.
 */
static void* sb_get_iommu_pagetable_log_addr(int iType, int iIndex)
{
	u64* table_array;

	switch(iType)
	{
	case IOMMU_TYPE_PML4:
		table_array = g_iommu_info.pml4_page_addr_array;
		break;

	case IOMMU_TYPE_PDPTEPD:
		table_array = g_iommu_info.pdpte_pd_page_addr_array;
		break;

	case IOMMU_TYPE_PDEPT:
		table_array = g_iommu_info.pdept_page_addr_array;
		break;

	case IOMMU_TYPE_PTE:
	default:
		table_array = g_iommu_info.pte_page_addr_array;
		break;
	}

	return (void*)table_array[iIndex];
}

/*
 * Get physical address of DMAR page table by index and type.
 */
static void* sb_get_iommu_pagetable_phy_addr(int iType, int iIndex)
{
	void* pvLogAddr;

	pvLogAddr = sb_get_iommu_pagetable_log_addr(iType, iIndex);
	return (void*)virt_to_phys(pvLogAddr);
}

/*
 * Hide a physical page to protect it from unauthorized modification.
 */
void sb_set_iommu_hide_page(u64 phy_addr)
{
	sb_set_iommu_page_flags(phy_addr, 0);
}

/*
 * Set all permissions to a physcial page.
 */
void sb_set_iommu_all_access_page(u64 phy_addr)
{
	sb_set_iommu_page_flags(phy_addr, IOMMU_PAGE_ALL_ACCESS);
}

/*
 * Set permissions to a physical page in DMAR table.
 */
void sb_set_iommu_page_flags(u64 phy_addr, u32 flags)
{
	u64 page_offset;
	u64* page_table_addr;
	u64 page_index;

	page_offset = phy_addr / IOMMU_PAGE_SIZE;
	page_index = page_offset % IOMMU_PAGE_ENT_COUNT;
	page_table_addr = sb_get_iommu_pagetable_log_addr(IOMMU_TYPE_PTE,
		page_offset / IOMMU_PAGE_ENT_COUNT);
	page_table_addr[page_index] = (page_table_addr[page_index] & MASK_PAGEADDR) |
		flags;
}

/*
 * Setup DMAR page table.
 */
void sb_setup_iommu_pagetable_4KB(void)
{
	struct sb_iommu_pagetable* iommu_info;
	u64 next_page_table;
	u64 i;
	u64 j;
	u64 loop_cnt;
	u64 base_addr;

	/* Setup PML4. */
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "Setup PLML4\n");
	iommu_info = (struct sb_iommu_pagetable*)sb_get_iommu_pagetable_log_addr(
		IOMMU_TYPE_PML4, 0);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Setup PML4 %016lX, %016lX\n",
			(u64)iommu_info, virt_to_phys((void*)iommu_info));
	memset(iommu_info, 0, sizeof(struct sb_iommu_pagetable));

	/* Map all physical range. */
	for (i = 0 ; i < IOMMU_PAGE_ENT_COUNT ; i++)
	{
		next_page_table = (u64)sb_get_iommu_pagetable_phy_addr(IOMMU_TYPE_PDPTEPD,
			i);
		iommu_info->entry[i] = next_page_table | IOMMU_PAGE_ALL_ACCESS;
		if (i == 0)
		{
			sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] %016lX\n",
				(u64)next_page_table);
		}
	}
	clflush_cache_range(iommu_info, IOMMU_PAGE_SIZE);

	/* Setup PDPTEPD. */
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "Setup PDPTEPD\n");
	base_addr = 0;
	for (j = 0 ; j < g_iommu_info.pdpte_pd_page_count ; j++)
	{
		iommu_info = (struct sb_iommu_pagetable*)sb_get_iommu_pagetable_log_addr(
			IOMMU_TYPE_PDPTEPD, j);
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Setup PDPTEPD [%d] %016lX "
			"%016lX\n", j, (u64)iommu_info, virt_to_phys((void*)iommu_info));
		memset(iommu_info, 0, sizeof(struct sb_iommu_pagetable));

		/*
		 * Map 1:1 for all address spaces for IOMEM.
		 * 	Some devices have own IOMEM areas far from the RAM space.
		 */
		if (j * IOMMU_PAGE_ENT_COUNT > g_iommu_info.pdpte_pd_ent_count)
		{
			for (i = 0 ; i < IOMMU_PAGE_ENT_COUNT ; i++)
			{
				iommu_info->entry[i] = base_addr | IOMMU_PAGE_ALL_ACCESS | MASK_PAGE_SIZE_FLAG;
				base_addr += VAL_1GB;
			}

			continue;
		}

		loop_cnt = g_iommu_info.pdpte_pd_ent_count - (j * IOMMU_PAGE_ENT_COUNT);
		if (loop_cnt > IOMMU_PAGE_ENT_COUNT)
		{
			loop_cnt = IOMMU_PAGE_ENT_COUNT;
		}

		for (i = 0 ; i < IOMMU_PAGE_ENT_COUNT ; i++)
		{
			if(i < loop_cnt)
			{
				next_page_table = (u64)sb_get_iommu_pagetable_phy_addr(
					IOMMU_TYPE_PDEPT, (j * IOMMU_PAGE_ENT_COUNT) + i);
				iommu_info->entry[i] = next_page_table | IOMMU_PAGE_ALL_ACCESS;

				if (i == 0)
				{
					sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] %016lX\n",
						(u64)next_page_table);
				}
			}
			else
			{
				iommu_info->entry[i] = base_addr | IOMMU_PAGE_ALL_ACCESS | MASK_PAGE_SIZE_FLAG;
			}

			base_addr += VAL_1GB;
		}
		clflush_cache_range(iommu_info, IOMMU_PAGE_SIZE);
	}

	/* Setup PDEPT. */
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "Setup PDEPT\n");
	base_addr = 0;
	for (j = 0 ; j < g_iommu_info.pdept_page_count ; j++)
	{
		iommu_info = (struct sb_iommu_pagetable*)sb_get_iommu_pagetable_log_addr(
			IOMMU_TYPE_PDEPT, j);
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Setup PDEPT [%d] %016lX "
			"%016lX\n", j, (u64)iommu_info, virt_to_phys(iommu_info));
		memset(iommu_info, 0, sizeof(struct sb_iommu_pagetable));

		loop_cnt = g_iommu_info.pdept_ent_count - (j * IOMMU_PAGE_ENT_COUNT);
		if (loop_cnt > IOMMU_PAGE_ENT_COUNT)
		{
			loop_cnt = IOMMU_PAGE_ENT_COUNT;
		}

		for (i = 0 ; i < IOMMU_PAGE_ENT_COUNT ; i++)
		{
			if (i < loop_cnt)
			{
				next_page_table = (u64)sb_get_iommu_pagetable_phy_addr(IOMMU_TYPE_PTE,
					(j * IOMMU_PAGE_ENT_COUNT) + i);
				iommu_info->entry[i] = next_page_table | IOMMU_PAGE_ALL_ACCESS;

				if (i == 0)
				{
					sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] %016lX\n",
						(u64)next_page_table);
				}
			}
			else
			{
				iommu_info->entry[i] = base_addr | IOMMU_PAGE_ALL_ACCESS | MASK_PAGE_SIZE_FLAG;
			}

			base_addr += VAL_2MB;
		}
		clflush_cache_range(iommu_info, IOMMU_PAGE_SIZE);
	}

	/* Setup PTE. */
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "Setup PTE\n");
	for (j = 0 ; j < g_iommu_info.pte_page_count ; j++)
	{
		iommu_info = (struct sb_iommu_pagetable*)sb_get_iommu_pagetable_log_addr(
			IOMMU_TYPE_PTE, j);
		memset(iommu_info, 0, sizeof(struct sb_iommu_pagetable));

		for (i = 0 ; i < IOMMU_PAGE_ENT_COUNT ; i++)
		{
			next_page_table = ((u64)j * IOMMU_PAGE_ENT_COUNT + i) * IOMMU_PAGE_SIZE;
			iommu_info->entry[i] = next_page_table | IOMMU_PAGE_ALL_ACCESS;
		}
		clflush_cache_range(iommu_info, IOMMU_PAGE_SIZE);
	}
}

/*
 *	Allocate pages for IOMMU internally.
 */
static int sb_alloc_iommu_pages_internal(u64 *array, int count)
{
	int i;

	for (i = 0 ; i < count ; i++)
	{
		array[i] = (u64)__get_free_page(GFP_KERNEL);
		if (array[i] == 0)
		{
			return -1;
		}
	}
	return 0;
}

/*
 * Free pages for IOMMU internally.
 */
static void sb_free_iommu_pages_internal(u64 *array, int count)
{
	int i;

	for (i = 0 ; i < count ; i++)
	{
		if (array[i] != 0)
		{
			free_page(array[i]);
		}
	}
}
/*
 * Allocate memory for DMAR table and setup.
 */
int sb_alloc_iommu_pages(void)
{
	struct sb_root_entry* root_entry_table;
	struct sb_context_entry* context_entry_table;

	g_iommu_info.pml4_ent_count = CEIL(g_max_ram_size, VAL_512GB);
	g_iommu_info.pdpte_pd_ent_count = CEIL(g_max_ram_size, VAL_1GB);
	g_iommu_info.pdept_ent_count = CEIL(g_max_ram_size, VAL_2MB);
	g_iommu_info.pte_ent_count = CEIL(g_max_ram_size, VAL_4KB);

	g_iommu_info.pml4_page_count = PML4_PAGE_COUNT;
	g_iommu_info.pdpte_pd_page_count = IOMMU_PAGE_ENT_COUNT;
	g_iommu_info.pdept_page_count = CEIL(g_iommu_info.pdept_ent_count,
		IOMMU_PAGE_ENT_COUNT);
	g_iommu_info.pte_page_count = CEIL(g_iommu_info.pte_ent_count,
		IOMMU_PAGE_ENT_COUNT);

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Setup IOMMU Page Table & Root/Context "
		"Entry Table, Max RAM Size %ld\n", g_max_ram_size);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IOMMU Size: %d\n",
		(int)sizeof(struct sb_iommu_pagetable));
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PML4 Entry Count: %d\n",
		(int)g_iommu_info.pml4_ent_count);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PDPTE PD Entry Count: %d\n",
		(int)g_iommu_info.pdpte_pd_ent_count);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PDE PT Entry Count: %d\n",
		(int)g_iommu_info.pdept_ent_count);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PTE Entry Count: %d\n",
		(int)g_iommu_info.pte_ent_count);

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PML4 Page Count: %d\n",
		(int)g_iommu_info.pml4_page_count);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PDPTE PD Page Count: %d\n",
		(int)g_iommu_info.pdpte_pd_page_count);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PDE PT Page Count: %d\n",
		(int)g_iommu_info.pdept_page_count);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PTE Page Count: %d\n",
		(int)g_iommu_info.pte_page_count);

	/* Allocate memory for page table. */
	g_iommu_info.pml4_page_addr_array =
		(u64*)vzalloc(g_iommu_info.pml4_page_count * sizeof(u64*));
	g_iommu_info.pdpte_pd_page_addr_array =
		(u64*)vzalloc(g_iommu_info.pdpte_pd_page_count * sizeof(u64*));
	g_iommu_info.pdept_page_addr_array =
		(u64*)vzalloc(g_iommu_info.pdept_page_count * sizeof(u64*));
	g_iommu_info.pte_page_addr_array =
		(u64*)vzalloc(g_iommu_info.pte_page_count * sizeof(u64*));

	if ((g_iommu_info.pml4_page_addr_array == 0) ||
		(g_iommu_info.pdpte_pd_page_addr_array == 0) ||
		(g_iommu_info.pdept_page_addr_array == 0) ||
		(g_iommu_info.pte_page_addr_array == 0))
	{
		goto ERROR;
	}

	if (sb_alloc_iommu_pages_internal(g_iommu_info.pml4_page_addr_array,
		g_iommu_info.pml4_page_count) != 0)
	{
		goto ERROR;
	}

	if (sb_alloc_iommu_pages_internal(g_iommu_info.pdpte_pd_page_addr_array,
		g_iommu_info.pdpte_pd_page_count) != 0)
	{
		goto ERROR;
	}

	if (sb_alloc_iommu_pages_internal(g_iommu_info.pdept_page_addr_array,
		g_iommu_info.pdept_page_count) != 0)
	{
		goto ERROR;
	}

	if (sb_alloc_iommu_pages_internal(g_iommu_info.pte_page_addr_array,
		g_iommu_info.pte_page_count) != 0)
	{
		goto ERROR;
	}

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Page Table Memory Alloc Success\n");

	/* Allocate memory for root table and context table. */
	root_entry_table = (struct sb_root_entry*)__get_free_page(GFP_KERNEL);
	context_entry_table = (struct sb_context_entry*)__get_free_page(GFP_KERNEL);
	if ((root_entry_table == NULL) || (context_entry_table == NULL))
	{
		sb_printf(LOG_LEVEL_ERROR, LOG_INFO " sb_alloc_iommu_pages alloc fail\n");
		return -1;
	}

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] root_entry_table Logical: %016lX "
		"Physical: %016lX\n", root_entry_table, virt_to_phys(root_entry_table));
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] context_entry_table Logical: %016lX "
		"Physical: %016lX\n", context_entry_table, virt_to_phys(context_entry_table));

	g_iommu_info.root_entry_table_addr = (u64*)root_entry_table;
	g_iommu_info.context_entry_table_addr = (u64*)context_entry_table;

	return 0;

ERROR:
	sb_printf(LOG_LEVEL_ERROR, LOG_INFO "sb_alloc_iommu_pages alloc fail\n");
	return -1;
}

/*
 * Free allocated memory for DMAR.
 *	The pages which already used by DMAR should not be free.
 */
void sb_free_iommu_pages(void)
{
	if (g_iommu_info.pml4_page_addr_array != 0)
	{
		sb_free_iommu_pages_internal(g_iommu_info.pml4_page_addr_array,
			g_iommu_info.pml4_page_count);

		vfree(g_iommu_info.pml4_page_addr_array);
		g_iommu_info.pml4_page_addr_array = 0;
	}

	if (g_iommu_info.pdpte_pd_page_addr_array != 0)
	{
		sb_free_iommu_pages_internal(g_iommu_info.pdpte_pd_page_addr_array,
			g_iommu_info.pdpte_pd_page_count);

		vfree(g_iommu_info.pdpte_pd_page_addr_array);
		g_iommu_info.pdpte_pd_page_addr_array = 0;
	}

	if (g_iommu_info.pdept_page_addr_array != 0)
	{
		sb_free_iommu_pages_internal(g_iommu_info.pdept_page_addr_array,
			g_iommu_info.pdept_page_count);

		vfree(g_iommu_info.pdept_page_addr_array);
		g_iommu_info.pdept_page_addr_array = 0;
	}

	if (g_iommu_info.pte_page_addr_array != 0)
	{
		sb_free_iommu_pages_internal(g_iommu_info.pte_page_addr_array,
			g_iommu_info.pte_page_count);

		vfree(g_iommu_info.pte_page_addr_array);
		g_iommu_info.pte_page_addr_array = 0;
	}

	if (g_iommu_info.root_entry_table_addr != 0)
	{
		free_page((u64)g_iommu_info.root_entry_table_addr);
		g_iommu_info.root_entry_table_addr = 0;
	}

	if (g_iommu_info.context_entry_table_addr != 0)
	{
		free_page((u64)g_iommu_info.context_entry_table_addr);
		g_iommu_info.context_entry_table_addr  = 0;
	}
}

/*
 * Setup root table entry.
 */
static void sb_setup_root_table_entry(void)
{
	struct sb_root_entry* root_entry_table;
	struct sb_context_entry* context_entry_table;
	int i;

	root_entry_table = (struct sb_root_entry*)g_iommu_info.root_entry_table_addr;
	context_entry_table = (struct sb_context_entry*)g_iommu_info.context_entry_table_addr;
	for (i = 0 ; i < 256 ; i++)
	{
		root_entry_table[i].rsvd1 = 0;
		root_entry_table[i].val = (u64)virt_to_phys(context_entry_table) |
			ENTRY_PRESENT;

		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "Root Table [%d] %016lX %016lX\n",
			i, root_entry_table[i].rsvd1, root_entry_table[i].val);
	}
	clflush_cache_range(root_entry_table, IOMMU_PAGE_SIZE);
}

/*
 * Setup context table entry.
 */
static void sb_setup_context_table_entry(void)
{
	struct sb_context_entry* context_entry_table;
	u64 table_array;
	int i;

	context_entry_table = (struct sb_context_entry*)g_iommu_info.context_entry_table_addr;
	if (g_entry_level == ENTRY_3LEVEL_PTE)
	{
		table_array = g_iommu_info.pdpte_pd_page_addr_array[0];
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "3 Level PTE\n");
	}
	else
	{
		table_array = g_iommu_info.pml4_page_addr_array[0];
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "4 Level PTE\n");
	}

	for (i = 0 ; i < 256 ; i++)
	{
		context_entry_table[i].hi = g_entry_level;
		context_entry_table[i].lo = (u64)virt_to_phys((void*)table_array) |
			ENTRY_PRESENT;
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "Context Table [%d] %016lX %016lX\n",
			i, context_entry_table[i].hi, context_entry_table[i].lo);
	}
	clflush_cache_range(context_entry_table, IOMMU_PAGE_SIZE);
}

/*
 * Protect DMAR table from unauthorized modification.
 */
void sb_protect_iommu_pages(void)
{
	int i;
	u64 end;

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Protect IOMMU\n");

	/* Hide page table. */
	end = (u64)g_iommu_info.pml4_page_addr_array +
		g_iommu_info.pml4_page_count * sizeof(u64*);
	sb_hide_range((u64)g_iommu_info.pml4_page_addr_array, end, 1);

	end = (u64)g_iommu_info.pdpte_pd_page_addr_array +
		g_iommu_info.pdpte_pd_page_count * sizeof(u64*);
	sb_hide_range((u64)g_iommu_info.pdpte_pd_page_addr_array, end, 1);

	end = (u64)g_iommu_info.pdept_page_addr_array +
		g_iommu_info.pdept_page_count * sizeof(u64*);
	sb_hide_range((u64)g_iommu_info.pdept_page_addr_array, end, 1);

	end = (u64)g_iommu_info.pte_page_addr_array +
		g_iommu_info.pte_page_count * sizeof(u64*);
	sb_hide_range((u64)g_iommu_info.pte_page_addr_array, end, 1);

	for (i = 0 ; i < g_iommu_info.pml4_page_count ; i++)
	{
		end = (u64)g_iommu_info.pml4_page_addr_array[i] + VAL_4KB;
		sb_hide_range((u64)g_iommu_info.pml4_page_addr_array[i], end, 0);
	}

	for (i = 0 ; i < g_iommu_info.pdpte_pd_page_count ; i++)
	{
		end = (u64)g_iommu_info.pdpte_pd_page_addr_array[i] + VAL_4KB;
		sb_hide_range((u64)g_iommu_info.pdpte_pd_page_addr_array[i], end, 0);
	}

	for (i = 0 ; i < g_iommu_info.pdept_page_count ; i++)
	{
		end = (u64)g_iommu_info.pdept_page_addr_array[i] + VAL_4KB;
		sb_hide_range((u64)g_iommu_info.pdept_page_addr_array[i], end, 0);
	}

	for (i = 0 ; i < g_iommu_info.pte_page_count ; i++)
	{
		end = (u64)g_iommu_info.pte_page_addr_array[i] + VAL_4KB;
		sb_hide_range((u64)g_iommu_info.pte_page_addr_array[i], end, 0);
	}

	/* Hide root table and context table. */
	end = (u64)g_iommu_info.root_entry_table_addr + VAL_4KB;
	sb_hide_range((u64)g_iommu_info.root_entry_table_addr, end, 0);

	end = (u64)g_iommu_info.context_entry_table_addr + VAL_4KB;
	sb_hide_range((u64)g_iommu_info.context_entry_table_addr, end, 0);

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Complete\n");
}

/*
 * Start IOMMU.
 */
static void start_iommu(u8* reg_remap_addr, int skip)
{
	u64 extend_cap = 0;

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "IOMMU Start\n");

	sb_setup_root_table_entry();
	sb_setup_context_table_entry();

	flush_cache_all();

	extend_cap = dmar_readq(reg_remap_addr + DMAR_ECAP_REG);
	if (ecap_ecs(extend_cap))
	{
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Extended Context Supported\n");
	}

	if (skip == 0)
	{
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Root entry %016lX\n",
			g_iommu_info.root_entry_table_addr);
		sb_set_iommu_root_entry_register(reg_remap_addr,
			(u64)virt_to_phys(g_iommu_info.root_entry_table_addr));

		sb_enable_iommu(reg_remap_addr);
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IOMMU STATUS = %08X\n",
			readl(reg_remap_addr + DMAR_GSTS_REG));
	}
	else
	{
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Root entry is skipped\n");

		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IOMMU STATUS = %08X\n",
			readl(reg_remap_addr + DMAR_GSTS_REG));
	}
}

#if SHADOWBOX_USE_I915_WORKAROUND
/*
 * Workaround for i915 driver.
 * To support IOMMU, GFX DRHD is skipped.
 */
static int sb_need_intel_i915_workaround(void)
{
	struct module *mod;
	struct list_head *pos, *node;
	unsigned long mod_head_node;

	node = &THIS_MODULE->list;
	mod_head_node = sb_get_symbol_address("modules");

	list_for_each(pos, node)
	{
		if(mod_head_node == (unsigned long)pos)
			break;

		mod = container_of(pos, struct module, list);
		if (strcmp(mod->name, "i915") == 0)
		{
			sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] i915 driver is detected.\n");
			return 1;
		}
	}

	return 0;
}

/*
 * Check if Intel integrated graphics is in DRHD.
 */
static int sb_is_intel_graphics_in(struct acpi_dmar_hardware_unit* drhd)
{
	struct acpi_dmar_device_scope* device_scope;
	struct acpi_dmar_pci_path* pci_path;
	u64 start_device_scope;
	u64 start_pci_path;
	int device_count = 0;
	int path_count = 0;
	int is_bus_device_function_match = 0;

	/* Parse device scope structure. */
	for (start_device_scope = sizeof(struct acpi_dmar_hardware_unit) ;
		 start_device_scope < drhd->header.length ; )
	{
		device_scope = (struct acpi_dmar_device_scope*)(start_device_scope + (u64)drhd);

		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Device Scope %d\n", device_count);
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "        [*] Type %d\n", device_scope->entry_type);
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "        [*] Length %d, PCI path %d\n", device_scope->length, sizeof(struct acpi_dmar_pci_path));
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "        [*] Enum ID %d\n", device_scope->enumeration_id);
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "        [*] Bus %d\n", device_scope->bus);

		for (start_pci_path = sizeof(struct acpi_dmar_device_scope) ;
			 start_pci_path < device_scope->length ; )
		{
			pci_path = (struct acpi_dmar_pci_path*)(start_pci_path + (u64)device_scope);
			sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "        [*] PCI Path\n");
			sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "            [*] Device %d, Function %d\n", pci_path->device, pci_path->function);

			start_pci_path += sizeof(struct acpi_dmar_pci_path);
			path_count++;

			if ((device_scope->entry_type == ACPI_DMAR_SCOPE_TYPE_ENDPOINT) &&
				(device_scope->bus == 0) && (pci_path->device == 2) &&
				(pci_path->function == 0))
			{
				is_bus_device_function_match = 1;
			}
		}

		start_device_scope += device_scope->length;
		device_count++;
	}

	if ((device_count == 1) && (is_bus_device_function_match == 1))
	{
		sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "    [*] Intel Integrated Graphics is detected\n");
		return 1;
	}

	return 0;
}
#else
static int sb_need_intel_i915_workaround(void)
{
	return 0;
}

static int sb_is_intel_graphics_in(struct acpi_dmar_hardware_unit* drhd)
{
	return 0;
}
#endif

/*
 * Get DMAR table header.
 */
static acpi_status sb_get_acpi_dmar_table_header(struct acpi_table_dmar** dmar_ptr)
{
	acpi_status result = AE_OK;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	acpi_size dmar_table_size = 0;
#endif /* LINUX_VERSION_CODE */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	result = acpi_get_table_with_size(ACPI_SIG_DMAR, 0,
		(struct acpi_table_header **)dmar_ptr, &dmar_table_size);
#else /* LINUX_VERSION_CODE */
	result = acpi_get_table(ACPI_SIG_DMAR, 0, (struct acpi_table_header **)dmar_ptr);
#endif /* LINUX_VERSION_CODE */

	return result;
}

/*
 * Lock IOMMU area.
 */
void sb_lock_iommu(void)
{
	struct acpi_table_dmar* dmar_ptr;
	struct acpi_dmar_header* dmar_header;
	struct acpi_dmar_hardware_unit* drhd;
	u8* remap_addr;
	u64 start;
	u64 root_table_addr = 0;
	acpi_status result = AE_OK;
	int i;
	int need_i915_workaround = 0;

	sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "Lock IOMMU\n");

	need_i915_workaround = sb_need_intel_i915_workaround();

	/* Read ACPI. */
	result = sb_get_acpi_dmar_table_header(&dmar_ptr);
	if (!ACPI_SUCCESS(result) || (dmar_ptr == NULL))
	{
		sb_printf(LOG_LEVEL_ERROR, LOG_INFO "    [*] WARNING: DMAR find error.\n");
		sb_printf(LOG_LEVEL_ERROR, LOG_INFO "    [*] WARNING: IOMMU is disabled.\n");
		return ;
	}

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] DMAR find success %016lX\n",
		(u64)dmar_ptr);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Signature: %s\n",
		dmar_ptr->header.signature);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Length: %d\n",
		dmar_ptr->header.length);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Revision: %X\n",
		dmar_ptr->header.revision);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Checksum: %X\n",
		dmar_ptr->header.checksum);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] OEM ID: %s\n",
		dmar_ptr->header.oem_id);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Width: %X\n", dmar_ptr->width);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Flag: %X\n", dmar_ptr->flags);

	/* Parse ACPI. */
	for (start = sizeof(struct acpi_table_dmar) ; start < dmar_ptr->header.length ; )
	{
		dmar_header = (struct acpi_dmar_header*) (start + (u64)dmar_ptr);
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] DMAR Type: %d\n",
			dmar_header->type);
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] DMAR Length: %d\n",
			dmar_header->length);

		if (dmar_header->type == ACPI_DMAR_TYPE_HARDWARE_UNIT)
		{
			drhd = (struct acpi_dmar_hardware_unit*)dmar_header;
			sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Flag: %X\n",
				drhd->flags);
			sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Segment: %X\n",
				drhd->segment);
			sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Address: %016lX\n",
				(u64)drhd->address);

			remap_addr = (u8*)ioremap_uc((resource_size_t)(drhd->address),
				VTD_PAGE_SIZE);
			root_table_addr = dmar_readq(remap_addr + DMAR_CAP_REG);
			sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] CAP Register: %016lX\n",
				root_table_addr);

			if (root_table_addr & (0x01 << 10))
			{
				g_entry_level = ENTRY_4LEVEL_PTE;
			}
			else
			{
				g_entry_level = ENTRY_3LEVEL_PTE;
			}

			for (i = 0 ; i < 1024 ; i++)
			{
				sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Data %d %08X\n", i,
					readl(remap_addr + 4 * i));
			}

			root_table_addr = dmar_readq(remap_addr + DMAR_RTADDR_REG);

			sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Root Table Address: "
				"%016lX\n", root_table_addr);

			/* If IOMMU is already activated, use it. */
			if (root_table_addr != 0)
			{
#if SHADOWBOX_USE_IOMMU_DEBUG
				sb_parse_iommu_root_entry(root_table_addr);
#endif /* SHADOWBOX_USE_IOMMU_DEBUG */
			}
			else
			{
				/* Intel Internal Graphics has dedicated DRHD, and for the sleep
				   workaround, it should be skipped. */
				if ((need_i915_workaround == 1) &&
					(sb_is_intel_graphics_in(drhd) == 1))
				{
					start_iommu(remap_addr, need_i915_workaround);
					need_i915_workaround = 0;
				}
				else
				{
					start_iommu(remap_addr, 0);
				}

#if SHADOWBOX_USE_EPT
				sb_set_ept_read_only_page(drhd->address);
#endif /* SHADOWBOX_USE_EPT */
				sb_set_iommu_hide_page(drhd->address);
				sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] MM Register Lock OK"
					" %016X\n", drhd->address);
			}

			iounmap(remap_addr);
		}
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "\n");

		start += dmar_header->length;
	}

	sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "    [*] Lock IOMMU complete\n");
}

/*
 * Unlock IOMMU area.
 */
void sb_unlock_iommu(void)
{
	struct acpi_table_dmar* dmar_ptr;
	struct acpi_dmar_header* dmar_header;
	struct acpi_dmar_hardware_unit* hardware_unit;
	u8* remap_addr;
	u64 start;
	acpi_status result = AE_OK;

	/* Read ACPI. */
	result = sb_get_acpi_dmar_table_header(&dmar_ptr);
	if (!ACPI_SUCCESS(result) || (dmar_ptr == NULL))
	{
		return ;
	}

	/* Parse ACPI. */
	for (start = sizeof(struct acpi_table_dmar) ; start < dmar_ptr->header.length ; )
	{
		dmar_header = (struct acpi_dmar_header*) (start + (u64)dmar_ptr);

		if (dmar_header->type == ACPI_DMAR_TYPE_HARDWARE_UNIT)
		{
			hardware_unit = (struct acpi_dmar_hardware_unit*)dmar_header;
			remap_addr = (u8*)ioremap_uc((resource_size_t)(hardware_unit->address),
				VTD_PAGE_SIZE);

			sb_disable_iommu(remap_addr);
#if SHADOWBOX_USE_EPT
			sb_set_ept_all_access_page(hardware_unit->address);
#endif /* SHADOWBOX_USE_EPT */
			sb_set_iommu_all_access_page(hardware_unit->address);

			iounmap(remap_addr);
		}
		start += dmar_header->length;
	}
}
