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
#include <linux/rwlock_types.h>
#include <linux/reboot.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/version.h>
#include <asm/io.h>
#include "mmu.h"
#include "shadow_box.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
#include <linux/vmalloc.h>
#endif

/*
 * Variables.
 */
/*
 * Set buffer to protect Shadow-box data section from module structure.
 * 	Module structure is in front of data section and is not aligned by 4KB.
 */
char sb_dummy_buffer_for_4KB_align[0x2000] = {0, };
struct sb_ept_info g_ept_info = {0,};
static u64 g_ram_end;

/*
 * Functions.
 */
static void sb_set_ept_page_addr(u64 phy_addr, u64 addr);
static void sb_set_ept_page_flags(u64 phy_addr, u32 flags);
static int sb_callback_walk_ram(unsigned long start, unsigned long size,
	void* arg);
static int sb_callback_set_write_back_to_ram(unsigned long start,
	unsigned long size, void* arg);
static void sb_setup_ept_system_ram_range(void);
static int sb_alloc_ept_pages_internal(u64 *array, int count);
static void sb_free_ept_pages_internal(u64 *array, int count);

/*
 * Protect page table memory for EPT.
 */
void sb_protect_ept_pages(void)
{
	int i;
	u64 end;

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Protect EPT\n");

	/* Hide the EPT page table */
	end = (u64)g_ept_info.pml4_page_addr_array + g_ept_info.pml4_page_count *
		sizeof(u64*);
	sb_hide_range((u64)g_ept_info.pml4_page_addr_array, end, ALLOC_VMALLOC);

	end = (u64)g_ept_info.pdpte_pd_page_addr_array +
		g_ept_info.pdpte_pd_page_count * sizeof(u64*);
	sb_hide_range((u64)g_ept_info.pdpte_pd_page_addr_array, end, ALLOC_VMALLOC);

	end = (u64)g_ept_info.pdept_page_addr_array +
		g_ept_info.pdept_page_count * sizeof(u64*);
	sb_hide_range((u64)g_ept_info.pdept_page_addr_array, end, ALLOC_VMALLOC);

	end = (u64)g_ept_info.pte_page_addr_array +
		g_ept_info.pte_page_count * sizeof(u64*);
	sb_hide_range((u64)g_ept_info.pte_page_addr_array, end, ALLOC_VMALLOC);

	for (i = 0 ; i < g_ept_info.pml4_page_count ; i++)
	{
		end = (u64)g_ept_info.pml4_page_addr_array[i] + EPT_PAGE_SIZE;
		sb_hide_range((u64)g_ept_info.pml4_page_addr_array[i], end,
			ALLOC_KMALLOC);
	}

	for (i = 0 ; i < g_ept_info.pdpte_pd_page_count ; i++)
	{
		end = (u64)g_ept_info.pdpte_pd_page_addr_array[i] + EPT_PAGE_SIZE;
		sb_hide_range((u64)g_ept_info.pdpte_pd_page_addr_array[i], end,
			ALLOC_KMALLOC);
	}

	for (i = 0 ; i < g_ept_info.pdept_page_count ; i++)
	{
		end = (u64)g_ept_info.pdept_page_addr_array[i] + EPT_PAGE_SIZE;
		sb_hide_range((u64)g_ept_info.pdept_page_addr_array[i], end,
			ALLOC_KMALLOC);
	}

	for (i = 0 ; i < g_ept_info.pte_page_count ; i++)
	{
		end = (u64)g_ept_info.pte_page_addr_array[i] + EPT_PAGE_SIZE;
		sb_hide_range((u64)g_ept_info.pte_page_addr_array[i], end,
			ALLOC_KMALLOC);
	}

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Complete\n");
}

/*
 * Hide a physical page to protect it from the guest.
 */
void sb_set_ept_hide_page(u64 phy_addr)
{
	sb_set_ept_page_flags(phy_addr, EPT_BIT_MEM_TYPE_WB);
}

/*
 * Set read-only to a physical page to protect it from the guest.
 */
void sb_set_ept_read_only_page(u64 phy_addr)
{
	sb_set_ept_page_flags(phy_addr, EPT_READ | EPT_BIT_MEM_TYPE_WB);
	sb_set_ept_page_addr(phy_addr, phy_addr);
}

/*
 * Lock a physical page to protect it from the guest.
 */
void sb_set_ept_lock_page(u64 phy_addr)
{
	sb_set_ept_page_flags(phy_addr, EPT_READ | EPT_EXECUTE | EPT_BIT_MEM_TYPE_WB);
	sb_set_ept_page_addr(phy_addr, phy_addr);
}

/*
 * Set all permissions to a physcial page.
 */
void sb_set_ept_all_access_page(u64 phy_addr)
{
	sb_set_ept_page_flags(phy_addr, EPT_ALL_ACCESS | EPT_BIT_MEM_TYPE_WB);
	sb_set_ept_page_addr(phy_addr, phy_addr);
}

/*
 * Change physical address in EPT.
 */
static void sb_set_ept_page_addr(u64 phy_addr, u64 addr)
{
	u64 page_offset;
	u64* page_table_addr;
	u64 page_index;

	page_offset = phy_addr / EPT_PAGE_SIZE;
	page_index = page_offset % EPT_PAGE_ENT_COUNT;
	page_table_addr = sb_get_pagetable_log_addr(EPT_TYPE_PTE,
		page_offset / EPT_PAGE_ENT_COUNT);
	page_table_addr[page_index] = (addr & MASK_PAGEADDR) |
		(page_table_addr[page_index] & ~MASK_PAGEADDR);
}

/*
 * Set permissions to a physical page in EPT.
 */
static void sb_set_ept_page_flags(u64 phy_addr, u32 flags)
{
	u64 page_offset;
	u64* page_table_addr;
	u64 page_index;

	page_offset = phy_addr / EPT_PAGE_SIZE;
	page_index = page_offset % EPT_PAGE_ENT_COUNT;
	page_table_addr = sb_get_pagetable_log_addr(EPT_TYPE_PTE,
			page_offset / EPT_PAGE_ENT_COUNT);
	page_table_addr[page_index] = (page_table_addr[page_index] & MASK_PAGEADDR) |
		flags;
}

/*
 * Setup EPT.
 */
void sb_setup_ept_pagetable_4KB(void)
{
	struct sb_ept_pagetable* ept_info;
	u64 next_page_table_addr;
	u64 i;
	u64 j;
	u64 loop_cnt;
	u64 base_addr;

	/* Setup PML4. */
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "Setup PLML4\n");
	ept_info = (struct sb_ept_pagetable*)sb_get_pagetable_log_addr(EPT_TYPE_PML4, 0);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Setup PML4 %016lX\n",
			(u64)ept_info);
	memset(ept_info, 0, sizeof(struct sb_ept_pagetable));

	/* Map all physical range. */
	for (i = 0 ; i < EPT_PAGE_ENT_COUNT ; i++)
	{
		next_page_table_addr = (u64)sb_get_pagetable_phy_addr(EPT_TYPE_PDPTEPD,
			i);
		ept_info->entry[i] = next_page_table_addr | EPT_ALL_ACCESS;

		if (i == 0)
		{
			sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] %016lX\n",
				(u64)next_page_table_addr);
		}
	}

	/* Setup PDPTE PD. */
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "Setup PDPTEPD\n");
	base_addr = 0;
	for (j = 0 ; j < g_ept_info.pdpte_pd_page_count ; j++)
	{
		ept_info = (struct sb_ept_pagetable*)sb_get_pagetable_log_addr(EPT_TYPE_PDPTEPD,
			j);
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Setup PDPTEPD [%d] %016lX\n",
			j, (u64)ept_info);
		memset(ept_info, 0, sizeof(struct sb_ept_pagetable));

		/*
		 * Map 1:1 for all address spaces for IOMEM.
		 * 	Some devices have own IOMEM areas far from the RAM space.
		 */
		if (j * EPT_PAGE_ENT_COUNT > g_ept_info.pdpte_pd_ent_count)
		{
			for (i = 0 ; i < EPT_PAGE_ENT_COUNT ; i++)
			{
				ept_info->entry[i] = base_addr | EPT_ALL_ACCESS | MASK_PAGE_SIZE_FLAG;
				base_addr += VAL_1GB;
			}

			continue;
		}

		loop_cnt = g_ept_info.pdpte_pd_ent_count - (j * EPT_PAGE_ENT_COUNT);
		if (loop_cnt > EPT_PAGE_ENT_COUNT)
		{
			loop_cnt = EPT_PAGE_ENT_COUNT;
		}

		for (i = 0 ; i < EPT_PAGE_ENT_COUNT ; i++)
		{
			if (i < loop_cnt)
			{
				next_page_table_addr = (u64)sb_get_pagetable_phy_addr(EPT_TYPE_PDEPT,
					(j * EPT_PAGE_ENT_COUNT) + i);
				ept_info->entry[i] = next_page_table_addr | EPT_ALL_ACCESS;

				if (i == 0)
				{
					sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] %016lX\n",
						(u64)next_page_table_addr);
				}
			}
			else
			{
				ept_info->entry[i] = base_addr | EPT_ALL_ACCESS | MASK_PAGE_SIZE_FLAG;
			}

			base_addr += VAL_1GB;
		}
	}

	/* Setup PDEPT. */
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "Setup PDEPT\n");
	base_addr = 0;
	for (j = 0 ; j < g_ept_info.pdept_page_count ; j++)
	{
		ept_info = (struct sb_ept_pagetable*)sb_get_pagetable_log_addr(EPT_TYPE_PDEPT,
			j);
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Setup PDEPT [%d] %016lX\n",
			j, (u64)ept_info);
		memset(ept_info, 0, sizeof(struct sb_ept_pagetable));

		loop_cnt = g_ept_info.pdept_ent_count - (j * EPT_PAGE_ENT_COUNT);
		if (loop_cnt > EPT_PAGE_ENT_COUNT)
		{
			loop_cnt = EPT_PAGE_ENT_COUNT;
		}

		for (i = 0 ; i < EPT_PAGE_ENT_COUNT ; i++)
		{
			if (i < loop_cnt)
			{
				next_page_table_addr = (u64)sb_get_pagetable_phy_addr(EPT_TYPE_PTE,
					(j * EPT_PAGE_ENT_COUNT) + i);
				ept_info->entry[i] = next_page_table_addr | EPT_ALL_ACCESS;

				if (i == 0)
				{
					sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] %016lX\n",
						(u64)next_page_table_addr);
				}
			}
			else
			{
				ept_info->entry[i] = base_addr | EPT_ALL_ACCESS | MASK_PAGE_SIZE_FLAG;
			}

			base_addr += VAL_2MB;
		}
	}

	/* Setup PTE. */
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "Setup PTE\n");
	for (j = 0 ; j < g_ept_info.pte_page_count ; j++)
	{
		ept_info = (struct sb_ept_pagetable*)sb_get_pagetable_log_addr(EPT_TYPE_PTE,
			j);
		memset(ept_info, 0, sizeof(struct sb_ept_pagetable));

		for (i = 0 ; i < EPT_PAGE_ENT_COUNT ; i++)
		{
			next_page_table_addr = ((u64)j * EPT_PAGE_ENT_COUNT + i) *
				EPT_PAGE_SIZE;
			/*
			 * Set uncacheable type by default.
			 * Set write-back type to "System RAM" areas at the end of this
			 * function.
			 */
			ept_info->entry[i] = next_page_table_addr | EPT_ALL_ACCESS;
		}
	}

	/* Set write-back type to "System RAM" areas. */
	sb_setup_ept_system_ram_range();
}

/*
 *	Allocate pages for EPT internally.
 */
static int sb_alloc_ept_pages_internal(u64 *array, int count)
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
 * Free pages for EPT internally.
 */
static void sb_free_ept_pages_internal(u64 *array, int count)
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
 * Allocate memory for EPT.
 */
int sb_alloc_ept_pages(void)
{
	g_ept_info.pml4_ent_count = CEIL(g_max_ram_size, VAL_512GB);
	g_ept_info.pdpte_pd_ent_count = CEIL(g_max_ram_size, VAL_1GB);
	g_ept_info.pdept_ent_count = CEIL(g_max_ram_size, VAL_2MB);
	g_ept_info.pte_ent_count = CEIL(g_max_ram_size, VAL_4KB);

	g_ept_info.pml4_page_count = PML4_PAGE_COUNT;
	g_ept_info.pdpte_pd_page_count = EPT_PAGE_ENT_COUNT;
	g_ept_info.pdept_page_count = CEIL(g_ept_info.pdept_ent_count, EPT_PAGE_ENT_COUNT);
	g_ept_info.pte_page_count = CEIL(g_ept_info.pte_ent_count, EPT_PAGE_ENT_COUNT);

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Setup EPT, Max RAM Size %ld\n",
		g_max_ram_size);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] EPT Size: %d\n",
		(int)sizeof(struct sb_ept_pagetable));
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PML4 Entry Count: %d\n",
		(int)g_ept_info.pml4_ent_count);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PDPTE PD Entry Count: %d\n",
		(int)g_ept_info.pdpte_pd_ent_count);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PDE PT Entry Count: %d\n",
		(int)g_ept_info.pdept_ent_count);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PTE Entry Count: %d\n",
		(int)g_ept_info.pte_ent_count);

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PML4 Page Count: %d\n",
		(int)g_ept_info.pml4_page_count);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PDPTE PD Page Count: %d\n",
		(int)g_ept_info.pdpte_pd_page_count);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PDE PT Page Count: %d\n",
		(int)g_ept_info.pdept_page_count);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PTE Page Count: %d\n",
		(int)g_ept_info.pte_page_count);

	/* Allocate memory for page table. */
	g_ept_info.pml4_page_addr_array = (u64*)vzalloc(g_ept_info.pml4_page_count *
		sizeof(u64*));
	g_ept_info.pdpte_pd_page_addr_array = (u64*)vzalloc(g_ept_info.pdpte_pd_page_count *
		sizeof(u64*));
	g_ept_info.pdept_page_addr_array = (u64*)vzalloc(g_ept_info.pdept_page_count *
		sizeof(u64*));
	g_ept_info.pte_page_addr_array = (u64*)vzalloc(g_ept_info.pte_page_count *
		sizeof(u64*));

	if ((g_ept_info.pml4_page_addr_array == NULL) ||
		(g_ept_info.pdpte_pd_page_addr_array == NULL) ||
		(g_ept_info.pdept_page_addr_array == NULL) ||
		(g_ept_info.pte_page_addr_array == NULL))
	{
		goto ERROR;
	}

	if (sb_alloc_ept_pages_internal(g_ept_info.pml4_page_addr_array,
		g_ept_info.pml4_page_count) != 0)
	{
		goto ERROR;
	}

	if (sb_alloc_ept_pages_internal(g_ept_info.pdpte_pd_page_addr_array,
		g_ept_info.pdpte_pd_page_count) != 0)
	{
		goto ERROR;
	}

	if (sb_alloc_ept_pages_internal(g_ept_info.pdept_page_addr_array,
		g_ept_info.pdept_page_count) != 0)
	{
		goto ERROR;
	}

	if (sb_alloc_ept_pages_internal(g_ept_info.pte_page_addr_array,
		g_ept_info.pte_page_count) != 0)
	{
		goto ERROR;
	}

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Page Table Memory Alloc Success\n");

	return 0;

ERROR:
	sb_printf(LOG_LEVEL_ERROR, LOG_INFO " sb_alloc_ept_pages alloc fail\n");

	return -1;
}

/*
 * Free allocated memory for EPT.
 */
void sb_free_ept_pages(void)
{
	if (g_ept_info.pml4_page_addr_array != 0)
	{
		sb_free_ept_pages_internal(g_ept_info.pml4_page_addr_array,
			g_ept_info.pml4_page_count);

		vfree(g_ept_info.pml4_page_addr_array);
		g_ept_info.pml4_page_addr_array = 0;
	}

	if (g_ept_info.pdpte_pd_page_addr_array != 0)
	{
		sb_free_ept_pages_internal(g_ept_info.pdpte_pd_page_addr_array,
			g_ept_info.pdpte_pd_page_count);

		vfree(g_ept_info.pdpte_pd_page_addr_array);
		g_ept_info.pdpte_pd_page_addr_array = 0;
	}

	if (g_ept_info.pdept_page_addr_array != 0)
	{
		sb_free_ept_pages_internal(g_ept_info.pdept_page_addr_array,
			g_ept_info.pdept_page_count);

		vfree(g_ept_info.pdept_page_addr_array);
		g_ept_info.pdept_page_addr_array = 0;
	}

	if (g_ept_info.pte_page_addr_array != 0)
	{
		sb_free_ept_pages_internal(g_ept_info.pte_page_addr_array,
			g_ept_info.pte_page_count);

		vfree(g_ept_info.pte_page_addr_array);
		g_ept_info.pte_page_addr_array = 0;
	}
}

/*
 * Process callback of walk_system_ram_range().
 *
 * This function sets write-back cache type to EPT page.
 */
static int sb_callback_set_write_back_to_ram(unsigned long start,
	unsigned long size, void* arg)
{
	struct sb_ept_pagetable* ept_info;
	unsigned long i;

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "System RAM start %016lX, end %016lX, "
		"size %016lX\n", start * PAGE_SIZE, start * PAGE_SIZE + size * PAGE_SIZE,
		size * PAGE_SIZE);

	for (i = start ; i < start + size ; i++)
	{
		ept_info = (struct sb_ept_pagetable*)sb_get_pagetable_log_addr(EPT_TYPE_PTE,
			i / EPT_PAGE_ENT_COUNT);
		ept_info->entry[i %  EPT_PAGE_ENT_COUNT] |= EPT_BIT_MEM_TYPE_WB;
	}

	return 0;
}

/*
 * Set write-back permission to System RAM area.
 */
static void sb_setup_ept_system_ram_range(void)
{
	my_walk_system_ram_range func = NULL;

	func = (my_walk_system_ram_range)sb_get_symbol_address("walk_system_ram_range");
	if (func == NULL)
	{
		sb_printf(LOG_LEVEL_ERROR, LOG_INFO "walk_system_ram_range fail\n");
		return ;
	}

	func(0, g_max_ram_size / PAGE_SIZE, NULL, sb_callback_set_write_back_to_ram);
}


/*
 * Process callback of walk_system_ram_range().
 *
 * This function adds the end of system RAM.
 */
static int sb_callback_walk_ram(unsigned long start, unsigned long size, void* arg)
{
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "System RAM start %016lX, end %016lX, "
		"size %016lX\n", start * PAGE_SIZE, start * PAGE_SIZE + size * PAGE_SIZE,
		size * PAGE_SIZE);

	if (g_ram_end < ((start + size) * PAGE_SIZE))
	{
		g_ram_end = (start + size) * PAGE_SIZE;
	}

	return 0;
}

/*
 * Calculate System RAM size.
 */
u64 sb_get_max_ram_size(void)
{
	my_walk_system_ram_range func = NULL;
	u64 total_pages;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
	total_pages = totalram_pages;
#else /* LINUX_VERSION_CODE */
	total_pages = totalram_pages();
#endif /* LINUX_VERSION_CODE */

	g_ram_end = 0;

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Get walk_system_ram_range\n");
	func = (my_walk_system_ram_range)sb_get_symbol_address("walk_system_ram_range");
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Get walk_system_ram_range, %016lX\n", func);
	if (func == NULL)
	{
		sb_printf(LOG_LEVEL_ERROR, LOG_INFO "walk_system_ram_range fail\n");
		return total_pages * 2 * VAL_4KB;
	}

	func(0, total_pages * 2, NULL, sb_callback_walk_ram);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Max RAM Size %016ld, total_pages %016ld\n", g_max_ram_size, total_pages * 4096);

	return g_ram_end;
}

/*
 * Get logical address of page table pointer of index and type.
 */
void* sb_get_pagetable_log_addr(int type, int index)
{
	u64* table_array_addr;

	switch(type)
	{
	case EPT_TYPE_PML4:
		table_array_addr = g_ept_info.pml4_page_addr_array;
		break;

	case EPT_TYPE_PDPTEPD:
		table_array_addr = g_ept_info.pdpte_pd_page_addr_array;
		break;

	case EPT_TYPE_PDEPT:
		table_array_addr = g_ept_info.pdept_page_addr_array;
		break;

	case EPT_TYPE_PTE:
	default:
		table_array_addr = g_ept_info.pte_page_addr_array;
		break;
	}

	return (void*)table_array_addr[index];
}

/*
 * Get physical address of page table pointer of index and type.
 */
void* sb_get_pagetable_phy_addr(int type, int index)
{
	void* table_log_addr;

	table_log_addr = sb_get_pagetable_log_addr(type, index);
	return (void*)virt_to_phys(table_log_addr);
}
