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
#ifndef __SHADOW_WATCHER_H__
#define __SHADOW_WATCHER_H__

/*
 * Macros.
 */
/*
 * Max count of tasks and modules.
 * If your system has more than 100000 tasks or 10000 modules, change these
 * values.
 */
#define TASK_NODE_MAX		(PID_MAX_LIMIT)
#define MODULE_NODE_MAX		(10000)

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
#define GET_D_INODE_FROM_FILE_PTR(x)	((x)->f_dentry->d_inode)
#else
#define GET_D_INODE_FROM_FILE_PTR(x)	((x)->f_path.dentry->d_inode)
#endif

/* Task information structure. */
struct sb_task_node
{
	struct list_head list;
	pid_t pid;
	pid_t tgid;
	struct task_struct* task;
	char comm[TASK_COMM_LEN];
};

/* Module information structure. */
struct sb_module_node
{
	struct list_head list;
	struct module* module;
	int protect;
	u64 base;
	u64 size;
	char name[MODULE_NAME_LEN];
};

/* Task manager structure. */
struct sb_task_manager
{
	struct list_head free_node_head;
	struct list_head existing_node_head;
	struct sb_task_node* pool;
};

/* Module manager structure. */
struct sb_module_manager
{
	struct list_head free_node_head;
	struct list_head existing_node_head;
	struct sb_module_node* pool;
};

/*
 * Functions.
 */
int sb_prepare_shadow_watcher(void);
void sb_init_shadow_watcher(int reinitialize);
void sb_sw_callback_vm_timer(int cpu_id);
void sb_sw_callback_task_switch(int cpu_id);
void sb_sw_callback_add_task(int cpu_id, struct sb_vm_exit_guest_register* context);
void sb_sw_callback_del_task(int cpu_id, struct sb_vm_exit_guest_register* context);
void sb_sw_callback_insmod(int cpu_id, struct sb_vm_exit_guest_register* context);
void sb_sw_callback_rmmod(int cpu_id, struct sb_vm_exit_guest_register* context);
void sb_protect_shadow_watcher_data(void);

#endif
