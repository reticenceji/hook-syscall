/**
 * @file kernel_module.c
 * @author Ji Gaoqiang (jigaoqiang@bolean.com.cn)
 * @brief It's a Loadable kernel module that hooks the `execve` system call.
 * Before real syscall execve, it will call `guard_main(user_pathname,
 * user_argv, user_envp)` if `guard_main` return 0, real execve won't do. if
 * `guard_main` return not 0, real execve will do
 *
 * The log can be filtered by `dmesg | grep [Gurad]`
 * @version 0.1
 * @date 2021-11-15
 *
 * @copyright Copyright (c) 2021
 *
 * // TODO 检查类型
 */

#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h> /* which will have params */
#include <linux/types.h>
#include <linux/unistd.h> /* The list of system calls */
#include <linux/version.h>

/* For the current (process) structure, we need this to know who the
 * current user is.
 */
#include <linux/kallsyms.h> /* For sprint_symbol */
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
extern int before_execve(const char *user_pathname, char *const user_argv[],
                         char *const user_envp[]);
extern int after_execve(const char *user_pathname, char *const user_argv[],
                        char *const user_envp[]);
/* The address of the sys_call_table, which can be obtained with looking up
 * "/boot/System.map" or "/proc/kallsyms". When the kernel version is v5.7+,
 * without CONFIG_KPROBES, you can input the parameter or the module will look
 * up all the memory.
 */
static unsigned long sym = 0;
module_param(sym, ulong, 0644);

/* A pointer to the original system call. The reason we keep this, rather
 * than call the original function (sys_open), is because somebody else
 * might have replaced the system call before us. Note that this is not
 * 100% safe, because if another module replaced sys_open before us,
 * then when we are inserted, we will call the function in that module -
 * and it might be removed before we are.
 */
static unsigned long **sys_call_table;
static asmlinkage int (*original_call)(const char *pathname, char *const argv[],
                                       char *const envp[]);

static asmlinkage int our_sys_execve(const char *user_pathname,
                                     char *const user_argv[],
                                     char *const user_envp[]) {
    int ret;
    before_execve(user_pathname, user_argv, user_envp);
    ret = original_call(user_pathname, user_argv, user_envp);
    after_execve(user_pathname, user_argv, user_envp);
    return ret;
}

static unsigned long **get_sys_call_table(void) {
    const char sct_name[15] = "sys_call_table";
    char symbol[40] = {0};

    if (sym == 0) {
        pr_err("You have to specify the address of sys_call_table symbol\n");
        pr_err(
            "by /boot/System.map or /proc/kallsyms, which contains all the\n");
        pr_err("symbol addresses, into sym parameter.\n");
        return NULL;
    }
    sprint_symbol(symbol, sym);
    if (!strncmp(sct_name, symbol, sizeof(sct_name) - 1))
        return (unsigned long **)sym;
    return NULL;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
static inline void __write_cr0(unsigned long cr0) {
    asm volatile("mov %0,%%cr0" : "+r"(cr0) : : "memory");
}
#else
#define __write_cr0 write_cr0
#endif

static void enable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    __write_cr0(cr0);
}

static void disable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    __write_cr0(cr0);
}

static int __init hook_init(void) {
    if (!(sys_call_table = get_sys_call_table()))
        return -1;

    pr_info("Start hook sys_execve\n");
    disable_write_protection();

/* Kernels lower than 4.6 use assembly stubs to harden the hooking of critical
 * system calls like fork */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
    /* keep track of the original open function */
    original_call = (void *)sys_call_table[__NR_execve];

    /* use our open function instead */
    sys_call_table[__NR_execve] = (unsigned long *)our_sys_execve;
#else
#define CALL_LENGTH 5
    // const unsigned char token[] = "\x85\xc0\x74\x01\xc3";
    /* The address of `call sys_execve` */
    unsigned char *call = (unsigned char *)sys_call_table[__NR_execve];
    if (call[0] != 0xe8 || call[5] != 0x85)
        return -1;
    int original_offset = *(int *)(call + 1);
    int offset =
        (unsigned long)our_sys_execve - ((unsigned long)call + CALL_LENGTH);
    original_call = (void *)(call + CALL_LENGTH + original_offset);
    *(int *)(call + 1) = offset;
#endif

    enable_write_protection();

    return 0;
}

static void __exit hook_exit(void) {
    if (!sys_call_table)
        return;

    disable_write_protection();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
    /* Return the system call back to normal */
    if (sys_call_table[__NR_execve] != (unsigned long *)our_sys_execve) {
        pr_err("Somebody else also change the execve system call\n");
        pr_err("The system may be left in an unstable state.\n");
    }
    sys_call_table[__NR_execve] = (unsigned long *)original_call;
#else
    void *call = (void *)sys_call_table[__NR_execve];
    int original_offset = (void *)original_call - call - CALL_LENGTH;
    *(int *)(call + 1) = original_offset;
#endif
    enable_write_protection();
    pr_info("End hook sys_execve\n");
    msleep(1000);
}

module_init(hook_init);
module_exit(hook_exit);

MODULE_LICENSE("GPL");