#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

int before_execve(const char *user_pathname, char *const user_argv[],
                  char *const user_envp[]) {
    int ret;
    char *pathname;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
    struct pt_regs *regs = (struct pt_regs *)user_pathname;
    user_pathname = (char *)regs->di;
#endif

    pathname = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
    if (!pathname) {
        return -ENOBUFS;
    }
    ret = strncpy_from_user(pathname, user_pathname, PATH_MAX);
    if (ret < 0) {
        goto fail;
    }
    pr_info("%s execve\n", pathname);
    return 0;

fail:
    kfree(pathname);
    return ret;
}

int after_execve(const char *user_pathname, char *const user_argv[],
                 char *const user_envp[]) {
    return 0;
}