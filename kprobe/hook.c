#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

/* kprobe pre_handler: called just before the probed instruction is executed */
int __kprobes handler_pre(struct kprobe *p, struct pt_regs *regs) {
    char *pathname = (char *)regs->di; 
    pr_info("%s execve\n", pathname);
    pr_info("<%s> p->addr = 0x%p, ip = %lx\n", p->symbol_name, p->addr, regs->ip);

    return 0;
}

/* called after the probed instruction is executed */
void __kprobes handler_post(struct kprobe *p, struct pt_regs *regs,
				unsigned long flags)
{
    return;
}