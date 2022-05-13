#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>

#define MAX_SYMBOL_LEN	64
static char symbol[MAX_SYMBOL_LEN] = "__x64_sys_execve";
module_param_string(symbol, symbol, sizeof(symbol), 0644);
extern int handler_pre(struct kprobe *p, struct pt_regs *regs);
extern void handler_post(struct kprobe *p, struct pt_regs *regs,unsigned long flags);

/* For each probe you need to allocate a kprobe structure */
static struct kprobe kp = {
	.symbol_name	= symbol,
};

static int __init kprobe_init(void) {
    int ret;
    kp.pre_handler = handler_pre;
    kp.post_handler = handler_post;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("register_kprobe failed, returned %d\n", ret);
        return ret;
    }
    pr_info("Planted kprobe at %p\n", kp.addr);
    return 0;
}

static void __exit kprobe_exit(void) {
    unregister_kprobe(&kp);
    pr_info("kprobe at %p unregistered\n", kp.addr);
}

module_init(kprobe_init)
module_exit(kprobe_exit) 
MODULE_LICENSE("GPL");