#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
#define PROC_NAME "syscall_live"

static unsigned long (*kallsyms_lookup_name_ptr)(const char *name);
static unsigned long *sys_call_table;

static int resolve_kallsyms(void) {
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    int ret = register_kprobe(&kp);
    if (ret < 0) return ret;
    kallsyms_lookup_name_ptr = (void *)kp.addr;
    unregister_kprobe(&kp);
    return kallsyms_lookup_name_ptr ? 0 : -ENOENT;
}

static int syscall_live_show(struct seq_file *m, void *v) {
    int i;
    char namebuf[KSYM_NAME_LEN];
    for (i = 0; i < NR_syscalls; i++) {
        unsigned long addr = sys_call_table[i];
        sprint_symbol(namebuf, addr);
        seq_printf(m, "%s\n",namebuf);
    }
    return 0;
}

static int syscall_live_open(struct inode *inode, struct file *file) {
    return single_open(file, syscall_live_show, NULL);
}

static const struct proc_ops proc_fops = {
    .proc_open    = syscall_live_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

static int __init reporter_init(void) {
    if (resolve_kallsyms()) return -ENOENT;
    sys_call_table = (unsigned long *)kallsyms_lookup_name_ptr("sys_call_table");
    if (!sys_call_table) return -ENOENT;

    if (!proc_create(PROC_NAME, 0400, NULL, &proc_fops)) return -ENOMEM;
    pr_info("syscall_live module loaded\n");
    return 0;
}

static void __exit reporter_exit(void) {
    remove_proc_entry(PROC_NAME, NULL);
    pr_info("syscall_live module unloaded\n");
}

module_init(reporter_init);
module_exit(reporter_exit);
