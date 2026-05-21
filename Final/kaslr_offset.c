#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>

MODULE_LICENSE("GPL");

struct syscall_anchor {
    const char *name;
    unsigned long static_addr;
};

static struct syscall_anchor anchors[] = {
#ifdef SYSCALL1_NAME
    {SYSCALL1_NAME, STATIC_ADDR1},
#endif
#ifdef SYSCALL2_NAME
    {SYSCALL2_NAME, STATIC_ADDR2},
#endif
#ifdef SYSCALL3_NAME
    {SYSCALL3_NAME, STATIC_ADDR3},
#endif
};

static unsigned long (*kallsyms_lookup_name_ptr)(const char *name);
static unsigned long kaslr_offset_result = 0;
static int kaslr_verified =0;

static struct proc_dir_entry *proc_entry;

/* o/p to proc */
static int kaslr_proc_show(struct seq_file *m, void *v) {
    switch (kaslr_verified) {
        case  1:  seq_printf(m, "0x%lx\n", kaslr_offset_result); break;
        case -1:  seq_printf(m, "ERROR: offset mismatch across anchors\n"); break;
        case -2:  seq_printf(m, "ERROR: one or more anchors unresolvable\n"); break;
        case -3:  seq_printf(m, "ERROR: no anchors resolved\n"); break;
        default:  seq_printf(m, "ERROR: unknown state\n"); break;
    }
    return 0;
}


static int kaslr_proc_open(struct inode *inode, struct file *file){
        return single_open(file, kaslr_proc_show,NULL);
}

static const struct proc_ops kaslr_proc_ops = {
        .proc_open = kaslr_proc_open,
        .proc_read = seq_read,
        .proc_lseek = seq_lseek,
        .proc_release = single_release,
};


static int resolve_kallsyms(void)
{
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
    };

    int ret = register_kprobe(&kp);
    if (ret < 0) {
        return ret;
    }
    
    kallsyms_lookup_name_ptr = (void *)kp.addr;
    unregister_kprobe(&kp);
    
    return kallsyms_lookup_name_ptr ? 0 : -ENOENT;
}

static int __init kaslr_finder_init(void)
{
    unsigned long runtime_addr;
    unsigned long kaslr_offset = 0;
    unsigned long first_offset = 0;
    int i;
    int matches = 0;
    int unresolved = 0;   /* anchors kallsyms couldn't find */
    int mismatches = 0;   /* anchors with inconsistent offsets */

    if (resolve_kallsyms()) {
        pr_err("KASLR Finder: Failed to resolve kallsyms_lookup_name\n");
        return -1;
    }

    if (ARRAY_SIZE(anchors) == 0) {
        pr_err("KASLR Finder: No syscall anchors defined.\n");
        return -EINVAL;
    }

    for (i = 0; i < ARRAY_SIZE(anchors); i++) {
        runtime_addr = (unsigned long)kallsyms_lookup_name_ptr(anchors[i].name);
        if (!runtime_addr) {
            pr_warn("KASLR Finder: Could not resolve anchor '%s'\n",
                    anchors[i].name);
            unresolved++;
            continue;
        }

        kaslr_offset = runtime_addr - anchors[i].static_addr;

        if (matches == 0) {
            first_offset = kaslr_offset;
            matches++;
        } else {
            if (kaslr_offset == first_offset) {
                matches++;
            } else {
                pr_warn("KASLR Finder: Anchor '%s' gave offset 0x%lx, "
                        "expected 0x%lx\n",
                        anchors[i].name, kaslr_offset, first_offset);
                mismatches++;
            }
        }
    }

    /* Every anchor must resolve and agree — no partial passes */
    if (unresolved > 0) {
        kaslr_verified = -2;
        pr_err("KASLR Finder: %d anchor(s) could not be resolved\n",
               unresolved);
    } else if (mismatches > 0) {
        kaslr_verified = -1;
        pr_err("KASLR Finder: %d anchor(s) produced inconsistent offsets — "
               "rootkit activity possible\n", mismatches);
    } else if (matches == ARRAY_SIZE(anchors) && matches > 0) {
        kaslr_offset_result = first_offset;
        kaslr_verified = 1;
        pr_info("KASLR Finder: offset confirmed by %d anchor(s): 0x%lx\n",
                matches, kaslr_offset_result);
    } else {
        kaslr_verified = -3;
        pr_err("KASLR Finder: No anchors resolved successfully\n");
    }

    proc_entry = proc_create("kaslr_offset", 0400, NULL, &kaslr_proc_ops);
    if (!proc_entry) {
        pr_err("KASLR Finder: Failed to create /proc/kaslr_offset\n");
        return -ENOMEM;
    }

    pr_info("KASLR Finder: /proc/kaslr_offset created\n");
    return 0;
}
static void __exit kaslr_finder_exit(void)
{
    
    if (proc_entry)
        proc_remove(proc_entry);
    pr_info("KASLR Finder: unloaded\n");
}

module_init(kaslr_finder_init);
module_exit(kaslr_finder_exit);
