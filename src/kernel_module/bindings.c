#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/namei.h>
#include <linux/pid.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/uprobes.h>

// List of exported wrappers functions
void c_pr_err(const char *);
void c_pr_warn(const char *);
void c_pr_info(const char *);
void c_pr_debug(const char *);
void *c_kmalloc(size_t);
void c_kfree(void *);
void c_ndelay(unsigned long);
void c_udelay(unsigned long);
void c_mdelay(unsigned long);
u64 c_ktime_get_ns(void);
pid_t c_pid(void);
pid_t c_tid(void);
int c_register_kprobe(struct kprobe *);
void c_unregister_kprobe(struct kprobe *);
struct path c_kern_path(const char *);
void c_path_put(struct path *);
void *c_d_inode(void *);
struct uprobe *c_uprobe_register(void *, u64, struct uprobe_consumer *);
void c_uprobe_unregister(struct uprobe *, struct uprobe_consumer *);

// Implementations
void c_pr_err(const char *msg) { pr_err("%s", msg); }
void c_pr_warn(const char *msg) { pr_warn("%s", msg); }
void c_pr_info(const char *msg) { pr_info("%s", msg); }
void c_pr_debug(const char *msg) { pr_debug("%s", msg); }
void *c_kmalloc(size_t size) { return kmalloc(size, GFP_KERNEL); }
void c_kfree(void *ptr) { kfree(ptr); }
void c_ndelay(unsigned long nsec) { ndelay(nsec); }
void c_udelay(unsigned long usec) { udelay(usec); }
void c_mdelay(unsigned long msec) { mdelay(msec); }
u64 c_ktime_get_ns() { return ktime_get_ns(); }
pid_t c_pid(void) { return task_tgid_nr(current); }
pid_t c_tid(void) { return task_pid_nr(current); }
int c_register_kprobe(struct kprobe *probe) { return register_kprobe(probe); }
void c_unregister_kprobe(struct kprobe *probe) { unregister_kprobe(probe); }
struct path c_kern_path(const char *path) {
  struct path p;
  kern_path(path, LOOKUP_FOLLOW, &p);
  return p;
}
void c_path_put(struct path *path) { path_put(path); }
void *c_d_inode(void *dentry) { return d_inode(dentry); }
struct uprobe *c_uprobe_register(void *inode, u64 offset,
                                 struct uprobe_consumer *uc) {
  return uprobe_register(inode, offset, 0, uc);
}

void c_uprobe_unregister(struct uprobe *u, struct uprobe_consumer *uc) {
  uprobe_unregister_nosync(u, uc);
  uprobe_unregister_sync();
}
