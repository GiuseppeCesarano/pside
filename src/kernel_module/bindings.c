#include <linux/delay.h>
#include <linux/ktime.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/types.h>

// List of exported wrappers functions
void c_pr_err(const char *);
void c_pr_warn(const char *);
void c_pr_info(const char *);
void c_pr_debug(const char *);
void *c_kmalloc(size_t);
void c_kfree(void *);
void c_udelay(unsigned long);
u64 c_ktime_get_ns(void);

// Implementations
void c_pr_err(const char *msg) { pr_err("%s", msg); }
void c_pr_warn(const char *msg) { pr_warn("%s", msg); }
void c_pr_info(const char *msg) { pr_info("%s", msg); }
void c_pr_debug(const char *msg) { pr_debug("%s", msg); }
void *c_kmalloc(size_t size) { return kmalloc(size, GFP_KERNEL); }
void c_kfree(void *ptr) { kfree(ptr); }
void c_udelay(unsigned long usec) { udelay(usec); }
u64 c_ktime_get_ns() { return ktime_get_ns(); }
