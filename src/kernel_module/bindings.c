#include <linux/delay.h>
#include <linux/ktime.h>
#include <linux/pid.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/types.h>

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
