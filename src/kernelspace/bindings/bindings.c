#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/fprobe.h>
#include <linux/fs.h>
#include <linux/ktime.h>
#include <linux/namei.h>
#include <linux/pid.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uprobes.h>

/* Forward declarations */

/* Logging */
void c_pr_err(const char *);
void c_pr_warn(const char *);
void c_pr_info(const char *);
void c_pr_debug(const char *);

/* Copy from/to userspace */
unsigned long c_copy_to_user(void *, const void *, unsigned long);
unsigned long c_copy_from_user(void *, const void *, unsigned long);

/* Memory management */
void *c_kmalloc(size_t);
void c_kfree(void *);

/* Delay utilities */
void c_ndelay(unsigned long);
void c_udelay(unsigned long);
void c_mdelay(unsigned long);

/* Time */
u64 c_ktime_get_ns(void);

/* Task info */
pid_t c_pid(void);
pid_t c_tid(void);

/* Paths */
struct path c_kern_path(const char *, int *);
void c_path_put(struct path *);

/* Dentry / inode */
void *c_d_inode(void *);

/* Uprobes */
struct uprobe *c_uprobe_register(void *, u64, struct uprobe_consumer *);
void c_uprobe_unregister(struct uprobe *, struct uprobe_consumer *);

/* Fprobes */
int c_register_fprobe(struct fprobe *, const char *, const char *);
int c_unregister_fprobe(struct fprobe *);

/* Chardev */
struct chardev {
  struct cdev cdev;
  struct file_operations fops;
  dev_t dev;
  struct class *class;
  struct device *device;
};

typedef ssize_t (*read_fn)(struct file *file, char __user *buf, size_t count,
                           loff_t *offset);
typedef ssize_t (*write_fn)(struct file *file, const char __user *buf,
                            size_t count, loff_t *offset);
int c_chardev_register(struct chardev *, const char *, read_fn, write_fn);
void c_chardev_unregister(struct chardev *);

/* Implementations */

/* Logging */
void c_pr_err(const char *msg) { pr_err("%s", msg); }
void c_pr_warn(const char *msg) { pr_warn("%s", msg); }
void c_pr_info(const char *msg) { pr_info("%s", msg); }
void c_pr_debug(const char *msg) { pr_debug("%s", msg); }

/* Copy from/to userspace */
unsigned long c_copy_to_user(void *to, const void *from, unsigned long n) {
  return copy_to_user(to, from, n);
}

unsigned long c_copy_from_user(void *to, const void *from, unsigned long n) {
  return copy_from_user(to, from, n);
}

/* Memory management */
void *c_kmalloc(size_t size) { return kmalloc(size, GFP_KERNEL); }
void c_kfree(void *ptr) { kfree(ptr); }

/* Delay utilities */
void c_ndelay(unsigned long nsec) { ndelay(nsec); }
void c_udelay(unsigned long usec) { udelay(usec); }
void c_mdelay(unsigned long msec) { mdelay(msec); }

/* Time */
u64 c_ktime_get_ns(void) { return ktime_get_ns(); }

/* Task info */
pid_t c_pid(void) { return task_tgid_nr(current); }
pid_t c_tid(void) { return task_pid_nr(current); }

/* Paths */
struct path c_kern_path(const char *path, int *err) {
  struct path p;
  *err = kern_path(path, LOOKUP_FOLLOW, &p);
  return p;
}

void c_path_put(struct path *path) { path_put(path); }

/* Dentry / inode */
void *c_d_inode(void *dentry) { return d_inode(dentry); }

/* Uprobes */
struct uprobe *c_uprobe_register(void *inode, u64 offset,
                                 struct uprobe_consumer *uc) {
  return uprobe_register(inode, offset, 0, uc);
}

void c_uprobe_unregister(struct uprobe *u, struct uprobe_consumer *uc) {
  uprobe_unregister_nosync(u, uc);
  uprobe_unregister_sync();
}

/* Fprobes */
int c_register_fprobe(struct fprobe *probe, const char *filter,
                      const char *nofilter) {
  return register_fprobe(probe, filter, nofilter);
}

int c_unregister_fprobe(struct fprobe *probe) {
  return unregister_fprobe(probe);
}

/* Chardev */

int c_chardev_register(struct chardev *d, const char *name, read_fn rd_fn,
                       write_fn wr_fn) {
  alloc_chrdev_region(&d->dev, 0, 1, name);

  d->fops.owner = THIS_MODULE;
  d->fops.read = rd_fn;
  d->fops.write = wr_fn;

  cdev_init(&d->cdev, &d->fops);
  cdev_add(&d->cdev, d->dev, 1);

  d->class = class_create(name);
  d->device = device_create(d->class, NULL, d->dev, NULL, name);

  return 0;
}

void c_chardev_unregister(struct chardev *d) {
  device_destroy(d->class, d->dev);
  class_destroy(d->class);
  cdev_del(&d->cdev);
  unregister_chrdev_region(d->dev, 1);
}
