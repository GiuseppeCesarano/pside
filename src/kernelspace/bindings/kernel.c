#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/fprobe.h>
#include <linux/fs.h>
#include <linux/ftrace_regs.h>
#include <linux/io.h>
#include <linux/ktime.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/perf_event.h>
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
void *c_kmalloc_atomic(size_t);

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
void c_disable_fprobe(struct fprobe *);
void c_enable_fprobe(struct fprobe *);

/* ftrace_regs */
unsigned long c_ftrace_regs_get_instruction_pointer(struct ftrace_regs *);
unsigned long c_ftrace_regs_get_argument(struct ftrace_regs *, unsigned int);
unsigned long c_ftrace_regs_get_stack_pointer(struct ftrace_regs *);
unsigned long c_ftrace_regs_get_return_value(struct ftrace_regs *);
void c_ftrace_regs_set_return_value(struct ftrace_regs *, unsigned long);
void c_ftrace_override_function_with_return(struct ftrace_regs *);
int c_ftrace_regs_query_register_offset(const char *);
unsigned long c_ftrace_regs_get_frame_pointer(struct ftrace_regs *);

/* Chardev */

struct chardev {
  dev_t dev;
  struct cdev cdev;
  struct class *class;
  struct device *device;
  struct file_operations fops;
  void *shared_buffer;
};

typedef long (*ioctl_fn)(struct file *, unsigned int, unsigned long);
int c_chardev_register(struct chardev *, const char *, ioctl_fn);
void c_chardev_unregister(struct chardev *);
void *c_get_shared_buffer(struct chardev *);

/* File */

struct file *c_filp_open(const char *, int, umode_t);
ssize_t c_kernel_write(struct file *, const void *, size_t, loff_t *);
ssize_t c_kernel_read(struct file *, void *, size_t, loff_t *);

/* Perf */
struct perf_event *c_perf_event_create_kernel_counter(struct perf_event_attr *,
                                                      int, pid_t,
                                                      perf_overflow_handler_t,
                                                      void *);
void c_perf_event_enable(struct perf_event *);
void c_perf_event_disable(struct perf_event *);
int c_perf_event_release_kernel(struct perf_event *);

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
void *c_kmalloc_atomic(size_t size) { return kmalloc(size, GFP_ATOMIC); }

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

void c_disable_fprobe(struct fprobe *fp) { disable_fprobe(fp); }
void c_enable_fprobe(struct fprobe *fp) { enable_fprobe(fp); }

/* ftrace_regs */
unsigned long c_ftrace_regs_get_instruction_pointer(struct ftrace_regs *regs) {
  return ftrace_regs_get_instruction_pointer(regs);
}

unsigned long c_ftrace_regs_get_argument(struct ftrace_regs *regs,
                                         unsigned int n) {
  return ftrace_regs_get_argument(regs, n);
}

unsigned long c_ftrace_regs_get_stack_pointer(struct ftrace_regs *regs) {
  return ftrace_regs_get_stack_pointer(regs);
}

unsigned long c_ftrace_regs_get_return_value(struct ftrace_regs *regs) {
  return ftrace_regs_get_return_value(regs);
}

void c_ftrace_regs_set_return_value(struct ftrace_regs *regs,
                                    unsigned long ret) {
  ftrace_regs_set_return_value(regs, ret);
}

unsigned long c_ftrace_regs_get_frame_pointer(struct ftrace_regs *regs) {
  return ftrace_regs_get_frame_pointer(regs);
}

/* Chardev */

static int internal_open(struct inode *inode, struct file *filp) {
  filp->private_data = container_of(inode->i_cdev, struct chardev, cdev);
  return 0;
}

static int internal_mmap(struct file *filp, struct vm_area_struct *vma) {
  struct chardev *d = filp->private_data;

  unsigned long pfn = virt_to_phys(d->shared_buffer) >> PAGE_SHIFT;
  unsigned long size = vma->vm_end - vma->vm_start;

  if (remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot)) {
    return -EAGAIN;
  }
  return 0;
}

int c_chardev_register(struct chardev *d, const char *name, ioctl_fn callback) {
  d->shared_buffer = (void *)get_zeroed_page(GFP_KERNEL);
  if (!d->shared_buffer)
    return -ENOMEM;

  if (alloc_chrdev_region(&d->dev, 0, 1, name) < 0) {
    free_page((unsigned long)d->shared_buffer);
    return -1;
  }

  d->fops.owner = THIS_MODULE;
  d->fops.open = internal_open;
  d->fops.mmap = internal_mmap;
  d->fops.unlocked_ioctl = callback;

  cdev_init(&d->cdev, &d->fops);
  if (cdev_add(&d->cdev, d->dev, 1) < 0) {
    unregister_chrdev_region(d->dev, 1);
    free_page((unsigned long)d->shared_buffer);
    return -1;
  }

  d->class = class_create(name);
  if (IS_ERR(d->class)) {
    cdev_del(&d->cdev);
    unregister_chrdev_region(d->dev, 1);
    free_page((unsigned long)d->shared_buffer);
    return -1;
  }

  d->device = device_create(d->class, NULL, d->dev, NULL, name);
  if (IS_ERR(d->device)) {
    class_destroy(d->class);
    cdev_del(&d->cdev);
    unregister_chrdev_region(d->dev, 1);
    free_page((unsigned long)d->shared_buffer);
    return -1;
  }

  return 0;
}

void c_chardev_unregister(struct chardev *d) {
  device_destroy(d->class, d->dev);
  class_destroy(d->class);
  cdev_del(&d->cdev);
  unregister_chrdev_region(d->dev, 1);

  if (d->shared_buffer) {
    free_page((unsigned long)d->shared_buffer);
    d->shared_buffer = NULL;
  }
}

void *c_get_shared_buffer(struct chardev *d) { return d->shared_buffer; }

/* File */

struct file *c_filp_open(const char *path, int permissions, umode_t mode) {
  return filp_open(path, permissions, mode);
}

ssize_t c_kernel_write(struct file *fd, const void *buff, size_t len,
                       loff_t *off) {
  return kernel_write(fd, buff, len, off);
}

ssize_t c_kernel_read(struct file *fd, void *buff, size_t len, loff_t *off) {
  return kernel_read(fd, buff, len, off);
}

/* Perf */
struct perf_event *
c_perf_event_create_kernel_counter(struct perf_event_attr *attr, int cpu,
                                   pid_t pid, perf_overflow_handler_t callback,
                                   void *context) {
  struct task_struct *task;
  struct pid *pid_struct;

  pid_struct = find_get_pid(pid);
  if (!pid_struct)
    return ERR_PTR(-ESRCH);

  task = get_pid_task(pid_struct, PIDTYPE_PID);
  put_pid(pid_struct);

  if (!task)
    return ERR_PTR(-ESRCH);

  struct perf_event *event =
      perf_event_create_kernel_counter(attr, cpu, task, callback, context);

  put_task_struct(task);

  return event;
}

void c_perf_event_enable(struct perf_event *event) { perf_event_enable(event); }
void c_perf_event_disable(struct perf_event *event) {
  perf_event_disable(event);
}

int c_perf_event_release_kernel(struct perf_event *event) {
  return perf_event_release_kernel(event);
}
