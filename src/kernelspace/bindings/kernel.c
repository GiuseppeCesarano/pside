#include <linux/cdev.h>
#include <linux/dcache.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/ftrace_regs.h>
#include <linux/io.h>
#include <linux/kprobes.h>
#include <linux/kthread.h>
#include <linux/ktime.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/perf_event.h>
#include <linux/pid.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/tracepoint.h>

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

/* Task */
struct task_struct *c_current_task(void);
pid_t c_pid(struct task_struct *);
pid_t c_tid(struct task_struct *);
int c_task_is_running(struct task_struct *);
struct callback_head **c_task_work_ptr(struct task_struct *);
typedef int (*task_work_add_t)(struct task_struct *, struct callback_head *,
                               int);
int c_task_work_add(struct task_struct *, struct callback_head *, int);
struct task_struct *c_get_task_from_tid(pid_t);
void c_get_task_struct(struct task_struct *t);
void c_put_task_struct(struct task_struct *t);

/* RCU */
void c_rcu_read_lock(void);
void c_rcu_read_unlock(void);

/* VMA */
struct vm_area_struct *c_find_vma(struct task_struct *, unsigned long);
unsigned long c_vma_start(struct vm_area_struct *);
const char *c_vma_filename(struct vm_area_struct *);

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
void *c_perf_event_context(struct perf_event *);

/* Kthread */

struct task_struct *c_kthread_run(int (*)(void *), void *, const char *);
int c_kthread_stop(struct task_struct *);
bool c_kthread_should_stop(void);

/* Sleep */

void c_sleep(unsigned long);

/* Tracepoints */
void c_tracepoint_init(void);
int c_register_sched_fork(void *, void *);
void c_unregister_sched_fork(void *, void *);
int c_register_sched_switch(void *, void *);
void c_unregister_sched_switch(void *, void *);
int c_register_sched_exit(void *, void *);
void c_unregister_sched_exit(void *, void *);
int c_register_sched_waking(void *, void *);
void c_unregister_sched_waking(void *, void *);
void c_tracepoint_sync(void);

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

/* Task */
struct task_struct *c_current_task(void) { return current; }
pid_t c_pid(struct task_struct *task) { return task_tgid_nr(task); }
pid_t c_tid(struct task_struct *task) { return task_pid_nr(task); }
int c_task_is_running(struct task_struct *task) {
  return task_is_running(task);
}
int c_task_is_dead(struct task_struct *task) {
    return (task->flags & PF_EXITING) || (task->exit_state != 0);
}
struct callback_head **c_task_work_ptr(struct task_struct *task) {
  return &task->task_works;
}

int c_task_work_add(struct task_struct *task, struct callback_head *twork,
                    int notify_mode) {
  static task_work_add_t real_task_work_add = NULL;

  if (unlikely(!task)) {
    struct kprobe kp = {.symbol_name = "task_work_add"};

    if (register_kprobe(&kp) < 0)
      return -ENOSYS;

    real_task_work_add = (task_work_add_t)kp.addr;
    unregister_kprobe(&kp);

    return 0;
  }

  if (!real_task_work_add)
    return -ENOSYS;
  return real_task_work_add(task, twork, notify_mode);
}

struct task_struct *c_get_task_from_tid(pid_t tid) {
  struct pid *pid_struct;
  struct task_struct *task;

  pid_struct = find_get_pid(tid);
  if (!pid_struct) {
    return NULL;
  }

  task = get_pid_task(pid_struct, PIDTYPE_PID);

  put_pid(pid_struct);

  return task;
}

void c_get_task_struct(struct task_struct *task) { get_task_struct(task); }
void c_put_task_struct(struct task_struct *task) { put_task_struct(task); }

/* RCU */
void c_rcu_read_lock(void) { rcu_read_lock(); }
void c_rcu_read_unlock(void) { rcu_read_unlock(); }

/* VMA */
struct vm_area_struct *c_find_vma(struct task_struct *task,
                                  unsigned long addr) {
  if (!task || !task->mm)
    return NULL;

  return vma_lookup(task->mm, addr);
}

unsigned long c_vma_start(struct vm_area_struct *vma) {
  return vma ? vma->vm_start : 0;
}

const char *c_vma_filename(struct vm_area_struct *vma) {
  if (vma && vma->vm_file) {
    return (const char *)vma->vm_file->f_path.dentry->d_name.name;
  }
  return NULL;
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

void *c_perf_event_context(struct perf_event *event) {
  return event->overflow_handler_context;
}

/* Kthread */
struct task_struct *c_kthread_run(int (*threadfn)(void *data), void *data,
                                  const char *name) {
  return kthread_run(threadfn, data, name);
}

int c_kthread_stop(struct task_struct *k) { return kthread_stop(k); }

bool c_kthread_should_stop(void) { return kthread_should_stop(); }

/* Sleep */
void c_sleep(unsigned long usecs) { usleep_range(usecs - 5, usecs + 5); }

// This is the actual tracepoint object defined in the kernel core
extern struct tracepoint __tracepoint_sched_process_fork;

/* Tracepoints */

struct tracepoint_provider {
  struct tracepoint *sched_fork;
  struct tracepoint *sched_exit;
  struct tracepoint *sched_waking;
  struct tracepoint *sched_switch;
} tp_prov = {0};

static void lookup_all_tps(struct tracepoint *tp, void *priv) {
  if (strcmp(tp->name, "sched_process_fork") == 0)
    tp_prov.sched_fork = tp;
  else if (strcmp(tp->name, "sched_process_exit") == 0)
    tp_prov.sched_exit = tp;
  else if (strcmp(tp->name, "sched_waking") == 0)
    tp_prov.sched_waking = tp;
  else if (strcmp(tp->name, "sched_switch") == 0)
    tp_prov.sched_switch = tp;
}

void c_tracepoint_init(void) {
  for_each_kernel_tracepoint(lookup_all_tps, NULL);
}

int c_register_sched_fork(void *callback, void *data) {
  if (!tp_prov.sched_fork)
    return -ENOENT;
  return tracepoint_probe_register(tp_prov.sched_fork, callback, data);
}

void c_unregister_sched_fork(void *callback, void *data) {
  if (tp_prov.sched_fork)
    tracepoint_probe_unregister(tp_prov.sched_fork, callback, data);
}

int c_register_sched_switch(void *callback, void *data) {
  if (!tp_prov.sched_switch)
    return -ENOENT;
  return tracepoint_probe_register(tp_prov.sched_switch, callback, data);
}

void c_unregister_sched_switch(void *callback, void *data) {
  if (tp_prov.sched_switch)
    tracepoint_probe_unregister(tp_prov.sched_switch, callback, data);
}

int c_register_sched_exit(void *callback, void *data) {
  if (!tp_prov.sched_exit)
    return -ENOENT;
  return tracepoint_probe_register(tp_prov.sched_exit, callback, data);
}

void c_unregister_sched_exit(void *callback, void *data) {
  if (tp_prov.sched_exit)
    tracepoint_probe_unregister(tp_prov.sched_exit, callback, data);
}

int c_register_sched_waking(void *callback, void *data) {
  if (!tp_prov.sched_waking)
    return -ENOENT;
  return tracepoint_probe_register(tp_prov.sched_waking, callback, data);
}

void c_unregister_sched_waking(void *callback, void *data) {
  if (tp_prov.sched_waking)
    tracepoint_probe_unregister(tp_prov.sched_waking, callback, data);
}

void c_tracepoint_sync(void) { tracepoint_synchronize_unregister(); }
