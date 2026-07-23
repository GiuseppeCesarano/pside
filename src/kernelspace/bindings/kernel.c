#include <linux/cdev.h>
#include <linux/completion.h>
#include <linux/dcache.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/ftrace_regs.h>
#include <linux/io.h>
#include <linux/kprobes.h>
#include <linux/kthread.h>
#include <linux/ktime.h>
#include <linux/mm.h>
#include <linux/namei.h>
#include <linux/perf_event.h>
#include <linux/pid.h>
#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/tracepoint.h>
#include <linux/uaccess.h>

/* Types shared with the Zig bindings */

struct VmaRange {
  unsigned long begin;
  unsigned long end;
};

struct chardev {
  dev_t dev;
  struct cdev cdev;
  struct class *class;
  struct device *device;
  struct file_operations fops;
};

struct session {
  struct chardev *dev;
  void *progress_page;
  void *engine; 
};

/* The Zig side mirrors these as fixed-size opaque byte arrays. */
_Static_assert(sizeof(struct chardev) <= 512,
               "CharDevice placeholder in kernel.zig is too small");
_Static_assert(sizeof(struct completion) <= 64,
               "Completion placeholder in kernel.zig is too small");

typedef int (*task_work_add_t)(struct task_struct *, struct callback_head *,
                               int);
typedef long (*ioctl_fn)(struct file *, unsigned int, unsigned long);

/* Prototypes */

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
int c_task_thread_count(struct task_struct *);
int c_task_is_running(struct task_struct *);
int c_task_is_dead(struct task_struct *);
int c_task_is_reaped(struct task_struct *);
int c_task_work_resolve(void);
int c_task_work_add(struct task_struct *, struct callback_head *, int);
struct task_struct *c_get_task_from_tid(pid_t);
void c_get_task_struct(struct task_struct *);
void c_put_task_struct(struct task_struct *);
unsigned long c_current_user_ip(void);
int c_regs_in_kernel(struct pt_regs *);
long c_copy_from_user_nofault(void *, const void *, unsigned long);

/* RCU */
void c_rcu_read_lock(void);
void c_rcu_read_unlock(void);

/* VMA */
int c_snapshot_executable_vmas(struct task_struct *, const char *,
                               struct VmaRange *, int);

/* Chardev */
int c_chardev_register(struct chardev *, const char *, ioctl_fn);
void c_chardev_unregister(struct chardev *);
void *c_session_progress_page(struct file *);
void *c_session_get_engine(struct file *);
void c_session_set_engine(struct file *, void *);

/* Defined in Zig (main.zig): tears down an engine owned by a session. */
extern void pside_engine_release(void *);

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
int c_register_sched_switch(void *, void *);
void c_unregister_sched_switch(void *, void *);
int c_register_sched_waking(void *, void *);
void c_unregister_sched_waking(void *, void *);
int c_register_task_newtask(void *, void *);
void c_unregister_task_newtask(void *, void *);
void c_tracepoint_sync(void);

/* Preemption */
void c_preempt_disable(void);
void c_preempt_enable(void);

/* Execution context */
int c_in_task(void);

/* Completion */
void c_init_completion(struct completion *);
void c_wait_for_completion(struct completion *);
void c_complete(struct completion *);
void c_reinit_completion(struct completion *);

/* File */
struct file *c_fget(int);
void c_fput(struct file *);
ssize_t c_kernel_write(struct file *, const void *, size_t, loff_t *);
ssize_t c_file_size(struct file *);

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
int c_task_thread_count(struct task_struct *task) { return get_nr_threads(task); }
int c_task_is_running(struct task_struct *task) {
  return task_is_running(task);
}
int c_task_is_dead(struct task_struct *task) {
  return (task->flags & PF_EXITING) || (task->exit_state != 0);
}
int c_task_is_reaped(struct task_struct *task) {
  return task->exit_state == EXIT_DEAD;
}

unsigned long c_current_user_ip(void) {
  return instruction_pointer(task_pt_regs(current));
}

int c_regs_in_kernel(struct pt_regs *regs) { return !user_mode(regs); }

long c_copy_from_user_nofault(void *dst, const void *src, unsigned long size) {
  return copy_from_user_nofault(dst, src, size);
}

static task_work_add_t real_task_work_add = NULL;

int c_task_work_resolve(void) {
  struct kprobe kp = {.symbol_name = "task_work_add"};

  if (register_kprobe(&kp) < 0)
    return -ENOSYS;

  real_task_work_add = (task_work_add_t)kp.addr;
  unregister_kprobe(&kp);

  return 0;
}

int c_task_work_add(struct task_struct *task, struct callback_head *twork,
                    int notify_mode) {
  if (!real_task_work_add)
    return -ENOSYS;
  return real_task_work_add(task, twork, notify_mode);
}

struct task_struct *c_get_task_from_tid(pid_t tid) {
  struct pid *pid_struct = NULL;
  struct task_struct *task = NULL;

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
int c_snapshot_executable_vmas(struct task_struct *task, const char *filter,
                               struct VmaRange *ranges, int max) {
  struct mm_struct *mm = task->mm;
  if (!mm)
    return 0;

  int count = 0;
  struct vm_area_struct *vma;
  VMA_ITERATOR(vmi, mm, 0);

  mmap_read_lock(mm);
  for_each_vma(vmi, vma) {
    if (!(vma->vm_flags & VM_EXEC))
      continue;

    if (filter && *filter) {
      if (!vma->vm_file ||
          strcmp(vma->vm_file->f_path.dentry->d_name.name, filter) != 0)
        continue;
    }

    if (count < max)
      ranges[count] = (struct VmaRange){vma->vm_start, vma->vm_end};
    count++;
  }
  mmap_read_unlock(mm);

  return count;
}

/* Chardev */
static int internal_open(struct inode *inode, struct file *filp) {
  struct chardev *d = container_of(inode->i_cdev, struct chardev, cdev);

  struct session *s = kzalloc(sizeof(*s), GFP_KERNEL);
  if (!s)
    return -ENOMEM;

  s->progress_page = (void *)get_zeroed_page(GFP_KERNEL);
  if (!s->progress_page) {
    kfree(s);
    return -ENOMEM;
  }

  s->dev = d;
  filp->private_data = s;
  return 0;
}

static int internal_release(struct inode *inode, struct file *filp) {
  struct session *s = filp->private_data;
  if (!s)
    return 0;

  if (s->engine)
    pside_engine_release(s->engine);

  if (s->progress_page)
    free_page((unsigned long)s->progress_page);

  kfree(s);
  return 0;
}

static int internal_mmap(struct file *filp, struct vm_area_struct *vma) {
  struct session *s = filp->private_data;

  unsigned long size = vma->vm_end - vma->vm_start;

  if (vma->vm_pgoff != 0 || size > PAGE_SIZE)
    return -EINVAL;

  unsigned long pfn = virt_to_phys(s->progress_page) >> PAGE_SHIFT;

  if (remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot)) {
    return -EAGAIN;
  }
  return 0;
}

int c_chardev_register(struct chardev *d, const char *name, ioctl_fn callback) {
  int rc;

  rc = alloc_chrdev_region(&d->dev, 0, 1, name);
  if (rc < 0)
    return rc;

  d->fops.owner = THIS_MODULE;
  d->fops.open = internal_open;
  d->fops.release = internal_release;
  d->fops.mmap = internal_mmap;
  d->fops.unlocked_ioctl = callback;
  cdev_init(&d->cdev, &d->fops);

  rc = cdev_add(&d->cdev, d->dev, 1);
  if (rc < 0)
    goto unregister_region;

  d->class = class_create(name);
  if (IS_ERR(d->class)) {
    rc = PTR_ERR(d->class);
    goto del_cdev;
  }

  d->device = device_create(d->class, NULL, d->dev, NULL, name);
  if (IS_ERR(d->device)) {
    rc = PTR_ERR(d->device);
    goto destroy_class;
  }

  return 0;

destroy_class:
  class_destroy(d->class);
del_cdev:
  cdev_del(&d->cdev);
unregister_region:
  unregister_chrdev_region(d->dev, 1);
  return rc;
}

void c_chardev_unregister(struct chardev *d) {
  device_destroy(d->class, d->dev);
  class_destroy(d->class);
  cdev_del(&d->cdev);
  unregister_chrdev_region(d->dev, 1);
}

void *c_session_progress_page(struct file *filp) {
  struct session *s = filp->private_data;
  return s->progress_page;
}

void *c_session_get_engine(struct file *filp) {
  struct session *s = filp->private_data;
  return s->engine;
}

void c_session_set_engine(struct file *filp, void *engine) {
  struct session *s = filp->private_data;
  s->engine = engine;
}

/* Perf */
struct perf_event *
c_perf_event_create_kernel_counter(struct perf_event_attr *attr, int cpu,
                                   pid_t pid, perf_overflow_handler_t callback,
                                   void *context) {
  struct task_struct *task = NULL;
  struct pid *pid_struct = NULL;

  pid_struct = find_get_pid(pid);
  if (!pid_struct) {
    return ERR_PTR(-ESRCH);
  }

  task = get_pid_task(pid_struct, PIDTYPE_PID);
  put_pid(pid_struct);

  if (!task) {
    return ERR_PTR(-ESRCH);
  }

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
void c_sleep(unsigned long usecs) {
  unsigned long min = usecs > 5 ? usecs - 5 : usecs;
  usleep_range(min, usecs + 5);
}

/* Tracepoints */

static struct tracepoint_provider {
  struct tracepoint *sched_waking;
  struct tracepoint *sched_switch;
  struct tracepoint *task_newtask;
} __attribute__((aligned(32))) tp_prov = {0};

static void lookup_all_tps(struct tracepoint *tp, void *priv) {
  if (strcmp(tp->name, "sched_waking") == 0) {
    tp_prov.sched_waking = tp;
  } else if (strcmp(tp->name, "sched_switch") == 0) {
    tp_prov.sched_switch = tp;
  } else if (strcmp(tp->name, "task_newtask") == 0) {
    tp_prov.task_newtask = tp;
  }
}

void c_tracepoint_init(void) {
  for_each_kernel_tracepoint(lookup_all_tps, NULL);
}

int c_register_sched_switch(void *callback, void *data) {
  if (!tp_prov.sched_switch)
    return -ENOENT;
  return tracepoint_probe_register(tp_prov.sched_switch, callback, data);
}

void c_unregister_sched_switch(void *callback, void *data) {
  if (tp_prov.sched_switch) {
    tracepoint_probe_unregister(tp_prov.sched_switch, callback, data);
  }
}

int c_register_sched_waking(void *callback, void *data) {
  if (!tp_prov.sched_waking)
    return -ENOENT;
  return tracepoint_probe_register(tp_prov.sched_waking, callback, data);
}

void c_unregister_sched_waking(void *callback, void *data) {
  if (tp_prov.sched_waking) {
    tracepoint_probe_unregister(tp_prov.sched_waking, callback, data);
  }
}

int c_register_task_newtask(void *callback, void *data) {
  if (!tp_prov.task_newtask)
    return -ENOENT;
  return tracepoint_probe_register(tp_prov.task_newtask, callback, data);
}
void c_unregister_task_newtask(void *callback, void *data) {
  if (tp_prov.task_newtask) {
    tracepoint_probe_unregister(tp_prov.task_newtask, callback, data);
  }
}
void c_tracepoint_sync(void) { tracepoint_synchronize_unregister(); }

/* Preemption */
void c_preempt_disable(void) { preempt_disable(); }
void c_preempt_enable(void) { preempt_enable(); }

/* Execution context */
int c_in_task(void) { return in_task(); }

/* Completion */
void c_init_completion(struct completion *c) { init_completion(c); }
void c_wait_for_completion(struct completion *c) { wait_for_completion(c); }
void c_complete(struct completion *c) { complete(c); }
void c_reinit_completion(struct completion *c) { reinit_completion(c); }

/* File */
struct file *c_fget(int fd) { return fget(fd); }
void c_fput(struct file *f) { fput(f); }
ssize_t c_kernel_write(struct file *f, const void *buf, size_t count,
                       loff_t *pos) {
  return kernel_write(f, buf, count, pos);
}
ssize_t c_file_size(struct file *f) { return i_size_read(file_inode(f)); }
