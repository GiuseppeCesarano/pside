#include "kconfig_overrides.h"
#include <linux/cdev.h>
#include <linux/completion.h>
#include <linux/dcache.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/ftrace_regs.h>
#include <linux/hrtimer.h>
#include <linux/io.h>
#include <linux/irqflags.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/perf_event.h>
#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/tracepoint.h>
#include <linux/uaccess.h>
#include <linux/wait_bit.h>

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
  struct mutex lock;
};

/* The Zig side mirrors these as fixed-size opaque byte arrays. */
_Static_assert(sizeof(struct chardev) <= 512,
               "Chardev placeholder in kernel.zig is too small");
_Static_assert(_Alignof(struct chardev) <= 8,
               "Chardev placeholder in kernel.zig is underaligned");
_Static_assert(sizeof(struct completion) <= 64,
               "Completion placeholder in bindings.zig is too small");
_Static_assert(_Alignof(struct completion) <= 8,
               "Completion placeholder in bindings.zig is underaligned");
_Static_assert(sizeof(spinlock_t) <= 64,
               "Spinlock placeholder in bindings.zig is too small");
_Static_assert(_Alignof(spinlock_t) <= 8,
               "Spinlock placeholder in bindings.zig is underaligned");
_Static_assert(sizeof(struct wait_bit_queue_entry) <= 64,
               "WaitBitQueueEntry placeholder in bindings.zig is too small");
_Static_assert(_Alignof(struct wait_bit_queue_entry) <= 8,
               "WaitBitQueueEntry placeholder in bindings.zig is underaligned");

/* The Zig side mirrors these values as enums. */
_Static_assert(TASK_RUNNING == 0x0,
               "TaskState.running in bindings.zig is out of sync");
_Static_assert(TASK_IDLE == 0x402,
               "TaskState.idle in bindings.zig is out of sync");
_Static_assert(HRTIMER_MODE_ABS == 0x0,
               "HrtimerMode.abs in bindings.zig is out of sync");

typedef int (*task_work_add_t)(struct task_struct *, struct callback_head *,
                               int);
typedef long (*ioctl_fn)(struct file *, unsigned int, unsigned long);

/* Prototypes */

/* Logging */
void c_printk(int, const char *, size_t);

/* Symbolization */
size_t c_ksym_symbol_len(void);

/* Copy from userspace */
unsigned long c_copy_from_user(void *, const void *, unsigned long);

/* Memory management */
extern const gfp_t c_gfp_kernel;
extern const gfp_t c_gfp_atomic;
void *c_kmalloc(size_t, gfp_t);

/* Time */
unsigned int c_hrtimer_resolution(void);

/* Task */
struct task_struct *c_get_current(void);
pid_t c_task_tgid_nr(struct task_struct *);
int c_get_nr_threads(struct task_struct *);
int c_task_is_running(struct task_struct *);
int c_task_is_dead(struct task_struct *);
int c_task_work_resolve(void);
int c_task_work_add(struct task_struct *, struct callback_head *, int);
void c_get_task_struct(struct task_struct *);
void c_put_task_struct(struct task_struct *);
unsigned long c_current_user_ip(void);
int c_user_mode(struct pt_regs *);

/* VMA */
int c_snapshot_executable_vmas(struct task_struct *, const char *,
                               struct VmaRange *, int);

/* Chardev */
int c_chardev_register(struct chardev *, const char *, ioctl_fn);
void c_chardev_unregister(struct chardev *);
void *c_session_progress_page(struct file *);
void *c_session_get_engine(struct file *);
void c_session_set_engine(struct file *, void *);
void c_session_lock(struct file *);
void c_session_unlock(struct file *);

/* Defined in Zig (main.zig): tears down an engine owned by a session. */
extern void pside_engine_release(void *);

/* Perf */
void *c_perf_event_overflow_handler_context(struct perf_event *);

/* Kthread */
struct task_struct *c_kthread_run(int (*)(void *), void *, const char *);

/* Scheduler */
void c_set_current_state(unsigned int);

/* Tracepoints */
void c_tracepoint_init(void);
int c_register_trace_sched_switch(void *, void *);
void c_unregister_trace_sched_switch(void *, void *);
int c_register_trace_sched_waking(void *, void *);
void c_unregister_trace_sched_waking(void *, void *);
int c_register_trace_task_newtask(void *, void *);
void c_unregister_trace_task_newtask(void *, void *);
int c_register_trace_sched_process_exit(void *, void *);
void c_unregister_trace_sched_process_exit(void *, void *);
void c_tracepoint_synchronize_unregister(void);

/* Preemption */
void c_preempt_disable(void);
void c_preempt_enable(void);

/* Execution context */
int c_in_task(void);
int c_in_nmi(void);
int c_preemptible(void);
int c_in_atomic(void);
int c_irqs_disabled(void);

/* Barriers */
void c_smp_mb(void);

/* Completion */
void c_init_completion(struct completion *);
void c_reinit_completion(struct completion *);

/* Spinlock */
void c_spin_lock_init(spinlock_t *);
unsigned long c_spin_lock_irqsave(spinlock_t *);
void c_spin_unlock_irqrestore(spinlock_t *, unsigned long);

/* Wait queue */
long c_prepare_to_wait_event(struct wait_queue_head *,
                             struct wait_bit_queue_entry *, int);
void c_finish_wait(struct wait_queue_head *, struct wait_bit_queue_entry *);

/* File */
loff_t c_file_size(struct file *);

/* Implementations */

/* Logging */
void c_printk(int level, const char *line, size_t len) {
  switch (level) {
  case 0:
    pr_err("%.*s\n", (int)len, line);
    break;
  case 1:
    pr_warn("%.*s\n", (int)len, line);
    break;
  case 2:
    pr_info("%.*s\n", (int)len, line);
    break;
  default:
    pr_debug("%.*s\n", (int)len, line);
    break;
  }
}

/* Symbolization */
size_t c_ksym_symbol_len(void) { return KSYM_SYMBOL_LEN; }

/* Copy from userspace */
unsigned long c_copy_from_user(void *to, const void *from, unsigned long n) {
  return copy_from_user(to, from, n);
}

/* Memory management */
const gfp_t c_gfp_kernel = GFP_KERNEL;
const gfp_t c_gfp_atomic = GFP_ATOMIC;

void *c_kmalloc(size_t size, gfp_t flags) { return kmalloc(size, flags); }

/* Time */
unsigned int c_hrtimer_resolution(void) { return hrtimer_resolution; }

/* Task */
struct task_struct *c_get_current(void) { return current; }
pid_t c_task_tgid_nr(struct task_struct *task) { return task_tgid_nr(task); }
int c_get_nr_threads(struct task_struct *task) { return get_nr_threads(task); }
int c_task_is_running(struct task_struct *task) {
  return task_is_running(task);
}
int c_task_is_dead(struct task_struct *task) {
  return (task->flags & PF_EXITING) || (task->exit_state != 0);
}

unsigned long c_current_user_ip(void) {
  return instruction_pointer(task_pt_regs(current));
}

int c_user_mode(struct pt_regs *regs) { return user_mode(regs); }

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

void c_get_task_struct(struct task_struct *task) { get_task_struct(task); }
void c_put_task_struct(struct task_struct *task) { put_task_struct(task); }

/* VMA */
int c_snapshot_executable_vmas(struct task_struct *task, const char *filter,
                               struct VmaRange *ranges, int max) {
  struct mm_struct *mm = get_task_mm(task);
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
  mmput(mm);

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

  mutex_init(&s->lock);
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

void c_session_lock(struct file *filp) {
  struct session *s = filp->private_data;
  mutex_lock(&s->lock);
}

void c_session_unlock(struct file *filp) {
  struct session *s = filp->private_data;
  mutex_unlock(&s->lock);
}

/* Perf */
void *c_perf_event_overflow_handler_context(struct perf_event *event) {
  return event->overflow_handler_context;
}

/* Kthread */
struct task_struct *c_kthread_run(int (*threadfn)(void *data), void *data,
                                  const char *name) {
  return kthread_run(threadfn, data, name);
}

/* Scheduler */
void c_set_current_state(unsigned int state) { set_current_state(state); }

/* Tracepoints */

static struct tracepoint_provider {
  struct tracepoint *sched_waking;
  struct tracepoint *sched_switch;
  struct tracepoint *task_newtask;
  struct tracepoint *sched_process_exit;
} __attribute__((aligned(32))) tp_prov = {0};

static void lookup_all_tps(struct tracepoint *tp, void *priv) {
  if (strcmp(tp->name, "sched_waking") == 0) {
    tp_prov.sched_waking = tp;
  } else if (strcmp(tp->name, "sched_switch") == 0) {
    tp_prov.sched_switch = tp;
  } else if (strcmp(tp->name, "task_newtask") == 0) {
    tp_prov.task_newtask = tp;
  } else if (strcmp(tp->name, "sched_process_exit") == 0) {
    tp_prov.sched_process_exit = tp;
  }
}

void c_tracepoint_init(void) {
  for_each_kernel_tracepoint(lookup_all_tps, NULL);
}

static int register_tp(struct tracepoint *tp, void *callback, void *data) {
  if (!tp)
    return -ENOENT;
  return tracepoint_probe_register(tp, callback, data);
}

static void unregister_tp(struct tracepoint *tp, void *callback, void *data) {
  if (tp)
    tracepoint_probe_unregister(tp, callback, data);
}

int c_register_trace_sched_switch(void *callback, void *data) {
  return register_tp(tp_prov.sched_switch, callback, data);
}

void c_unregister_trace_sched_switch(void *callback, void *data) {
  unregister_tp(tp_prov.sched_switch, callback, data);
}

int c_register_trace_sched_waking(void *callback, void *data) {
  return register_tp(tp_prov.sched_waking, callback, data);
}

void c_unregister_trace_sched_waking(void *callback, void *data) {
  unregister_tp(tp_prov.sched_waking, callback, data);
}

int c_register_trace_task_newtask(void *callback, void *data) {
  return register_tp(tp_prov.task_newtask, callback, data);
}

void c_unregister_trace_task_newtask(void *callback, void *data) {
  unregister_tp(tp_prov.task_newtask, callback, data);
}

int c_register_trace_sched_process_exit(void *callback, void *data) {
  return register_tp(tp_prov.sched_process_exit, callback, data);
}

void c_unregister_trace_sched_process_exit(void *callback, void *data) {
  unregister_tp(tp_prov.sched_process_exit, callback, data);
}

void c_tracepoint_synchronize_unregister(void) {
  tracepoint_synchronize_unregister();
}

/* Preemption */
void c_preempt_disable(void) { preempt_disable(); }
void c_preempt_enable(void) { preempt_enable(); }

/* Execution context */
int c_in_task(void) { return in_task(); }
int c_in_nmi(void) { return in_nmi(); }
int c_preemptible(void) { return preemptible(); }
int c_in_atomic(void) { return in_atomic(); }
int c_irqs_disabled(void) { return irqs_disabled(); }

/* Barriers */
void c_smp_mb(void) { smp_mb(); }

/* Completion */
void c_init_completion(struct completion *c) { init_completion(c); }
void c_reinit_completion(struct completion *c) { reinit_completion(c); }

/* Spinlock */
void c_spin_lock_init(spinlock_t *lock) { spin_lock_init(lock); }

unsigned long c_spin_lock_irqsave(spinlock_t *lock) {
  unsigned long flags;
  spin_lock_irqsave(lock, flags);
  return flags;
}

void c_spin_unlock_irqrestore(spinlock_t *lock, unsigned long flags) {
  spin_unlock_irqrestore(lock, flags);
}

/* Wait queue */
long c_prepare_to_wait_event(struct wait_queue_head *wq_head,
                             struct wait_bit_queue_entry *entry, int state) {
  return prepare_to_wait_event(wq_head, &entry->wq_entry, state);
}

void c_finish_wait(struct wait_queue_head *wq_head,
                   struct wait_bit_queue_entry *entry) {
  finish_wait(wq_head, &entry->wq_entry);
}

/* File */
loff_t c_file_size(struct file *f) { return i_size_read(file_inode(f)); }
