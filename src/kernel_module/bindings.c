#include <linux/printk.h>
#include <linux/slab.h>

// List of exported functions
void c_printk(const char *);
void *c_kmalloc(size_t);
void c_kfree(void*);

void c_printk(const char *msg) { printk(KERN_INFO "%s", msg); }
void *c_kmalloc(size_t size) { return kmalloc(size, GFP_KERNEL); }
void c_kfree(void *ptr) { kfree(ptr); }
