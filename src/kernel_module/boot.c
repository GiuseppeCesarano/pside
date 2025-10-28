#include <linux/fs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

MODULE_AUTHOR("");
MODULE_DESCRIPTION("");
MODULE_LICENSE("MIT");

extern int init(void);
extern void deinit(void);

static int __init c_init(void) { return init(); }
static void __exit c_deinit(void) { deinit(); }

module_init(c_init);
module_exit(c_deinit);
