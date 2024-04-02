#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/minmax.h>
#include <linux/init.h>
#include <linux/atomic.h>
#include <linux/printk.h>


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
#define HAVE_PROC_OPS
#endif

#define PROCFS_MAX_SIZE 1024

#define PROCFS_NAME "dmce_hmk"

static struct proc_dir_entry *proc_file;

static size_t procfs_buffer_size = 0;

extern atomic64_t* dmce_magic;
//extern atomic_t dmce_buffer[];
extern int nbr_probes;

atomic_t __attribute__((common)) alloced = ATOMIC_INIT(0);

int magic = 0xAAAD11CE;

int* magic_buf;

static ssize_t proc_read(struct file *fp, char __user *buf, size_t buf_len, loff_t *offset)
{
    if (*offset)// || procfs_buffer_size == 0)
    {
        pr_debug("procfs_read: END\n");
        *offset = 0;
        return 0;
    }

    int* dmce_tmp_buffer = kmalloc(sizeof(int) * nbr_probes, GFP_KERNEL);

    for (size_t i = 0; i < nbr_probes; i++)
    {
        dmce_tmp_buffer[i] = atomic_fetch_add(0, &dmce_magic[i]);
    }

    procfs_buffer_size = min(sizeof(int) * nbr_probes, buf_len);

    if (copy_to_user(buf + *offset, dmce_tmp_buffer + *offset, procfs_buffer_size))
    {
        kfree(dmce_tmp_buffer);
        return -EFAULT;
    }
    kfree(dmce_tmp_buffer);


    *offset += procfs_buffer_size;

    // Write dmce buffer data to proc file

    pr_info("procfs_read: read %lu bytes\n", procfs_buffer_size);
    return procfs_buffer_size;
}

static ssize_t proc_write(struct file *fp, const char __user *buf, size_t buf_len, loff_t *offset)
{
    procfs_buffer_size = min(PROCFS_MAX_SIZE, buf_len);

    if (copy_from_user(dmce_magic, buf, procfs_buffer_size))
        return -EFAULT;

    *offset += procfs_buffer_size;

    pr_debug("procfs_write: write %lu bytes\n", procfs_buffer_size);
    return procfs_buffer_size;
}


#ifdef HAVE_PROC_OPS
static const struct proc_ops proc_file_fops = {
    .proc_read = proc_read,
    .proc_write = proc_write,
};
#else
static const struct file_operations proc_file_fops = {
    .read = proc_read,
    .write = proc_write,
};
#endif


int __init init_module(void)
{
    magic_buf = kmalloc(sizeof(int) * 1, GFP_KERNEL);
    magic_buf[0] = magic;
    //printk("dmce_mod: magic buffer allocated at: %px\n", magic_buf);
    proc_file = proc_create(PROCFS_NAME, 0644, NULL, &proc_file_fops);
    if (NULL == proc_file)
    {
        proc_remove(proc_file);
        pr_alert("error: could not create /proc/%s\n", PROCFS_NAME);
        return -ENOMEM;
    }

    pr_info("/proc/%s created\n", PROCFS_NAME);

    return 0;
}

void __exit cleanup_module(void)
{
    kfree(magic_buf);
    proc_remove(proc_file);
    pr_info("/proc/%s removed\n", PROCFS_NAME);
}


module_init(init_module);
module_exit(cleanup_module);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("In-tree test");