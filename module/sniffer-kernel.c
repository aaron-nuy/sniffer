#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/kfifo.h>
#include <linux/wait.h>
#include <linux/atomic.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

#include "../ebpf/sniffer-ebpf.h"

#define EVENT_QUEUE_CAPACITY 256

static DEFINE_KFIFO(captured_events, packet_event, EVENT_QUEUE_CAPACITY);
static DEFINE_SPINLOCK(captured_events_lock);
static DECLARE_WAIT_QUEUE_HEAD(reader_wait_queue);
static atomic_t reader_is_attached = ATOMIC_INIT(0);
static u32 watched_process_id;

static int sniffer_open(struct inode *inode, struct file *file)
{
	unsigned long interrupt_flags;

	if (atomic_cmpxchg(&reader_is_attached, 0, 1))
		return -EBUSY;

	WRITE_ONCE(watched_process_id, 0);

	spin_lock_irqsave(&captured_events_lock, interrupt_flags);
	kfifo_reset(&captured_events);

	spin_unlock_irqrestore(&captured_events_lock, interrupt_flags);

	return 0;
}

static int sniffer_release(struct inode *inode, struct file *file)
{
	WRITE_ONCE(watched_process_id, 0);
	atomic_set(&reader_is_attached, 0);
	return 0;
}

static ssize_t sniffer_read(struct file *file, char __user *user_buffer,
							size_t buffer_size, loff_t *file_offset)
{
	packet_event event;

	if (buffer_size < sizeof(event))
		return -EINVAL;

	if (wait_event_interruptible(reader_wait_queue,
								 kfifo_out_spinlocked(&captured_events, &event, 1,
													  &captured_events_lock)))
		return -ERESTARTSYS;

	if (copy_to_user(user_buffer, &event, sizeof(event)))
		return -EFAULT;

	return sizeof(event);
}

static long sniffer_ioctl(struct file *file, unsigned int command, unsigned long argument)
{
	uint32_t process_id;

	if (command != SNIFFER_SET_PID)
		return -ENOTTY;

	if (get_user(process_id, (uint32_t __user *)argument))
		return -EFAULT;

	WRITE_ONCE(watched_process_id, process_id);
	return 0;
}

static const struct file_operations sniffer_file_operations = {
	.owner = THIS_MODULE,
	.open = sniffer_open,
	.release = sniffer_release,
	.read = sniffer_read,
	.unlocked_ioctl = sniffer_ioctl,
};

static struct miscdevice sniffer_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "sniffer",
	.fops = &sniffer_file_operations,
};

static int __init sniffer_module_init(void)
{
	int error;

	error = misc_register(&sniffer_device);
	if (error)
		return error;

	pr_info("sniffer: /dev/sniffer ready\n");
	return 0;
}

static void __exit sniffer_module_exit(void)
{
	misc_deregister(&sniffer_device);
	pr_info("sniffer: gone\n");
}

module_init(sniffer_module_init);
module_exit(sniffer_module_exit);
MODULE_LICENSE("GPL");
