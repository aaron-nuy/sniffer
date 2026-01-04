#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/kfifo.h>
#include <linux/wait.h>
#include <linux/atomic.h>
#include <linux/sched.h>
#include <linux/timekeeping.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <net/sock.h>

#include "../ebpf/sniffer-ebpf.h"

#define EVENT_QUEUE_CAPACITY 256

static DEFINE_KFIFO(captured_events, packet_event, EVENT_QUEUE_CAPACITY);
static DEFINE_SPINLOCK(captured_events_lock);
static DECLARE_WAIT_QUEUE_HEAD(reader_wait_queue);
static atomic_t reader_is_attached = ATOMIC_INIT(0);
static u32 watched_process_id;

struct receive_context
{
	struct sock *socket;
	struct msghdr *message;
	void __user *user_buffer;
	uint64_t available_length;
};

static bool is_watched_process(void)
{
	u32 process_id = READ_ONCE(watched_process_id);

	return process_id && current->tgid == (int)process_id;
}

static bool find_first_user_buffer(const struct iov_iter *iterator, uint64_t requested_length,
								   void __user **user_buffer, uint64_t *available_length)
{
	uint64_t segment_length;

	if (iter_is_ubuf(iterator))
	{
		*user_buffer = iterator->ubuf + iterator->iov_offset;
		segment_length = iterator->count;
	}
	else if (iter_is_iovec(iterator))
	{
		const struct iovec *first_vector = iter_iov(iterator);

		if ((uint64_t)iterator->iov_offset > (uint64_t)first_vector->iov_len)
			return false;

		*user_buffer = first_vector->iov_base + iterator->iov_offset;
		segment_length = first_vector->iov_len - iterator->iov_offset;
	}
	else
	{
		return false;
	}

	if (!segment_length)
		return false;

	*available_length = requested_length < segment_length ? requested_length : segment_length;
	return true;
}

static void queue_event(packet_event *event, const void __user *user_buffer, uint64_t length)
{
	unsigned long uncopied_bytes;

	event->timestamp = ktime_get_real_fast_ns();
	event->process_id = (uint32_t)current->tgid;
	get_task_comm(event->process_name, current);

	if (length > PAYLOAD_LIMIT)
		length = PAYLOAD_LIMIT;

	pagefault_disable();
	uncopied_bytes = copy_from_user(event->payload, user_buffer, length);
	pagefault_enable();
	event->captured_length = (uint32_t)(length - uncopied_bytes);

	kfifo_in_spinlocked(&captured_events, event, 1, &captured_events_lock);
	wake_up_interruptible(&reader_wait_queue);
}

static int on_send_message(struct kprobe *probe, struct pt_regs *cpu_registers)
{
	struct sock *socket = (struct sock *)regs_get_kernel_argument(cpu_registers, 0);
	struct msghdr *message = (struct msghdr *)regs_get_kernel_argument(cpu_registers, 1);

	uint64_t bytes_to_send = regs_get_kernel_argument(cpu_registers, 2);
	
	const struct sockaddr_in *named_address = message->msg_name;
	void __user *user_buffer;
	uint64_t available_length;
	packet_event event;

	if (!is_watched_process() || socket->sk_family != AF_INET)
		return 0;

	if (!find_first_user_buffer(&message->msg_iter, bytes_to_send, &user_buffer, &available_length))
		return 0;

	memset(&event, 0, sizeof(event));
	event.direction = DIRECTION_TRANSMIT;
	event.protocol = socket->sk_protocol;
	event.packet_length = (uint32_t)bytes_to_send;
	event.source_address = socket->sk_rcv_saddr;
	event.source_port = htons(socket->sk_num);
	event.destination_address = socket->sk_daddr;
	event.destination_port = socket->sk_dport;

	if (named_address && message->msg_namelen >= sizeof(*named_address) &&
		named_address->sin_family == AF_INET)
	{
		event.destination_address = named_address->sin_addr.s_addr;
		event.destination_port = named_address->sin_port;
	}

	queue_event(&event, user_buffer, available_length);
	return 0;
}

static int on_receive_entry(struct kretprobe_instance *probe_instance, struct pt_regs *cpu_registers)
{
	struct receive_context *context = (struct receive_context *)probe_instance->data;
	struct sock *socket = (struct sock *)regs_get_kernel_argument(cpu_registers, 0);
	struct msghdr *message = (struct msghdr *)regs_get_kernel_argument(cpu_registers, 1);
	uint64_t requested_length = regs_get_kernel_argument(cpu_registers, 2);
	int receive_flags = (int)regs_get_kernel_argument(cpu_registers, 3);

	if (!is_watched_process() || socket->sk_family != AF_INET)
		return 1;

	if (receive_flags & MSG_ERRQUEUE)
		return 1;

	if (!find_first_user_buffer(&message->msg_iter, requested_length,
								&context->user_buffer, &context->available_length))
		return 1;

	context->socket = socket;
	context->message = message;
	return 0;
}

static int on_receive_return(struct kretprobe_instance *probe_instance, struct pt_regs *cpu_registers)
{
	struct receive_context *context = (struct receive_context *)probe_instance->data;
	const struct sockaddr_in *sender_address = context->message->msg_name;
	int received_bytes = (int)regs_return_value(cpu_registers);
	packet_event event;

	if (received_bytes <= 0)
		return 0;

	memset(&event, 0, sizeof(event));
	event.direction = DIRECTION_RECEIVE;
	event.protocol = context->socket->sk_protocol;
	event.packet_length = (uint32_t)received_bytes;
	event.source_address = context->socket->sk_daddr;
	event.source_port = context->socket->sk_dport;
	event.destination_address = context->socket->sk_rcv_saddr;
	event.destination_port = htons(context->socket->sk_num);

	if (sender_address && context->message->msg_namelen >= sizeof(*sender_address) &&
		sender_address->sin_family == AF_INET)
	{
		event.source_address = sender_address->sin_addr.s_addr;
		event.source_port = sender_address->sin_port;
	}

	queue_event(&event, context->user_buffer, min(context->available_length, (uint64_t)received_bytes));
	return 0;
}

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

static struct kprobe tcp_send_probe = {
	.symbol_name = "tcp_sendmsg",
	.pre_handler = on_send_message,
};

static struct kprobe udp_send_probe = {
	.symbol_name = "udp_sendmsg",
	.pre_handler = on_send_message,
};

static struct kprobe *send_probes[] = {&tcp_send_probe, &udp_send_probe};

static struct kretprobe tcp_receive_probe = {
	.kp = {.symbol_name = "tcp_recvmsg"},
	.entry_handler = on_receive_entry,
	.handler = on_receive_return,
	.maxactive = 64,
	.data_size = sizeof(struct receive_context),
};

static struct kretprobe udp_receive_probe = {
	.kp = {.symbol_name = "udp_recvmsg"},
	.entry_handler = on_receive_entry,
	.handler = on_receive_return,
	.maxactive = 64,
	.data_size = sizeof(struct receive_context),
};

static struct kretprobe *receive_probes[] = {&tcp_receive_probe, &udp_receive_probe};

static int __init sniffer_module_init(void)
{
	int error;

	error = register_kprobes(send_probes, ARRAY_SIZE(send_probes));
	if (error)
		return error;

	error = register_kretprobes(receive_probes, ARRAY_SIZE(receive_probes));
	if (error)
		goto unregister_send_probes;

	error = misc_register(&sniffer_device);
	if (error)
		goto unregister_receive_probes;

	pr_info("sniffer: /dev/sniffer ready\n");
	return 0;

unregister_receive_probes:
	unregister_kretprobes(receive_probes, ARRAY_SIZE(receive_probes));

unregister_send_probes:
	unregister_kprobes(send_probes, ARRAY_SIZE(send_probes));

	return error;
}

static void __exit sniffer_module_exit(void)
{
	misc_deregister(&sniffer_device);
	unregister_kretprobes(receive_probes, ARRAY_SIZE(receive_probes));
	unregister_kprobes(send_probes, ARRAY_SIZE(send_probes));
	pr_info("sniffer: gone\n");
}

module_init(sniffer_module_init);
module_exit(sniffer_module_exit);
MODULE_LICENSE("GPL");