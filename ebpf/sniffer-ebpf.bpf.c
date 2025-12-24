#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "sniffer-ebpf.h"

char bpf_license[] SEC("license") = "GPL";

struct pt_regs
{
    uint64_t r15, r14, r13, r12, rbp, rbx, r11, r10, r9, r8;
    uint64_t rax, rcx, rdx, rsi, rdi, orig_ax, rip, cs, flags, rsp, ss;
};

struct sk_buff
{
    uint8_t *head;
    uint8_t *data;
    uint32_t len;
    uint16_t transport_header;
    uint16_t network_header;
} __attribute__((preserve_access_index));

struct sock_common
{
    uint32_t skc_daddr;
    uint32_t skc_rcv_saddr;
    uint16_t skc_dport;
    uint16_t skc_num;
    uint16_t skc_family;
} __attribute__((preserve_access_index));

struct sock
{
    struct sock_common __sk_common;
} __attribute__((preserve_access_index));

struct iov_iter
{
    uint8_t iter_type;
    uint64_t iov_offset;
    void *ubuf;
    void *__iov;
    uint64_t count;
} __attribute__((preserve_access_index));

struct msghdr
{
    void *msg_name;
    uint32_t msg_namelen;
    struct iov_iter msg_iter;
} __attribute__((preserve_access_index));

// ubuf and iovec are the only iterator kinds plain user sends and receives use
#define ITER_KIND_UBUF 0
#define ITER_KIND_IOVEC 1

#define FAMILY_INET 2

typedef struct
{
    uint64_t base;
    uint64_t length;
} iovec_segment;

typedef struct
{
    uint16_t family;
    uint16_t port;
    uint32_t address;
    uint8_t padding[8];
} socket_address;

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, uint32_t);
    __type(value, uint8_t);
} selected_pids SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, uint32_t);
} configuration SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} packet_events SEC(".maps");

typedef struct
{
    uint64_t user_pointer;
    uint64_t length;
    uint32_t process_id;
    uint32_t source_address;
    uint32_t destination_address;
    uint16_t source_port;
    uint16_t destination_port;
    uint8_t protocol;
    char process_name[PROCESS_NAME_LENGTH];
} pending_copy;

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, uint64_t);
    __type(value, pending_copy);
} pending_copies SEC(".maps");

typedef struct
{
    uint8_t protocol;
    uint32_t source_address;
    uint32_t destination_address;
    uint16_t source_port;
    uint16_t destination_port;
} packet_headers;

static __always_inline uint8_t parse_packet_headers(uint8_t *packet_head, uint16_t network_offset,
                                                    uint16_t transport_offset, packet_headers *headers,
                                                    uint32_t *payload_length)
{
    struct iphdr ip_header = {0};
    if (bpf_probe_read_kernel(&ip_header, sizeof(ip_header), packet_head + network_offset))
        return 0;
    if (ip_header.version != 4 || ip_header.ihl < 5)
        return 0;
    headers->protocol = ip_header.protocol;
    headers->source_address = ip_header.saddr;
    headers->destination_address = ip_header.daddr;
    uint16_t total_length = __builtin_bswap16(ip_header.tot_len);
    if (ip_header.protocol == 6)
    {
        struct tcphdr tcp_header = {0};
        if (bpf_probe_read_kernel(&tcp_header, sizeof(tcp_header), packet_head + transport_offset))
            return 0;
        headers->source_port = tcp_header.source;
        headers->destination_port = tcp_header.dest;
        *payload_length = total_length - ip_header.ihl * 4 - tcp_header.doff * 4;
    }
    else if (ip_header.protocol == 17)
    {
        struct udphdr udp_header = {0};
        if (bpf_probe_read_kernel(&udp_header, sizeof(udp_header), packet_head + transport_offset))
            return 0;
        headers->source_port = udp_header.source;
        headers->destination_port = udp_header.dest;
        *payload_length = total_length - ip_header.ihl * 4 - sizeof(udp_header);
    }
    else
    {
        return 0;
    }
    return 1;
}

static __always_inline void emit_transfer(uint32_t process_id, const char *process_name, uint8_t direction,
                                          uint8_t protocol, uint32_t source_address, uint32_t destination_address,
                                          uint16_t source_port, uint16_t destination_port, uint32_t packet_length,
                                          uint64_t user_pointer, uint64_t available)
{
    uint32_t configuration_key = 0;
    uint32_t capture_limit = 256;
    uint32_t *configured_limit = bpf_map_lookup_elem(&configuration, &configuration_key);
    if (configured_limit)
        capture_limit = *configured_limit;
    if (capture_limit > PAYLOAD_LIMIT)
        capture_limit = PAYLOAD_LIMIT;
    if (available > capture_limit)
        available = capture_limit;
    uint32_t captured_length = (uint32_t)available;

    packet_event *event = bpf_ringbuf_reserve(&packet_events, sizeof(packet_event), 0);
    if (!event)
        return;

    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp = bpf_ktime_get_ns();
    event->process_id = process_id;
    event->direction = direction;
    event->protocol = protocol;
    event->source_address = source_address;
    event->destination_address = destination_address;
    event->source_port = source_port;
    event->destination_port = destination_port;
    event->packet_length = packet_length;
    if (process_name)
    {
        __builtin_memcpy(event->process_name, process_name, PROCESS_NAME_LENGTH);
    }
    else
    {
        bpf_get_current_comm(event->process_name, PROCESS_NAME_LENGTH);
    }
    if (captured_length && bpf_probe_read_user(event->payload, captured_length, (void *)user_pointer))
        captured_length = 0;
    event->captured_length = captured_length;
    bpf_ringbuf_submit(event, 0);
}

static __always_inline uint8_t segment_from_fields(uint8_t iterator_kind, uint64_t iterator_offset,
                                                   uint64_t remaining, void *segments, void *single_buffer,
                                                   uint64_t requested, uint64_t *user_pointer, uint64_t *available)
{
    if (iterator_kind == ITER_KIND_UBUF)
    {
        if (!single_buffer || iterator_offset > remaining)
            return 0;
        uint64_t usable = remaining - iterator_offset;
        *user_pointer = (uint64_t)single_buffer + iterator_offset;
        *available = requested < usable ? requested : usable;
        return 1;
    }
    if (iterator_kind == ITER_KIND_IOVEC)
    {
        iovec_segment first = {0};
        if (!segments || bpf_probe_read_kernel(&first, sizeof(first), segments))
            return 0;
        if (!first.base || iterator_offset > first.length)
            return 0;
        uint64_t usable = first.length - iterator_offset;
        *user_pointer = (uint64_t)first.base + iterator_offset;
        *available = requested < usable ? requested : usable;
        return 1;
    }
    return 0;
}

static __always_inline uint8_t first_pointer_segment(struct iov_iter *iterator, uint64_t requested,
                                                     uint64_t *user_pointer, uint64_t *available)
{
    return segment_from_fields(BPF_CORE_READ(iterator, iter_type), BPF_CORE_READ(iterator, iov_offset),
                               BPF_CORE_READ(iterator, count), BPF_CORE_READ(iterator, __iov),
                               BPF_CORE_READ(iterator, ubuf), requested, user_pointer, available);
}

static __always_inline uint8_t first_message_segment(struct msghdr *message, uint64_t requested,
                                                     uint64_t *user_pointer, uint64_t *available)
{
    return segment_from_fields(BPF_CORE_READ(message, msg_iter.iter_type), BPF_CORE_READ(message, msg_iter.iov_offset),
                               BPF_CORE_READ(message, msg_iter.count), BPF_CORE_READ(message, msg_iter.__iov),
                               BPF_CORE_READ(message, msg_iter.ubuf), requested, user_pointer, available);
}

static __always_inline uint8_t destination_from_message(struct msghdr *message, uint32_t *destination_address,
                                                        uint16_t *destination_port)
{
    void *name_pointer = BPF_CORE_READ(message, msg_name);
    int64_t name_length = BPF_CORE_READ(message, msg_namelen);
    if (name_pointer && name_length >= (int64_t)sizeof(socket_address))
    {
        socket_address endpoint = {0};
        if (!bpf_probe_read_user(&endpoint, sizeof(endpoint), name_pointer) ||
            !bpf_probe_read_kernel(&endpoint, sizeof(endpoint), name_pointer))
        {
            if (endpoint.family == FAMILY_INET)
            {
                *destination_address = endpoint.address;
                *destination_port = endpoint.port;
                return 1;
            }
        }
    }
    return 0;
}

static __always_inline void send_from_socket(struct msghdr *message, struct sock *socket, uint32_t send_length,
                                             uint8_t protocol)
{
    uint32_t process_id = bpf_get_current_pid_tgid() >> 32;
    if (!bpf_map_lookup_elem(&selected_pids, &process_id))
        return;
    uint16_t family = BPF_CORE_READ(socket, __sk_common.skc_family);
    if (family != FAMILY_INET)
        return;

    uint64_t user_pointer;
    uint64_t available;
    if (!first_message_segment(message, send_length, &user_pointer, &available))
        return;

    uint32_t local_address = BPF_CORE_READ(socket, __sk_common.skc_rcv_saddr);
    uint32_t remote_address = BPF_CORE_READ(socket, __sk_common.skc_daddr);
    
    uint16_t local_port = __builtin_bswap16(BPF_CORE_READ(socket, __sk_common.skc_num));
    uint16_t remote_port = BPF_CORE_READ(socket, __sk_common.skc_dport);
    destination_from_message(message, &remote_address, &remote_port);
    emit_transfer(process_id, 0, DIRECTION_TRANSMIT, protocol, local_address, remote_address,
                  local_port, remote_port, send_length, user_pointer, available);
}

static __always_inline void remember_pending_copy(struct sk_buff *packet, struct iov_iter *iterator,
                                                  uint32_t copy_length)
{
    if (!iterator || !copy_length)
        return;
    uint64_t thread_key = bpf_get_current_pid_tgid();
    uint32_t process_id = thread_key >> 32;
    if (!bpf_map_lookup_elem(&selected_pids, &process_id))
        return;
    uint8_t *packet_head = (uint8_t *)BPF_CORE_READ(packet, head);
    uint16_t network_offset = BPF_CORE_READ(packet, network_header);
    uint16_t transport_offset = BPF_CORE_READ(packet, transport_header);
    packet_headers headers = {0};
    uint32_t payload_length;
    // unix sockets and other non ip copies share this copy function
    if (!parse_packet_headers(packet_head, network_offset, transport_offset, &headers, &payload_length))
        return;

    uint64_t user_pointer;
    uint64_t available;
    if (!first_pointer_segment(iterator, copy_length, &user_pointer, &available))
        return;

    pending_copy pending = {0};
    pending.user_pointer = user_pointer;
    pending.length = available;
    pending.process_id = process_id;
    pending.source_address = headers.source_address;
    pending.destination_address = headers.destination_address;
    pending.source_port = headers.source_port;
    pending.destination_port = headers.destination_port;
    pending.protocol = headers.protocol;
    bpf_get_current_comm(pending.process_name, PROCESS_NAME_LENGTH);
    bpf_map_update_elem(&pending_copies, &thread_key, &pending, BPF_ANY);
}

static __always_inline void store_udp_receive(struct msghdr *message, int64_t peek_length)
{
    if (!message || peek_length <= 0)
        return;
    uint64_t thread_key = bpf_get_current_pid_tgid();
    uint32_t process_id = thread_key >> 32;
    if (!bpf_map_lookup_elem(&selected_pids, &process_id))
        return;

    uint64_t user_pointer;
    uint64_t available;
    if (!first_message_segment(message, (uint64_t)peek_length, &user_pointer, &available))
        return;

    pending_copy pending = {0};
    pending.user_pointer = user_pointer;
    pending.length = available;
    pending.process_id = process_id;
    bpf_get_current_comm(pending.process_name, PROCESS_NAME_LENGTH);
    bpf_map_update_elem(&pending_copies, &thread_key, &pending, BPF_ANY);
}


static __always_inline void finalize_udp_receive(struct sk_buff *packet)
{
    if (!packet)
        return;
    uint64_t thread_key = bpf_get_current_pid_tgid();
    pending_copy *pending = bpf_map_lookup_elem(&pending_copies, &thread_key);
    if (!pending || pending->protocol)
        return;

    uint8_t *packet_head = (uint8_t *)BPF_CORE_READ(packet, head);
    uint16_t network_offset = BPF_CORE_READ(packet, network_header);
    uint16_t transport_offset = BPF_CORE_READ(packet, transport_header);
    packet_headers headers = {0};
    uint32_t payload_length;
    if (!parse_packet_headers(packet_head, network_offset, transport_offset, &headers, &payload_length))
        return;

    pending->protocol = headers.protocol;
    pending->source_address = headers.source_address;
    pending->destination_address = headers.destination_address;
    pending->source_port = headers.source_port;
    pending->destination_port = headers.destination_port;
    if (pending->length > payload_length)
        pending->length = payload_length;
}

static __always_inline void receive_from_pending(void)
{
    uint64_t thread_key = bpf_get_current_pid_tgid();
    pending_copy *pending = bpf_map_lookup_elem(&pending_copies, &thread_key);
    if (!pending)
        return;
    if (pending->protocol)
        emit_transfer(pending->process_id, pending->process_name, DIRECTION_RECEIVE, pending->protocol,
                      pending->source_address, pending->destination_address, pending->source_port,
                      pending->destination_port, (uint32_t)pending->length, pending->user_pointer, pending->length);
    bpf_map_delete_elem(&pending_copies, &thread_key);
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(on_tcp_sendmsg, struct sock *socket, struct msghdr *message, int64_t send_length)
{
    if (socket && message && send_length > 0)
        send_from_socket(message, socket, (uint32_t)send_length, 6);
    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(on_udp_sendmsg, struct sock *socket, struct msghdr *message, int64_t send_length)
{
    if (socket && message && send_length > 0)
        send_from_socket(message, socket, (uint32_t)send_length, 17);
    return 0;
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(on_udp_recvmsg_entry, struct sock *socket, struct msghdr *message, int64_t peek_length)
{
    (void)socket;
    if (message)
        store_udp_receive(message, peek_length);
    return 0;
}

SEC("kretprobe/__skb_recv_udp")
int BPF_KRETPROBE(on_skb_recv_udp_return, struct sk_buff *packet)
{
    finalize_udp_receive(packet);
    return 0;
}

SEC("kretprobe/udp_recvmsg")
int on_udp_recvmsg_return(struct pt_regs *registers)
{
    (void)registers;
    receive_from_pending();
    return 0;
}

SEC("kprobe/skb_copy_datagram_iter")
int BPF_KPROBE(on_datagram_copy_wrapper_entry, struct sk_buff *packet, int32_t copy_offset,
               struct iov_iter *iterator, int32_t copy_length)
{
    (void)copy_offset;
    if (packet)
        remember_pending_copy(packet, iterator, (uint32_t)copy_length);
    return 0;
}

SEC("kretprobe/skb_copy_datagram_iter")
int on_datagram_copy_wrapper_return(struct pt_regs *registers)
{
    (void)registers;
    receive_from_pending();
    return 0;
}
