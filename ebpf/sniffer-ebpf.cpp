#include <arpa/inet.h>
#include <cerrno>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <vector>

#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "sniffer-ebpf.h"

static void print_payload(const packet_event *event)
{
    for (uint32_t offset = 0; offset < event->captured_length; offset += 16)
    {
        printf("  %04x  ", offset);
        for (uint32_t index = 0; index < 16; index++)
        {
            if (offset + index < event->captured_length)
                printf("%02x ", event->payload[offset + index]);
            else
                printf("   ");
        }
        printf(" |");
        for (uint32_t index = 0; index < 16 && offset + index < event->captured_length; index++)
        {
            unsigned char byte = event->payload[offset + index];
            putchar(isprint(byte) ? byte : '.');
        }
        printf("|\n");
    }
}

static void print_event(const packet_event *event)
{
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    struct tm local_time;
    localtime_r(&now.tv_sec, &local_time);

    char process_name[PROCESS_NAME_LENGTH + 1];
    memcpy(process_name, event->process_name, PROCESS_NAME_LENGTH);
    process_name[PROCESS_NAME_LENGTH] = 0;

    const char *direction_name = event->direction == DIRECTION_TRANSMIT ? "tx" : "rx";
    const char *protocol_name = "other";
    if (event->protocol == 6)
        protocol_name = "tcp";
    else if (event->protocol == 17)
        protocol_name = "udp";
    else if (event->protocol == 1)
        protocol_name = "icmp";

    char source_endpoint[32] = "-";
    char destination_endpoint[32] = "-";
    if (event->protocol == 6 || event->protocol == 17)
    {
        char source_address[INET_ADDRSTRLEN];
        char destination_address[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &event->source_address, source_address, sizeof(source_address));
        inet_ntop(AF_INET, &event->destination_address, destination_address, sizeof(destination_address));
        snprintf(source_endpoint, sizeof(source_endpoint), "%s:%u", source_address, ntohs(event->source_port));
        snprintf(destination_endpoint, sizeof(destination_endpoint), "%s:%u", destination_address,
                 ntohs(event->destination_port));
    }

    printf("%02d:%02d:%02d.%03ld  %-6u %-15s %s %-5s %s -> %s  len %u\n",
           local_time.tm_hour, local_time.tm_min, local_time.tm_sec, now.tv_nsec / 1000000,
           event->process_id, process_name, direction_name, protocol_name,
           source_endpoint, destination_endpoint, event->packet_length);
    print_payload(event);
}

static int handle_event(void *context, void *data, size_t size)
{
    (void)context;
    if (size < sizeof(packet_event))
        return 0;
    print_event((const packet_event *)data);
    fflush(stdout);
    return 0;
}

static void usage(const char *program_name)
{
    fprintf(stderr, "usage: %s --pid <pid> [--pid <pid>...] [--payload <bytes>]\n", program_name);
}

int main(int argument_count, char **arguments)
{
    std::vector<uint32_t> process_ids;
    uint32_t payload_limit = 256;

    for (int index = 1; index < argument_count; index++)
    {
        if (strcmp(arguments[index], "--pid") == 0 && index + 1 < argument_count)
        {
            process_ids.push_back((uint32_t)strtoul(arguments[++index], nullptr, 10));
        }
        else if (strcmp(arguments[index], "--payload") == 0 && index + 1 < argument_count)
        {
            payload_limit = (uint32_t)strtoul(arguments[++index], nullptr, 10);
            if (payload_limit > PAYLOAD_LIMIT)
                payload_limit = PAYLOAD_LIMIT;
        }
        else
        {
            usage(arguments[0]);
            return 1;
        }
    }
    if (process_ids.empty())
    {
        usage(arguments[0]);
        return 1;
    }
    if (geteuid() != 0)
        fprintf(stderr, "warning: loading bpf programs needs root\n");

    bpf_object *object = bpf_object__open_file("sniffer-ebpf.bpf.o", nullptr);
    if (!object)
    {
        fprintf(stderr, "cannot open sniffer.bpf.o\n");
        return 1;
    }

    int error = bpf_object__load(object);
    if (error)
    {
        fprintf(stderr, "load failed: %s\n", strerror(-error));
        return 1;
    }

    bpf_map *pid_map = bpf_object__find_map_by_name(object, "selected_pids");
    bpf_map *configuration_map = bpf_object__find_map_by_name(object, "configuration");
    bpf_map *event_map = bpf_object__find_map_by_name(object, "packet_events");
    if (!pid_map || !configuration_map || !event_map)
    {
        fprintf(stderr, "maps missing from object\n");
        return 1;
    }

    for (uint32_t process_id : process_ids)
    {
        uint32_t key = process_id;
        uint8_t value = 1;
        if (bpf_map_update_elem(bpf_map__fd(pid_map), &key, &value, BPF_ANY))
        {
            fprintf(stderr, "cannot add pid %u: %s\n", process_id, strerror(errno));
            return 1;
        }
    }
    uint32_t configuration_key = 0;
    if (bpf_map_update_elem(bpf_map__fd(configuration_map), &configuration_key, &payload_limit, BPF_ANY))
    {
        fprintf(stderr, "cannot set payload limit: %s\n", strerror(errno));
        return 1;
    }

    const char *hook_programs[] = {
        "on_tcp_sendmsg",
        "on_udp_sendmsg",
        "on_udp_recvmsg_entry",
        "on_skb_recv_udp_return",
        "on_udp_recvmsg_return",
        "on_datagram_copy_wrapper_entry",
        "on_datagram_copy_wrapper_return",
    };
    std::vector<bpf_link *> links;
    for (const char *program_name : hook_programs)
    {
        bpf_program *program = bpf_object__find_program_by_name(object, program_name);
        if (!program)
            continue;
        bpf_link *link = bpf_program__attach(program);
        if (!link)
        {
            fprintf(stderr, "cannot attach %s: %s\n", program_name, strerror(errno));
            return 1;
        }
        links.push_back(link);
    }

    ring_buffer *reader = ring_buffer__new(bpf_map__fd(event_map), handle_event, nullptr, nullptr);
    if (!reader)
    {
        fprintf(stderr, "cannot create ring buffer reader: %s\n", strerror(errno));
        return 1;
    }

    fprintf(stderr, "capturing pids:");
    for (uint32_t process_id : process_ids)
        fprintf(stderr, " %u", process_id);
    fprintf(stderr, ", payload limit %u bytes, ctrl-c to stop\n", payload_limit);

    while (true)
    {
        int result = ring_buffer__poll(reader, 200);
        if (result < 0 && result != -EINTR)
        {
            fprintf(stderr, "ring buffer poll failed: %s\n", strerror(-result));
            break;
        }
    }

    return 0;
}
