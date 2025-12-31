#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include "../ebpf/sniffer-ebpf.h"

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

		for (uint32_t index = 0; index < 16 && offset + index < event->captured_length;
			 index++)
		{
			unsigned char byte = event->payload[offset + index];
			putchar(isprint(byte) ? byte : '.');
		}
		
		printf("|\n");
	}
}

static void print_event(const packet_event *event)
{
	time_t seconds = (time_t)(event->timestamp / 1000000000);
	struct tm local_time;
	localtime_r(&seconds, &local_time);

	char process_name[PROCESS_NAME_LENGTH + 1];
	memcpy(process_name, event->process_name, PROCESS_NAME_LENGTH);
	process_name[PROCESS_NAME_LENGTH] = 0;

	const char *direction_name = event->direction == DIRECTION_TRANSMIT ? "tx" : "rx";
	const char *protocol_name = "other";
	if (event->protocol == 6)
		protocol_name = "tcp";
	else if (event->protocol == 17)
		protocol_name = "udp";

	char source_endpoint[32] = "-";
	char destination_endpoint[32] = "-";
	if (event->protocol == 6 || event->protocol == 17)
	{
		char source_address[INET_ADDRSTRLEN];
		char destination_address[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &event->source_address, source_address, sizeof(source_address));
		inet_ntop(AF_INET, &event->destination_address, destination_address,
				  sizeof(destination_address));
		snprintf(source_endpoint, sizeof(source_endpoint), "%s:%u", source_address,
				 ntohs(event->source_port));
		snprintf(destination_endpoint, sizeof(destination_endpoint), "%s:%u",
				 destination_address, ntohs(event->destination_port));
	}

	printf("%02d:%02d:%02d.%03d  %-6u %-15s %s %-5s %s -> %s  len %u\n",
		   local_time.tm_hour, local_time.tm_min, local_time.tm_sec,
		   (int)(event->timestamp % 1000000000) / 1000000,
		   event->process_id, process_name, direction_name, protocol_name,
		   source_endpoint, destination_endpoint, event->packet_length);
	print_payload(event);
}

int main(int argument_count, char **arguments)
{
	if (argument_count != 2)
	{
		fprintf(stderr, "usage: sniffer <pid>\n");
		return 1;
	}

	uint32_t watched_pid = (uint32_t)strtoul(arguments[1], NULL, 10);

	int device = open("/dev/sniffer", O_RDONLY);

	if (device < 0)
	{
		fprintf(stderr, "cannot open /dev/sniffer: %s\n", strerror(errno));
		return 1;
	}

	if (ioctl(device, SNIFFER_SET_PID, &watched_pid) < 0)
	{
		fprintf(stderr, "cannot set pid: %s\n", strerror(errno));
		return 1;
	}

	packet_event event;
	while (1) {
		ssize_t amount = read(device, &event, sizeof(event));

		if (amount != (ssize_t)sizeof(event))
		{
			if (amount < 0 && errno == EINTR)
				continue;
			fprintf(stderr, "reading /dev/sniffer failed: %s\n", strerror(errno));
			return 1;
		}

		print_event(&event);
	}
}
