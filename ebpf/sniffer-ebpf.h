#ifndef SNIFFER_H
#define SNIFFER_H

#ifdef __KERNEL__
#include <linux/types.h>
typedef __u64 uint64_t;
typedef __u32 uint32_t;
typedef __u16 uint16_t;
typedef __u8 uint8_t;
#else
#include <stdint.h>
#endif

#ifndef _IOC_NRBITS
#define _IOC_NRBITS	3
#define _IOC_TYPEBITS	8
#define _IOC_SIZEBITS	14
#define _IOC_DIRBITS	2

#define _IOC_NRSHIFT	0
#define _IOC_TYPESHIFT	(_IOC_NRSHIFT + _IOC_NRBITS)
#define _IOC_SIZESHIFT	(_IOC_TYPESHIFT + _IOC_TYPEBITS)
#define _IOC_DIRSHIFT	(_IOC_SIZESHIFT + _IOC_SIZEBITS)

#define _IOC_NONE	0
#define _IOC_WRITE	1
#define _IOC_READ	2

#define _IOC(dir, type, nr, size)					\
	((((uint32_t)dir) << _IOC_DIRSHIFT) |				\
	 (((uint32_t)type) << _IOC_TYPESHIFT) |				\
	 (((uint32_t)nr) << _IOC_NRSHIFT) |				\
	 (((uint32_t)size) << _IOC_SIZESHIFT))
#endif

#define SNIFFER_SET_PID _IOC(_IOC_WRITE, 'S', 1, sizeof(uint32_t))

#define PAYLOAD_LIMIT 512
#define PROCESS_NAME_LENGTH 16

#define DIRECTION_TRANSMIT 1
#define DIRECTION_RECEIVE 2

typedef struct {
    uint64_t timestamp;
    uint32_t process_id;
    uint32_t packet_length;
    uint32_t captured_length;
    uint32_t source_address;
    uint32_t destination_address;
    uint16_t source_port;
    uint16_t destination_port;
    uint8_t direction;
    uint8_t protocol;
    uint8_t padding[2];
    char process_name[PROCESS_NAME_LENGTH];
    uint8_t payload[PAYLOAD_LIMIT];
} packet_event;

#endif
