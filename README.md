# sniffer

sniffer watches the tcp and udp packets of one pid and prints each packet as a timestamped line followed by a hexdump of the payload

## ebpf edition

ebpf/sniffer-ebpf.bpf.c holds the probes and ebpf/sniffer-ebpf.cpp is a loader that attaches them and prints the events

make builds both into bin/sniffer-ebpf.bpf.o and bin/sniffer-ebpf

run it as root

sudo ./bin/sniffer-ebpf --pid 1234

--pid can be repeated and --payload sets how many bytes are captured per packet

## kernel module edition

module/sniffer-kernel.c hooks tcp and udp send and receive, queues the packets of the watched pid and exposes them on /dev/sniffer

one reader can hold the device open at a time and tells the module which pid to watch

bin/sniffer-kernel is the reader, give it a pid

./bin/sniffer-kernel 1234

make run boots the debian kernel with the module already loaded in a qemu vm so none of this has to touch the host
