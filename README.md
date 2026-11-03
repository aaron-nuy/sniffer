# Sniffer

Proof of concept Linux kernel TCP sniffers using eBPF and Kernel Module Hooks

## eBPF

`ebpf/sniffer-ebpf.bpf.c` holds the probes and `ebpf/sniffer-ebpf.cpp` is a loader that attaches them and prints the events.

`make` builds both into `bin/sniffer-ebpf.bpf.o` and `bin/sniffer-ebpf`.

Run it as root:

```bash
sudo ./bin/sniffer-ebpf --pid 1234
```

`--pid` can be repeated and `--payload` sets how many bytes are captured per packet.

### Example Output

```text
$ sudo ./bin/sniffer-ebpf --pid $(pidof telnet)
capturing pids: 193715, payload limit 256 bytes, ctrl-c to stop
18:20:13.063  193715 telnet       rx tcp  188.226.141.86:10080 -> 10.216.186.167:35932  len 3
    0000  1b 5b 48                        |.[H|
18:20:13.107  193715 telnet       rx tcp  188.226.141.86:10080 -> 10.216.186.167:35932  len 35
    0000  1b 5b 32 3b 33 30 66 1b 5b 33 30 3b 34 38 3b 35  |.[2;30f.[30;48;5|
    0010  3b 34 30 6d 00 37 37 35 39 31 2e 32 33 30 30 30  |;40m.77591.23000|
    0020  1b 5b 48                        |.[H|
```

## Kernel Module

`module/sniffer-kernel.c` hooks TCP and UDP send and receive, queues the packets of the watched PID, and exposes them on `/dev/sniffer`.

One reader can hold the device open at a time and tells the module which PID to watch.

`bin/sniffer-kernel` is the reader; give it a PID:

```bash
./bin/sniffer-kernel 1234
```

`make run` boots the Debian kernel with the module already loaded in a QEMU VM so none of this has to touch the host.

### Example Output

```text
$ ./bin/sniffer-kernel $pid
17:21:04.836  134  nc             tx tcp  127.0.0.1:42947 -> 127.0.0.1:9000  len 6
    0000  68 65 6c 6c 6f 0a               |hello.|
17:21:06.841  134  nc             tx tcp  127.0.0.1:42947 -> 127.0.0.1:9000  len 6
    0000  68 65 6c 6c 6f 0a               |hello.|
17:21:08.845  134  nc             tx tcp  127.0.0.1:42947 -> 127.0.0.1:9000  len 6
    0000  68 65 6c 6c 6f 0a               |hello.|
```
