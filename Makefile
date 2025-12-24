all: bin/sniffer-ebpf bin/sniffer-ebpf.bpf.o

bin/sniffer-ebpf.bpf.o: ebpf/sniffer-ebpf.bpf.c ebpf/sniffer-ebpf.h
	mkdir -p bin
	clang -O2 -g -D__TARGET_ARCH_x86 -target bpf -c $< -o $@

bin/sniffer-ebpf: ebpf/sniffer-ebpf.cpp ebpf/sniffer-ebpf.h
	mkdir -p bin
	g++ -O2 -o $@ $< -lbpf

clean:
	rm -rf bin

.PHONY: all clean
