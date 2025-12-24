all: bin/sniffer-ebpf

bin/sniffer-ebpf: ebpf/sniffer-ebpf.cpp ebpf/sniffer-ebpf.h
	mkdir -p bin
	g++ -O2 -o $@ $< -lbpf

clean:
	rm -rf bin

.PHONY: all clean
