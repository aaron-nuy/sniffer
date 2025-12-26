all: bin/sniffer-ebpf bin/sniffer-ebpf.bpf.o

bin/sniffer-ebpf.bpf.o: ebpf/sniffer-ebpf.bpf.c ebpf/sniffer-ebpf.h
	mkdir -p bin
	clang -O2 -g -D__TARGET_ARCH_x86 -target bpf -c $< -o $@

bin/sniffer-ebpf: ebpf/sniffer-ebpf.cpp ebpf/sniffer-ebpf.h
	mkdir -p bin
	g++ -O2 -o $@ $< -lbpf

vm/kernel:
	mkdir -p vm/debs vm/kdev
	wget -c -O vm/debs/image.deb https://deb.debian.org/debian/pool/main/l/linux-signed-amd64/linux-image-6.12.107+deb13-amd64_6.12.107-1_amd64.deb
	wget -c -O vm/debs/headers.deb https://deb.debian.org/debian/pool/main/l/linux/linux-headers-6.12.107+deb13-amd64_6.12.107-1_amd64.deb
	wget -c -O vm/debs/common.deb https://deb.debian.org/debian/pool/main/l/linux/linux-headers-6.12.107+deb13-common_6.12.107-1_all.deb
	wget -c -O vm/debs/kbuild.deb https://deb.debian.org/debian/pool/main/l/linux/linux-kbuild-6.12.107+deb13_6.12.107-1_amd64.deb
	for deb in vm/debs/*.deb; do ar p $$deb "$$(ar t $$deb | grep '^data.tar')" | bsdtar -xf - -C vm/kdev; done
	sed -i 's|^include /usr/src/|include ../|' vm/kdev/usr/src/linux-headers-6.12.107+deb13-amd64/Makefile
	sed -i '/^override CROSS_COMPILE/d' vm/kdev/usr/src/linux-headers-6.12.107+deb13-amd64/.kernelvariables
	ln -sfn kdev/usr/src/linux-headers-6.12.107+deb13-amd64 vm/headers
	ln -sfn kdev/boot/vmlinuz-6.12.107+deb13-amd64 vm/vmlinuz
	touch vm/kernel

vm/headers vm/vmlinuz: vm/kernel

clean:
	rm -rf bin

.PHONY: all clean
