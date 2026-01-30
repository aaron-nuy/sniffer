all: bin/sniffer-kernel.ko bin/sniffer-kernel bin/sniffer-ebpf bin/sniffer-ebpf.bpf.o

bin/sniffer-ebpf.bpf.o: ebpf/sniffer-ebpf.bpf.c ebpf/sniffer-ebpf.h
	mkdir -p bin
	clang -O2 -g -D__TARGET_ARCH_x86 -target bpf -c $< -o $@

bin/sniffer-ebpf: ebpf/sniffer-ebpf.cpp ebpf/sniffer-ebpf.h
	mkdir -p bin
	g++ -O2 -o $@ $< -lbpf

bin/sniffer-kernel.ko: module/sniffer-kernel.c module/Makefile ebpf/sniffer-ebpf.h vm/kernel
	$(MAKE) -C vm/headers M=$(CURDIR)/module modules CC=gcc CROSS_COMPILE=
	mkdir -p bin
	cp module/sniffer-kernel.ko bin/

bin/sniffer-kernel: module/tool.c ebpf/sniffer-ebpf.h
	mkdir -p bin
	gcc -O2 -static -o $@ $<

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

vm/busybox:
	wget -O - https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/busybox-static-1.37.0-r31.apk | tar -xzO bin/busybox.static > vm/busybox
	chmod 755 vm/busybox

bin/initramfs.cpio.gz: vm/init vm/busybox bin/sniffer-kernel.ko bin/sniffer-kernel
	rm -rf vm/ramfs
	mkdir -p vm/ramfs/bin vm/ramfs/proc vm/ramfs/sys vm/ramfs/tmp
	cp vm/busybox vm/ramfs/bin/busybox
	ln -s busybox vm/ramfs/bin/sh
	cp vm/init bin/sniffer-kernel.ko bin/sniffer-kernel vm/ramfs/
	cd vm/ramfs && find . | cpio -o -H newc | gzip -9 > ../../bin/initramfs.cpio.gz

run: bin/initramfs.cpio.gz vm/vmlinuz
	qemu-system-x86_64 -enable-kvm -m 512 -nographic -no-reboot -kernel vm/vmlinuz -initrd bin/initramfs.cpio.gz -append "console=ttyS0"

clean:
	rm -rf bin
	if [ -d vm/headers ]; then $(MAKE) -C vm/headers M=$(CURDIR)/module clean CC=gcc CROSS_COMPILE=; fi

distclean: clean
	rm -rf vm/kdev vm/debs vm/headers vm/vmlinuz vm/kernel vm/busybox vm/ramfs

.PHONY: all run clean distclean
