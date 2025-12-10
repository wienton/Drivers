ifneq ($(KERNELRELEASE),)
	obj-m := redirector.o
else
	KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) CC=clang LD=ld.lld modules

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean
endif