obj-m:=CCModule.o
CCModule-objs   :=sdthook.o  netlink.o 

#obj-m:=sdthook.o
MY_CFLAGS += -g -DDEBUG
ccflags-y += ${MY_CFLAGS}
CC += ${MY_CFLAGS}

KDIR   := /lib/modules/$(shell uname -r)/build
PWD   := $(shell pwd)
default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
debug:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 
	EXTRA_CFLAGS="$(MY_CFLAGS)"
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean                                                                                                                                     
