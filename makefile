obj-m += netfilter.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) netfilter.c

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean