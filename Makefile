obj-m += execve.o
execve-objs := main.o hook.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

# should be run at root privilege
install: all
	insmod execve.ko sym=0x`cat /proc/kallsyms | grep " sys_call_table" | awk '{print $1}'`

uninstall:
	rmmod execve