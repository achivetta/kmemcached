# see Documentation/kbuild/modules.txt

obj-m := kmemcached.o
kmemcached-y := main.o storage.o interface.o libmp/protocol_handler.o libmp/binary_handler.o libmp/byteorder.o libmp/cache.o libmp/ascii_handler.o libmp/pedantic.o hash.o

all:
	make -C $(KERNEL_TREE) M=$(PWD) modules

clean:
	make -C $(KERNEL_TREE) M=$(PWD) clean

tags:
	make -C $(KERNEL_TREE) M=$(PWD) tags

todo:
	grep -A 10 TODO *.c *.h libmp/*.c libmp/*.h
