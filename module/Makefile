obj-m += firewall.o
firewall-m += hw5secws.o rule_table.o fw_log.o connection_entry.o connection_table.o net_utils.o connection.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
