CC=     gcc
LIBS=   -lpam
OBJ=    pam2control.o config.o log.o smtp.o conv.o

ifeq ($(shell uname -m), x86_64)
	LIB_PATH = /lib64
else ifeq ($(shell uname -m), aarch64)
	LIB_PATH = /lib/aarch64-linux-gnu
else
	LIB_PATH = /lib
endif

ifneq (,$(wildcard $(/lib/x86_64-linux-gnu))","")
	LIB_PATH = /lib/x86_64-linux-gnu
endif

ifneq (,$(wildcard $(/usr/lib/i386-linux-gnu))","")
	LIB_PATH = /usr/lib/i386-linux-gnu
endif

pam2control: $(OBJ)
	$(CC) -Wall -fPIC -c pam2control.c config.c log.c smtp.c conv.c
	$(CC) -shared -o pam2control.so $(OBJ) $(LIBS)


install:
	install -m 755 pam2control.so $(LIB_PATH)/security/
	mkdir -p /etc/pam2control
	mkdir -p /var/log/pam2control
	mkdir -p /usr/share/man/man5/
	install -m 644 p2c.conf.5 /usr/share/man/man5/p2c.conf.5
	gzip -f /usr/share/man/man5/p2c.conf.5

ifneq ("$(wildcard /etc/pam2control/p2c.conf)","")
	@echo "Config file is already exist"
else
	install -m 600 p2c.conf.default /etc/pam2control/p2c.conf
endif


clean:
	rm -f $(OBJ) pam2control.so


uninstall:
	rm -rf /etc/pam2control/
	rm -rf /usr/share/man/man5/p2c.conf.5.gz
	rm -rf $(LIB_PATH)/security/pam2control.so
