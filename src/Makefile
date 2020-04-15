CC=     gcc
LIBS=   -lpam
OBJ=    pam2control.o config.o log.o

ifeq ($(shell uname -m), x86_64)
	LIB_PATH = /lib64
else
	LIB_PATH = /lib
endif


ifeq ($(shell cat /etc/issue | cut -d " " -f 1), Debian)
	LIB_PATH=/lib
endif


pam2control: $(OBJ)
	$(CC) -Wall -fPIC -c pam2control.c config.c log.c
	$(CC) -shared -o pam2control.so $(OBJ) $(LIBS)

install:
	install -m 755 pam2control.so $(LIB_PATH)/security/
	mkdir -p /etc/pam2control
	install -m 600 p2c.conf.default /etc/pam2control/
	mkdir -p /var/log/pam2control
	mkdir -p /usr/share/man/man5/
	install -m 644 p2c.conf.5 /usr/share/man/man5/p2c.conf.5
	gzip /usr/share/man/man5/p2c.conf.5

clean:
	rm -f $(OBJ)

uninstall:
	rm -rf /usr/share/man/man5/p2c.conf.5.gz
	rm -rf $(LIB_PATH)/security/pam2control.so
