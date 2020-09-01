CC=	gcc
LIBS=	-lpam
OBJ= 	pam2control.o config.o log.o smtp.o conv.o
BIN=	/usr/sbin

all: pam2control p2ctl

pam2control: $(OBJ)
	$(CC) -Wall -fPIC -c pam2control.c config.c log.c smtp.c conv.c
	$(CC) -shared -o pam2control.so $(OBJ) $(LIBS)

p2ctl: p2ctl.c
	$(CC) -Wall p2ctl.c -o p2ctl


install:
	install -m 755 pam2control.so $(shell ./p2ctl search_path)
	install -m 750 p2ctl $(BIN)
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
	rm -f $(OBJ) pam2control.so p2ctl


uninstall:
	rm -rf /etc/pam2control/
	rm -rf /usr/share/man/man5/p2c.conf.5.gz
	rm -rf $(shell p2ctl search_path)/pam2control.so
	rm -rf $(BIN)/p2ctl
