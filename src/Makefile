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

clean:
	rm -f $(OBJ)
