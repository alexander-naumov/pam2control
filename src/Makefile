CC=gcc
LIBS=-lpam

OBJ = pam2control.o config.o log.o

pam2control: $(OBJ)
	$(CC) -Wall -fPIC -c pam2control.c config.c log.c
	$(CC) -shared -o pam2control.so $(OBJ) $(LIBS)

install:
	mv pam2control.so /lib/security/

clean:
	rm -f $(OBJ)
