# for Linux
OPENSSL_DIR=/usr
# for Mac OS X with brew
#OPENSSL_DIR=/usr/local/opt/openssl

CC=cc

OPENSSL_INCLUDE_DIR=$(OPENSSL_DIR)/include
OPENSSL_LIB_DIR=$(OPENSSL_DIR)/lib

CFLAGS=-O3 -std=gnu11 -Wall -Wextra -I$(OPENSSL_INCLUDE_DIR) #-DDEBUG_LOGS
LDFLAGS=-L$(OPENSSL_LIB_DIR) -lcrypto -lssl

all:
	$(CC) $(CFLAGS) -o generate_a generate_a.c $(LDFLAGS) 
	$(CC) $(CFLAGS) -c lwekex.c
	$(CC) $(CFLAGS) -o test test.c lwekex.o $(LDFLAGS) 

test: all
	./test

clean:
	rm -f *.o
	rm -f generate_a
	rm -f test

prettyprint:
	astyle --style=java --indent=tab --pad-header --pad-oper --align-pointer=name --align-reference=name --suffix=none *.c *.h
