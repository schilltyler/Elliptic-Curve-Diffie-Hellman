# Megan and Tyler
# Makefile for babylon: CS62 final project 

LIBS = -lcrypto
CFLAGS = -Wall -pedantic -ggdb
CC = gcc
MAKE = make


all: ecdh test_key

ecdh: ecdh.o
	$(CC) $(CFLAGS) $^ $(LIBS) -o $@
ecdh.o: ecdh.c

test_key: test_key.o
	$(CC) $(CFLAGS) $^ $(LIBS) -o $@
test_key.o: test_key.c



clean:
	rm -rf *.dSYM
	rm -rf *~ *.o
	rm -rf ecdh
	rm -rf test_key
