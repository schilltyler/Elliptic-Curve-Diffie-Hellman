# Megan and Tyler
# Makefile for babylon: CS62 final project 

LIBS = -lcrypto
CFLAGS = -Wall -pedantic -ggdb
CC = gcc
MAKE = make

ecdh: ecdh.o
	$(CC) $(CFLAGS) $^ $(LIBS) -o $@
ecdh.o: ecdh.c

clean:
	rm -rf *.dSYM
	rm -rf *~ *.o
	rm -rf ecdh
