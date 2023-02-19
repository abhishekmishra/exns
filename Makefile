.PHONY:	all build run clean exns.o exns

CC = gcc
CFLAGS = -std=c99 -Wall -g

all:	build

build:	exns

run:
	./exns

exns:	exns.o
	$(CC) $(CFLAGS) -o exns exns.o

exns.o:	exns.c
	$(CC) $(CFLAGS) -c exns.c

clean:
	rm -f *.o
	rm -f exns
