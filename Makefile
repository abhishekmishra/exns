.PHONY:	all build run clean exns.o exns

CC = gcc
CFLAGS = -std=c99 -Wall -g -Icoll/src -Izclk/src `pkg-config --cflags lua5.4`
LIBS = `pkg-config --libs lua5.4`

zclk_objects := $(patsubst %.c,%.o,$(wildcard zclk/src/zclk*.c))

all:	build

build:	exns

run:
	./exns

exns:	exns.o $(zclk_objects) coll_arraylist.o
	$(CC) $(CFLAGS) -o exns exns.o $(zclk_object) coll_arraylist.o $(LIBS)

exns.o:	exns.c
	$(CC) $(CFLAGS) -c exns.c

zclk/src/zclk%.o:	zclk/src/zclk%.c
	$(CC) $(CFLAGS) -c $<

coll_arraylist.o:	coll/src/coll_arraylist.c
	$(CC) $(CFLAGS) -c coll/src/coll_arraylist.c

clean:
	rm -f *.o
	rm -f exns
