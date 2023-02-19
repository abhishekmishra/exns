.PHONY:	all clean exns.o exns

all:	exns

exns:	exns.o
	gcc -o exns exns.o

exns.o:	exns.c
	gcc -c exns.c

clean:
	rm *.o
	rm exns
