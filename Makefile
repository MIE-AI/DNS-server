cc=gcc
SRCS=main.o server.o cache.o parse.o linkedList.o log.o 
TARGET=dns_svr
CFLAGS=-Wall -g

dns_svr: $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS)

.PHONY: clean

clean: 
	rm -f *.o
	rm -f dns_svr