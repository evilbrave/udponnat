CC=gcc
CFLAGS=-g -Wall
LDFLAGS=-static
OBJS=
LIBS=

all: server client

server: server.o ${OBJS}
	${CC} ${LDFLAGS} -o server server.o ${OBJS} ${LIBS}

server.o: server.c
	${CC} ${CFLAGS} -c server.c

client: client.o ${OBJS}
	${CC} ${LDFLAGS} -o client client.o ${OBJS} ${LIBS}

client.o: client.c
	${CC} ${CFLAGS} -c client.c

clean: 
	rm -f *.o server client
