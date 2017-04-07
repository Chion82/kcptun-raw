CC=gcc

default:
	make build

build:
	make clean
	$(CC) -std=gnu99 vector.c trans_packet.c ikcp.c common.c client.c -o client -lev -lcrypto -O2
	$(CC) -std=gnu99 vector.c trans_packet.c ikcp.c common.c server.c -o server -lev -lcrypto -O2 -D SERVER

clean:
	rm -rf server client