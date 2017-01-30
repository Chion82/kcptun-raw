CC=gcc

default:
	make build

build:
	make clean
	$(CC) -std=gnu99 trans_packet.c ikcp.c common.c client.c -o client_bin -lev -O2
	$(CC) -std=gnu99 trans_packet.c ikcp.c common.c server.c -o server_bin -lev -O2

clean:
	rm -rf server_bin client_bin