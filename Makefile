CC=gcc

build:
	$(CC) trans_packet.c ikcp.c common.c client.c -o client -lev -O2
	$(CC) trans_packet.c ikcp.c common.c server.c -o server -lev -O2


clean:
	rm -rf client server