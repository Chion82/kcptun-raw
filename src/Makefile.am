bin_PROGRAMS = kcpraw_client kcpraw_server
DEPS = -std=gnu99 -lev -lcrypto -D_GNU_SOURCE
kcpraw_client_SOURCES = client.c common.c trans_packet.c ikcp.c vector.c
kcpraw_server_SOURCES = server.c common.c trans_packet.c ikcp.c vector.c
kcpraw_client_CFLAGS = $(DEPS)
kcpraw_server_CFLAGS = $(DEPS) -D SERVER
