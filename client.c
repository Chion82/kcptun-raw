#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <ev.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#include "ikcp.h"
#include "trans_packet.h"

#include "common.h"

// #define tcp_listen_port 9999
// #define remote_ip "127.0.0.1"
// #define remote_port 888
// #define local_ip "127.0.0.1"
// #define local_port 34567

int tcp_listen_port;

int init_server_socket() {
  // Create server socket
  int sd;
  struct sockaddr_in addr;

  if( (sd = socket(PF_INET, SOCK_STREAM, 0)) < 0 ) {
    perror("socket error");
    exit(-1);
    return -1;
  }

  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(tcp_listen_port);
  addr.sin_addr.s_addr = INADDR_ANY;

  // Bind socket to address
  if (bind(sd, (struct sockaddr*) &addr, sizeof(addr)) != 0) {
    perror("bind error");
    exit(-1);
    return -1;
  }

  // Start listing on the socket
  if (listen(sd, 2) < 0) {
    perror("listen error");
    exit(-1);
    return -1;
  }

  setnonblocking(sd);

  return sd;
}

void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {

  struct sockaddr_in client_addr;
  socklen_t client_len = sizeof(client_addr);
  
  if(EV_ERROR & revents) {
    return;
  }

  int local_fd = accept(watcher->fd, (struct sockaddr *)&client_addr, &client_len);
  int client_port = ntohs(client_addr.sin_port);

  setnonblocking(watcher->fd);

  if (local_fd < 0) {
    return;
  }

  setnonblocking(local_fd);


  struct connection_info* connection = &(connection_queue[client_port % MAX_CONNECTIONS]);

  if (connection->in_use) {
    LOG("conv=%d already in use. Closing.", connection->conv);
    close_connection(connection);
  }

  connection->in_use = 1;

  connection->local_fd = local_fd;

  connection->pending_send_buf = NULL;
  connection->pending_send_buf_len = 0;

  LOG("New connection conv %d.", connection->conv);


  struct ev_io *local_read_io = &((connection->read_io).io);
  struct ev_io *local_write_io = &((connection->write_io).io);

  ev_io_init(local_read_io, read_cb, local_fd, EV_READ);
  ev_io_init(local_write_io, write_cb, local_fd, EV_WRITE);
  ev_io_start(loop, local_read_io);
  ev_io_start(loop, local_write_io);

  notify_remote_connect(connection);

}

int main(int argc, char* argv[]) {

  signal(SIGPIPE, SIG_IGN);

  srand(time(NULL));

  if (argc < 5) {
    printf("Usage: ./client_bin SERVER_IP SERVER_PORT LOCAL_IP LISTEN_PORT [mode] [noseq]\n");
    exit(1);
  }

  tcp_listen_port = atoi(argv[4]);

  init_kcp_mode(argc, argv);

  for (int i=0; i<MAX_CONNECTIONS; i++) {
    connection_queue[i].in_use = 0;
    connection_queue[i].conv = i;
    connection_queue[i].local_fd = -1;
    connection_queue[i].pending_send_buf_len = 0;
    connection_queue[i].pending_send_buf = NULL;
    connection_queue[i].write_io.connection = &(connection_queue[i]);
    connection_queue[i].read_io.connection = &(connection_queue[i]);
  }

  strcpy(packetinfo.dest_ip, argv[1]);
  packetinfo.dest_port = atoi(argv[2]);
  strcpy(packetinfo.source_ip, argv[3]);
  packetinfo.source_port = 30000 + rand() % 10000;
  packetinfo.on_packet_recv = on_packet_recv;
  packetinfo.is_server = 0;
  packetinfo.disable_seq_update = 0;

  for (int i=0; i<argc; i++) {
    if (!strcmp(argv[i], "noseq")) {
      LOG("Disable TCP sequense counter.");
      packetinfo.disable_seq_update = 1;
    }
  }

  init_packet(&packetinfo);
  set_packet_recv_nonblocking();

  loop = ev_default_loop(0);

  struct ev_io w_accept;

  ev_timer_init(&kcp_update_timer, kcp_update_timer_cb, 0.1, 0.003);
  ev_timer_start(loop, &kcp_update_timer);

  int server_fd = init_server_socket();

  ev_io_init(&w_accept, accept_cb, server_fd, EV_READ);
  ev_io_start(loop, &w_accept);

  ev_io_init(&packet_recv_io, packet_read_cb, packet_recv_sd, EV_READ);
  ev_io_start(loop, &packet_recv_io);

  ev_timer_init(&heart_beat_timer, heart_beat_timer_cb, 0, 2);
  ev_timer_start(loop, &heart_beat_timer);

  init_kcp();

  ev_run(loop, 0);

  return 0;
}
