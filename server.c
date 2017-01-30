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

// #define tcp_connect_to_ip "127.0.0.1"
// #define tcp_connect_to_port 80
// #define local_ip "127.0.0.1"
// #define local_port 888

char tcp_connect_to_ip[128];
int tcp_connect_to_port;

int init_connect_to_socket() {
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
  addr.sin_port = htons(tcp_connect_to_port);
  if (inet_pton(AF_INET, tcp_connect_to_ip, &addr.sin_addr) <=0 ) {
    perror("Error address.\n");
    exit(6);
    return -1;
  }

  setnonblocking(sd);

  int conn_ret = connect(sd, (struct sockaddr*)&addr, sizeof(addr));

  if (conn_ret < 0 && errno != EINPROGRESS) {
    perror("Connect error.\n");
    return -1;
  }

  return sd;
}

void on_packet_recv(char* from_ip, uint16_t from_port, char* payload, int size, unsigned int identifier) {

  if (!is_valid_packet(payload)) {
    return;
  }

  strcpy(packetinfo.dest_ip, from_ip);
  packetinfo.dest_port = from_port;

  if (is_packet_command(payload, HEART_BEAT)) {
    return;
  }

  if (!(identifier >= 0 && identifier < MAX_CONNECTIONS)) {
    return;
  }

  struct connection_info* connection = &(connection_queue[identifier]);

  if (is_packet_command(payload, CONNECTION_CONNECT)) {

    if (connection->in_use == 1) {
      LOG("conv=%d already in use. Closing.", connection->conv);
      close_connection(connection);
    }

    connection->in_use = 1;
    connection->pending_close = 0;

    int local_fd = init_connect_to_socket();

    if (local_fd < 0) {
      connection->in_use = 0;
      return;
    }

    if (connection->kcp == NULL) {
      connection->kcp = ikcp_create(connection->conv, connection);
      (connection->kcp)->output = packet_output;
      ikcp_setmtu(connection->kcp, KCP_MTU);
      ikcp_wndsize(connection->kcp, KCP_MAX_WND_SIZE, KCP_MAX_WND_SIZE);
      ikcp_nodelay(connection->kcp, kcpconfig.nodelay, kcpconfig.interval, kcpconfig.resend, kcpconfig.nc);
    }

    LOG("New connection conv %d.", connection->conv);

    connection->local_fd = local_fd;

    struct ev_io *local_read_io = &((connection->read_io).io);
    struct ev_io *local_write_io = &((connection->write_io).io);

    memset(local_read_io, 0x00, sizeof(struct ev_io));
    memset(local_write_io, 0x00, sizeof(struct ev_io));

    ev_io_init(local_read_io, read_cb, local_fd, EV_READ);
    ev_io_init(local_write_io, write_cb, local_fd, EV_WRITE);
    ev_io_start(loop, local_read_io);
    ev_io_start(loop, local_write_io);

  }

  if (is_packet_command(payload, CONNECTION_PUSH) && size > 8 && connection->kcp != NULL && connection->in_use == 1) {
    ikcp_input(connection->kcp, payload + 8, size - 8);
  }

  if (is_packet_command(payload, CONNECTION_CLOSE) && connection->in_use == 1) {
    LOG("Remote notifies immediately closing. conv=%d", identifier);
    close_connection(connection);
  }

}

int main(int argc, char* argv[]) {

  signal(SIGPIPE, SIG_IGN);
  srand(time(NULL));

  if (argc < 5) {
    printf("Usage: ./server_bin TCP_CONNECT_TO_IP TCP_CONNECT_TO_PORT SERVER_IP SERVER_PORT [mode] [noseq]\n");
    exit(1);
  }

  strcpy(tcp_connect_to_ip, argv[1]);
  tcp_connect_to_port = atoi(argv[2]);

  init_kcp_mode(argc, argv);


  for (int i=0; i<MAX_CONNECTIONS; i++) {
    connection_queue[i].in_use = 0;
    connection_queue[i].conv = i;
    connection_queue[i].kcp = NULL;
    connection_queue[i].local_fd = -1;
    connection_queue[i].pending_send_buf_len = 0;
    connection_queue[i].pending_send_buf = NULL;
    connection_queue[i].write_io.connection = &(connection_queue[i]);
    connection_queue[i].read_io.connection = &(connection_queue[i]);
  }

  strcpy(packetinfo.dest_ip, "0.0.0.0");
  packetinfo.dest_port = 0;
  strcpy(packetinfo.source_ip, argv[3]);
  packetinfo.source_port = atoi(argv[4]);
  packetinfo.on_packet_recv = on_packet_recv;
  packetinfo.is_server = 1;
  packetinfo.disable_seq_update = 0;

  for (int i=0; i<argc; i++) {
    if (!strcmp(argv[i], "noseq")) {
      LOG("Disable TCP sequense counter.");
      packetinfo.disable_seq_update = 1;
    }
  }

  loop = ev_default_loop(0);

  init_packet(&packetinfo);

  set_packet_recv_nonblocking();

  ev_timer_init(&kcp_update_timer, kcp_update_timer_cb, 0.003, 0.003);
  ev_timer_start(loop, &kcp_update_timer);

  ev_io_init(&packet_recv_io, packet_read_cb, packet_recv_sd, EV_READ);
  ev_io_start(loop, &packet_recv_io);

  ev_timer_init(&heart_beat_timer, heart_beat_timer_cb, 0, 2);
  ev_timer_start(loop, &heart_beat_timer);

  ev_run(loop, 0);

  return 0;
}
