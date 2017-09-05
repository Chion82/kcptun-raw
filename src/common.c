#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>

#include <stdarg.h>

#include "ikcp.h"
#include "trans_packet.h"

#include "vector.h"
#include "common.h"

char* pending_recv_stream = NULL;
int pending_recv_stream_len = 0;
ikcpcb *kcp = NULL;

int bpf_enabled = 0;

#ifndef SERVER
int temp_port_sd = -1;
#endif

void handle_recv_stream();

unsigned int getclock() {
  struct timeval te; 
  gettimeofday(&te, NULL); // get current time
  long long milliseconds = te.tv_sec*1000LL + te.tv_usec/1000; // caculate milliseconds
  return milliseconds;
}

int setnonblocking(int fd) {
  int flags;
  if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
    flags = 0;
  }
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int packet_is_command(char* packet_buf, const char* command) {
  for (int i=0; i<8; i++) {
    if (packet_buf[i] != command[i]) {
      return 0;
    }
  }
  return 1;
}

void on_packet_recv(char* from_addr, uint16_t from_port, char* buffer, int length) {

  if (length < 8) {
    return;
  }

#ifdef SERVER
  strcpy(packetinfo.dest_ip, from_addr);
  packetinfo.dest_port = from_port;
#endif

  if (packet_is_command(buffer, HEART_BEAT)) {
    last_recv_heart_beat = getclock();
    return;
  }

  if (packet_is_command(buffer, PUSH_DATA) && length > 8) {
    last_recv_heart_beat = getclock();
    if (kcp != NULL) {
      ikcp_input(kcp, buffer + 8, length - 8);
    }
  }

#ifdef SERVER
  if (packet_is_command(buffer, INIT_KCP)) {
    LOG("Remote notifies re-init KCP connection.");
    init_kcp();
    send_packet(&packetinfo, KCP_READY, 8, 0);
  }
#endif

#ifndef SERVER
  if (packet_is_command(buffer, KCP_READY)) {
    LOG("kcp ready.");
    init_kcp();
    ev_timer_stop(loop, &init_kcp_timer);
  }
#endif

}


int packet_output(const char* buf, int len, ikcpcb *kcp, void *user) {
  char* send_buf = malloc(len + 8);
  memcpy(send_buf, PUSH_DATA, 8);
  memcpy(send_buf + 8, buf, len);
  int ret = send_packet(&packetinfo, send_buf, len + 8, 0);

  free(send_buf);
  return ret;
}

void read_cb(struct ev_loop *loop, struct ev_io *w_, int revents) {

  struct connection_info *connection = ((struct io_wrap*)w_)->connection;
  struct ev_io *watcher = &(((struct io_wrap*)w_)->io);

  char buffer[BUFFER_SIZE];
  char* fragment_payload = buffer + sizeof(struct fragment_header);

  if(EV_ERROR & revents) {
    return;
  }

  int recv_bytes = recv(watcher->fd, 
    fragment_payload, 
    BUFFER_SIZE - sizeof(struct fragment_header), 
    0);

  if ((recv_bytes == -1 && errno != EAGAIN && errno != EWOULDBLOCK) || recv_bytes == 0) {
    LOG("recv ends. conv=%d", connection->conv);
    close_connection(connection);
    notify_remote_close(connection);
    return;
  }

  if (recv_bytes == -1) {
    return;
  }

  int fragment_payload_length = recv_bytes;

  struct fragment_header* command_header = (struct fragment_header*)buffer;
  bzero(command_header, sizeof(struct fragment_header));
  command_header->conv = htonl(connection->conv);
  command_header->command = CONNECTION_PUSH;
  command_header->length = htonl(fragment_payload_length);

  ikcp_send(kcp, buffer, sizeof(struct fragment_header) + fragment_payload_length);

  kcp_update_interval();

}

void write_cb(struct ev_loop *loop, struct ev_io *w_, int revents) {

  struct connection_info *connection = ((struct io_wrap*)w_)->connection;
  struct ev_io *watcher = &(((struct io_wrap*)w_)->io);

  char buffer[BUFFER_SIZE];

  if(EV_ERROR & revents) {
    return;
  }

  if (connection->pending_send_buf_len == 0) {
    ev_io_stop(loop, &((connection->write_io).io));
    return;
  }

  int sent_bytes = send(watcher->fd, connection->pending_send_buf, connection->pending_send_buf_len, 0);

  if (sent_bytes == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
    LOG("send ends. conv=%d", connection->conv);
    close_connection(connection);
    notify_remote_close(connection);
    return;
  }

  if (sent_bytes == -1) {
    sent_bytes = 0;
  }

  if (sent_bytes == connection->pending_send_buf_len) {
    // LOG("write_cb(): all pending data sent out.");
    connection->pending_send_buf_len = 0;
    free(connection->pending_send_buf);
    connection->pending_send_buf = NULL;
    if (connection->pending_close) {
      close_connection(connection);
      return;
    }
  } else {
    // LOG("write_cb(): partially sent.");
    memmove(connection->pending_send_buf,
      connection->pending_send_buf + sent_bytes,
      connection->pending_send_buf_len - sent_bytes);
    connection->pending_send_buf_len -= sent_bytes;
  }

}

void kcp_update_timer_cb(struct ev_loop *loop, struct ev_timer* timer, int revents) {
  kcp_update_interval();

  if (kcp && (iqueue_get_len(&(kcp->snd_queue)) > 10 || iqueue_get_len(&(kcp->rcv_queue)) > 10)) {
    ev_timer_stop(loop, timer);
    ev_timer_set(timer, 0.001, 0.001);
    ev_timer_start(loop, timer);
  } else {
    ev_timer_stop(loop, timer);
    ev_timer_set(timer, 0.01, 0.01);
    ev_timer_start(loop, timer);
  }
}

void kcp_update_interval() {
  char recv_buf[BUFFER_SIZE];

  if (kcp == NULL) {
    return;
  }

  ikcp_update(kcp, getclock());

  struct connection_info* connection = NULL;

  for (int i = 0; i < vector_total(&open_connections_vector); i++) {
    connection = vector_get(&open_connections_vector, i);
    if (connection->in_use && (connection->pending_send_buf_len) > MAX_QUEUE_LENGTH * BUFFER_SIZE) {
      return;
    }
  }

  int recv_len = ikcp_recv(kcp, recv_buf, BUFFER_SIZE);

  int stop_recv = (iqueue_get_len(&(kcp->snd_queue)) > MAX_QUEUE_LENGTH) ? 1 : 0;

  for (int i = 0; i < vector_total(&open_connections_vector); i++) {
    connection = vector_get(&open_connections_vector, i);
    if (!(connection->in_use)) {
      continue;
    }
    if (stop_recv) {
      ev_io_stop(loop, &((connection->read_io).io));
    } else {
      ev_io_start(loop, &((connection->read_io).io));
    }
  }

  if (recv_len <= 0) {
    return;
  }

  last_kcp_recv = getclock();

  pending_recv_stream = realloc(pending_recv_stream, pending_recv_stream_len + recv_len);

  memcpy(pending_recv_stream + pending_recv_stream_len, recv_buf, recv_len);

  pending_recv_stream_len += recv_len;

  if (pending_recv_stream_len >= sizeof(struct fragment_header)) {
    struct fragment_header* command_header = (struct fragment_header*)pending_recv_stream;
    if (pending_recv_stream_len >= sizeof(struct fragment_header) + ntohl(command_header->length)) {
      handle_recv_stream();
    }
  }
}

void handle_recv_stream() {
  struct fragment_header* command_header = (struct fragment_header*)pending_recv_stream;
  int fragment_payload_length = ntohl(command_header->length);
  char* fragment_payload = (char*)command_header + sizeof(struct fragment_header);
  int conv = ntohl(command_header->conv);
  struct connection_info* connection = &connection_queue[conv];

  switch(command_header->command) {
    case CONNECTION_NOP:
      break;

#ifdef SERVER

    case CONNECTION_CONNECT:
      LOG("Remote notifies new connection. conv=%d", conv);

      if (connection->in_use) {
        LOG("conv %d already in use. Closing", conv);
        close_connection(connection);
      }

      int local_fd = init_connect_to_socket();

      if (local_fd < 0) {
        LOG("connect failed.");
        close_connection(connection);
        notify_remote_close(connection);
        break;
      }

      connection->in_use = 1;
      connection->local_fd = local_fd;
      connection->pending_send_buf = NULL;
      connection->pending_send_buf_len = 0;
      connection->pending_close = 0;

      vector_add(&open_connections_vector, connection);

      struct ev_io *local_read_io = &((connection->read_io).io);
      struct ev_io *local_write_io = &((connection->write_io).io);

      ev_io_init(local_read_io, read_cb, local_fd, EV_READ);
      ev_io_init(local_write_io, write_cb, local_fd, EV_WRITE);
      ev_io_start(loop, local_read_io);
      ev_io_start(loop, local_write_io);

      break;

#endif

    case CONNECTION_PUSH:
      if (!(connection->in_use)) {
        break;
      }
      int sent_bytes = 0;

      if (connection->pending_send_buf_len == 0) {
        sent_bytes = send(connection->local_fd, fragment_payload, fragment_payload_length, 0);
      }

      if (sent_bytes == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
        LOG("send ends. conv=%d", conv);
        close_connection(connection);
        notify_remote_close(connection);
        break;
      }

      if (sent_bytes == -1) {
        sent_bytes = 0;
      }

      if (sent_bytes < fragment_payload_length) {
        // LOG("handle_recv_stream(): partially sent.");
        connection->pending_send_buf = realloc(connection->pending_send_buf,
          connection->pending_send_buf_len + fragment_payload_length - sent_bytes);
        memcpy(connection->pending_send_buf + connection->pending_send_buf_len,
          fragment_payload + sent_bytes,
          fragment_payload_length - sent_bytes);
        connection->pending_send_buf_len += (fragment_payload_length - sent_bytes);
        ev_io_start(loop, &((connection->write_io).io));
      }

      break;
    case CONNECTION_CLOSE:
      if (!(connection->in_use)) {
        break;
      }
      LOG("Remote notifies closing. conv=%d", conv);
      if (connection->pending_send_buf_len == 0) {
        close_connection(connection);
      } else {
        pending_close_connection(connection);
      }
      break;
  }

  memmove(pending_recv_stream,
    pending_recv_stream + sizeof(struct fragment_header) + fragment_payload_length,
    pending_recv_stream_len - sizeof(struct fragment_header) - fragment_payload_length);

  pending_recv_stream_len -= (sizeof(struct fragment_header) + fragment_payload_length);

}

void notify_remote_connect(struct connection_info* connection) {
  LOG("Notifying remote new connection. conv=%d", connection->conv);
  struct fragment_header command_header;
  command_header.conv = htonl(connection->conv);
  command_header.command = CONNECTION_CONNECT;
  command_header.length = 0;
  ikcp_send(kcp, (char*)&command_header, sizeof(struct fragment_header));
}

void notify_remote_close(struct connection_info* connection) {
  LOG("Notifying remote closing. conv=%d", connection->conv);
  struct fragment_header command_header;
  command_header.conv = htonl(connection->conv);
  command_header.command = CONNECTION_CLOSE;
  command_header.length = 0;
  ikcp_send(kcp, (char*)&command_header, sizeof(struct fragment_header));
}

void close_connection(struct connection_info* connection) {
  if (!(connection->in_use)) {
    return;
  }

  LOG("Closing connection. conv=%d", connection->conv);

  close(connection->local_fd);
  ev_io_stop(loop, &((connection->write_io).io));
  ev_io_stop(loop, &((connection->read_io).io));

  connection->local_fd = -1;
  if (connection->pending_send_buf != NULL) {
    free(connection->pending_send_buf);
  }
  connection->pending_send_buf = NULL;
  connection->pending_send_buf_len = 0;

  bzero(&((connection->write_io).io), sizeof(struct ev_io));
  bzero(&((connection->read_io).io), sizeof(struct ev_io));

  connection->in_use = 0;
  connection->pending_close = 0;

  for (int i = vector_total(&open_connections_vector) - 1; i>=0; i--) {
    if (vector_get(&open_connections_vector, i) == connection) {
      vector_delete(&open_connections_vector, i);
    }
  }

}

void pending_close_connection(struct connection_info* connection) {
  LOG("Pending close connection. conv=%d", connection->conv);
  connection->pending_close = 1;
}

void packet_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
  if(EV_ERROR & revents) {
    return;
  }
  check_packet_recv(&packetinfo);
  kcp_update_interval();
}

void heart_beat_timer_cb(struct ev_loop *loop, struct ev_timer* timer, int revents) {
  if (!strcmp(packetinfo.dest_ip, "0.0.0.0")) {
    return;
  }

#ifndef SERVER

  struct sockaddr_in temp_bind_addr;
  
  if (getclock() - last_recv_heart_beat > HEART_BEAT_TIMEOUT * 1000) {
    last_recv_heart_beat = getclock() - 3 * 1000;
    (packetinfo.state).seq = 0;
    (packetinfo.state).ack = 1;
    LOG("Re-init fake TCP connection.");

    do {
      // Find an unused port by binding and listening.
      // By this way we tell the kernel the port is occupied.
      if (temp_port_sd != -1) {
        close(temp_port_sd);
      }
      packetinfo.source_port = 30000 + rand() % 10000;

      temp_port_sd = socket(PF_INET, SOCK_STREAM, 0);
      bzero(&temp_bind_addr, sizeof(temp_bind_addr));
      temp_bind_addr.sin_family = AF_INET;
      temp_bind_addr.sin_port = htons(packetinfo.source_port);
      temp_bind_addr.sin_addr.s_addr = INADDR_ANY;

      LOG("Trying port %d", packetinfo.source_port);

    } while (bind(temp_port_sd, (struct sockaddr*)&temp_bind_addr, sizeof(temp_bind_addr)) != 0
      || listen(temp_port_sd, SOMAXCONN) != 0);

    init_bpf();
    send_packet(&packetinfo, "", 0, FIRST_SYN);
    return;
  }

#endif

  send_packet(&packetinfo, HEART_BEAT, 8, 0);
}

void kcp_nop_timer_cb(struct ev_loop *loop, struct ev_timer* timer, int revents) {
  if (kcp == NULL) {
    return;
  }
  struct fragment_header command_header;
  command_header.conv = 0;
  command_header.command = CONNECTION_NOP;
  command_header.length = 0;
  ikcp_send(kcp, (char*)&command_header, sizeof(struct fragment_header));

#ifndef SERVER
  if (getclock() - last_kcp_recv > KCP_RECV_TIMEOUT * 1000) {
    LOG("KCP recv timeout. Re-init KCP connection.");
    last_kcp_recv = getclock() - 10 * 1000;

    for (int i=0; i<MAX_CONNECTIONS; i++) {
      if (connection_queue[i].in_use) {
        close_connection(&(connection_queue[i]));
      }
    }

    ikcp_release(kcp);
    kcp = NULL;

    ev_timer_start(loop, &init_kcp_timer);
  }
#endif
}

void init_kcp_mode(int argc, char* argv[]) {

  kcpconfig.nodelay = 1;
  kcpconfig.interval = 10;
  kcpconfig.resend = 2;
  kcpconfig.nc = 1;

  for(int i=0; i<argc; i++) {
    if ((!strcmp(argv[i], "--mode")) && i != argc -1) {
      char* arg = argv[i + 1];

      if (!strcmp(arg, "normal")) {
        LOG("normal mode enabled.");
        kcpconfig.nodelay = 0;
        kcpconfig.interval = 30;
        kcpconfig.resend = 2;
        kcpconfig.nc = 1;
      } else if (!strcmp(arg, "fast")) {
        LOG("fast mode enabled.");
        kcpconfig.nodelay = 0;
        kcpconfig.interval = 20;
        kcpconfig.resend = 2;
        kcpconfig.nc = 1;
      } else if (!strcmp(arg, "fast2")) {
        LOG("fast2 mode enabled.");
        kcpconfig.nodelay = 1;
        kcpconfig.interval = 20;
        kcpconfig.resend = 2;
        kcpconfig.nc = 1;
      } else if (!strcmp(arg, "fast3")) {
        LOG("fast3 mode enabled.");
        kcpconfig.nodelay = 1;
        kcpconfig.interval = 10;
        kcpconfig.resend = 2;
        kcpconfig.nc = 1;
      } else {
        LOG("Unsupported mode. (normal/fast/fast2/fast3)");
        exit(1);
      }
    }
  }

}

void init_aes_key(int argc, char* argv[]) {
  for(int i=0; i<argc; i++) {
    char* arg = argv[i];

    if ((!strcmp(arg, "--key")) && i != argc - 1) {
      char* key = argv[i+1];
      if (strlen(key) != 16) {
        printf("key must be 16 bytes long.\n");
        exit(-1);
      }
      aes_ckey = malloc(16);
      memcpy(aes_ckey, key, 16);
    }

  }
}

void LOG(const char* message, ...) {
  time_t now = time(NULL);
  char timestr[20];
  strftime(timestr, 20, "%Y-%m-%d %H:%M:%S", localtime(&now));
  printf("[%s] ", timestr);
  va_list argptr;
  va_start(argptr, message);
  vfprintf(stdout, message, argptr);
  va_end(argptr);
  printf("\n");
  fflush(stdout);
}

void init_kcp() {
  if (kcp != NULL) {
    ikcp_release(kcp);
  }

  for (int i=0; i<MAX_CONNECTIONS; i++) {
    if (connection_queue[i].in_use) {
      close_connection(&(connection_queue[i]));
    }
  }

  if (pending_recv_stream != NULL) {
    free(pending_recv_stream);
  }
  pending_recv_stream = NULL;
  pending_recv_stream_len = 0;

  kcp = ikcp_create(0, NULL);
  kcp->output = packet_output;
  ikcp_setmtu(kcp, KCP_MTU);
  ikcp_wndsize(kcp, KCP_MAX_WND_SIZE, KCP_MAX_WND_SIZE);
  ikcp_nodelay(kcp, kcpconfig.nodelay, kcpconfig.interval, kcpconfig.resend, kcpconfig.nc);
}

int iqueue_get_len(struct IQUEUEHEAD* queue) {
  struct IQUEUEHEAD* head = queue;
  struct IQUEUEHEAD* node = queue->next;
  int ret = 0;
  while (node != head) {
    ret++;
    node = node->next;
  }
  return ret;
}

void enable_bpf(int argc, char* argv[]) {
  bpf_enabled = 0;
  for(int i=0; i<argc; i++) {
    char* arg = argv[i];
    if (!strcmp(arg, "--bpf")) {
      LOG("BPF enabled.");
      bpf_enabled = 1;
    }
  }
}
