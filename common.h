#define BUFFER_SIZE 1024
#define MAX_CONNECTIONS 100

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

#define CONNECTION_CONNECT "CONNECT0"
#define CONNECTION_PUSH "PUSH0000"
#define CONNECTION_CLOSE "CLOSE000"
#define HEART_BEAT "HARTBEAT"
#define IS_VALID_PACKET(payload) (is_packet_command((payload), CONNECTION_CONNECT) || is_packet_command((payload), CONNECTION_PUSH) || is_packet_command((payload), CONNECTION_CLOSE) || is_packet_command((payload), HEART_BEAT))
#define is_valid_packet IS_VALID_PACKET

struct io_wrap {
  struct ev_io io;
  struct connection_info* connection;
};

struct connection_info {
  int in_use;
  int conv;
  ikcpcb *kcp;
  int local_fd;
  char* pending_send_buf;
  int pending_send_buf_len;
  struct io_wrap read_io;
  struct io_wrap write_io;
};

void notify_remote_close(struct connection_info* connection);
void close_connection(struct connection_info* connection);

struct packet_info packetinfo;

struct connection_info connection_queue[MAX_CONNECTIONS];

struct ev_loop* loop;

struct ev_io packet_recv_io;
struct ev_timer kcp_update_timer;
struct ev_timer heart_beat_timer;

unsigned int getclock();
int setnonblocking(int fd);
int packet_output(const char* buf, int len, ikcpcb *kcp, void *user);
void read_cb(struct ev_loop *loop, struct ev_io *w_, int revents);
void write_cb(struct ev_loop *loop, struct ev_io *w_, int revents);
void kcp_update_timer_cb(struct ev_loop *loop, struct ev_timer* timer, int revents);
void kcp_update_interval();
void notify_remote_close(struct connection_info* connection);
void close_connection(struct connection_info* connection);
void packet_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
int is_packet_command(char* packet_buffer, const char* command);
void heart_beat_timer_cb(struct ev_loop *loop, struct ev_timer* timer, int revents);
int iqueue_get_len(struct IQUEUEHEAD* queue);
