#define KCP_MTU (MTU - 40 - 4 - 20)
#define BUFFER_SIZE (KCP_MTU - 30)
#define KCP_MAX_WND_SIZE 1024
#define MAX_CONNECTIONS 2048
#define MAX_QUEUE_LENGTH 5000
#define HEART_BEAT_TIMEOUT 7
#define KCP_RECV_TIMEOUT 30

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

#define CONNECTION_CONNECT 1
#define CONNECTION_PUSH 2
#define CONNECTION_CLOSE 3
#define CONNECTION_NOP 0
#define HEART_BEAT "HARTBEAT"
#define PUSH_DATA "PUSHDATA"
#define INIT_KCP "INITKCP0"
#define IS_VALID_PACKET(payload) (is_packet_command((payload), CONNECTION_CONNECT) || is_packet_command((payload), CONNECTION_PUSH) || is_packet_command((payload), CONNECTION_CLOSE) || is_packet_command((payload), HEART_BEAT))
#define is_valid_packet IS_VALID_PACKET

struct fragment_header {
  int conv;
  char command; 
  int length;
};

struct io_wrap {
  struct ev_io io;
  struct connection_info* connection;
};

struct connection_info {
  int in_use;
  int conv;
  int local_fd;
  char* pending_send_buf;
  int pending_send_buf_len;
  struct io_wrap read_io;
  struct io_wrap write_io;
  int pending_close;
};

struct kcp_config {
  int nodelay;
  int interval;
  int resend;
  int nc;
};

ikcpcb *kcp;

unsigned int last_recv_heart_beat;
unsigned int last_kcp_recv;

struct packet_info packetinfo;

struct connection_info connection_queue[MAX_CONNECTIONS];

struct ev_loop* loop;

struct ev_io packet_recv_io;
struct ev_timer kcp_update_timer;
struct ev_timer heart_beat_timer;
struct ev_timer kcp_nop_timer;

struct kcp_config kcpconfig;

void init_kcp_mode(int argc, char* argv[]);

unsigned int getclock();
int setnonblocking(int fd);
int packet_output(const char* buf, int len, ikcpcb *kcp, void *user);
void on_packet_recv(char* from_addr, uint16_t from_port, char* buffer, int length);
void read_cb(struct ev_loop *loop, struct ev_io *w_, int revents);
void write_cb(struct ev_loop *loop, struct ev_io *w_, int revents);
void kcp_update_timer_cb(struct ev_loop *loop, struct ev_timer* timer, int revents);
void kcp_nop_timer_cb(struct ev_loop *loop, struct ev_timer* timer, int revents);
void kcp_update_interval();
void notify_remote_connect(struct connection_info* connection);
void notify_remote_close(struct connection_info* connection);
void close_connection(struct connection_info* connection);
void pending_close_connection(struct connection_info* connection);
void packet_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void heart_beat_timer_cb(struct ev_loop *loop, struct ev_timer* timer, int revents);
void LOG(const char* message, ...);
void init_kcp();
void init_aes_key(int argc, char* argv[]);
int iqueue_get_len(struct IQUEUEHEAD* queue);

int init_connect_to_socket();
