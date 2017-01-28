#define MTU 1440

struct trans_packet_state {
  unsigned int seq;
  unsigned int ack;
};

struct packet_info {
  char dest_ip[128];
  char source_ip[128];
  uint16_t dest_port;
  uint16_t source_port;
  void (*on_packet_recv)(char*, uint16_t, char*, int, unsigned int);
  int is_server;
  struct trans_packet_state state;
};

int packet_send_sd;
int packet_recv_sd;

void init_packet();
int send_packet(struct packet_info* packetinfo, char* source_payload, int payloadlen, unsigned int identifier);

void set_packet_recv_nonblocking();
void set_packet_send_nonblocking();
void check_packet_recv(struct packet_info* packetinfo);
