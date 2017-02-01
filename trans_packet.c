#include <stdio.h> //for printf
#include <string.h> //memset
#include <limits.h>
#include <sys/socket.h>    //for socket ofcourse
#include <sys/types.h>
#include <stdlib.h> //for exit(0);
#include <errno.h> //For errno - the error number
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <byteswap.h>
#include <ev.h>

#include "trans_packet.h"

#include "ikcp.h"
#include "common.h"

/* 
    96 bit (12 bytes) pseudo header needed for tcp header checksum calculation 
*/
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

unsigned short csum(unsigned short *ptr,int nbytes);

void init_packet(struct packet_info* packetinfo) {
    packet_send_sd = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    packet_recv_sd = socket(AF_PACKET , SOCK_DGRAM , htons(ETH_P_IP));
    // packet_recv_sd = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    if(packet_send_sd == -1 || packet_recv_sd == -1) {
        //socket creation failed, may be because of non-root privileges
        perror("Failed to create socket");
        exit(1);
    }

    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
    if (setsockopt (packet_send_sd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0) {
        perror("Error setting IP_HDRINCL");
        exit(2);
    }

    (packetinfo->state).seq = 0;
    (packetinfo->state).ack = 1;

}

void set_packet_recv_nonblocking() {
    int flags;
    if (-1 == (flags = fcntl(packet_recv_sd, F_GETFL, 0))) {
        flags = 0;
    }
    fcntl(packet_recv_sd, F_SETFL, flags | O_NONBLOCK);
}

void set_packet_send_nonblocking() {
    int flags;
    if (-1 == (flags = fcntl(packet_send_sd, F_GETFL, 0))) {
        flags = 0;
    }
    fcntl(packet_send_sd, F_SETFL, flags | O_NONBLOCK);
}

char* pending_stream_buffer = NULL;
int pending_stream_capability = 0;
int pending_stream_len = 0;

void check_packet_recv(struct packet_info* packetinfo) {
    int saddr_size , size;
    struct sockaddr saddr;
    unsigned short iphdrlen;

    struct in_addr from_addr;

    char buffer[MTU];

    saddr_size = sizeof(saddr);

    size = recvfrom(packet_recv_sd, buffer, MTU, 0 ,&saddr , &saddr_size);
    
    if(size < 0 || size < sizeof(struct iphdr) + sizeof(struct tcphdr)) {
        return;
    }

    struct iphdr *iph = (struct iphdr *)buffer;
    iphdrlen =iph->ihl*4;

    if (iph->protocol != IPPROTO_TCP) {
        return;
    }

    from_addr.s_addr = iph->saddr;

    struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);

    if (ntohs(tcph->dest) != packetinfo->source_port) {
        return;
    }

    if (packetinfo->is_server == 1 && tcph->syn == 1 && tcph->ack == 0 && tcph->psh == 0) {
        // Server replies SYN + ACK
        (packetinfo->state).seq = 1;
        (packetinfo->state).ack = 1;
        strcpy(packetinfo->dest_ip, inet_ntoa(from_addr));
        packetinfo->dest_port = ntohs(tcph->source);
        send_packet(packetinfo, "", 0, REPLY_SYN_ACK);
        return;
    }

    if (packetinfo->is_server == 0 && tcph->syn == 1 && tcph->ack == 1 && tcph->psh == 0) {
        //Client replies first ACK
        (packetinfo->state).seq = 1;
        (packetinfo->state).ack = 1;
        send_packet(packetinfo, "", 0, REPLY_ACK);
        return;
    }

    if(size < sizeof(struct iphdr) + sizeof(struct tcphdr) + 4) {
        return;
    }

    // verify TCP checksum

    char pseudo_tcp_buffer[MTU];

    memcpy(pseudo_tcp_buffer, buffer + iphdrlen, size - iphdrlen);

    struct tcphdr* pseudo_tcp_header = (struct tcphdr*)pseudo_tcp_buffer;
    pseudo_tcp_header->check = 0;

    struct pseudo_header psh;

    int payloadlen = size - tcph->doff*4 - iphdrlen;

    char *pseudogram = malloc(sizeof(struct pseudo_header) + sizeof(struct tcphdr) + payloadlen);

    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + payloadlen );

    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), pseudo_tcp_buffer, size - iphdrlen);

    unsigned short tcp_checksum = csum((short unsigned int*)pseudogram, sizeof(struct pseudo_header) + sizeof(struct tcphdr) + payloadlen);

    free(pseudogram);

    if (tcp_checksum != tcph->check) {
        // printf("[trans_packet]TCP checksum failed.\n");
        return;
    }

    if (!(packetinfo->disable_seq_update)) {
        (packetinfo->state).ack = __bswap_32(tcph->seq) + payloadlen;
    }

    char* data_payload_buf = buffer + iphdrlen + tcph->doff*4 + 4;
    int data_payload_len = payloadlen - 4;

    unsigned short data_payload_checksum = *((unsigned short*)(buffer + iphdrlen + tcph->doff*4));

    if (csum((unsigned short*)data_payload_buf, data_payload_len) != data_payload_checksum) {
        LOG("[trans_packet]Data checksum verification failed. Dropping.");
        return;
    }

    (*(packetinfo->on_packet_recv))(inet_ntoa(from_addr), ntohs(tcph->source), data_payload_buf, data_payload_len);

}

int send_packet(struct packet_info* packetinfo, char* source_payload, int source_payloadlen, unsigned int flag) {
    //Datagram to represent the packet
    char datagram[MTU], *data , *pseudogram;

    if (source_payloadlen > MTU - 40 - 4) {
        LOG("[trans_packet]Packet length should not be greater than MTU.");
        return -1;
    }

    char* payload = "";
    int payloadlen = 0;

    if (flag < UINT_MAX - 2) {
        payload = malloc(source_payloadlen + 4);
        unsigned short data_payload_checksum = csum((unsigned short*)source_payload, source_payloadlen);
        memcpy(payload, &data_payload_checksum, 2);
        memset(payload + 2, 0x00, 2);   // 2 reserved bytes
        memcpy(payload + 4, source_payload, source_payloadlen);
        payloadlen = source_payloadlen + 4;
    }

    //zero out the packet buffer
    memset (datagram, 0, MTU);
    //IP header
    struct iphdr *iph = (struct iphdr *) datagram;

    //TCP header
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
    struct sockaddr_in sin;
    struct pseudo_header psh;

    //Data part
    data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);

    memcpy(data , payload, payloadlen);

    //some address resolution
    sin.sin_family = AF_INET;
    sin.sin_port = htons(packetinfo->dest_port);
    sin.sin_addr.s_addr = inet_addr (packetinfo->dest_ip);

    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + payloadlen;
    iph->id = htonl (54321); //Id of this packet
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0; //Set to 0 before calculating checksum
    iph->saddr = inet_addr(packetinfo->source_ip);    //Spoof the source ip address
    iph->daddr = sin.sin_addr.s_addr;

    //TCP Header
    tcph->source = htons(packetinfo->source_port);
    tcph->dest = sin.sin_port;
    tcph->seq = __bswap_32((packetinfo->state).seq);
    tcph->ack_seq = __bswap_32((packetinfo->state).ack);
    tcph->doff = 5;  //tcp header size
    tcph->fin=0;
    tcph->syn=0;
    tcph->rst=0;
    tcph->psh=1;
    tcph->ack=1;
    tcph->urg=0;
    tcph->window = htons(129600);
    tcph->check = 0; //leave checksum 0 now, filled later by pseudo header
    tcph->urg_ptr = 0;

    if (flag == FIRST_SYN) {
        tcph->seq = 0;
        tcph->ack = 0;
        tcph->syn = 1;
        tcph->ack_seq = 0;
        tcph->psh=0;
        LOG("[trans_packet]Client sending SYN.");
    }

    if (flag == REPLY_SYN_ACK) {
        tcph->seq = 0;
        tcph->ack_seq = __bswap_32(1);
        tcph->syn = 1;
        tcph->ack = 1;
        tcph->psh=0;
        LOG("[trans_packet]Server replying SYN+ACK.");
    }

    if (flag == REPLY_ACK) {
        tcph->seq = __bswap_32(1);
        tcph->ack_seq = __bswap_32(1);
        tcph->syn = 0;
        tcph->ack = 1;
        tcph->psh=0;
        LOG("[trans_packet]Client replying ACK.");
    }

    //Now the TCP checksum
    psh.source_address = inet_addr(packetinfo->source_ip);
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + payloadlen );

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + payloadlen;
    pseudogram = malloc(psize);

    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + payloadlen);

    tcph->check = csum( (unsigned short*) pseudogram , psize);

    //Ip checksum
    iph->check = csum ((unsigned short *) datagram, iph->tot_len);

    free(pseudogram);
    
    int ret = sendto (packet_send_sd, datagram, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin));

    // printf("[trans_packet]Sent %d bytes packet.\n", ret);
    if (flag < UINT_MAX - 2) {
        free(payload);
        if (!(packetinfo->disable_seq_update)) {
            ((packetinfo->state).seq) += payloadlen;
        }
    }

    if (ret > 0) {
        return source_payloadlen;
    } else {
        return -1;
    }
}
 
/*
    Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr,int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
 
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}
