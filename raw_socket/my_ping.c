#include <stdlib.h>
#include <stdio.h>
#include <unistd.h> // close()
#include <string.h> // bzero() memset()

/* socket and internet API */
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* personal includes */ 
#include "IP_header.h"
#include "ICMP_header.h"
#include "util_func.h"


#define BUFFER_SIZE 4096
#define IP_ADDR "192.168.10.103"

typedef struct {
    IP_header ip;
    ICMP_echo icmp;
} Echo_Ping; 

static void print_echo_request(uint8_t *buffer, size_t size);
static void print_ip_header(IP_header *ip);

int main(int agrc, char *agrv[]) {
    uint8_t buffer[BUFFER_SIZE];
    int sock_fd, n_bytes;
    struct sockaddr_in my_socket, peer_socket;
    int peer_size = sizeof(peer_socket);

    /* create raw socket */
    sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock_fd == -1)
        exit_after_err_msg("Failed to create raw socket");
    /* bind raw socket to interface */
    bzero((void *)&my_socket, sizeof(my_socket));
    my_socket.sin_family = AF_INET;
    my_socket.sin_addr.s_addr = inet_addr(IP_ADDR);
    my_socket.sin_port = 0x0;

    if (bind(sock_fd, (const struct sockaddr *) &my_socket, sizeof(my_socket)) == -1)
        exit_after_err_msg("Failed to bind to interface");
    /* ready to recieve information */ 
    bzero((void *)buffer, BUFFER_SIZE);
    if ((n_bytes = recvfrom(sock_fd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&peer_socket, &peer_size)) == -1)
        exit_after_err_msg("Failed to populate buffer");
    
    printf("read: %u bytes.\n", n_bytes);
    print_echo_request(buffer, n_bytes);
    print_IP_header_in_hex((IP_header *)buffer, IP_SIZE);
    close(sock_fd);
    return 0;
}


static void print_echo_request(uint8_t *buffer, size_t size) {
    Echo_Ping *echo_data = malloc(sizeof(Echo_Ping)); 
    bzero(echo_data, sizeof(echo_data));
    echo_data = (Echo_Ping *)buffer;
    print_ip_header(&echo_data->ip);
    free(echo_data);

}
static void print_ip_header(IP_header *ip) {
    struct in_addr src, dst;
    src.s_addr = ip->src_ip_addr;
    dst.s_addr = ip->dst_ip_addr;

    printf("IP Header\n");
    printf("Version: %u\n"
           "Header Length: %u\n"
           "Type of Serivce: 0x%x\n"
           "Total Length: %u\n"
           "Identifier: 0x%x\n"
           "Flags: 0x%x\n"
           "Offset: %u\n"
           "TTL: %u\n"
           "Protocol: %u\n"
           "Checksum: 0x%x\n"
           "Source IP: %s\n"
           "Destination IP: %s\n",
           ip->ver, ip->len, ip->tos,
           ip->total_len, ip->ID, ip->flags,
           ip->offset, ip->TTL, ip->proto,
           ip->checksum, inet_ntoa(src), inet_ntoa(dst));
}