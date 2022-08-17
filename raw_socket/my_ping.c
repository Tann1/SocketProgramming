#include <stdlib.h>
#include <stdio.h>
#include <unistd.h> // close()
#include <string.h> // bzero() memset()
#include <time.h>   // used for ICMP timestamp

/* socket and internet API */
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* personal includes */ 
#include "IP_header.h"
#include "ICMP_header.h"
#include "util_func.h"
#include "util_packet_info.h" // it's a packet sniffer to display the content

#define BUFFER_SIZE 512
#define IP_ADDR "192.168.10.103"

int main(int agrc, char *agrv[]) {
    uint32_t buffer[BUFFER_SIZE];
    int sock_fd, n_bytes = 0;
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
    while (1) {
    bzero((void *)buffer, BUFFER_SIZE);
    if ((n_bytes = recvfrom(sock_fd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&peer_socket, &peer_size)) == -1)
        exit_after_err_msg("Failed to populate buffer");
    
    print_echo_request((Echo_Ping *)buffer, n_bytes);
    }
    close(sock_fd); 

    return 0;
}