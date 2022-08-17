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
#define IP_ADDR "192.168.10.103" // default IP that has been mannual configured

static void icmp_format_reply_header(ICMP_echo *icmp_header, uint32_t size_of_icmp_packet);
static void ip_format_reply_header(IP_header *ip_header, uint32_t size_of_ip_header);

int main(int argc, char *agrv[]) {
    uint32_t buffer[BUFFER_SIZE];
    char *binding_addr = IP_ADDR;
    int sock_fd, n_bytes = 0;
    struct sockaddr_in my_socket, peer_socket;
    int peer_size = sizeof(peer_socket);
    Echo_Ping *echo_packet = NULL; // holds the header for ip and icmp_echo format

    /* let the user change addr through command argument else just use default IP that has already been set */
    if (argc == 2)
        binding_addr = agrv[1];

    if (inet_addr(binding_addr) == INADDR_NONE)
        exit_after_err_msg("invalid IP address");
    /* create raw socket */
    sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock_fd == -1)
        exit_after_err_msg("Failed to create raw socket");
    /* let raw socket know that we intend to write IP packets into it as well (naturally only expects ICMP) */
    const int on = 1;
    setsockopt(sock_fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)); 
    /* bind raw socket to interface */
    bzero((void *)&my_socket, sizeof(my_socket));
    my_socket.sin_family = AF_INET;
    my_socket.sin_addr.s_addr = inet_addr(binding_addr);
    my_socket.sin_port = 0x0;

    if (bind(sock_fd, (const struct sockaddr *) &my_socket, sizeof(my_socket)) == -1)
        exit_after_err_msg("Failed to bind to interface");
    /* ready to recieve information */ 
    while (1) {
    bzero((void *)buffer, BUFFER_SIZE);
    if ((n_bytes = recvfrom(sock_fd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&peer_socket, &peer_size)) == -1)
        exit_after_err_msg("Failed to populate buffer");
    echo_packet = (Echo_Ping *)buffer;

    /* Format both IP and ICMP with echo reply packet (also uncomment the follow commented lines to see more details) */
    //printf("IP and ICMP Request Packet Format\n");
    //print_echo_request(echo_packet, n_bytes); 

    icmp_format_reply_header(&echo_packet->icmp, n_bytes - IP_SIZE);
    ip_format_reply_header(&echo_packet->ip, IP_SIZE);

    //printf("IP and ICMP Reply Packet Format\n");
    //print_echo_request(echo_packet, n_bytes);

    /* send the echo reply packet */ 
    sendto(sock_fd, echo_packet, n_bytes, 0, (const struct sockaddr *)&peer_socket, peer_size);
    printf("Replied to %s\n", inet_ntoa(peer_socket.sin_addr));
    }
    close(sock_fd); 

    return 0;
}

static void icmp_format_reply_header(ICMP_echo *icmp_header, uint32_t size_of_icmp_packet) {
    if (icmp_header == NULL)
        return;

    icmp_header->icmp_header.type = 0;
    icmp_header->icmp_header.code = 0;
    icmp_header->icmp_header.checksum = 0; // set checksum to 0 before calculating new checksum
    icmp_header->icmp_header.checksum = inet_checksum((uint16_t *)icmp_header, size_of_icmp_packet);
}

static void ip_format_reply_header(IP_header *ip_header, uint32_t size_of_ip_header) {
    if (ip_header == NULL)
        return;
    
    static uint32_t ID = 0;
    uint32_t new_dst_addr = ip_header->src_ip_addr;

    ip_header->ID = ID++;
    ip_header->src_ip_addr = ip_header->dst_ip_addr;
    ip_header->dst_ip_addr = new_dst_addr;
    ip_header->checksum = 0;
    ip_header->checksum = inet_checksum((uint16_t *)ip_header, size_of_ip_header);
}