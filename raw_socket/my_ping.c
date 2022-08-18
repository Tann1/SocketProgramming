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
#include <linux/if_packet.h> 
#include <net/ethernet.h>  // L2 protocols 
#include <net/if.h>        // needed for struct ifreq to find ifindex
#include <sys/ioctl.h>


/* personal includes */ 
#include "Ether_header.h"
#include "IP_header.h"
#include "ICMP_header.h"
#include "util_func.h"
#include "util_packet_info.h" // it's a packet sniffer to display the content

#define BUFFER_SIZE 512
#define IP_ADDR "192.168.10.104" // default IP that has been mannual configured
#define INTERFACE "enp132s0f0"     // default interface 

static void icmp_format_reply_header(ICMP_echo *icmp_header, uint32_t size_of_icmp_packet);
static void ip_format_reply_header(IP_header *ip_header, uint32_t size_of_ip_header);
static void ether_format_reply_header(Ether_header *ether_header);

static void format_reply(Echo_Ping *frame, uint32_t size_of_frame_in_bytes);

int main(int argc, char *agrv[]) {
    uint32_t buffer[BUFFER_SIZE];
    char *if_name = INTERFACE; 
    int sock_fd, n_bytes = 0;
    struct sockaddr_ll my_socket, peer_socket;
    int peer_size = sizeof(peer_socket);
    Echo_Ping *echo_packet = NULL; // holds the header for ip and icmp_echo format
    
    /* let the user change interface through command argument else just use default interface that has already been set */
    if (argc == 2)
        if_name = agrv[1];

    /* create raw socket (this will include L2) */
    sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (sock_fd == -1)
        exit_after_err_msg("Failed to create raw socket");
    /* bind raw socket to interface */
    struct ifreq ifr;
    bzero(&ifr, sizeof(ifr));
    strncpy((char *)&ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
    if (ioctl(sock_fd, SIOCGIFINDEX, &ifr) == -1)
        exit_after_err_msg("Failed to retrieve interface index");
    /* if here means we've successfully got the ifindex and are ready to bind */
    bzero(&my_socket, sizeof(my_socket));
    my_socket.sll_family = AF_PACKET;
    my_socket.sll_protocol = htons(ETH_P_IP);
    my_socket.sll_ifindex = ifr.ifr_ifindex;
 

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
    format_reply(echo_packet, n_bytes);
    //printf("IP and ICMP Reply Packet Format\n");
    //print_echo_request(echo_packet, n_bytes);

    /* send the echo reply packet */ 
    sendto(sock_fd, echo_packet, n_bytes, 0, (const struct sockaddr *)&peer_socket, peer_size);
    printf("reply sent.\n");
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
static void ether_format_reply_header(Ether_header *ether_header) {
    if (ether_header == NULL)
        return;
    
    uint8_t new_dst_mac[6];
    memcpy(new_dst_mac, ether_header->src_mac, 6);
    memcpy(ether_header->src_mac, ether_header->dst_mac, 6);
    memcpy(ether_header->dst_mac, new_dst_mac, 6);
}
static void format_reply(Echo_Ping *frame, uint32_t size_of_frame_in_bytes) {
    if (frame == NULL)
        return;
    ether_format_reply_header(&frame->ether);
    ip_format_reply_header(&frame->ip, IP_SIZE);
    icmp_format_reply_header(&frame->icmp, size_of_frame_in_bytes - ETHER_SIZE - IP_SIZE);
}