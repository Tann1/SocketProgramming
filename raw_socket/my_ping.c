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


#define BUFFER_SIZE 512
#define IP_ADDR "192.168.10.103"

#define PRINT_IP_MEMCONTENT 0 // flag to print memory content of ip (mainly for debugging purposes)

typedef struct {
    IP_header ip;
    ICMP_echo icmp;
} Echo_Ping; 

static void print_echo_request(Echo_Ping *echo_data, size_t size);
static void print_ip_header(IP_header *ip);
static void print_icmp_echo_header(ICMP_echo *icmp_echo);
static void print_payload_data(uint8_t *data, uint32_t size_in_bytes);

/*
    TODO
    validate ICMP checksum (header + data)
*/

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
    
    printf("read: %u bytes.\n", n_bytes);
    print_echo_request((Echo_Ping *)buffer, n_bytes);
    }
    close(sock_fd); 

    return 0;
}


static void print_echo_request(Echo_Ping *echo_data, size_t size) {
    if (size < sizeof(Echo_Ping)) // somehow have an invalid size
        return;

    uint8_t *payload_data = (uint8_t *)(echo_data + sizeof(Echo_Ping));
    uint32_t size_of_payload = size - sizeof(Echo_Ping);

    print_ip_header(&echo_data->ip);
    printf("\n\n"); // space out the two headers
    print_icmp_echo_header(&echo_data->icmp);
    printf("\n\n");
    print_payload_data(payload_data, size_of_payload);
    printf("x-------------------------------x\n");

}
static void print_ip_header(IP_header *ip) {
    #if PRINT_IP_MEMCONTENT // print the memory content before any modifcations
    print_IP_header_in_hex(ip, IP_SIZE);
    #endif 


    char* src = ip_deci_format(ntohl(ip->src_ip_addr));
    char* dst = ip_deci_format(ntohl(ip->dst_ip_addr));
    uint16_t checksum = ip->checksum; // now we can set ip checksum to 0 to validate
    ip->checksum = 0;
    uint16_t valid_checksum = inet_validate_checksum((uint16_t *)ip, IP_SIZE, checksum);
    ip->checksum = checksum; // put the checksum back
    char* valid_prompt = valid_checksum ? "Not Valid" : "Valid";

    printf("IP Header\n");
    printf("Version: %u\n"
           "Header Length: %u\n"
           "Type of Serivce: 0x%x\n"
           "Total Length: %u\n"
           "Identifier: 0x%x\n"
           "Offset: 0x%04x\n"
           "TTL: %u\n"
           "Protocol: %u\n"
           "Checksum: 0x%04x (%s)\n"
           "Source IP: %s\n"
           "Destination IP: %s\n",
           ip->ver, ip->len, ip->tos,
           ntohs(ip->total_len), ip->ID,
           ntohs(ip->offset), ip->TTL, ip->proto,
           checksum, valid_prompt, src, dst);
    free(src);
    free(dst);
}


static void print_icmp_echo_header(ICMP_echo *icmp_echo) {
    struct tm *info = localtime((const time_t *)&icmp_echo->timestamp);
    printf("ICMP Echo Header\n");
    printf("Type: %u\n"
           "Code: %u\n"
           "Checksum (ICMP header + data): 0x%04x\n"
           "Identifier: 0x%04x\n"
           "Sequence #: 0x%04x\n"
           "Timestamp: %s\n",
           icmp_echo->icmp_header.type,
           icmp_echo->icmp_header.code,
           ntohs(icmp_echo->icmp_header.checksum),
           icmp_echo->ID, icmp_echo->seq,
           asctime(info));
}


static void print_payload_data(uint8_t *data, uint32_t size_in_bytes) {
    uint32_t walker = 0;

    printf("Data Portion (%u bytes)\n", size_in_bytes);
    while (walker < size_in_bytes) {
        if (walker != 0 && walker % 16 == 0) // 16 bytes per line
            printf("\n");
        printf("0x%02x ", *(data + walker));
        walker++;
    }
    printf("\n");

}