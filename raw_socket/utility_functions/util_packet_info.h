#ifndef UTIL_PACKET_INFO_H
#define UTIL_PACKET_INFO_H

#include "ICMP_header.h"
#include "IP_header.h"


typedef struct {
    IP_header ip;
    ICMP_echo icmp;
} Echo_Ping;


#define PRINT_IP_MEMCONTENT 0 // flag to print memory content of ip (mainly for debugging purposes)

char* ip_deci_format(uint32_t ip_addr);
void print_echo_request(Echo_Ping *echo_data, size_t size);
void print_ip_header(IP_header *ip);
void print_icmp_echo_header(ICMP_echo *icmp_echo, uint32_t total_size_of_payload);
void print_payload_data(uint8_t *data, uint32_t size_in_bytes);

#endif 