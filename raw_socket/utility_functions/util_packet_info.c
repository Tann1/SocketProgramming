#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <arpa/inet.h>

#include "util_packet_info.h"
#include "util_func.h"



static char* ether_mac_format(uint8_t *mac_addr) {
    char* mac_format_str = malloc(sizeof(uint8_t) * 18);
    
    bzero(mac_format_str, 18);
    sprintf(mac_format_str, "%x:%x:%x:%x:%x:%x", mac_addr[0], mac_addr[1], mac_addr[2],
                                                 mac_addr[3], mac_addr[4], mac_addr[5]);

    return mac_format_str;
}



static char* ip_deci_format(uint32_t ip_addr) {
    uint32_t mask = 0xff;
    uint8_t octet[4] = {0};
    char *octet_str = malloc(sizeof(char) * 16);

    for (int idx = 0; idx < 4; idx++) 
        octet[idx] = (ip_addr >> (idx * 8)) & mask;
    sprintf(octet_str, "%u.%u.%u.%u", octet[3], octet[2], octet[1], octet[0]);
    
    return octet_str;
}

void print_echo_request(Echo_Ping *echo_data, size_t size) {
    if (size < sizeof(Echo_Ping)) // somehow have an invalid size
        return;

    uint8_t *payload_data = ((uint8_t *)echo_data) + ETHER_SIZE + IP_SIZE;
    uint32_t size_of_payload = ntohs(echo_data->ip.total_len) - IP_SIZE;
    printf("Payload start: %p data start: %p data end:%p\n", echo_data, payload_data, payload_data + size_of_payload);

    printf("read: %lu bytes.\n", size);
    print_ether_header(&echo_data->ether);
    printf("\n\n");
    print_ip_header(&echo_data->ip);
    printf("\n\n"); // space out the two headers
    //print_icmp_echo_header(&echo_data->icmp, size);
    //printf("\n\n");
    print_payload_data(payload_data, size_of_payload);
    printf("x-------------------------------x\n");

}


void print_ether_header(Ether_header *ether) {
    char *dst_mac = NULL, *src_mac = NULL;
    dst_mac = ether_mac_format(ether->dst_mac);
    src_mac = ether_mac_format(ether->src_mac);
    printf("Ether Header\n");
    printf("Dst Mac Address: %s\n"
           "Src Mac Address: %s\n"
           "Type: 0x%04x\n",
           dst_mac, src_mac,
           ntohs(ether->type));

    free(dst_mac);
    free(src_mac);
}


void print_ip_header(IP_header *ip) {
    #if PRINT_IP_MEMCONTENT // print the memory content before any modifcations
    printf("Printing IP Memory Content.\n");
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
           ntohs(ip->total_len), ntohs(ip->ID),
           ntohs(ip->offset), ip->TTL, ip->proto,
           checksum, valid_prompt, src, dst);
    free(src);
    free(dst);
}


void print_icmp_echo_header(ICMP_echo *icmp_echo, uint32_t total_size_of_payload) {

    uint16_t checksum = icmp_echo->icmp_header.checksum; // extract the checksum
    icmp_echo->icmp_header.checksum = 0;
    uint16_t valid_checksum = inet_validate_checksum((uint16_t *)icmp_echo, total_size_of_payload - IP_SIZE, checksum);
    icmp_echo->icmp_header.checksum = checksum; // put the checksum back after calculations
    char *valid_prompt = valid_checksum ? "Not Valid" : "Valid";


    printf("ICMP Echo Header\n");
    printf("Type: %u\n"
           "Code: %u\n"
           "Checksum (ICMP header + data): 0x%04x (%s)\n"
           "Identifier: 0x%04x\n"
           "Sequence #: 0x%04x\n",
           icmp_echo->icmp_header.type,
           icmp_echo->icmp_header.code,
           ntohs(icmp_echo->icmp_header.checksum),
           valid_prompt, icmp_echo->ID, icmp_echo->seq);
}


void print_payload_data(uint8_t *data, uint32_t size_in_bytes) {
    uint32_t walker = 0;

    printf("Data Portion (%u bytes)\n", size_in_bytes);
    printf("%p: ", data);
    while (walker < size_in_bytes) {
        if (walker != 0 && walker % 16 == 0) // 16 bytes per line
            printf("\n%p: ", data + walker);
        printf("0x%02x ", *(data + walker));
        walker++;
    }
    printf("\n");

}


void print_mem_content(void *addr, uint32_t len) {
    if (addr == NULL)
        return;
    uint32_t *word_addr = (uint32_t *)addr;
    uint32_t walker = 0;
    const uint32_t BOUNDARY = len / sizeof(uint32_t);

    while (walker < BOUNDARY)
        printf("%p: 0x%08x\n", word_addr + walker, *(word_addr + walker++));

}