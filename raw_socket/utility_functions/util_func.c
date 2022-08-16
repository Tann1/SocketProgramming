#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "IP_header.h"
#include "util_func.h"

/* private helper function(s) definition */

uint16_t wrap_around_sum(uint16_t *start, uint32_t size_in_bytes) {
    if (start == NULL)
        return 0;

    uint32_t result = 0, walker = 0, carry = 0;
    const uint32_t BOUNDARY = size_in_bytes / sizeof(uint16_t); // make it half-word oriented boundary 
    const uint32_t carry_mask = 0xff0000; // lower 16 bits are part of the sum so ignore them 

    while (walker < BOUNDARY) {
        if (carry_mask && result) { // meaning there is a carry
            carry = 1;
            result = result & (~carry_mask); // clear the carry
        }
        result += *(start + walker) + carry;
        if (carry) // reset carry
            carry = 0;
        walker++;
    }

    return result;
}

/* public helper function(s) definition */ 

uint16_t inet_checksum(uint16_t *header, uint32_t size_in_bytes) {
    return ~wrap_around_sum(header, size_in_bytes);
}

uint16_t inet_validate_checksum(uint16_t *header, uint32_t size_in_bytes, uint16_t checksum) {
    return ~(wrap_around_sum(header, size_in_bytes) + checksum); // should return 0 if valid 
}
void populate_IP_header(IP_header* ip, uint8_t tos, uint16_t ID, uint16_t proto, uint32_t src_ip, uint32_t dst_ip) {
    if (ip == NULL)
        return;

    ip->ver = 0x4;
    ip->len = sizeof(IP_header) / sizeof(uint32_t);
    ip->tos = tos;
    ip->ID = ID;
    ip->flags = IP__DF;
    ip->offset = 0x00;
    ip->TTL = 64;
    ip->proto = proto;
    ip->src_ip_addr = src_ip;
    ip->dst_ip_addr = dst_ip;
    ip->checksum = inet_checksum((uint16_t *)ip, IP_SIZE);
}

void print_IP_header_in_hex(IP_header* ip, size_t size) {
    if (ip == NULL)
        return;
    
    uint32_t *word_addr = (uint32_t *) ip;
    uint32_t walker = 0;
    const uint32_t BOUNDARY = size / sizeof(uint32_t); // size would be 20 so 20 / word size
    
    printf("BOUNDARY: %u\n",BOUNDARY);
    do {
        printf("%p: ", word_addr);
        printf("0x%.8x\n", *word_addr);
        word_addr++;
        walker++;
    } while (walker < BOUNDARY);   
}



void to_net_byte_order(void *addr, uint32_t size) {
    if (addr == NULL)
        return;

    uint32_t *word = (uint32_t *)addr;
    uint32_t walker = 0;
    const uint32_t BOUNDARY = size / sizeof(uint32_t); // word oriented boundary

    while (walker < BOUNDARY) {
        *(word + walker) = htonl(*(word + walker));
        walker++;
    }
}


void exit_after_err_msg(char* err_msg) {
    perror(err_msg);
    exit(1);
}