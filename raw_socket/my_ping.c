#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

#include "IP_header.h"

/* utility function(s) used primarily for testing purposes */
static void print_IP_header_in_hex(IP_header* ip, size_t size);


int main(int agrc, char *agrv[]) {
    IP_header ip = {0};

    bzero((void *) &ip, sizeof(ip));

    ip.ver = 0x09;
    ip.len = 0x05;
    ip.tos = 0x00;
    ip.total_len = 95;
    ip.ID = 0x1234;
    ip.flags = 0;
    ip.offset = 0x78;
    ip.TTL = 0x22;

    print_IP_header_in_hex(&ip, sizeof(ip));
    return 0;
}

static void print_IP_header_in_hex(IP_header* ip, size_t size) {
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