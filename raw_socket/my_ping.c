#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

#include "IP_header.h"

/* utility function(s) used primarily for testing purposes */
static void print_IP_header_in_hex(IP_header* ip, size_t size);
static uint16_t inet_checksum(uint16_t *header, uint32_t size_in_bytes);


int main(int agrc, char *agrv[]) {
    IP_header ip = {0};
    char data[] = {0xaa, 0x66, 0xc3, 0xf0};
    bzero((void *) &ip, sizeof(ip));

    uint16_t *data_word = (uint16_t *)data;

    printf("0x%x\n", *data_word);
    printf("0x%x\n", *(data_word + 1));
    printf("0x%x\n", inet_checksum((uint16_t *)data, sizeof(data)));

    //print_IP_header_in_hex(&ip, sizeof(ip));
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


static uint16_t inet_checksum(uint16_t *header, uint32_t size_in_bytes) {
    uint32_t result = 0, walker = 0, carry = 0;
    const uint32_t BOUNDARY = size_in_bytes / sizeof(uint16_t); // make it half-word oriented boundary 
    const uint32_t carry_mask = 0xff0000;

    while (walker < BOUNDARY) {
        if (carry_mask && result) { // meaning there is a carry
            carry = 1;
            result = result & (~carry_mask); // clear the carry
        }
        result += *(header + walker) + carry;
        if (carry) // reset carry
            carry = 0;
        walker++;
    }

    return ~result;
}