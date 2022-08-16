#ifndef ICMP_HEADER_H
#define ICMP_HEADER_H

#include <stdint.h>


typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
} ICMP_header;

typedef struct {
    ICMP_header icmp_header;
    uint16_t ID;
    uint16_t seq;
    uint32_t timestamp;
} ICMP_echo; 

#endif