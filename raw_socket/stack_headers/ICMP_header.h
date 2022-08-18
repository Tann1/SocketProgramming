#ifndef ICMP_HEADER_H
#define ICMP_HEADER_H

#include <stdint.h>


typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
} ICMP_header;

typedef struct __attribute__((__packed__)){
    ICMP_header icmp_header;
    uint16_t ID;
    uint16_t seq;
    uint32_t timestamp;
} ICMP_echo; 

#endif