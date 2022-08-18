#ifndef ETHER_HEADER_H
#define ETHER_HEADER_H

#include <stdint.h>

#define ETHER_SIZE sizeof(Ether_header)

typedef struct __attribute__((__packed__)) {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t type;
}  Ether_header;

#endif