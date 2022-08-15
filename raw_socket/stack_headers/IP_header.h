#ifndef IP_HEADER_H
#define IP_HEADER_H

#include <stdint.h>

#define IP__DF 0x4              // don't fragment
#define IP__MF 0x2              // more fragments

typedef struct {
    uint8_t ver : 4;            // len (header only length) 4:7 and ver 0 : 3
    uint8_t len : 4;
    uint8_t tos;                // tos = type of service
    uint16_t total_len;         // total length header + payload
    uint16_t ID;                // Identifier
    uint8_t flags : 3;  
    uint16_t offset : 13;       // 0:3 are flags and 4 : 15 are offset
    uint8_t TTL;                // Time To Live
    uint8_t proto;              // protocol
    uint16_t checksum;          // checksum
    uint32_t src_ip_addr;
    uint32_t dst_ip_addr;
}   IP_header;

#endif