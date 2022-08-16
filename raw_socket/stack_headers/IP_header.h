#ifndef IP_HEADER_H
#define IP_HEADER_H

#include <stdint.h>

#define IP__DF 0x4              // don't fragment
#define IP__MF 0x2              // more fragments
#define IP_SIZE sizeof(IP_header)

typedef struct {
    uint8_t len : 4;            // len of header
    uint8_t ver : 4;            // version (almost always 4)
    uint8_t tos;                // tos = type of service
    uint16_t total_len;         // total length header + payload
    uint16_t ID;                // Identifier
    uint16_t offset;            // 0:3 are flags and 4 : 15 are offset
    uint8_t TTL;                // Time To Live
    uint8_t proto;              // protocol
    uint16_t checksum;          // checksum
    uint32_t src_ip_addr;
    uint32_t dst_ip_addr;
}   IP_header;


#endif