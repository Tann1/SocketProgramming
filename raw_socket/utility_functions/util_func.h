#ifndef UTIL_FUNC_H
#define UTIL_FUNC_H

/* private helper function(s) */
static uint16_t wrap_around_sum(uint16_t *start, uint32_t size_in_bytes);


/* public helper functions(s) */ 
uint16_t inet_checksum(uint16_t *header, uint32_t size_in_bytes);
uint16_t inet_validate_checksum(uint16_t *header, uint32_t size_in_bytes, uint16_t checksum);
void populate_IP_header(IP_header* ip, uint8_t tos, uint16_t ID, uint16_t proto, uint32_t src_ip, uint32_t dst_ip);
void print_IP_header_in_hex(IP_header* ip, size_t size);
void to_net_byte_order(void *addr, uint32_t size);

#endif 