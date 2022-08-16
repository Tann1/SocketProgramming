#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* socket and internet API */
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* personal includes */ 
#include "IP_header.h"
#include "util_func.h"


int main(int agrc, char *agrv[]) {
    IP_header *ip = malloc(sizeof(IP_SIZE));

    bzero((void *) ip, IP_SIZE);
    populate_IP_header(ip, 0x00, 0xdead, 0x01, inet_addr("10.2.14.102"), inet_addr("10.2.14.104"));
    print_IP_header_in_hex(ip, IP_SIZE);
    to_net_byte_order(ip, IP_SIZE);
    print_IP_header_in_hex(ip, IP_SIZE);
    free(ip);

    return 0;
}