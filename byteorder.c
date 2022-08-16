#include <stdio.h>

union {
    short s;
    char c[sizeof(short)];
} un;

int main(void) {
    
    un.s = 0x0102;

    if (un.c[0] == 0x01 && un.c[1] == 0x02)
        printf("Big Endian\n");
    else if (un.c[0] == 0x02 && un.c[1] == 0x01)
        printf("Little Endian\n");
    else
        printf("Unable to determine Endianess\n");
    
    return 0;
}