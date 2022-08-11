#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h> // bzero func

/* socket API header includes */
#include <sys/socket.h>
#include <sys/types.h>

/* Internet Address Family struct definitions */
#include <netinet/in.h>

#define DEFAULT_PORT 5050
#define BUFFER_SIZE 256

void exit_after_err_msg(char *msg) {
    perror(msg);
    exit(1);
}

int main(int agrc, char *agrv[]) {
    
    return 0;
}