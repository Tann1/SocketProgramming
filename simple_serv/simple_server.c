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
#define BACKLOG 5
#define BUFFER_SIZE 256

void exit_after_err_msg(char *msg) {
    perror(msg);
    exit(1);
}
/*  
    Steps to establish a server side socket and communicate with the client 
    1.) create a socket respective to sa_family 
    2.) decide on address and port to bind to
    3.) bind the socket to the address and port
    4.) invoke listen API to start passively listening for connections to the server
    5.) invoke accept to create a new file descriptor that will allow for communcation with the client
    6.) communicate with the new file descriptor and service as requested by the client whatever that may be
*/

int main(int agrc, char *agrv[]) {
    int sock_fd, new_sock_fd, port_num, cli_len;
    struct sockaddr_in serv_info, cli_info;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    port_num = agrc == 2 ? atoi(agrv[1]) : DEFAULT_PORT; // port number can be user defined or default
    /* 1.) create socket file descriptor */
    sock_fd = socket(AF_INET, SOCK_STREAM, 0); // AF_INET = ip4; SOCK_STREAM = connection orientated
    if (sock_fd < 0) // failed to create an fd for socket
        exit_after_err_msg("Failed to create file descriptor for socket. . .");
    bzero((void *) &serv_info, sizeof(serv_info)); // set the sockaddr space of serv info to null
    /* 2.) populate server info */
    serv_info.sin_family = AF_INET;
    serv_info.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    serv_info.sin_port = htons(port_num);
    /* 3.) ready to bind the socket to server addr and port */
    if (bind(sock_fd, (const struct sockaddr *) &serv_info, sizeof(serv_info)) == -1)
        exit_after_err_msg("Failed to bind socket to the respective address and port. . .");
    /* 4.) invoke listen to passively listen for connections */
    listen(sock_fd, BACKLOG); // BACKLOG is the maximum length to which the queue of pending connections for sock_fd may grow
    cli_len = sizeof(cli_info);
    /* 5.) invoke accept in order to start communicating with incoming client */
    new_sock_fd = accept(sock_fd, (struct sockaddr *) &cli_info, &cli_len);
    if (new_sock_fd == -1)
        exit_after_err_msg("Failed to connect. . .");
    /* at this point connection is established to the peer host and is ready for communication */
    bytes_read = read(new_sock_fd, &buffer, BUFFER_SIZE);
    write(1, &buffer, bytes_read); write(1, "\n", 1);
    return 0;
}


