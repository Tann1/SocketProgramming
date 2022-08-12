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

/*
    Steps to establish a client side socket and communicate with the server
    1.) create a socket
    2.) connect the socket to the address of the server
    3.) ready to communicate (if no errors from trying to connect)
*/

int main(int agrc, char *agrv[]) {
    int sock_fd, port_num;
    struct sockaddr_in serv_info;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_written, bytes_read;
    

    port_num = agrc == 2 ? atoi(agrv[1]) : DEFAULT_PORT; // port number can be user defined or default
    /* 1.) create a socket */
    sock_fd = socket(AF_INET, SOCK_STREAM, 0); // AF_INET = ip4; SOCK_STREAM = connection oriented (TCP)
    if (sock_fd == -1)
        exit_after_err_msg("Failed to create file despcriptor for socket. . .");
    /* populate server info for this program it's just a loop back */
    bzero((void *) &serv_info, sizeof(serv_info));
    serv_info.sin_family = AF_INET;
    serv_info.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    serv_info.sin_port = htons(port_num);
    /* 2.) connect the socket to the address of the server */
    if (connect(sock_fd, (const struct sockaddr *) &serv_info, sizeof(serv_info)) == -1)
        exit_after_err_msg("Failed to connect to the server . . .");
    printf("Please enter a message: ");
    bzero(buffer, BUFFER_SIZE);
    fgets(buffer, BUFFER_SIZE - 1, stdin);

    bytes_written = write(sock_fd, buffer, strlen(buffer)); // write request to the server
    if (bytes_written < 0)
        exit_after_err_msg("Failed to write to socket. . .");
    
    /* read the response from the server */
    bzero(buffer, BUFFER_SIZE);
    bytes_read = read(sock_fd, buffer, BUFFER_SIZE - 1);
    write(1, buffer, bytes_read);

    if (bytes_read < 0)
        exit_after_err_msg("Failed to read from socket. . .");
    close(sock_fd);

    return 0;
}