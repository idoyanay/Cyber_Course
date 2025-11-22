#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>        // for close()
#include <arpa/inet.h>     // for inet_ntoa, htons, etc.
#include <sys/socket.h>    // for socket(), bind(), listen(), accept()

#define SERVER_IP "192.168.1.201"
#define SERVER_PORT 12345
#define BUFFER_SIZE 1024


int main(){
    // create socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket failed");
        return 1;
    }

    // set socket options to reuse address and port
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed...\n");
        close(sockfd);
        return 1;
    }
    opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        perror("setsockopt(SO_REUSEPORT) failed...\n");
        close(sockfd);
        return 1;
    }

    // bind socket
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_port = htons(SERVER_PORT);
    address.sin_addr.s_addr = inet_addr(SERVER_IP);

    if (bind(sockfd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        return 1;
    }

    // listen on socket
    if (listen(sockfd, 1) < 0) {
        perror("listen failed");
        return 1;
    }


    // accept connection
    int addrlen = sizeof(address);
    int new_socket = accept(sockfd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
    if (new_socket < 0) {
        perror("accept failed");
        return 1;
    }

    char buf[1024];
    int n = (int)recv(new_socket, buf, sizeof(buf)-1, 0);
    if (n < 0) { perror("recv failed"); close(new_socket); close(sockfd); return 1; }
    buf[n] = '\0';

    /* spec reply */
    const char *msg = "Hello client,";  // exact text per spec
    if (send(new_socket, msg, strlen(msg), 0) < 0) { perror("send failed"); }


    // send the client 'Hello client'
    const char *message = "Hello client\n";
    send(new_socket, message, strlen(message), 0);

    // ending server
    close(new_socket);
    return 0;
}


