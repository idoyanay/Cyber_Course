#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>        // for close()
#include <arpa/inet.h>     // for inet_ntoa, htons, etc.
#include <sys/socket.h>    // for socket(), bind(), listen(), accept()

#define SERVER_IP "192.168.1.201"
#define SERVER_PORT 12345
#define BUFFER_SIZE 1024


int main() {
    // Create a TCP socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket failed");
        return 1;
    }


    // Define server address
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);

    // Convert IPv4 address from text to binary form
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        perror("invalid address");
        return 1;
    }
    // Connect to the server
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connection failed");
        return 1;
    }

    // send 'Hello server' message to server
    const char *message = "Hello server";
    send(sockfd, message, strlen(message), 0);

    // receive response from server
    char buffer[BUFFER_SIZE] = {0};
    int bytes_received = (int) recv(sockfd, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received < 0) {
        perror("recv failed");
        return 1;
    }
    buffer[bytes_received] = '\0'; // Null-terminate the received string
    // Close the socket
    close(sockfd);
    return 0;
    
}