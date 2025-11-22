#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>  // for mprotect()
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

///////////////////////////////////////////////////////////////////////////////////////
//// COMPILE with -fno-stack-protector to avoid the GCC stack canary protection!!! ////
///////////////////////////////////////////////////////////////////////////////////////

#define QWORD_SIZE 8
#define PAGE_SIZE 4096
#define PROT_RWX (PROT_READ|PROT_WRITE|PROT_EXEC)
#define NUM_PAGES 2
#define BUF_SIZE 10
#define EXIT_OK 0
#define EXIT_ERROR 1

int sockfd = -1;
int connfd = -1;

void segfault_handler(int signum) {
    printf("Segmentation fault caught!\n");
    close(connfd);
    close(sockfd);
    exit(EXIT_ERROR);
}

int main_loop(int* dummy)
{
	char x[BUF_SIZE];
	register unsigned long my_rbp __asm__("rbp");

	//printf("x=0x%lx, rbp=0x%lx (return address at rbp+8 = 0x%lx)\n",(unsigned long)x, my_rbp, my_rbp+8);

	// x is the buffer that will be overflowed, when printing the address of x, we will get the address of the buffer on the stack
	// my_rbp is the address of the base pointer of the current stack frame
	printf("x=0x%lx, return address offset=%ld\n",(unsigned long)x, my_rbp+QWORD_SIZE-(unsigned long)x);
	printf("Run attacker.exe 0x%lx %ld\n", (unsigned long)x, my_rbp+QWORD_SIZE-(unsigned long)x);
	printf("mprotect return value: %d (0 is OK)\n", mprotect((void*)(((unsigned long)x)&0xFFFFFFFFFFFFF000ul),NUM_PAGES*PAGE_SIZE,PROT_READ|PROT_WRITE|PROT_EXEC));
	//fread(x,sizeof(char),1000,stdin);
	
	
	//int sockfd, connfd, len;
	int len;
    struct sockaddr_in servaddr, cli;


    // socket create and verification 
    sockfd = socket(AF_INET, SOCK_STREAM, 0); 
    if (sockfd == -1) { 
        printf("socket creation failed...\n"); 
        exit(EXIT_ERROR);
    } 
    else
        printf("Socket successfully created..\n");

    // Set the SO_REUSEADDR option on the socket
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
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    servaddr.sin_port = htons(12345); 
   
    // Binding newly created socket to given IP and verification
    // If bind failed, we try again up to 3 times (to avoid the "Address already in use" error)
    // WHen success, we print a message and continue
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
        printf("Server listening..\n"); 
    len = sizeof(cli); 
   
    // Accept the data packet from client and verification 
    connfd = accept(sockfd, (struct sockaddr*)&cli, &len); 
    if (connfd < 0) { 
        printf("server accept failed...\n");
        close(sockfd);
        exit(EXIT_ERROR);
    } 
    else
        printf("server accept the client...\n"); 
   
    // Function for chatting between client and server 
    int bytes_revc = recv(connfd,x,1000,0);
    if (bytes_revc < 0) {
        printf("server read failed...\n");
        close(connfd); // Close the connection socket
        close(sockfd); // Close the listening socket
        exit(EXIT_ERROR);
    }
    else{
        printf("server read the client...\n");
        printf("Received %d bytes: ", bytes_revc);
        for(int i=0;i<bytes_revc;i++){
            printf("%02x ", (unsigned char)x[i]);
        }
    }

    // After chatting close the socket
    close(connfd); // Close the connection socket
    close(sockfd); // Close the listening socket
	
	return EXIT_OK;
}
int main(int argc, char* argv[])
{
    signal(SIGSEGV, segfault_handler);
	int z[1000];   // To make sure the stack has enough place...
	main_loop(z);
	return 0;
}
