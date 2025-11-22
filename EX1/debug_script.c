#include <stdio.h>
#include <stdlib.h>


int main(int argc, char **argv){
    int ret_val = 0;
    if (argc != 2){
        fprintf(stderr, "Usage: %s <USER-ID>\n", argv[1]);
        ret_val = 1;
    }
    const char* user_id = argv[1];
    printf("Using USER-ID: %s\n", user_id);

    printf("==========================\n");
    printf("argc: %d\n", argc);
    printf("argv:\n");
    for(int i=0;argv[i]!=NULL;i++){
        printf("argv[%d]: %s\n", i, argv[i]);
    }
    printf("==========================\n");

    return ret_val;
}