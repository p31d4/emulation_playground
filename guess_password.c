#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Password: !%%
char pass[4] = {(char) 0xDE, (char) 0xDA, (char) 0xDA, (char) 0x00};

char * xor_op() {
    int idx;

    for (idx = 0; idx < 3; idx += 1) {
        pass[idx] = pass[idx] ^ 0xFF;
    }
    return pass;
}

int main(int argc, char ** argv) {

    if (2 != argc) {printf("Provide a password\n"); return -1;}

    if (3 != strlen(argv[1])) {printf("Password shall have 3 chars\n"); return -2;}

    if (0 != strcmp(argv[1], xor_op())) {printf("Wrong!\n"); return -3;}

    // ./guessPpassword \!\%\%
    return 0;
}
