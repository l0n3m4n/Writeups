// suid-test.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    printf("Real UID: %d\n", getuid());
    printf("Effective UID: %d\n", geteuid());
    system("/bin/bash");
    return 0;
}
