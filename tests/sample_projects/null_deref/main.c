#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char *ptr = malloc(32);
    if (!ptr) return 1;
    if (argc > 2) {
        ptr = NULL;
    }
    strcpy(ptr, argv[1]);
    free(ptr);
    return 0;
}
