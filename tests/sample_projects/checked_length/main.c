#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    size_t len = strlen(argv[1]);
    if (len > 100) {
        fprintf(stderr, "Too long\n");
        return 1;
    }
    char *buffer = malloc(len + 1);
    if (!buffer) return 1;
    strcpy(buffer, argv[1]);
    printf("%s\n", buffer);
    free(buffer);
    return 0;
}
