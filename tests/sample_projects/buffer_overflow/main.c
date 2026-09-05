#include <string.h>
#include <stdio.h>

void copy_field(const char *input, int len) {
    char buffer[64];
    memcpy(buffer, input, len);
    printf("%s\n", buffer);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    copy_field(argv[1], strlen(argv[1]));
    return 0;
}
