#include <string.h>
#include <stdio.h>

void safe_copy(const char *input, size_t len) {
    char buffer[64];
    if (len > sizeof(buffer) - 1) {
        fprintf(stderr, "Input too long\n");
        return;
    }
    memcpy(buffer, input, len);
    buffer[len] = '\0';
    printf("%s\n", buffer);
}

int main(void) {
    const char *msg = "hello";
    safe_copy(msg, strlen(msg));
    return 0;
}
