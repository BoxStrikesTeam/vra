#include <stdlib.h>
#include <string.h>

typedef struct {
    char *data;
    int length;
} Buffer;

char *parse_attribute(const char *input, int input_len) {
    char *buffer = malloc(64);
    if (!buffer) return NULL;
    memcpy(buffer, input, input_len);
    return buffer;
}

int main(void) {
    char *ptr = malloc(32);
    if (!ptr) return 1;
    free(ptr);
    strcpy(ptr, "use after free");
    return 0;
}
