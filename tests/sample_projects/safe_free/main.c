#include <stdlib.h>

int main(void) {
    char *ptr = malloc(16);
    if (!ptr) return 1;
    free(ptr);
    return 0;
}
