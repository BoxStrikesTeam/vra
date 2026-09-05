#include <stdlib.h>

int main(int argc, char **argv) {
    int count = 1000000;
    if (argc > 1) {
        count = atoi(argv[1]);
    }
    size_t size = count * sizeof(int);
    int *arr = malloc(size);
    if (!arr) return 1;
    free(arr);
    return 0;
}
