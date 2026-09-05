#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char *buffer = malloc(128);
    if (!buffer) return 1;
    FILE *f = fopen(argv[1], "r");
    if (!f) return 1;
    return 0;
}
