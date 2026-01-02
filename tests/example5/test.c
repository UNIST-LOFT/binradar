#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_INPUT 512

int model_malloc_max(int size)
{
    int* res = malloc(MAX_INPUT);
    memset((void *)res, size, MAX_INPUT);
    printf("MAX SIZE %d\n", size / (int)sizeof(int));
    return res[size];
}


int main(int argc, char* argv[]) {
    uint8_t input[MAX_INPUT];
    memset(input, 0, MAX_INPUT);
    if (argc != 2) {
        printf("Error\n");
        return 1;
    }
    FILE *file = fopen(argv[1], "r");
    if (!file) {
        printf("Error\n");
        return 1;
    }
    ssize_t consumed = fread(input, 1, sizeof input, file);
    if (consumed <= 0) {
        return 0;
    }

    size_t len = (size_t)consumed;
    int result;
    sscanf(input, "%d", &result);
    model_malloc_max(result);
    return 0;
}
