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
    if (size > MAX_INPUT) {
        free(res);
    }
    printf("MAX SIZE %d\n", MAX_INPUT / size);
    return res[MAX_INPUT / size];
}


int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Error\n");
        return 1;
    }
    FILE *file = fopen(argv[1], "r");
    if (!file) {
        printf("Error\n");
        return 1;
    }

    int result;
    fread(&result, sizeof(result), 1, file);
    if (result > 1024) {
        printf("Error\n");
        return 1;
    }
    if (result < 0) {
        printf("Error\n");
        return 1;
    }
    model_malloc_max(result);
    fclose(file);
    return 0;
}
