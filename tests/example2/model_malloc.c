#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int model_malloc_min(int size, int index)
{
    int* res = malloc(size);
    memset((void *)res, 0, size);
    printf("MIN SIZE %d, INDEX %d\n", size / (int)sizeof(int), index);
    return res[index];
}

int model_malloc_max(int size, int index)
{
    int* res = malloc(size);
    memset((void *)res, 0, size);
    printf("MAX SIZE %d, INDEX %d\n", size / (int)sizeof(int), index);
    return res[index];
}

int model_realloc_min(int size)
{
    void* res = realloc(malloc(8), size);
    return size == 0;
}

int model_realloc_max(int size)
{
    void* res = realloc(malloc(8), size);
    return size > 128;
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
    int data[4];
    fread(data, 4, 4, file);
    model_malloc_min(data[0], data[2]);
    model_malloc_max(data[1], data[3]);
    fclose(file);
}
