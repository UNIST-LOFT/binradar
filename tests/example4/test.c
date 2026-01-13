#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum {
    MAX_INPUT     = 512,
    STACK_WORDS   = 32,
    HEAP_CHUNKS   = 4,
    BLOCK_SIZE    = 64,
    GLOBAL_BLOCKS = 4
};

static uint8_t global_buf[GLOBAL_BLOCKS][BLOCK_SIZE];

struct GlobalNode {
    uint64_t tag;
    uint8_t  payload[BLOCK_SIZE];
};

static struct GlobalNode global_nodes[GLOBAL_BLOCKS];
static volatile uint64_t global_accumulator = 0x8badf00d5a5a5a5aULL;

static inline uint64_t rotl(uint64_t value, unsigned shift) {
    return (value << shift) | (value >> (64 - shift));
}

static __attribute__((noinline)) uint64_t crunch_stack(const uint8_t *input, size_t len) {
    uint64_t scratch[STACK_WORDS];
    struct GlobalNode temp_node;

    for (size_t i = 0; i < STACK_WORDS; ++i) {
        scratch[i] = global_accumulator ^ (0x9e3779b185ebca87ULL + i);
    }
    temp_node.tag = scratch[0] ^ 0xdeadbeefcafebabeULL;
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
        temp_node.payload[i] = 0xddULL;
    }

    for (size_t i = 0; i < len; ++i) {
        size_t idx = (input[i] + i) & (STACK_WORDS - 1);
        scratch[idx] = rotl(scratch[idx] ^ input[i], (input[i] & 7u) + 1u);
    }

    uint64_t acc = 0;
    for (size_t i = 0; i < STACK_WORDS; ++i) {
        acc ^= scratch[i];
    }
    acc ^= temp_node.tag;
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
        acc ^= (uint64_t)temp_node.payload[i] << ((i & 7u) * 8);
    }
    return acc;
}

static __attribute__((noinline)) uint64_t scramble_heap(const uint8_t *input, size_t len) {
    const size_t region_size = HEAP_CHUNKS * BLOCK_SIZE;
    uint8_t *region = calloc(1, region_size);
    if (!region) {
        perror("calloc");
        _exit(2);
    }

    size_t copy = len < region_size ? len : region_size;
    memcpy(region, input, copy);

    for (size_t chunk = 0; chunk < HEAP_CHUNKS; ++chunk) {
        uint8_t *base = region + chunk * BLOCK_SIZE;
        for (size_t i = 0; i < BLOCK_SIZE; ++i) {
            base[i] ^= (uint8_t)(chunk * 31u + i);
        }
    }

    memmove(region + BLOCK_SIZE / 2, region, region_size - BLOCK_SIZE / 2);

    uint64_t acc = 0;
    uint64_t *words = (uint64_t *)region;
    for (size_t i = 0; i < region_size / sizeof(uint64_t); ++i) {
        acc ^= rotl(words[i], i & 31u);
    }

    memset(region + region_size - BLOCK_SIZE, 0xA5, BLOCK_SIZE);
    free(region);
    return acc;
}

static __attribute__((noinline)) uint64_t mix_globals(const uint8_t *input, size_t len) {
    const size_t each = len < BLOCK_SIZE ? len : BLOCK_SIZE;

    for (size_t i = 0; i < GLOBAL_BLOCKS; ++i) {
        memcpy(global_buf[i], input, each);
        for (size_t j = 0; j < each; ++j) {
            global_nodes[i].payload[j] = global_buf[i][j] ^ (uint8_t)(i + j * 3u);
        }
        global_nodes[i].tag ^= ((uint64_t)global_nodes[i].payload[i % each] << 32) | each;
    }

    for (size_t i = 0; i < GLOBAL_BLOCKS - 1; ++i) {
        memmove(global_nodes[i].payload,
                global_nodes[i + 1].payload,
                BLOCK_SIZE);
    }

    uint64_t acc = global_accumulator;
    for (size_t i = 0; i < GLOBAL_BLOCKS; ++i) {
        for (size_t j = 0; j < BLOCK_SIZE; j += sizeof(uint64_t)) {
            uint64_t word;
            memcpy(&word, &global_nodes[i].payload[j], sizeof word);
            acc ^= rotl(word ^ global_nodes[i].tag, (unsigned)((i + j) & 63u));
        }
    }

    global_accumulator ^= acc + len;
    return acc;
}

static __attribute__((noinline)) void emit_side_effects(uint64_t acc, size_t len) {
    uint8_t digest[16];
    for (size_t i = 0; i < sizeof digest; ++i) {
        digest[i] = (uint8_t)(acc >> ((i & 7u) * 8)) ^ (uint8_t)(len + i);
    }
    (void)write(STDOUT_FILENO, digest, sizeof digest);
}

static void maybe_crash(const uint8_t *input, size_t len) {
    if (len >= 4 && memcmp(input, "CRSH", 4) == 0) {
        fprintf(stderr, "[demo] forcing crash so you can check forkserver recovery\n");
        __builtin_trap();
    }
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

    uint64_t acc = 0;
    acc ^= crunch_stack(input, len);
    acc ^= scramble_heap(input, len);
    acc ^= mix_globals(input, len);

    emit_side_effects(acc, len);
    maybe_crash(input, len);

    return (int)(acc & 0xff);
}
