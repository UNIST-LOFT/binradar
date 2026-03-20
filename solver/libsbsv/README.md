# libsbsv
`libsbsv` is a standalone C library for parsing SBSV (square bracket separated values) format.

## Build

```shell
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

## Install
Install (`find_package`):

```shell
cmake --install build
```

Consume from another CMake project:

```cmake
find_package(sbsv CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE sbsv::sbsv)
```

Alternative (monorepo/submodule):

```cmake
git clone https://github.com/hsh814/sbsv.git
add_subdirectory(path/to/sbsv/libsbsv)
target_link_libraries(my_app PRIVATE sbsv)
```

## Usage
```c
#include <sbsv.h>
const char *log = "[node] [id 1] [value 2]\n"
            "[node] [id 2] [value 3]\n"
            "[edge] [src 1] [dst 2] [value 6]\n";

sbsv_parser* parser = sbsv_parser_new(SBSV_PARSER_DEFAULT);
assert(sbsv_parser_add_schema(parser, "[node] [id: int] [value: int]") == SBSV_OK);
assert(sbsv_parser_add_schema(parser, "[edge] [src: int] [dst: int] [value: int]") == SBSV_OK);

assert(sbsv_parser_loads(parser, log) == SBSV_OK);

const sbsv_row** node_rows;
size_t node_count;
assert(sbsv_parser_get_rows(parser, "node", &node_rows, &node_count) == SBSV_OK);
for (size_t i = 0; i < node_count; i++) {
    const sbsv_row* row = node_rows[i];
    int id = sbsv_row_get_int(row, "id", NULL);
    int value = sbsv_row_get_int(row, "value", NULL);
    printf("Node id=%d value=%d\n", id, value);
}
sbsv_free_row_ref_array(node_rows);
assert(sbsv_parser_get_rows(parser, "edge", &edge_rows, &edge_count) == SBSV_OK);
for (size_t i = 0; i < edge_count; i++) {
    const sbsv_row* row = edge_rows[i];
    int src = sbsv_row_get_int(row, "src", NULL);
    int dst = sbsv_row_get_int(row, "dst", NULL);
    int value = sbsv_row_get_int(row, "value", NULL);
    printf("Edge src=%d dst=%d value=%d\n", src, dst, value);
}
sbsv_free_row_ref_array(edge_rows);
sbsv_parser_free(parser);
```
For more usage, see [tests/test_main.c](./tests/test_main.c).

