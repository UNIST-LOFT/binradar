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
const sbsv_row** edge_rows;
size_t edge_count;
assert(sbsv_parser_get_rows(parser, "node", &node_rows, &node_count) == SBSV_OK);
for (size_t i = 0; i < node_count; i++) {
    const sbsv_row* row = node_rows[i];
    long long id = sbsv_row_get_int(row, "id", NULL);
    long long value = sbsv_row_get_int(row, "value", NULL);
    printf("Node id=%lld value=%lld\n", id, value);
}
sbsv_free_row_ref_array(node_rows);
assert(sbsv_parser_get_rows(parser, "edge", &edge_rows, &edge_count) == SBSV_OK);
for (size_t i = 0; i < edge_count; i++) {
    const sbsv_row* row = edge_rows[i];
    long long src = sbsv_row_get_int(row, "src", NULL);
    long long dst = sbsv_row_get_int(row, "dst", NULL);
    long long value = sbsv_row_get_int(row, "value", NULL);
    printf("Edge src=%lld dst=%lld value=%lld\n", src, dst, value);
}
sbsv_free_row_ref_array(edge_rows);
sbsv_parser_free(parser);
```

### Ignored Prefixes

Call `sbsv_parser_ignore_prefix()` before adding schemas. Literal prefix fields must
match exactly. Capture fields start with `$`; captured fields are only stored when
`save_ignored` is non-zero.

```c
sbsv_parser* parser = sbsv_parser_new(SBSV_PARSER_DEFAULT);
assert(sbsv_parser_ignore_prefix(parser, "[$timestamp] [$level]", 1) == SBSV_OK);
assert(sbsv_parser_add_schema(parser, "[necessary] [from] [this: str]") == SBSV_OK);
assert(sbsv_parser_loads(
    parser,
    "[2024-03-04 13:22:56] [DEBUG] [necessary] [from] [this part]\n"
) == SBSV_OK);

const sbsv_row* row = sbsv_parser_row_at(parser, 0);
printf("%s %s\n", sbsv_row_get_string(row, "$level"), sbsv_row_get_string(row, "this"));
sbsv_parser_free(parser);
```

### Body Parser

Use `sbsv_body_parser` when the input has no schema name. The returned row is
owned by the caller and must be released with `sbsv_row_free()`.

```c
sbsv_body_parser* body = sbsv_body_parser_new();
sbsv_row* row = NULL;

assert(sbsv_body_parser_set_schema(body, "[id?: int] [value: int]") == SBSV_OK);
assert(sbsv_body_parser_parse(body, "[id] [value 2]", &row) == SBSV_OK);
assert(sbsv_row_get(row, "id")->type == SBSV_VALUE_NULL);

sbsv_row_free(row);
sbsv_body_parser_free(body);
```

### Detached Line Parsing

`sbsv_parser_parse_line_detached()` parses one full SBSV line using the parser's
schemas and ignored-prefix configuration without appending it to the parser's
stored result. On success it returns either `NULL` for an empty/comment/ignored
unknown line or a caller-owned `sbsv_row*`.

```c
sbsv_row* row = NULL;
assert(sbsv_parser_parse_line_detached(parser, "[node] [id 1] [value 2]", 1, &row) == SBSV_OK);
if (row != NULL) {
    /* row->id is (size_t)-1 because it is not part of the parser result. */
    sbsv_row_free(row);
}
```

## Validation Rules

- Names use `[A-Za-z0-9_-]`. Field tags use `$`, for example `node$0`.
- Custom types are parser-local and must be registered before schemas.
- Unknown schema types and unknown list subtypes fail during schema registration.
- `sbsv_parser_ignore_prefix()` must be called before schemas are added.
- The first body field of a full-line schema cannot be nullable. `sbsv_body_parser`
  allows nullable first fields.
- Strings support quoted values and balanced unquoted brackets. Escaping happens
  during value conversion, not during tokenization.

## Ownership And Memory

- Objects returned by `sbsv_parser_new()` and `sbsv_body_parser_new()` are owned by
  the caller and freed with `sbsv_parser_free()` and `sbsv_body_parser_free()`.
- Rows returned by `sbsv_parser_row_at()` and row-query functions are owned by the
  parser. Do not free those rows; they remain valid until the parser is freed or
  mutated by additional parsing.
- Row reference arrays returned by `sbsv_parser_get_rows*()` are caller-owned
  arrays of parser-owned row pointers. Free the array with `sbsv_free_row_ref_array()`.
- Rows returned by `sbsv_parser_parse_line_detached()` and `sbsv_body_parser_parse()`
  are caller-owned and freed with `sbsv_row_free()`.
- Strings returned through row getters are owned by their row. Strings allocated by
  `sbsv_escape_str()` and `sbsv_unescape_str()` are caller-owned and freed with
  `sbsv_free_string()`.
- `sbsv_tokenize_line()` allocates each token and the token array; release them with
  `sbsv_free_token_list()`.
- Custom values can store owned pointers with `sbsv_value_set_custom_ptr()`. Their
  `custom_free` callback runs from `sbsv_value_clear()` / `sbsv_row_free()` /
  `sbsv_parser_free()`.

The parser stores owned copies of schema names, field names, row values, tokenized
strings, and custom values. Query APIs avoid copying rows by returning row
references; this is the main zero-copy path. Full parsing still copies strings into
owned rows so parsed data remains valid after input buffers are released.

## Thread Safety And Incremental Parsing

Separate parser instances can be used concurrently from different threads. A single
`sbsv_parser` or `sbsv_body_parser` instance is not internally synchronized; guard
shared instances with your own lock.

`sbsv_parser_parse_line()` supports incremental parsing and appends rows as each
line arrives. Call `sbsv_parser_finish()` after the final line if you use groups
that can end implicitly at end-of-input. `sbsv_parser_loads()` and
`sbsv_parser_load_file()` call `sbsv_parser_finish()` automatically.

For more usage, see [tests/test_main.c](./tests/test_main.c).
