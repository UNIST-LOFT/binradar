#include "sbsv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int assert_no_error(int condition, const char *message) {
    if (condition) {
        fprintf(stderr, "Assertion failed: %s\n", message);
        exit(1);
    }
    return 0;
}

static int assert_true(int condition, const char* message) {
    if (!condition) {
        fprintf(stderr, "Assertion failed: %s\n", message);
        return 1;
    }
    return 0;
}

static int assert_str_eq(const char* actual, const char* expected, const char* message) {
    if ((actual == NULL && expected != NULL) || (actual != NULL && expected == NULL)) {
        fprintf(stderr, "Assertion failed: %s (null mismatch)\n", message);
        return 1;
    }

    if (actual != NULL && strcmp(actual, expected) != 0) {
        fprintf(stderr, "Assertion failed: %s\nExpected: %s\nActual  : %s\n", message, expected, actual);
        return 1;
    }

    return 0;
}

static int assert_contains(const char* haystack, const char* needle, const char* message) {
    if (haystack == NULL || needle == NULL || strstr(haystack, needle) == NULL) {
        fprintf(stderr, "Assertion failed: %s\n", message);
        return 1;
    }
    return 0;
}

static int test_escape_roundtrip(void) {
    const char* source = "should escape ]]\\ this";
    char* escaped = NULL;
    char* unescaped = NULL;
    sbsv_status status;
    int failed = 0;

    status = sbsv_escape_str(source, &escaped);
    failed |= assert_true(status == SBSV_OK, "escape should succeed");

    if (!failed) {
        status = sbsv_unescape_str(escaped, &unescaped);
        failed |= assert_true(status == SBSV_OK, "unescape should succeed");
    }

    if (!failed) {
        failed |= assert_str_eq(unescaped, source, "roundtrip should preserve source");
    }

    sbsv_free_string(escaped);
    sbsv_free_string(unescaped);
    return failed;
}

static int test_escape_examples(void) {
    char* escaped = NULL;
    char* unescaped = NULL;
    int failed = 0;

    failed |= assert_true(sbsv_escape_str("this is a test]", &escaped) == SBSV_OK, "escape literal should succeed");
    if (!failed) {
        failed |= assert_str_eq(escaped, "this is a test\\]", "escape ] should match python behavior");
    }
    sbsv_free_string(escaped);
    escaped = NULL;

    failed |= assert_true(sbsv_unescape_str("\\,|\\]\\]\\[\\[\\]", &unescaped) == SBSV_OK, "unescape literal should succeed");
    if (!failed) {
        failed |= assert_str_eq(unescaped, ",|]][[]", "unescape sequence should match python behavior");
    }
    sbsv_free_string(unescaped);

    return failed;
}

static int test_tokenize_escape(void) {
    sbsv_token_list tokens;
    int failed = 0;

    memset(&tokens, 0, sizeof(tokens));
    failed |= assert_true(
        sbsv_tokenize_line("[mem] [pos] [seed 123] [id should escape \\]\\]\\ this] [file /path/to/file\\\"]", &tokens) == SBSV_OK,
        "tokenize should succeed"
    );

    if (!failed) {
        failed |= assert_true(tokens.count == 5, "token count should be 5");
    }
    if (!failed) {
        failed |= assert_str_eq(tokens.items[0], "mem", "token 0");
        failed |= assert_str_eq(tokens.items[1], "pos", "token 1");
        failed |= assert_str_eq(tokens.items[2], "seed 123", "token 2");
        failed |= assert_str_eq(tokens.items[3], "id should escape ]]\\ this", "token 3");
        failed |= assert_str_eq(tokens.items[4], "file /path/to/file\"", "token 4");
    }

    sbsv_free_token_list(&tokens);
    return failed;
}

static int test_tokenize_remove_noise(void) {
    sbsv_token_list tokens;
    int failed = 0;

    memset(&tokens, 0, sizeof(tokens));
    failed |= assert_true(
        sbsv_tokenize_line("[mem] [neg] id is [id myid] and file is [file myfile!]", &tokens) == SBSV_OK,
        "tokenize with noise should succeed"
    );

    if (!failed) {
        failed |= assert_true(tokens.count == 4, "token count should be 4");
        failed |= assert_str_eq(tokens.items[0], "mem", "token 0");
        failed |= assert_str_eq(tokens.items[1], "neg", "token 1");
        failed |= assert_str_eq(tokens.items[2], "id myid", "token 2");
        failed |= assert_str_eq(tokens.items[3], "file myfile!", "token 3");
    }

    sbsv_free_token_list(&tokens);
    return failed;
}

static sbsv_status custom_hex(const char* input, sbsv_value* out_value, void* user_data) {
    char* end_ptr;
    (void)user_data;
    out_value->type = SBSV_VALUE_INT;
    out_value->data.int_value = strtoll(input, &end_ptr, 16);
    if (*end_ptr != '\0') {
        return SBSV_ERR_INVALID_ARG;
    }
    return SBSV_OK;
}

typedef struct {
    long long parsed;
} custom_boxed_int;

static int g_custom_boxed_int_freed = 0;

static void custom_boxed_int_free(void* ptr) {
    if (ptr != NULL) {
        g_custom_boxed_int_freed += 1;
        free(ptr);
    }
}

static sbsv_status custom_boxed_int_parse(const char* input, sbsv_value* out_value, void* user_data) {
    custom_boxed_int* boxed;
    char* end_ptr;
    (void)user_data;

    boxed = (custom_boxed_int*)malloc(sizeof(custom_boxed_int));
    if (boxed == NULL) {
        return SBSV_ERR_ALLOC;
    }

    boxed->parsed = strtoll(input, &end_ptr, 10);
    if (*end_ptr != '\0') {
        free(boxed);
        return SBSV_ERR_INVALID_ARG;
    }

    return sbsv_value_set_custom_ptr(out_value, boxed, custom_boxed_int_free);
}

static int test_parser_basic(void) {
    sbsv_parser* parser = sbsv_parser_new(SBSV_PARSER_DEFAULT);
    int failed = 0;
    const sbsv_row* row;
    const sbsv_value* value;

    failed |= assert_true(parser != NULL, "parser should be created");
    if (failed) {
        return failed;
    }

    failed |= assert_true(sbsv_parser_add_schema(parser, "[node] [id: int] [value: int]") == SBSV_OK, "add node schema");
    failed |= assert_true(sbsv_parser_add_schema(parser, "[edge] [src: int] [dst: int] [value: int]") == SBSV_OK, "add edge schema");

    failed |= assert_true(
        sbsv_parser_loads(
            parser,
            "[node] [id 1] [value 2]\n"
            "[node] [id 2] [value 3]\n"
            "[edge] [src 1] [dst 2] [value 6]\n"
        ) == SBSV_OK,
        "parse basic content"
    );

    if (!failed) {
        failed |= assert_true(sbsv_parser_row_count(parser) == 3, "row count should be 3");
    }

    if (!failed) {
        row = sbsv_parser_row_at(parser, 0);
        failed |= assert_true(row != NULL, "row 0 exists");
        if (row != NULL) {
            value = sbsv_row_get(row, "id");
            failed |= assert_true(value != NULL && value->type == SBSV_VALUE_INT && value->data.int_value == 1, "node.id should be int 1");
            value = sbsv_row_get(row, "value");
            failed |= assert_true(value != NULL && value->type == SBSV_VALUE_INT && value->data.int_value == 2, "node.value should be int 2");
        }
    }

    sbsv_parser_free(parser);
    return failed;
}

static int test_parser_nullable_and_list(void) {
    sbsv_parser* parser = sbsv_parser_new(SBSV_PARSER_DEFAULT);
    int failed = 0;
    const sbsv_row* row;
    const sbsv_value* file_value;
    const sbsv_value* vals;

    failed |= assert_true(parser != NULL, "parser should be created");
    failed |= assert_true(sbsv_parser_add_schema(parser, "[mem] [neg] [id: str] [file?: str]") == SBSV_OK, "add nullable schema");
    failed |= assert_true(sbsv_parser_add_schema(parser, "[data] [vals: list[int]]") == SBSV_OK, "add list schema");
    failed |= assert_true(
        sbsv_parser_loads(
            parser,
            "[mem] [neg] [id x] [file]\n"
            "[data] [vals [1] [2] [3]]\n"
        ) == SBSV_OK,
        "parse nullable and list"
    );

    if (!failed) {
        row = sbsv_parser_row_at(parser, 0);
        file_value = sbsv_row_get(row, "file");
        failed |= assert_true(file_value != NULL && file_value->type == SBSV_VALUE_NULL, "nullable empty value should become null");
    }

    if (!failed) {
        row = sbsv_parser_row_at(parser, 1);
        vals = sbsv_row_get(row, "vals");
        failed |= assert_true(vals != NULL && vals->type == SBSV_VALUE_LIST && vals->data.list.count == 3, "list should have 3 values");
        if (vals != NULL && vals->type == SBSV_VALUE_LIST && vals->data.list.count == 3) {
            failed |= assert_true(vals->data.list.items[0].data.int_value == 1, "list item 0");
            failed |= assert_true(vals->data.list.items[1].data.int_value == 2, "list item 1");
            failed |= assert_true(vals->data.list.items[2].data.int_value == 3, "list item 2");
        }
    }

    sbsv_parser_free(parser);
    return failed;
}

static int test_parser_custom_type_and_late_registration(void) {
    sbsv_parser* parser = sbsv_parser_new(SBSV_PARSER_DEFAULT);
    int failed = 0;
    const sbsv_row* row;
    const sbsv_value* value;

    failed |= assert_true(parser != NULL, "parser should be created");
    failed |= assert_true(sbsv_parser_add_schema(parser, "[d] [v: hex2]") == SBSV_OK, "add custom schema first");
    failed |= assert_true(sbsv_parser_add_custom_type(parser, "hex2", custom_hex, NULL) == SBSV_OK, "register custom type after schema");
    failed |= assert_true(sbsv_parser_loads(parser, "[d] [v 1a]\n") == SBSV_OK, "parse custom type data");

    if (!failed) {
        row = sbsv_parser_row_at(parser, 0);
        value = sbsv_row_get(row, "v");
        failed |= assert_true(value != NULL && value->type == SBSV_VALUE_INT && value->data.int_value == 26, "hex custom type should parse to 26");
    }

    sbsv_parser_free(parser);
    return failed;
}

static int test_parser_duplicating_names_with_tags(void) {
    sbsv_parser* parser = sbsv_parser_new(SBSV_PARSER_DEFAULT);
    int failed = 0;
    const sbsv_row* row;
    const sbsv_value* value;

    failed |= assert_true(parser != NULL, "parser should be created");
    failed |= assert_true(
        sbsv_parser_add_schema(parser, "[my-schema] [node$0: int] [node$1: int] [node$2: int]") == SBSV_OK,
        "add duplicate-name schema"
    );
    failed |= assert_true(
        sbsv_parser_loads(parser, "[my-schema] [node 1] [node 2] [node 3]\n") == SBSV_OK,
        "parse duplicate-name data"
    );

    if (!failed) {
        row = sbsv_parser_row_at(parser, 0);
        failed |= assert_true(row != NULL, "row 0 exists");
        if (row != NULL) {
            value = sbsv_row_get(row, "node$0");
            failed |= assert_true(value != NULL && value->type == SBSV_VALUE_INT && value->data.int_value == 1, "node$0 should be 1");
            value = sbsv_row_get(row, "node$1");
            failed |= assert_true(value != NULL && value->type == SBSV_VALUE_INT && value->data.int_value == 2, "node$1 should be 2");
            value = sbsv_row_get(row, "node$2");
            failed |= assert_true(value != NULL && value->type == SBSV_VALUE_INT && value->data.int_value == 3, "node$2 should be 3");
        }
    }

    sbsv_parser_free(parser);
    return failed;
}

static int test_parser_name_matching_ignores_unknown_in_order(void) {
    sbsv_parser* parser = sbsv_parser_new(SBSV_PARSER_DEFAULT);
    int failed = 0;
    const sbsv_row* row;
    const sbsv_value* node_value;
    const sbsv_value* value_value;

    failed |= assert_true(parser != NULL, "parser should be created");
    failed |= assert_true(sbsv_parser_add_schema(parser, "[my-schema] [node: int] [value: int]") == SBSV_OK, "add name matching schema");
    failed |= assert_true(
        sbsv_parser_loads(
            parser,
            "[my-schema] [node 1] [unknown element] [value 3] [trailing noise]\n"
        ) == SBSV_OK,
        "parse data with unknown elements"
    );

    if (!failed) {
        row = sbsv_parser_row_at(parser, 0);
        failed |= assert_true(row != NULL, "row 0 exists");
        if (row != NULL) {
            node_value = sbsv_row_get(row, "node");
            value_value = sbsv_row_get(row, "value");
            failed |= assert_true(node_value != NULL && node_value->type == SBSV_VALUE_INT && node_value->data.int_value == 1, "node should be 1");
            failed |= assert_true(value_value != NULL && value_value->type == SBSV_VALUE_INT && value_value->data.int_value == 3, "value should be 3");
        }
    }

    sbsv_parser_free(parser);
    return failed;
}

static int test_parser_group_and_index(void) {
    sbsv_parser* parser = sbsv_parser_new(SBSV_PARSER_DEFAULT);
    int failed = 0;
    sbsv_index_range* ranges = NULL;
    size_t range_count = 0;
    const sbsv_row** rows = NULL;
    size_t row_count = 0;

    failed |= assert_true(parser != NULL, "parser should be created");
    failed |= assert_true(sbsv_parser_add_schema(parser, "[data] [begin]") == SBSV_OK, "add begin schema");
    failed |= assert_true(sbsv_parser_add_schema(parser, "[data] [end]") == SBSV_OK, "add end schema");
    failed |= assert_true(sbsv_parser_add_schema(parser, "[block] [data: int]") == SBSV_OK, "add block schema");
    failed |= assert_true(sbsv_parser_add_group(parser, "data", "[data] [begin]", "[data] [end]") == SBSV_OK, "add group");
    failed |= assert_true(
        sbsv_parser_loads(
            parser,
            "[data] [begin]\n"
            "[block] [data 1]\n"
            "[block] [data 2]\n"
            "[data] [end]\n"
        ) == SBSV_OK,
        "parse grouped data"
    );

    failed |= assert_true(sbsv_parser_get_group_indices(parser, "data", &ranges, &range_count) == SBSV_OK, "read group indices");
    if (!failed) {
        failed |= assert_true(range_count == 1, "one group expected");
        failed |= assert_true(ranges[0].start == 0 && ranges[0].end == 3, "group range should match");
    }

    if (!failed) {
        failed |= assert_true(sbsv_parser_get_rows_by_index(parser, "[block]", ranges[0], &rows, &row_count) == SBSV_OK, "query by index range");
        failed |= assert_true(row_count == 2, "two block rows expected");
        if (row_count == 2) {
            const sbsv_value* first = sbsv_row_get(rows[0], "data");
            const sbsv_value* second = sbsv_row_get(rows[1], "data");
            failed |= assert_true(first != NULL && first->data.int_value == 1, "first block value");
            failed |= assert_true(second != NULL && second->data.int_value == 2, "second block value");
        }
    }

    sbsv_free_row_ref_array(rows);
    sbsv_free_group_indices(ranges);
    sbsv_parser_free(parser);
    return failed;
}

static int test_parser_group_schema_realloc_safety(void) {
    sbsv_parser* parser = sbsv_parser_new(SBSV_PARSER_DEFAULT);
    int failed = 0;
    sbsv_index_range* ranges = NULL;
    size_t range_count = 0;
    const sbsv_row** rows = NULL;
    size_t row_count = 0;
    int i;

    failed |= assert_true(parser != NULL, "parser should be created");
    failed |= assert_true(sbsv_parser_add_schema(parser, "[data] [begin]") == SBSV_OK, "add begin schema");
    failed |= assert_true(sbsv_parser_add_schema(parser, "[data] [end]") == SBSV_OK, "add end schema");
    failed |= assert_true(sbsv_parser_add_schema(parser, "[block] [data: int]") == SBSV_OK, "add block schema");
    failed |= assert_true(sbsv_parser_add_group(parser, "data", "[data] [begin]", "[data] [end]") == SBSV_OK, "add group before further schemas");

    for (i = 0; i < 64 && !failed; ++i) {
        char schema_expr[64];
        snprintf(schema_expr, sizeof(schema_expr), "[extra-%d] [v: int]", i);
        failed |= assert_true(sbsv_parser_add_schema(parser, schema_expr) == SBSV_OK, "add extra schema");
    }

    failed |= assert_true(
        sbsv_parser_loads(
            parser,
            "[data] [begin]\n"
            "[block] [data 11]\n"
            "[block] [data 22]\n"
            "[data] [end]\n"
        ) == SBSV_OK,
        "parse grouped data after schema realloc"
    );

    failed |= assert_true(sbsv_parser_get_group_indices(parser, "data", &ranges, &range_count) == SBSV_OK, "read group indices");
    if (!failed) {
        failed |= assert_true(range_count == 1, "one group expected");
        failed |= assert_true(ranges[0].start == 0 && ranges[0].end == 3, "group range should match");
    }

    if (!failed) {
        failed |= assert_true(sbsv_parser_get_rows_by_index(parser, "[block]", ranges[0], &rows, &row_count) == SBSV_OK, "query by index range");
        failed |= assert_true(row_count == 2, "two block rows expected");
        if (row_count == 2) {
            const sbsv_value* first = sbsv_row_get(rows[0], "data");
            const sbsv_value* second = sbsv_row_get(rows[1], "data");
            failed |= assert_true(first != NULL && first->data.int_value == 11, "first block value");
            failed |= assert_true(second != NULL && second->data.int_value == 22, "second block value");
        }
    }

    sbsv_free_row_ref_array(rows);
    sbsv_free_group_indices(ranges);
    sbsv_parser_free(parser);
    return failed;
}

static int test_parser_ordered_query(void) {
    sbsv_parser* parser = sbsv_parser_new(SBSV_PARSER_DEFAULT);
    int failed = 0;
    const char* schemas[2] = {"node", "edge"};
    const sbsv_row** rows = NULL;
    size_t row_count = 0;

    failed |= assert_true(parser != NULL, "parser should be created");
    failed |= assert_true(sbsv_parser_add_schema(parser, "[node] [id: int] [value: int]") == SBSV_OK, "add node schema");
    failed |= assert_true(sbsv_parser_add_schema(parser, "[edge] [src: int] [dst: int] [value: int]") == SBSV_OK, "add edge schema");
    failed |= assert_true(
        sbsv_parser_loads(
            parser,
            "[node] [id 1] [value 2]\n"
            "[node] [id 2] [value 3]\n"
            "[edge] [src 1] [dst 2] [value 6]\n"
            "[edge] [src 1] [dst 3] [value 10]\n"
        ) == SBSV_OK,
        "parse for ordered query"
    );

    failed |= assert_true(sbsv_parser_get_rows_in_order(parser, schemas, 2, &rows, &row_count) == SBSV_OK, "ordered filtered query");
    if (!failed) {
        failed |= assert_true(row_count == 4, "ordered query row count");
        if (row_count == 4) {
            failed |= assert_true(strcmp(rows[0]->schema_name, "node") == 0, "row0 schema");
            failed |= assert_true(strcmp(rows[1]->schema_name, "node") == 0, "row1 schema");
            failed |= assert_true(strcmp(rows[2]->schema_name, "edge") == 0, "row2 schema");
            failed |= assert_true(strcmp(rows[3]->schema_name, "edge") == 0, "row3 schema");
        }
    }

    sbsv_free_row_ref_array(rows);
    sbsv_parser_free(parser);
    return failed;
}

static int test_parser_get_rows_by_schema(void) {
    sbsv_parser* parser = sbsv_parser_new(SBSV_PARSER_DEFAULT);
    int failed = 0;
    const sbsv_row** rows = NULL;
    size_t row_count = 0;

    failed |= assert_true(parser != NULL, "parser should be created");
    failed |= assert_true(sbsv_parser_add_schema(parser, "[node] [id: int] [value: int]") == SBSV_OK, "add node schema");
    failed |= assert_true(sbsv_parser_add_schema(parser, "[edge] [src: int] [dst: int] [value: int]") == SBSV_OK, "add edge schema");
    failed |= assert_true(
        sbsv_parser_loads(
            parser,
            "[node] [id 1] [value 2]\n"
            "[edge] [src 1] [dst 2] [value 6]\n"
            "[node] [id 2] [value 3]\n"
        ) == SBSV_OK,
        "parse rows for schema query"
    );

    failed |= assert_true(sbsv_parser_get_rows(parser, "node", &rows, &row_count) == SBSV_OK, "query rows by schema name");
    if (!failed) {
        failed |= assert_true(row_count == 2, "node row count should be 2");
        if (row_count == 2) {
            const sbsv_value* id0 = sbsv_row_get(rows[0], "id");
            const sbsv_value* id1 = sbsv_row_get(rows[1], "id");
            failed |= assert_true(id0 != NULL && id0->data.int_value == 1, "first node id");
            failed |= assert_true(id1 != NULL && id1->data.int_value == 2, "second node id");
        }
    }
    sbsv_free_row_ref_array(rows);
    rows = NULL;

    failed |= assert_true(sbsv_parser_get_rows(parser, "[edge]", &rows, &row_count) == SBSV_OK, "query rows by schema expression");
    if (!failed) {
        failed |= assert_true(row_count == 1, "edge row count should be 1");
        if (row_count == 1) {
            const sbsv_value* val = sbsv_row_get(rows[0], "value");
            failed |= assert_true(val != NULL && val->data.int_value == 6, "edge value should be 6");
        }
    }
    sbsv_free_row_ref_array(rows);

    sbsv_parser_free(parser);
    return failed;
}

static int test_parser_unknown_schema_error_context(void) {
    sbsv_parser* parser = sbsv_parser_new(SBSV_PARSER_NO_IGNORE_UNKNOWN);
    int failed = 0;
    sbsv_status status;
    const char* error;

    failed |= assert_true(parser != NULL, "parser should be created");
    failed |= assert_true(sbsv_parser_add_schema(parser, "[node] [id: int]") == SBSV_OK, "add schema for unknown test");

    status = sbsv_parser_loads(parser, "[edge] [id 1]\n");
    failed |= assert_true(status == SBSV_ERR_INVALID_ARG, "unknown schema should fail when ignore_unknown=0");

    error = sbsv_parser_last_error(parser);
    failed |= assert_contains(error, "line=1", "error should contain line number");
    failed |= assert_contains(error, "schema=edge", "error should contain schema name");

    sbsv_parser_free(parser);
    return failed;
}

static int test_parser_error_detail_not_corrupted(void) {
    sbsv_parser* parser = sbsv_parser_new(SBSV_PARSER_DEFAULT);
    int failed = 0;
    sbsv_status status;
    const char* error;

    failed |= assert_true(parser != NULL, "parser should be created");
    failed |= assert_true(sbsv_parser_add_schema(parser, "[pointer] [size: int] [target: int]") == SBSV_OK, "add pointer schema");

    status = sbsv_parser_loads(parser, "[pointer] [sz 8] [target 10]\n");
    failed |= assert_true(status == SBSV_ERR_INVALID_ARG, "missing key should fail");

    error = sbsv_parser_last_error(parser);
    failed |= assert_contains(error, "line=1", "error should contain line number");
    failed |= assert_contains(error, "schema=pointer", "error should contain schema name");
    failed |= assert_contains(error, "missing key", "error should keep inner parse detail");

    sbsv_parser_free(parser);
    return failed;
}

static int test_parser_load_file_from_fp(void) {
    sbsv_parser* parser = sbsv_parser_new(SBSV_PARSER_DEFAULT);
    FILE* fp = NULL;
    int failed = 0;
    const sbsv_row* row;
    const sbsv_value* value;

    failed |= assert_true(parser != NULL, "parser should be created");
    if (failed) {
        return failed;
    }

    failed |= assert_true(sbsv_parser_add_schema(parser, "[node] [id: int] [value: int]") == SBSV_OK, "add node schema");
    failed |= assert_true(sbsv_parser_add_schema(parser, "[edge] [src: int] [dst: int] [value: int]") == SBSV_OK, "add edge schema");

    fp = tmpfile();
    failed |= assert_true(fp != NULL, "tmpfile should be created");
    if (!failed) {
        failed |= assert_true(
            fputs(
                "[node] [id 1] [value 2]\n"
                "[edge] [src 1] [dst 2] [value 6]\n",
                fp
            ) >= 0,
            "write tmp data"
        );
    }

    if (!failed) {
        rewind(fp);
        failed |= assert_true(sbsv_parser_load_file(parser, fp) == SBSV_OK, "load from FILE* should succeed");
    }

    if (!failed) {
        failed |= assert_true(sbsv_parser_row_count(parser) == 2, "row count should be 2");
        row = sbsv_parser_row_at(parser, 1);
        failed |= assert_true(row != NULL, "row 1 exists");
        if (row != NULL) {
            value = sbsv_row_get(row, "value");
            failed |= assert_true(value != NULL && value->type == SBSV_VALUE_INT && value->data.int_value == 6, "edge.value should be int 6");
        }
    }

    if (fp != NULL) {
        fclose(fp);
    }
    sbsv_parser_free(parser);
    return failed;
}

static int test_parser_custom_void_pointer_type(void) {
    sbsv_parser* parser = sbsv_parser_new(SBSV_PARSER_DEFAULT);
    int failed = 0;
    const sbsv_row* row;
    const sbsv_value* value;
    custom_boxed_int* boxed;

    g_custom_boxed_int_freed = 0;

    failed |= assert_true(parser != NULL, "parser should be created");
    failed |= assert_true(sbsv_parser_add_schema(parser, "[obj] [v: boxed_int]") == SBSV_OK, "add boxed custom schema");
    failed |= assert_true(sbsv_parser_add_custom_type(parser, "boxed_int", custom_boxed_int_parse, NULL) == SBSV_OK, "register boxed custom type");
    failed |= assert_true(sbsv_parser_loads(parser, "[obj] [v 123]\n") == SBSV_OK, "parse boxed custom type");

    if (!failed) {
        row = sbsv_parser_row_at(parser, 0);
        value = sbsv_row_get(row, "v");
        failed |= assert_true(value != NULL && value->type == SBSV_VALUE_CUSTOM, "custom value should have custom type");
        if (value != NULL && value->type == SBSV_VALUE_CUSTOM) {
            boxed = (custom_boxed_int*)value->data.custom_ptr;
            failed |= assert_true(boxed != NULL && boxed->parsed == 123, "boxed custom value should match");
        }
    }

    sbsv_parser_free(parser);
    failed |= assert_true(g_custom_boxed_int_freed == 1, "custom destructor should be called once");
    return failed;
}

static int test_row_typed_getters(void) {
    sbsv_parser* parser = sbsv_parser_new(SBSV_PARSER_DEFAULT);
    int failed = 0;
    const sbsv_row* row;
    const char* str_value;
    long long int_value = 0;
    double float_value = 0.0;
    int bool_value = 0;
    int int_valid = 0;
    int float_valid = 0;
    int bool_valid = 0;
    const sbsv_value_list* list_value;
    custom_boxed_int* boxed;

    g_custom_boxed_int_freed = 0;

    failed |= assert_true(parser != NULL, "parser should be created");
    failed |= assert_true(sbsv_parser_add_custom_type(parser, "boxed_int", custom_boxed_int_parse, NULL) == SBSV_OK, "register boxed custom type");
    failed |= assert_true(
        sbsv_parser_add_schema(
            parser,
            "[typed] [s: str] [i: int] [f: float] [b: bool] [l: list[int]] [c: boxed_int]"
        ) == SBSV_OK,
        "add typed schema"
    );
    failed |= assert_true(
        sbsv_parser_loads(
            parser,
            "[typed] [s hello] [i 42] [f 3.5] [b true] [l [1] [2]] [c 77]\n"
        ) == SBSV_OK,
        "parse typed row"
    );

    if (!failed) {
        row = sbsv_parser_row_at(parser, 0);
        failed |= assert_true(row != NULL, "row 0 exists");
        if (row != NULL) {
            str_value = sbsv_row_get_string(row, "s");
            failed |= assert_str_eq(str_value, "hello", "string getter");

            int_valid = 0;
            int_value = sbsv_row_get_int(row, "i", &int_valid);
            failed |= assert_true(int_valid == 1 && int_value == 42, "int getter");
            float_valid = 0;
            float_value = sbsv_row_get_float(row, "f", &float_valid);
            failed |= assert_true(float_valid == 1 && float_value == 3.5, "float getter");
            bool_valid = 0;
            bool_value = sbsv_row_get_bool(row, "b", &bool_valid);
            failed |= assert_true(bool_valid == 1 && bool_value == 1, "bool getter");

            list_value = sbsv_row_get_list(row, "l");
            failed |= assert_true(list_value != NULL && list_value->count == 2, "list getter count");
            if (list_value != NULL && list_value->count == 2) {
                failed |= assert_true(list_value->items[0].data.int_value == 1, "list getter item0");
                failed |= assert_true(list_value->items[1].data.int_value == 2, "list getter item1");
            }

            boxed = (custom_boxed_int*)sbsv_row_get_custom_ptr(row, "c");
            failed |= assert_true(boxed != NULL && boxed->parsed == 77, "custom pointer getter");

            failed |= assert_true(sbsv_row_get_string(row, "i") == NULL, "string getter type mismatch");
            int_valid = 1;
            int_value = sbsv_row_get_int(row, "s", &int_valid);
            failed |= assert_true(int_valid == 0 && int_value == 0, "int getter type mismatch");

            float_valid = 1;
            float_value = sbsv_row_get_float(row, "s", &float_valid);
            failed |= assert_true(float_valid == 0 && float_value == 0.0, "float getter type mismatch");

            bool_valid = 1;
            bool_value = sbsv_row_get_bool(row, "s", &bool_valid);
            failed |= assert_true(bool_valid == 0 && bool_value == 0, "bool getter type mismatch");

            int_value = sbsv_row_get_int(row, "i", NULL);
            failed |= assert_true(int_value == 42, "int getter should support NULL valid");
            float_value = sbsv_row_get_float(row, "f", NULL);
            failed |= assert_true(float_value == 3.5, "float getter should support NULL valid");
            bool_value = sbsv_row_get_bool(row, "b", NULL);
            failed |= assert_true(bool_value == 1, "bool getter should support NULL valid");
        }
    }

    sbsv_parser_free(parser);
    failed |= assert_true(g_custom_boxed_int_freed == 1, "typed getter custom value should be freed");
    return failed;
}

int main(void) {

    assert_no_error(test_escape_roundtrip(), "test_escape_roundtrip");
    assert_no_error(test_escape_examples(), "test_escape_examples");
    assert_no_error(test_tokenize_escape(), "test_tokenize_escape");
    assert_no_error(test_tokenize_remove_noise(), "test_tokenize_remove_noise");
    assert_no_error(test_parser_basic(), "test_parser_basic");
    assert_no_error(test_parser_nullable_and_list(), "test_parser_nullable_and_list");
    assert_no_error(test_parser_custom_type_and_late_registration(), "test_parser_custom_type_and_late_registration");
    assert_no_error(test_parser_duplicating_names_with_tags(), "test_parser_duplicating_names_with_tags");
    assert_no_error(test_parser_name_matching_ignores_unknown_in_order(), "test_parser_name_matching_ignores_unknown_in_order");
    assert_no_error(test_parser_group_and_index(), "test_parser_group_and_index");
    assert_no_error(test_parser_group_schema_realloc_safety(), "test_parser_group_schema_realloc_safety");
    assert_no_error(test_parser_ordered_query(), "test_parser_ordered_query");
    assert_no_error(test_parser_get_rows_by_schema(), "test_parser_get_rows_by_schema");
    assert_no_error(test_parser_unknown_schema_error_context(), "test_parser_unknown_schema_error_context");
    assert_no_error(test_parser_error_detail_not_corrupted(), "test_parser_error_detail_not_corrupted");
    assert_no_error(test_parser_load_file_from_fp(), "test_parser_load_file_from_fp");
    assert_no_error(test_parser_custom_void_pointer_type(), "test_parser_custom_void_pointer_type");
    assert_no_error(test_row_typed_getters(), "test_row_typed_getters");

    printf("sbsv C tests passed\n");
    return 0;
}
