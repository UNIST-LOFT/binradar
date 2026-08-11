# SBSV: square bracket separated values
A flexible, schema-driven structured log data format.
Human readable, easy to write (you can write it without any dependencies: simple `print()` works fine), and easy to parse.

## Install

```shell
python3 -m pip install sbsv
```

## C library (experimental)

[libsbsv](./libsbsv) is a C library for parsing SBSV files. It provides a C API for loading and querying SBSV data, and can be used in C/C++ projects.

## Use
You can read this log-like data:
```sbsv
[meta-data] [id 1] [format string]
[meta-data] [id 2] [format token]
[data] [string] [id 1] [actual some long string...]
[data] [token] [id 2] [actual [some] [multiple] [tokens]]
[stat] [rows 2]
```

```python
import sbsv

parser = sbsv.parser()
parser.add_schema("[meta-data] [id: int] [format: str]")
parser.add_schema("[data] [string] [id: int] [actual: str]")
parser.add_schema("[data] [token] [id: int] [actual: list[str]]")
parser.add_schema("[stat] [rows: int]")
with open("testfile.sbsv", "r") as f:
  result = parser.load(f)
```

`parser.load()` returns lists of `SbsvData` rows. Each row supports `row["field"]`
access, and its `.data` dictionary would look like:
```
{
  "meta-data": [{"id": 1, "format": "string"}, {"id": 2, "format": "token"}],
  "data": {
    "string": [{"id": 1, "actual": "some long string..."}],
    "token": [{"id": 2, "actual": ["some", "multiple", "tokens"]}]
  },
  "stat": [{"rows": 2}]
}
```

## Details
### Basic schema
Schema is consisted with schema name, variable name and type annotation.
```
[schema-name] [var-name: type]
```
You can use [A-Za-z0-9\-_] for names. 

### Sub schema
```
[my-schema] [sub-schema] [some: int] [other: str] [data: bool]
```
You can add any sub schema.
But if you add sub schema, you cannot add new schema with same schema name without sub schema.
```
[my-schema] [no: int] [sub: str] [schema: str]
# this will cause error
```

### Ignore
```
[2024-03-04 13:22:56] [DEBUG] [necessary] [from] [this part]
```
Regular log file may contain unnecessary data. You can specify parser to ignore `[2024-03-04 13:22:56] [DEBUG]` part.

```python
# This will ignore first two elements for all lines.
parser.ignore_prefix("[$timestamp] [$log_level]", save_ignored=True)
parser.add_schema("[necessary] [from] [this: str]")
result = parser.loads("[2024-03-04 13:22:56] [DEBUG] [necessary] [from] [this part]")
row = result["necessary"]["from"][0]
row["$timestamp"] == "2024-03-04 13:22:56"
row["$log_level"] == "DEBUG"
row["this"] == "part"
```
`save_ignored` is optional, and default is False.
Call `ignore_prefix()` before adding any schema. It raises `ValueError` if a schema already exists.

### Duplicating names
Sometimes, you may want to use same name multiple times. You can distinguish them using additional tags.
```
[my-schema] [node 1] [node 2] [node 3]
```
Tag is added like `node$some-tag`, after `$`. Data should not contain tags: they will be only used in schema.
```python
parser.add_schema("[my-schema] [node$0: int] [node$1: int] [node$2: int]")
result = parser.loads("[my-schema] [node 1] [node 2] [node 3]\n")
result["my-schema"][0]["node$0"] == 1
```

### Name matching
If there are additional element in data, it will be ignored.
The sequence of the names should not be changed.
```python
parser.add_schema("[my-schema] [node: int] [value: int]")
data = "[my-schema] [node 1] [unknown element] [value 3]\n"
result = parser.loads(data)
result["my-schema"][0].data == { "node": 1, "value": 3 }
```

### Ordering
You may need a global ordering of each line.
```python
parser.add_schema("[data] [string] [id: int] [actual: str]")
parser.add_schema("[data] [token] [id: int] [actual: list[str]]")
result = parser.load(f)
# This returns all elements in order
elems_all = parser.get_result_in_order()
# This returns elements matching names in order
# If it contains sub-schema, use $
# For example, [data] [string] [id: int] -> "data$string"
elems = parser.get_result_in_order(["[data] [string]", "[data] [token]"])
# You can also use ["data$string", "data$token"]
```
Or, you can get schema id (`data$string` and `data$token`) like this:
```python
sbsv.get_schema_id("node") == "node"
sbsv.get_schema_id("data", "string") == "data$string"
# this is equal to 
sbsv.get_schema_id("data", "string") == '$'.join(["data", "string"])
```

### Group
```
[data] [begin]
[block] [data 1]
[block] [data 2]
[data] [end]
[data] [begin]
[block] [data 3]
[block] [data 4]
[data] [end]
```
You can group block 1, 2

```python
# First, add all to schema
parser.add_schema("[data] [begin]")
parser.add_schema("[data] [end]")
parser.add_schema("[block] [data: int]")
# Second, add group name, group start, group end
parser.add_group("data", "[data] [begin]", "[data] [end]")
parser.load(sbsv_file)
# Iterate groups
for block in parser.iter_group("data"):
  print("group start")
  for block_data in block:
    if block_data.schema_name == "block":
      print(block_data["data"])
# Or, use index
block_indices = parser.get_group_index("data")
for index in block_indices:
  print("use index")
  for block in parser.get_result_by_index("[block]", index):
    print(block["data"])
```
Output:
```
group start
1
2
group start
3
4
use index
1
2
use index
3
4
```

You can use group without closing schema.
```
[group-wo-closing] [new-group a]
[some] [data 9]
[some] [data 8]
[some] [data 7]
[group-wo-closing] [new-group b]
[some] [data 6]
[some] [data 5]
[group-wo-closing] [new-group c]
[some] [data 4]
```

```python
# First, add all to schema
parser.add_schema("[group-wo-closing] [new-group: str]")
parser.add_schema("[some] [data: int]")
# Second, add group name, group start == group end
parser.add_group("new-group", "[group-wo-closing]", "[group-wo-closing]")
parser.load(sbsv_file)
# Iterate groups
for block in parser.iter_group("new-group"):
  print("group start")
  for block_data in block:
    if block_data.schema_name == "some":
      print(block_data["data"])
# Or, use index
block_indices = parser.get_group_index("new-group")
for index in block_indices:
  print("use index")
  for block in parser.get_result_by_index("[some]", index):
    print(block["data"])
```
Output
```
group start
9
8
7
group start
6
5
group start
4
use index
9
8
7
use index
6
5
use index
4
```


### Primitive types
Primitive types are `str`, `int`, `float`, `bool`, `null`.
Schema types are checked when `add_schema()` is called. Unknown types, including unknown list subtypes, raise `ValueError`.

### Complex types

#### nullable
```
[car] [id 1] [speed 100] [power 2] [price]
[car] [id 2] [speed 120] [power 3] [price 33000]
```

```python
parser.add_schema("[car] [id: int] [speed: int] [power: int] [price?: int]")
```
The first body field of a full line schema cannot be nullable. The following raises `ValueError`:
```python
parser.add_schema("[car] [id?: int] [speed: int] [power: int] [price: int]")
```
`body_parser` accepts nullable first fields because it has no schema-name prefix to match.

#### list
```
[data] [token] [id 2] [actual [some] [multiple] [tokens]]
```

```python
parser.add_schema("[data] [token] [id: int] [actual: list[str]]")
```

### Custom types
You can define your own types by providing a converter function that takes a string and returns a value (x: str -> custom_type).

```python
parser = sbsv.parser()

# Define a custom type "hex" to parse hexadecimal numbers
parser.add_custom_type("hex", lambda x: int(x, 16))

# Use the custom type in schema
parser.add_schema("[data] [id: hex] [val: hex]")

result = parser.loads("""
[data] [id ff] [val deadbeef]
""")

# result["data"][0]["id"] == 255
# result["data"][0]["val"] == 3735928559
```

Notes:
- Register custom types before adding any schema. `add_custom_type()` raises `ValueError` if a schema already exists.
- Schemas that reference an unregistered custom type raise `ValueError`.
- Custom types are local to each parser instance. Registering a custom type on one parser does not affect other parsers in the same process.

## Utilities
### parser.parse_line_detached() (stateless)
If you want to parse single line, you can use `parser.parse_line_detached()`. It does not store results in parser, but return `SbsvData` directly.
```python
parser = sbsv.parser()
parser.add_schema("[node] [id: int] [value: int]")
parser.add_schema("[edge] [src: int] [dst: int] [value: int]")
result = parser.parse_line_detached("[node] [id 1] [value 2]")
# result == SbsvData(schema_name="node", data={"id": 1, "value": 2})
# Note: result is not dict, but SbsvData object.
```
This can be useful in cases like parsing log lines one by one, without storing them in memory. 

### Body parser (stateless)
```python
parser = sbsv.body_parser("[id: int] [value: int]")
result = parser.loads("[id 1] [value 2]")
# result == {"id": 1, "value": 2}
```
This only takes schema body, without schema name. It is useful when you want to parse data without caring about schema name. 
For example, it can be used for custom types that implements nested type.
```python
parser = sbsv.parser()
body_parser = sbsv.body_parser("[id: int] [value: int]")
def custom_type_converter(x: str):
    return body_parser.loads(x)
parser.add_custom_type("mytype", custom_type_converter)
parser.add_schema("[data] [val: mytype]")
result = parser.loads("[data] [val [id 1] [value 2]]")
# result["data"][0]["val"] == {"id": 1, "value": 2}
```
If a body parser schema uses custom types, pass them when constructing the body parser:
```python
parser = sbsv.body_parser("[id: hex]", custom_types={"hex": lambda x: int(x, 16)})
parser.loads("[id ff]") == {"id": 255}
```

### Escape sequences for string
Quoted strings keep internal `[` and `]` as string content. Escape internal quotes with `\"`.
```
[car] [id 1] [name "[name with square bracket]"]
[car] [id 2] [name "name with \"quote\""]
```

Unquoted strings can contain balanced brackets without escaping. Escape unmatched brackets when they should be part of the string.
```
[car] [id 3] [name [name with square bracket]]
[car] [id 4] [name name with unmatched \] bracket]
```

Use `sbsv.escape_str()` to get an unquoted escaped string and `sbsv.escape_str(..., quote=True)` to get a quoted string. `sbsv.unescape_str()` decodes either form.
```python
sbsv.escape_str("[name with square bracket]") == "[name with square bracket]"
sbsv.escape_str("[name with square bracket]", quote=True) == '"[name with square bracket]"'
```
Quoted strings are strict: unknown escape sequences, unescaped internal quotes, trailing escapes, and unterminated quotes raise `ValueError`.

## Contribute
Install [uv](https://docs.astral.sh/uv/getting-started/installation/#standalone-installer)
```shell
# Linux
curl -LsSf https://astral.sh/uv/install.sh | sh
uv sync
```
You should run `black` linter before commit.
```shell
uv run black .
```

Before implementing new features or fixing bugs, add new tests in `tests/`.
```shell
uv run pytest
```

Build and update
```shell
uv build
uv publish
```