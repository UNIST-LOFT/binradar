CC=gcc

all: test

test: test.c
	$(CC) -O0 -g -fno-omit-frame-pointer -Wall -Wextra -o test test.c sbsv.c sbsv_parser.c
	objdump -d test > test.asm

clean:
	rm -f test
	rm -rf workdir
	rm -f *.core

run: test
	rm -rf workdir
	rm -f *.core
	# grep sbsv_parser_parse_line test.asm
	uv run ../../fuzzolic/fuzzolic.py --symbolic-models --forkserver-entrypoint 4000008319 --keep-run-dirs --address-reasoning --optimistic-solving --timeout 90000 -o ./workdir/ -i ./input.sbsv -- ./test @@

analyze:
	uv run ../../fuzzolic/analyze_type.py ./workdir/tracer-forkserver.log