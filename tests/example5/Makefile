all: test

test: test.c
	gcc -O0 -g -fno-omit-frame-pointer -Wall -Wextra -o test test.c

clean:
	rm -f test
	rm -rf workdir
	rm -f *.core

run: test
	rm -rf workdir
	rm -f *.core
	uv run ../../fuzzolic/fuzzolic.py --forkserver-entrypoint 4000001229 --keep-run-dirs --address-reasoning --optimistic-solving --timeout 90000 -o ./workdir/ -i ./input.txt -- ./test @@
