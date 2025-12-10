all: model_malloc gen_input


model_malloc: model_malloc.c
	clang -o model_malloc model_malloc.c

gen_input: gen_input.c
	clang -o gen_input gen_input.c
	
	
clean:
	rm -f model_malloc
	rm -f gen_input
	rm -f *.core

run: model_malloc
	rm -rf workdir
	rm -f *.core
	uv run ../../fuzzolic/fuzzolic.py --forkserver-entrypoint 401200 --keep-run-dirs --address-reasoning --optimistic-solving --timeout 90000 -o ./workdir/ -i ./malloc.in -- ./model_malloc @@
