all: val-runtime

val-runtime:
	./init.sh

run:
	cd val-runtime && uv run ../../../fuzzolic/fuzzolic.py --keep-run-dirs --address-reasoning --optimistic-solving --timeout 90000 -o ./workdir/ -i ./exploit.tif -- ./tiffcrop @@ /tmp/out.tif

clean:
	rm -rf val-runtime
