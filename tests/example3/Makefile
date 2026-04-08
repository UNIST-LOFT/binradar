all: val-runtime

val-runtime:
	./init.sh

run:
	# grep readSeparateTilesIntoBuffer tiffcrop.asm
	cd val-runtime && uv run ../../../fuzzolic/fuzzolic.py --symbolic-models --forkserver-entrypoint 4000006599 --keep-run-dirs --address-reasoning --optimistic-solving --timeout 90000 -o ./workdir/ -i ./exploit.tif -- ./tiffcrop @@ /tmp/out.tif

clean:
	rm -rf val-runtime
