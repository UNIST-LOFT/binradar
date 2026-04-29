# fuzzing + concolic = fuzzolic :)

Please refer to the documentation in the `docs` directory for build and usage instructions. You can also find it online on https://season-lab.github.io/fuzzolic/.

## Build
```
git clone https://github.com/hsh814/fuzzolic.git
cd fuzzolic
git submodule update --init --recursive
docker build -t fuzzolic:2204 -f docker/fuzzolic-runner/Dockerfile.Ubuntu2204 .
```


## Status
### Fuzzolic
- Forkserver: Implemented (fuzzolic/executor.py)
- Type Analyzer: Work in Progress (fuzzolic/analyze_type.py)

### tracer
`type-infer` branch
- Modified files:
  * tracer/linux-user/snapshot.c, h
  * tracer/linux-user/i386/signal.c
  * tracer/linux-user/syscall.c
  * tracer/tcg/symbolic/symbolic.c, h
  * tracer/tcg/symbolic/models.c
  * tracer/tcg/symbolic-i386.c
- Forkserver: Implemented
- Type Analyzer
  * Logging memory accesses with region info: (trace_mem())
    + Heap: hook into malloc()/free()
    + Stack: hook for callq/ret
    + Global: hook into program segments in elf load
    + Other: ignored
  * Post-processing analyzer: python script (fuzzolic/analyze_type.py)
    + Recover base addresses of each memory chunk using heuristic
    