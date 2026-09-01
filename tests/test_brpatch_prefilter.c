/*
 * Runtime tests for brpatch-prefilter.c's CWE-119 binary snapshot capture
 * (plan §8).
 *
 * Compiled WITHOUT BINRADAR_EVAL_ONLY with BRPATCH_CWE805 +
 * BRPATCH_ALLOC_MALLOC so the tracker and capture path are compiled in.
 * The test drives dest() with a constructed STATE and reads the pipe
 * records, printing parsed fields as RESULT lines that the Python test
 * (tests/test_binradar_setup_CWE805.py) asserts against.
 *
 * Record layout (little-endian, x86-64):
 *   header:  magic u32, version u32, stack_size u64, flags u64
 *   clamps:  256 * {begin u64, end u64}
 *   regs:    16 * u64 (rax..r15)
 *   stack:   stack_size bytes starting at state->rsp
 */

#define TAOSC_DEST 0x1234
#include "../benchmarks/loftix/brpatch-prefilter.c"

static int failures = 0;

static void set_state(struct STATE *state, const int64_t regs[16],
                      const uint8_t *stack, size_t stack_size)
{
	memset(state, 0, sizeof(*state));
	state->rax = regs[0]; state->rbx = regs[1]; state->rcx = regs[2];
	state->rdx = regs[3]; state->rsi = regs[4]; state->rdi = regs[5];
	state->rsp = (int64_t)(uintptr_t)stack;
	state->rbp = regs[7];
	state->r8 = regs[8]; state->r9 = regs[9]; state->r10 = regs[10];
	state->r11 = regs[11]; state->r12 = regs[12]; state->r13 = regs[13];
	state->r14 = regs[14]; state->r15 = regs[15];
	(void)stack_size;
}

/* Rebuild the tracker state: mark(1) arms the hooks, then record one
 * allocation clamp {begin, end}. */
static void set_one_clamp(uint64_t begin, uint64_t end)
{
	memset(buffers, 0, sizeof(buffers));
	next = 0;
	trace = 0;
	mark(1);
	set_size(end, 0);   /* malloc: end = rdi */
	set_base(begin);    /* begin = rax; end += rax */
}

static char env_buf[4][96];
static char *envp_arr[5];

static void setup_env(const char *stack_size, const char *max_hits,
                      const char *max_bytes)
{
	int n = 0;
	if (stack_size != NULL) {
		snprintf(env_buf[n], sizeof(env_buf[n]),
		         "PREFILTER_STACK_SIZE=%s", stack_size);
		envp_arr[n] = env_buf[n];
		n++;
	}
	if (max_hits != NULL) {
		snprintf(env_buf[n], sizeof(env_buf[n]),
		         "PREFILTER_MAX_HITS=%s", max_hits);
		envp_arr[n] = env_buf[n];
		n++;
	}
	if (max_bytes != NULL) {
		snprintf(env_buf[n], sizeof(env_buf[n]),
		         "PREFILTER_MAX_BYTES=%s", max_bytes);
		envp_arr[n] = env_buf[n];
		n++;
	}
	envp_arr[n] = NULL;
	init(0, NULL, envp_arr);
	/* Fresh capture state for each scenario. */
	hit_count = 0;
	captured_bytes = 0;
	truncated = 0;
}

/* Read exactly count bytes from fd (the record is written with a
 * full-write loop, so a full read is expected). */
static int read_all(int fd, void *buf, size_t count)
{
	char *p = buf;
	while (count > 0) {
		ssize_t n = read(fd, p, count);
		if (n <= 0)
			return -1;
		p += n;
		count -= (size_t)n;
	}
	return 0;
}

static void run_snapshot_scenario(void)
{
	static const int64_t regs[16] = {0x1111, 0x2222, 0x3333, 0x4444,
	                                 0x5555, 0x6666, 0x7777, 0x8888,
	                                 0x9999, 0xaaaa, 0xbbbb, 0xcccc,
	                                 0xdddd, 0xeeee, 0xffff, 0x1000};
	uint8_t stack_buf[64];
	for (int i = 0; i < 64; i++)
		stack_buf[i] = (uint8_t)(0xa0 + i);
	struct STATE state;
	set_state(&state, regs, stack_buf, sizeof(stack_buf));
	set_one_clamp(0x6000, 0x200);

	int fds[2];
	if (pipe(fds) < 0) {
		printf("RESULT snap pipe-error\n");
		failures++;
		return;
	}
	patch_fd = fds[1];
	setup_env("64", NULL, NULL);
	const void *ret = dest(&state);
	close(fds[1]);
	if (ret != NULL) {
		printf("RESULT snap dest-nonnull\n");
		failures++;
		close(fds[0]);
		return;
	}

	struct prefilter_snapshot_header header;
	if (read_all(fds[0], &header, sizeof(header)) < 0) {
		printf("RESULT snap short-header\n");
		failures++;
		close(fds[0]);
		return;
	}
	printf("RESULT snap-header %u %u %llu %llu\n",
	       header.magic, header.version,
	       (unsigned long long)header.stack_size,
	       (unsigned long long)header.flags);

	struct clamp clamps[256];
	if (read_all(fds[0], clamps, sizeof(clamps)) < 0) {
		printf("RESULT snap short-clamps\n");
		failures++;
		close(fds[0]);
		return;
	}
	printf("RESULT snap-clamp0 %llx %llx\n",
	       (unsigned long long)clamps[0].begin,
	       (unsigned long long)clamps[0].end);
	printf("RESULT snap-clamp1 %llx %llx\n",
	       (unsigned long long)clamps[1].begin,
	       (unsigned long long)clamps[1].end);

	uint64_t regs_out[16];
	if (read_all(fds[0], regs_out, sizeof(regs_out)) < 0) {
		printf("RESULT snap short-regs\n");
		failures++;
		close(fds[0]);
		return;
	}
	printf("RESULT snap-regs");
	for (int i = 0; i < 16; i++)
		printf(" %llx", (unsigned long long)regs_out[i]);
	printf("\n");

	uint8_t stack_out[64];
	if (read_all(fds[0], stack_out, sizeof(stack_out)) < 0) {
		printf("RESULT snap short-stack\n");
		failures++;
		close(fds[0]);
		return;
	}
	printf("RESULT snap-stack");
	for (int i = 0; i < 64; i++)
		printf(" %02x", stack_out[i]);
	printf("\n");
	close(fds[0]);
}

static void run_truncation_scenario(void)
{
	static const int64_t regs[16] = {0};
	uint8_t stack_buf[64] = {0};
	struct STATE state;
	set_state(&state, regs, stack_buf, sizeof(stack_buf));
	set_one_clamp(0x1000, 0x100);

	int fds[2];
	if (pipe(fds) < 0) {
		printf("RESULT snap-trunc pipe-error\n");
		failures++;
		return;
	}
	patch_fd = fds[1];
	setup_env("64", "1", NULL); /* one hit allowed */
	dest(&state);                /* full record */
	dest(&state);                /* hit limit -> truncation marker */
	close(fds[1]);

	struct prefilter_snapshot_header header;
	if (read_all(fds[0], &header, sizeof(header)) < 0) {
		printf("RESULT snap-trunc short-first\n");
		failures++;
		close(fds[0]);
		return;
	}
	/* Skip the first full record (header + clamps + regs + stack). */
	uint8_t skip[4096 + 128 + 64];
	if (read_all(fds[0], skip, sizeof(skip)) < 0) {
		printf("RESULT snap-trunc short-skip\n");
		failures++;
		close(fds[0]);
		return;
	}
	struct prefilter_snapshot_header marker;
	if (read_all(fds[0], &marker, sizeof(marker)) < 0) {
		printf("RESULT snap-trunc short-marker\n");
		failures++;
		close(fds[0]);
		return;
	}
	printf("RESULT snap-trunc %u %llu %llu\n",
	       marker.magic, (unsigned long long)marker.stack_size,
	       (unsigned long long)marker.flags);
	close(fds[0]);
}

static void run_generic_scenario(void)
{
	static const int64_t regs[16] = {0x42};
	uint8_t stack_buf[64] = {0};
	struct STATE state;
	set_state(&state, regs, stack_buf, sizeof(stack_buf));

	int fds[2];
	if (pipe(fds) < 0) {
		printf("RESULT snap-generic pipe-error\n");
		failures++;
		return;
	}
	patch_fd = fds[1];
	setup_env(NULL, NULL, NULL); /* no stack size: generic sbsv path */
	dest(&state);
	close(fds[1]);
	char line[512] = {0};
	ssize_t n = read(fds[0], line, sizeof(line) - 1);
	close(fds[0]);
	if (n <= 0) {
		printf("RESULT snap-generic no-line\n");
		failures++;
		return;
	}
	printf("RESULT snap-generic %s", line);
}

int main(void)
{
	run_snapshot_scenario();
	run_truncation_scenario();
	run_generic_scenario();

	if (failures) {
		printf("FAILED %d\n", failures);
		return 1;
	}
	printf("ALL-PASS\n");
	return 0;
}
