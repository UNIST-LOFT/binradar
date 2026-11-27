/* Real guest runtime/writer fixture, no replacement safe-read or evaluator.
 * cc -std=gnu11 -O2 -Wall -Wextra -Werror -Wno-unused-function \
 *   -Wno-unused-parameter -Wno-missing-field-initializers \
 *   -Wno-implicit-fallthrough -Iutils/e9patch/examples \
 *   -Itests/fixtures/brobs tests/test_br_observation.c -o /tmp/test_br_observation
 * Also build with -DBRPATCH_CWE805 -DBRPATCH_ALLOC_MALLOC.
 */
#define TAOSC_DEST 0x1234
/* Keep the plugin's private stdlib allocator distinct from the target's real
 * libc allocator: the hooks below must exercise actual Linux allocator edges. */
#define malloc fixture_plugin_malloc
#define calloc fixture_plugin_calloc
#define realloc fixture_plugin_realloc
#define free fixture_plugin_free
#include "../benchmarks/loftix/brpatch-cached.c"
#undef malloc
#undef calloc
#undef realloc
#undef free
extern void *malloc(size_t);
extern void *calloc(size_t, size_t);
extern void *realloc(void *, size_t);
extern void free(void *);
#define CHECK(condition) do { if (!(condition)) { \
	printf("observation check failed at line %d\n", __LINE__); return __LINE__; \
} } while (0)

struct fixture_node { uint64_t next; uint32_t value, padding; };
struct fixture_record {
	struct brcache_snapshot_header header;
#ifdef BRPATCH_CWE805
	struct clamp clamps[256];
#endif
	uint64_t regs[16], stack;
	uint8_t status[BROBS_STATUS_BYTES];
	uint64_t values[BROBS_COUNT];
};
_Static_assert(sizeof(struct fixture_record) == 40 + 128 + 8 + 16 + 14 * 8
#ifdef BRPATCH_CWE805
	+ 256 * 16
#endif
	, "fixture stream layout changed");

static char descriptor_env[256] = "TAOSC_PRED=p0";
static char *fixture_env[] = {descriptor_env, "PATCH_ID=1", "BRCACHE_STACK_SIZE=8", NULL};

static void *tracked_malloc(size_t size)
{
	char frame;
	brobs_alloc_enter(0, 0, size, 0, (uintptr_t)&frame);
	void *result = malloc(size);
	brobs_alloc_leave(0, (uintptr_t)result, (uintptr_t)&frame);
	return result;
}
static void *tracked_calloc(size_t n, size_t size)
{
	char frame;
	brobs_alloc_enter(1, 1, n, size, (uintptr_t)&frame);
	void *result = calloc(n, size);
	brobs_alloc_leave(1, (uintptr_t)result, (uintptr_t)&frame);
	return result;
}
static void *tracked_realloc(void *pointer, size_t size)
{
	char frame;
	brobs_alloc_enter(2, 2, (uintptr_t)pointer, size, (uintptr_t)&frame);
	void *result = realloc(pointer, size);
	brobs_alloc_leave(2, (uintptr_t)result, (uintptr_t)&frame);
	return result;
}
static void tracked_free(void *pointer)
{
	char frame;
	brobs_alloc_enter(3, 3, (uintptr_t)pointer, 0, (uintptr_t)&frame);
	free(pointer);
	brobs_alloc_leave(3, 0, (uintptr_t)&frame);
}

static int read_record(int fd, struct fixture_record *record)
{
	char *out = (char *)record;
	size_t remaining = sizeof(*record);
	while (remaining) {
		ssize_t n = read(fd, out, remaining);
		if (n <= 0) return -1;
		out += n;
		remaining -= n;
	}
	return 0;
}

static int check_descriptor(const struct STATE *state, const char *descriptor,
                            int branch, int status)
{
	CHECK(strlen(descriptor) + 12 < sizeof(descriptor_env));
	strcpy(descriptor_env + 11, descriptor);
	selected_initialized = selected_invalid = 0;
	int fds[2];
	CHECK(pipe(fds) == 0);
	cache_fd = fds[1];
	const void *result = dest(state);
	CHECK(result == (branch == 1 ? (const void *)TAOSC_DEST : NULL));
	close(fds[1]);
	struct fixture_record record;
	CHECK(read_record(fds[0], &record) == 0);
	close(fds[0]);
	cache_fd = -1;
	CHECK(record.header.magic == BRCACHE_SNAPSHOT_MAGIC);
	CHECK(record.header.version == 3 && record.header.branch == (uint32_t)branch);
	CHECK(record.header.obs_count == BROBS_COUNT);
	CHECK(record.header.obs_plan_crc32 == BROBS_PLAN_CRC32);
	CHECK(record.header.flags == (BRCACHE_FLAG_HAS_OBS
#ifdef BRPATCH_CWE805
		| BRCACHE_FLAG_CWE805
#endif
	));
	CHECK(record.status[2] == status);
	CHECK(record.status[14] == 0 && record.status[15] == 0);
	for (unsigned i = 0; i < BROBS_COUNT; ++i)
		CHECK(record.status[i] == BR_OBS_OK || record.values[i] == 0);
	return 0;
}

static int check_channel_faults(uint64_t address)
{
	for (unsigned mode = 0; mode < 4; ++mode) {
		pid_t child = fork();
		CHECK(child >= 0);
		if (!child) {
			uint64_t value = 0;
			long saved = brobs_pipe_flags[1];
			int fds[2];
			if (mode < 3 && pipe(fds)) exit(1);
			if (mode == 0) brobs_pipe[1] = fds[1]; /* forged naked fd */
			if (mode == 1) { /* closed/reused descriptor, same number */
				close(brobs_pipe[1]);
				if (dup2(fds[1], brobs_pipe[1]) < 0) exit(2);
			}
			if (mode == 2) brobs_pipe[0] = fds[0]; /* mismatched endpoint */
			if (mode == 3 && fcntl(brobs_pipe[1], 4, saved & ~O_NONBLOCK)) exit(3);
			int status = brobs_read(address, 4, &value);
			if (mode == 3 && fcntl(brobs_pipe[1], 4, saved)) exit(4);
			exit(status == BR_OBS_UNMAPPED && !brobs_channel_live ? 0 : 5);
		}
		int status;
		CHECK(waitpid(child, &status, 0) == child && status == 0);
	}
	/* A cancelled/partial predecessor cannot supply the next scalar. */
	uint64_t garbage = 0xdeadbeef, value = 0;
	CHECK(brobs_probe_syscall(SYS_write, brobs_pipe[1], (long)&garbage, 4) == 4);
	CHECK(brobs_read(address, 4, &value) == BR_OBS_OK);
	CHECK(value == (uint32_t)-7);
	uint8_t *pages = mmap(NULL, 8192, PROT_READ | PROT_WRITE,
	                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(pages != MAP_FAILED);
	CHECK(mprotect(pages + 4096, 4096, PROT_NONE) == 0);
	CHECK(brobs_read((uintptr_t)(pages + 4092), 8, &value) == BR_OBS_UNMAPPED);
	CHECK(brobs_read(address, 4, &value) == BR_OBS_OK && value == (uint32_t)-7);
	CHECK(munmap(pages, 8192) == 0);
	return 0;
}

static void *nested_allocation(unsigned depth)
{
	char frame;
	brobs_alloc_enter(0, 0, 8, 0, (uintptr_t)&frame);
	void *inner = depth ? nested_allocation(depth - 1) : NULL;
	void *result = malloc(8);
	brobs_alloc_leave(0, (uintptr_t)result, (uintptr_t)&frame);
	if (inner) tracked_free(inner);
	return result;
}

static int check_unmatched_return(void)
{
	char frame, other_frame;
	brobs_alloc_leave(0, 0, (uintptr_t)&frame);
	brobs_alloc_enter(0, 0, 8, 0, (uintptr_t)&frame);
	brobs_alloc_leave(0, 0, (uintptr_t)&other_frame);
	brobs_alloc_leave(1, 0, (uintptr_t)&frame);
	uint64_t *object = malloc(8);
	CHECK(object != NULL);
	brobs_alloc_leave(0, (uintptr_t)object, (uintptr_t)&frame);
	*object = 19;
	uint64_t value = 0;
	CHECK(brobs_hop(0, (uintptr_t)object, 0, 8, &value) == BR_OBS_OK && value == 19);
	tracked_free(object);
	return 0;
}

static int check_nesting(void)
{
	pid_t child = fork();
	CHECK(child >= 0);
	if (!child) {
		void *result = nested_allocation(BROBS_CALL_DEPTH);
		int failed = brobs_tracker_failed && !brobs_call_depth && !brobs_call_overflow;
		free(result);
		exit(failed ? 0 : 1);
	}
	int status;
	CHECK(waitpid(child, &status, 0) == child && status == 0);
	return 0;
}

static int check_capacity(void)
{
	pid_t child = fork();
	CHECK(child >= 0);
	if (!child) {
		void *objects[BROBS_OBJECT_CAPACITY + 1];
		for (unsigned i = 0; i < BROBS_OBJECT_CAPACITY + 1; ++i) {
			objects[i] = tracked_malloc(8);
			if (!objects[i]) exit(1);
		}
		uint64_t value;
		int status = brobs_hop(0, (uintptr_t)objects[0], 0, 8, &value);
		exit(brobs_tracker_failed && status == BR_OBS_UNMAPPED ? 0 : 2);
	}
	int status;
	CHECK(waitpid(child, &status, 0) == child && status == 0);
	return 0;
}

int main(void)
{
	init(0, NULL, fixture_env);
	CHECK(brobs_channel_live && brobs_validate_channel());
	uint64_t *globals = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
	                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(globals != MAP_FAILED);
	struct fixture_node *leaf = tracked_calloc(1, sizeof(*leaf));
	struct fixture_node *root = tracked_malloc(sizeof(*root));
	CHECK(leaf && root);
	leaf->value = 73;
	root->next = (uintptr_t)leaf;
	root->value = 42;
	globals[0] = (uint32_t)-7;
	globals[1] = (uintptr_t)root;
	globals[2] = UINT64_MAX;
	uint64_t stack = (uintptr_t)root;
	struct STATE state = {
		.rax = -1, .rbx = -1, .rdi = (uintptr_t)root,
		.rsi = (uintptr_t)root + 4, .rsp = (uintptr_t)&stack,
		.rip = (uintptr_t)globals + BROBS_PATCH_LOCATION,
	};
	struct brobs_capture capture;
	brobs_capture(&state, &capture);
	const uint64_t expected[BROBS_COUNT] = {
		UINT64_MAX, (uint64_t)-7, 42, 42, 42, 42, 73,
		16, 12, 1, 4, 16, UINT64_MAX, UINT32_MAX,
	};
	for (unsigned i = 0; i < BROBS_COUNT; ++i) {
		CHECK(capture.status[i] == BR_OBS_OK);
		CHECK(capture.values[i] == expected[i]);
	}
	CHECK(check_channel_faults((uintptr_t)globals) == 0);
	uint64_t value;
	CHECK(brobs_hop((uintptr_t)globals, (uintptr_t)root, -1, 1, &value) == BR_OBS_OOB);
	CHECK(brobs_hop((uintptr_t)globals, (uintptr_t)root, 16, 1, &value) == BR_OBS_OOB);

#ifdef BRPATCH_CWE805
	memset(buffers, 0, sizeof(buffers));
	buffers[255] = (struct clamp){10, 20};
	buffers[254] = (struct clamp){100, 200};
	CHECK(check_descriptor(&state, "c3Ac1o7c2o8q1", 1, BR_OBS_OK) == 0);
	buffers[255].end = 100;
	CHECK(check_descriptor(&state, "c3Ac1o7c2o8q1", 0, BR_OBS_OK) == 0);
#else
	CHECK(check_descriptor(&state, "=o2p42", 1, BR_OBS_OK) == 0);
#endif
	state.rdi = 0;
#ifdef BRPATCH_CWE805
	CHECK(check_descriptor(&state, "c3AV2c1o2", 1, BR_OBS_NULL) == 0);
	CHECK(check_descriptor(&state, "c1o2", 2, BR_OBS_NULL) == 0);
	CHECK(check_descriptor(&state, "c3OV0c1o2", 0, BR_OBS_NULL) == 0);
#else
	CHECK(check_descriptor(&state, "AV2=o2p42", 0, BR_OBS_NULL) == 0);
	CHECK(check_descriptor(&state, "=o2p42", 2, BR_OBS_NULL) == 0);
	CHECK(check_descriptor(&state, "Op1=o2p42", 1, BR_OBS_NULL) == 0);
#endif
	struct br_node nodes[BR_MAX_NODES];
	struct br_predicate predicate;
	CHECK(parse_predicate("Op1o14", &predicate, nodes, BR_MAX_NODES) < 0);
	CHECK(parse_predicate("c3OV0c1o14", &predicate, nodes, BR_MAX_NODES) < 0);
	state.rdi = 0x600000000000ULL;
	brobs_capture(&state, &capture);
	CHECK(capture.status[2] == BR_OBS_UNMAPPED && capture.values[2] == 0);
	state.rdi = (uintptr_t)root;
	CHECK(mprotect(globals, 4096, PROT_NONE) == 0);
	brobs_capture(&state, &capture);
	CHECK(capture.status[1] == BR_OBS_UNMAPPED && capture.status[3] == BR_OBS_UNMAPPED);
	CHECK(mprotect(globals, 4096, PROT_READ | PROT_WRITE) == 0);

	/* Evaluation and serialization reuse exactly the same immutable hit. */
	brobs_capture(&state, &capture);
	root->value = 99;
	CHECK(parse_predicate("=o2p42", &predicate, nodes, BR_MAX_NODES) == 0);
	int invalid = 0;
	CHECK(evaluate_predicate(&state, &predicate, &capture, &invalid) == 1 && !invalid);
	int fds[2];
	CHECK(pipe(fds) == 0);
	cache_fd = fds[1];
	capture_snapshot(&state, 3, 1, 0, &capture);
	close(fds[1]);
	struct fixture_record record;
	CHECK(read_record(fds[0], &record) == 0 && record.values[2] == 42);
	close(fds[0]);
	cache_fd = -1;

	/* A live root pointing at a retired leaf never probes freed bytes. */
	uintptr_t leaf_address = (uintptr_t)leaf;
	tracked_free(leaf);
	brobs_capture(&state, &capture);
	CHECK(capture.status[2] == BR_OBS_OK);
	CHECK(capture.status[6] == BR_OBS_FREED && capture.status[11] == BR_OBS_FREED);

	/* Real overflow/failure leave pre-existing allocations usable. */
	volatile size_t huge = SIZE_MAX;
	CHECK(tracked_calloc(huge, 2) == NULL && !brobs_tracker_failed);
	CHECK(tracked_realloc(root, huge) == NULL);
	CHECK(brobs_hop((uintptr_t)globals, (uintptr_t)root, 8, 4, &value) == BR_OBS_OK && value == 99);
	uintptr_t old_root = (uintptr_t)root;
	struct fixture_node *moved = tracked_realloc(root, 4096);
	CHECK(moved && moved->value == 99);
	if ((uintptr_t)moved != old_root)
		CHECK(brobs_hop((uintptr_t)globals, old_root, 0, 1, &value) == BR_OBS_FREED);
	root = moved;
	void *shrunk = tracked_realloc(root, 8);
	CHECK(shrunk);
	CHECK(brobs_hop((uintptr_t)globals, (uintptr_t)shrunk, 8, 1, &value) == BR_OBS_OOB);
	uintptr_t old_shrunk = (uintptr_t)shrunk;
	void *zero = tracked_realloc(shrunk, 0);
	if (zero) {
		CHECK(brobs_hop((uintptr_t)globals, (uintptr_t)zero, 0, 1, &value) == BR_OBS_OOB);
		tracked_free(zero);
	} else {
		CHECK(brobs_hop((uintptr_t)globals, old_shrunk, 0, 1, &value) == BR_OBS_FREED);
	}
	tracked_free(NULL);
	state.rdi = leaf_address;
	brobs_capture(&state, &capture);
	CHECK(capture.status[2] == BR_OBS_FREED && capture.values[2] == 0);
	CHECK(munmap(globals, 4096) == 0);
	brobs_capture(&state, &capture);
	CHECK(capture.status[1] == BR_OBS_UNMAPPED);
	CHECK(check_unmatched_return() == 0);
	CHECK(check_nesting() == 0);
	CHECK(check_capacity() == 0);
	return 0;
}
