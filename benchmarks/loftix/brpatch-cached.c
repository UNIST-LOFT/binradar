/*
 * Multi-predicate execution cache for BinRadar's concrete verifier.
 *
 * The concrete verifier selects one runtime predicate per process through
 * TAOSC_PRED.  The BinRadar tracer selects a runtime id and descriptor through
 * the extended BINRADAR_PATCH_SHM_KEY segment when PATCH_ID=123456.  Both modes
 * execute the predicate exactly as brpatch.c does, write the ordinary text
 * patch row on PATCH_FD, and record every pre-branch state plus the selected
 * branch on the separate binary PATCH_CACHED_FD channel.  Other predicates
 * may reuse the process result only when their complete branch vectors match.
 *
 * Generic ERM records contain the 16 register slots.  BRPATCH_CWE805 builds
 * also contain the 256 allocation clamps and BRCACHE_STACK_SIZE bytes from
 * state->rsp, populated by the same mark/set_size/set_base instrumentation as
 * the final .brpatched artifact.
 */

#define BINRADAR_EVAL_ONLY
#define init brpatch_base_init
#include "brpatch.c"
#undef init

/* e9patch's freestanding stdlib only forward-declares shmid_ds.  BinRadar's
 * patch runtime is x86-64 Linux; this layout matches its ipc64 ABI and lets
 * init verify the actual segment extent before reading the flexible payload. */
#ifndef IPC_STAT
#define IPC_STAT 2
#endif
struct shmid_ds {
	uint8_t shm_perm[48];
	size_t shm_segsz;
	uint8_t remainder[56];
};
_Static_assert(sizeof(struct shmid_ds) == 112,
	"unexpected x86-64 Linux shmid_ds layout");

#ifndef TAOSC_DEST
#error "TAOSC_DEST must be the patch destination address"
#endif

#define BRCACHE_SNAPSHOT_MAGIC 0x48435242u /* little-endian bytes "BRCH" */
#define BRCACHE_SNAPSHOT_VERSION 1u
#define BRCACHE_FLAG_TRUNCATED 1u
#define BRCACHE_FLAG_CWE805 2u
#define BRCACHE_FLAG_INVALID 4u
#define BRCACHE_DEFAULT_MAX_HITS 65536u
#define BRCACHE_DEFAULT_MAX_BYTES (8u * 1024u * 1024u)
#define BRCACHE_MAX_STACK_SIZE (1024u * 1024u)

/* The first two words are the legacy brpatch.c patch-id/iteration ABI. */
struct brcache_patch_selector {
	uint32_t patch_id;
	uint32_t iteration;
	uint32_t descriptor_length;
	uint32_t descriptor_capacity;
	char descriptor[];
};

_Static_assert(offsetof(struct brcache_patch_selector, descriptor) == 16,
	"cached selector header layout changed");

struct brcache_snapshot_header {
	uint32_t magic;
	uint32_t version;
	uint32_t patch_id;
	uint32_t branch;
	uint64_t stack_size;
	uint64_t flags;
};

_Static_assert(sizeof(struct brcache_snapshot_header) == 32,
	"cached snapshot header layout changed");

static uint64_t cache_stack_size;
static uint64_t cache_max_hits = BRCACHE_DEFAULT_MAX_HITS;
static uint64_t cache_max_bytes = BRCACHE_DEFAULT_MAX_BYTES;
static uint64_t cache_hit_count;
static uint64_t cache_captured_bytes;
static int cache_truncated;
static int cache_fd = -1;
static const struct brcache_patch_selector *cache_selector;
static size_t cache_selector_size;
static mutex_t cache_mutex = MUTEX_INITIALIZER;

static void attach_cache_selector(void)
{
	if (env_patch_id != MAGIC_VALUE_PATCH || patch_shm == NULL)
		return;
	const key_t key = (key_t)getenvul("BINRADAR_PATCH_SHM_KEY");
	if (!key)
		return;
	const int shmid = shmget(key, 1, 0666);
	if (shmid < 0)
		return;
	struct shmid_ds info;
	if (shmctl(shmid, IPC_STAT, &info) < 0
			|| info.shm_segsz < sizeof(struct brcache_patch_selector))
		return;
	cache_selector = (const struct brcache_patch_selector *)patch_shm;
	cache_selector_size = info.shm_segsz;
}

void init(int argc, const char *const *argv, char **envp)
{
	brpatch_base_init(argc, argv, envp);
	if (getenvul("PATCH_FD") <= 2)
		patch_fd = -1;
	const uint32_t fd = getenvul("PATCH_CACHED_FD");
	if (fd > 2)
		cache_fd = (int)fd;
	attach_cache_selector();
	const uint64_t stack_size = getenvull("BRCACHE_STACK_SIZE");
	if (stack_size <= BRCACHE_MAX_STACK_SIZE)
		cache_stack_size = stack_size;
	const uint64_t max_hits = getenvull("BRCACHE_MAX_HITS");
	if (max_hits > 0)
		cache_max_hits = max_hits;
	const uint64_t max_bytes = getenvull("BRCACHE_MAX_BYTES");
	if (max_bytes > 0)
		cache_max_bytes = max_bytes;
}

static int write_all(int fd, const void *buf, size_t count)
{
	const char *p = buf;
	while (count > 0) {
		const ssize_t n = write(fd, p, count);
		if (n <= 0)
			return -1;
		p += n;
		count -= (size_t)n;
	}
	return 0;
}

static void write_marker(uint32_t patch_id, int branch, uint64_t flags)
{
	const struct brcache_snapshot_header header = {
		.magic = BRCACHE_SNAPSHOT_MAGIC,
		.version = BRCACHE_SNAPSHOT_VERSION,
		.patch_id = patch_id,
		.branch = (uint32_t)branch,
		.stack_size = 0,
		.flags = flags,
	};
	(void)write_all(cache_fd, &header, sizeof(header));
}

static void capture_snapshot(const struct STATE *state, uint32_t patch_id,
                             int branch, int invalid)
{
	if (cache_fd < 0)
		return;
	while (mutex_lock(&cache_mutex) < 0);
	if (cache_truncated) {
		mutex_unlock(&cache_mutex);
		return;
	}

	uint64_t flags = 0;
#ifdef BRPATCH_CWE805
	flags |= BRCACHE_FLAG_CWE805;
	if (cache_stack_size == 0)
		invalid = 1;
#endif
	if (invalid) {
		write_marker(patch_id, branch, flags | BRCACHE_FLAG_INVALID);
		mutex_unlock(&cache_mutex);
		return;
	}

	uint64_t record_size = sizeof(struct brcache_snapshot_header)
		+ 16 * sizeof(uint64_t);
#ifdef BRPATCH_CWE805
	record_size += sizeof(buffers) + cache_stack_size;
#endif
	if (cache_hit_count >= cache_max_hits
			|| record_size > cache_max_bytes -
				(cache_captured_bytes <= cache_max_bytes
				 ? cache_captured_bytes : cache_max_bytes)) {
		cache_truncated = 1;
		write_marker(patch_id, branch, flags | BRCACHE_FLAG_TRUNCATED);
		mutex_unlock(&cache_mutex);
		return;
	}

	const struct brcache_snapshot_header header = {
		.magic = BRCACHE_SNAPSHOT_MAGIC,
		.version = BRCACHE_SNAPSHOT_VERSION,
		.patch_id = patch_id,
		.branch = (uint32_t)branch,
#ifdef BRPATCH_CWE805
		.stack_size = cache_stack_size,
#else
		.stack_size = 0,
#endif
		.flags = flags,
	};
	int64_t signed_regs[16];
	uint64_t regs[16];
	state_to_env(state, signed_regs);
	memcpy(regs, signed_regs, sizeof(regs));

	int failed = write_all(cache_fd, &header, sizeof(header));
#ifdef BRPATCH_CWE805
	if (!failed)
		failed = write_all(cache_fd, buffers, sizeof(buffers));
#endif
	if (!failed)
		failed = write_all(cache_fd, regs, sizeof(regs));
#ifdef BRPATCH_CWE805
	if (!failed)
		failed = write_all(cache_fd, (const void *)state->rsp,
		                   cache_stack_size);
#endif
	if (failed) {
		cache_truncated = 1;
	} else {
		cache_captured_bytes += record_size;
		cache_hit_count++;
	}
	mutex_unlock(&cache_mutex);
}

static const char *select_descriptor(uint32_t *patch_id,
                                     uint32_t *iteration, int *invalid)
{
	*patch_id = env_patch_id;
	*iteration = 0;
	if (env_patch_id != MAGIC_VALUE_PATCH)
		return getenv("TAOSC_PRED");

	if (cache_selector == NULL) {
		*patch_id = 0;
		*invalid = 1;
		return NULL;
	}
	*patch_id = cache_selector->patch_id;
	*iteration = cache_selector->iteration;
	const uint32_t length = cache_selector->descriptor_length;
	const uint32_t capacity = cache_selector->descriptor_capacity;
	const size_t header_size = offsetof(struct brcache_patch_selector,
	                                    descriptor);
	if (capacity == 0 || capacity > cache_selector_size - header_size
			|| length >= capacity
			|| cache_selector->descriptor[length] != '\0'
			|| memchr(cache_selector->descriptor, '\0', length) != NULL) {
		*invalid = 1;
		return NULL;
	}
	return cache_selector->descriptor;
}

static int evaluate_selected(const struct STATE *state, const char *encoded,
                             int *invalid)
{
	struct br_predicate predicate = {0};
	if (encoded == NULL || parse_predicate(encoded, &predicate) < 0) {
		*invalid = 1;
		return 0;
	}
	if (predicate.kind == BR_PRED_GENERIC) {
		int64_t env[16];
		state_to_env(state, env);
		int crashed = 0;
		const char *cursor = predicate.generic_branch_expression;
		const int branch = eval(&cursor, env, &crashed) != 0;
		if (*cursor != '\0') {
			*invalid = 1;
			return 0;
		}
		return crashed ? 2 : branch;
	}
#ifdef BRPATCH_CWE805
	return CWE805_branch_taken(state, &predicate);
#else
	*invalid = 1;
	return 0;
#endif
}

/* E9 action: if dest(state)@brpatch-cached goto */
const void *dest(const struct STATE *state)
{
	int invalid = 0;
	uint32_t patch_id;
	uint32_t iteration;
	const char *encoded = select_descriptor(&patch_id, &iteration, &invalid);
	const int branch = invalid ? 0
		: evaluate_selected(state, encoded, &invalid);

	log_patch(patch_id, branch, iteration);
	capture_snapshot(state, patch_id, branch, invalid);
	return branch == 1 ? (const void *)TAOSC_DEST : NULL;
}
