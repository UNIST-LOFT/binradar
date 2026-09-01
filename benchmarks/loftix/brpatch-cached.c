/*
 * Multi-predicate execution cache for BinRadar's concrete verifier.
 *
 * The verifier selects one runtime predicate with PATCH_ID.  This plugin
 * executes that predicate exactly as brpatch.c does and records every
 * pre-branch state plus the selected branch on PATCH_FD.  Python evaluates
 * the other runtime predicates over those states and reuses the process
 * result only when their complete branch vectors are identical.
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

#ifndef TAOSC_DEST
#error "TAOSC_DEST must be the patch destination address"
#endif
#ifndef BRPATCH_TOTAL_PATCHES
#error "BRPATCH_TOTAL_PATCHES must be the number of compiled predicates"
#endif

#define BRCACHE_SNAPSHOT_MAGIC 0x48435242u /* little-endian bytes "BRCH" */
#define BRCACHE_SNAPSHOT_VERSION 1u
#define BRCACHE_FLAG_TRUNCATED 1u
#define BRCACHE_FLAG_CWE805 2u
#define BRCACHE_FLAG_INVALID 4u
#define BRCACHE_DEFAULT_MAX_HITS 65536u
#define BRCACHE_DEFAULT_MAX_BYTES (8u * 1024u * 1024u)
#define BRCACHE_MAX_STACK_SIZE (1024u * 1024u)

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
static mutex_t cache_mutex = MUTEX_INITIALIZER;

void init(int argc, const char *const *argv, char **envp)
{
	brpatch_base_init(argc, argv, envp);
	if (getenvul("PATCH_FD") <= 2)
		patch_fd = -1;
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

static const char *get_cached_patch_str(uint32_t id)
{
	switch (id) {
#include "brpatches.inc"
	}
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
	(void)write_all(patch_fd, &header, sizeof(header));
}

static void capture_snapshot(const struct STATE *state, uint32_t patch_id,
                             int branch, int invalid)
{
	if (patch_fd < 0)
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

	int failed = write_all(patch_fd, &header, sizeof(header));
#ifdef BRPATCH_CWE805
	if (!failed)
		failed = write_all(patch_fd, buffers, sizeof(buffers));
#endif
	if (!failed)
		failed = write_all(patch_fd, regs, sizeof(regs));
#ifdef BRPATCH_CWE805
	if (!failed)
		failed = write_all(patch_fd, (const void *)state->rsp,
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

/* E9 action: if dest(state)@brpatch-cached goto */
const void *dest(const struct STATE *state)
{
	uint32_t ignored_iteration = 0;
	const uint32_t patch_id = select_patch_id(&ignored_iteration);
	int branch = 0;
	int invalid = patch_id == 0 || patch_id > BRPATCH_TOTAL_PATCHES;
	struct br_predicate predicate = {0};
	const char *encoded = get_cached_patch_str(patch_id);
	if (!invalid && parse_predicate(encoded, &predicate) < 0)
		invalid = 1;

	if (!invalid && predicate.kind == BR_PRED_GENERIC) {
		int64_t env[16];
		state_to_env(state, env);
		int crashed = 0;
		const char *cursor = predicate.generic_branch_expression;
		branch = eval(&cursor, env, &crashed) != 0;
		if (*cursor != '\0') {
			invalid = 1;
			branch = 0;
		} else if (crashed) {
			branch = 2;
		}
	} else if (!invalid) {
#ifdef BRPATCH_CWE805
		branch = CWE805_branch_taken(state, &predicate);
#else
		invalid = 1;
#endif
	}

	capture_snapshot(state, patch_id, branch, invalid);
	return branch == 1 ? (const void *)TAOSC_DEST : NULL;
}
