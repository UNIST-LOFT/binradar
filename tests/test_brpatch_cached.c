/*
 * Runtime contract harness for benchmarks/loftix/brpatch-cached.c.
 *
 * Compile with:
 *   cc -std=gnu11 -O2 -Wall -Wextra -Werror -Wno-unused-function \
 *     -Wno-unused-parameter -Wno-missing-field-initializers \
 *     -Wno-implicit-fallthrough \
 *     -Iutils/e9patch/examples -I<dir with brpatches.inc> \
 *     tests/test_brpatch_cached.c -o /tmp/test_brpatch_cached
 * (see tests/test_binradar_setup_cwe805.py::test_cached_runtime_captures_
 * generic_and_CWE805_states for the exact invocation).
 */

#define TAOSC_DEST 0x1234
#include "../benchmarks/loftix/brpatch-cached.c"

/*
 * Minimal setenv: one malloc'd "NAME=VALUE" entry at the tail of a local
 * environ copy.  Sufficient for this process-local harness; not a general
 * POSIX setenv implementation.
 */
static int setenv_checked(const char *name, const char *value)
{
	static char *entries[8];
	static bool initialized;
	if (!initialized) {
		initialized = true;
		environ = entries;
	}

	char *entry = malloc(strlen(name) + 1 + strlen(value) + 1);
	if (entry == NULL)
		return -1;
	strcpy(entry, name);
	strcat(entry, "=");
	strcat(entry, value);

	const size_t name_len = strlen(name);
	for (char **slot = entries; *slot != NULL; ++slot)
		if (strncmp(*slot, name, name_len) == 0
				&& (*slot)[name_len] == '=') {
			*slot = entry;
			return 0;
		}
	for (char **slot = entries; slot != entries + 8; ++slot)
		if (*slot == NULL) {
			*slot = entry;
			return 0;
		}
	return -1;
}

static int forward_pipe(int fd, int output_fd)
{
	char buf[8192];
	for (;;) {
		const ssize_t n = read(fd, buf, sizeof(buf));
		if (n == 0)
			return 0;
		if (n < 0 || write_all(output_fd, buf, (size_t)n) < 0)
			return -1;
	}
}

static int check_cached_admission(void)
{
#ifdef BRPATCH_CWE805
	const char *family_invalid = "Ap0p0";
	const char *extent_invalid = "c3Oc1p0c1s64i65535";
	const char *trap = "c2p0q8";
#else
	const char *family_invalid = "c1p0";
	const char *extent_invalid = "c3Oc1p0c1s64i65535";
	const char *trap = "A/p1p0p0";
#endif
	const char *descriptors[] = {"p0", "Op1v16", trap, family_invalid, extent_invalid};
	const int expected_branch[] = {0, 0, 2, 0, 0};
	const int expected_invalid[] = {0, 1, 0, 1, 1};
	struct STATE state = {.rax = -1};
	patch_fd = -1;
	for (unsigned i = 0; i < sizeof(descriptors) / sizeof(*descriptors); ++i) {
		int fds[2];
		if (pipe(fds) < 0 || setenv_checked("TAOSC_PRED", descriptors[i]) < 0)
			return 1;
		cache_fd = fds[1];
		selected_initialized = selected_invalid = 0;
		cache_stack_size = 0;
		if (dest(&state) != NULL)
			return 2;
		close(fds[1]);
		struct brcache_snapshot_header header;
		if (read(fds[0], &header, sizeof(header)) != (ssize_t)sizeof(header))
			return 3;
		close(fds[0]);
		if (header.branch != (uint32_t)expected_branch[i]
		    || !!(header.flags & BRCACHE_FLAG_INVALID) != expected_invalid[i])
			return 4;
	}
	cache_fd = -1;
	selected_initialized = selected_invalid = 0;
	cache_hit_count = cache_captured_bytes = 0;
	return 0;
}

int main(void)
{
	if (check_cached_admission())
		return 90;
	uint8_t stack[8] = {0};
	struct STATE state = {0};
	state.rsp = (int64_t)(uintptr_t)stack;
	int patch_fds[2], cache_fds[2];
	if (pipe(patch_fds) < 0 || pipe(cache_fds) < 0)
		return 1;
	patch_fd = patch_fds[1];
	cache_fd = cache_fds[1];

#ifdef BRPATCH_CWE805
	if (setenv_checked("TAOSC_PRED", "c1p0") < 0)
		return 2;
	cache_stack_size = 0;
	memset(buffers, 0, sizeof(buffers));
	buffers[0].begin = 0x1000;
	buffers[0].end = 0x2000;

	state.rax = 0x1500;
	if (dest(&state) != NULL)
		return 3;

	if (setenv_checked("TAOSC_PRED", "c1p1") < 0)
		return 4;
	state.rbx = 0x3000;
	selected_initialized = 0;
	if (dest(&state) != (const void *)TAOSC_DEST)
		return 5;
#else
	/* "=p1p0" is (v0 == 1); rax is 0, so the predicate is false and the
	 * original path continues. "=p0p0" is (v0 == 0), so it jumps. */
	if (setenv_checked("TAOSC_PRED", "=p1p0") < 0)
		return 6;
	if (dest(&state) != NULL)
		return 7;

	if (setenv_checked("TAOSC_PRED", "=p0p0") < 0)
		return 8;
	selected_initialized = 0;
	if (dest(&state) != (const void *)TAOSC_DEST)
		return 9;
#endif

	/* Dynamic tracer mode: the extended selector preserves the legacy id and
	 * iteration words while supplying the runtime descriptor as a string. */
	uint8_t selector_storage[
		sizeof(struct brcache_patch_selector) + 16] = {0};
	struct brcache_patch_selector *selector =
		(struct brcache_patch_selector *)selector_storage;
#ifdef BRPATCH_CWE805
	const char *dynamic_descriptor = "c1p1";
#else
	const char *dynamic_descriptor = "=p0p0";
#endif
	selector->descriptor_capacity = 16;
	cache_selector = selector;
	cache_selector_size = sizeof(selector_storage);
	env_patch_id = MAGIC_VALUE_PATCH;
	selected_initialized = 0;

	/* The instrumented call can run before the tracer reaches its entrypoint
	 * and publishes iteration 1.  Iteration 0 is an unpublished selector: it
	 * must preserve original control flow and emit no rows or snapshots. */
	if (dest(&state) != NULL)
		return 10;

	selector->patch_id = 7;
	selector->iteration = 11;
	selector->descriptor_length = strlen(dynamic_descriptor);
	strcpy(selector->descriptor, dynamic_descriptor);
	if (dest(&state) != (const void *)TAOSC_DEST)
		return 11;

	close(patch_fds[1]);
	close(cache_fds[1]);
	const int patch_result = forward_pipe(patch_fds[0], 2);
	const int cache_result = forward_pipe(cache_fds[0], 1);
	close(patch_fds[0]);
	close(cache_fds[0]);
	return patch_result < 0 || cache_result < 0 ? 12 : 0;
}