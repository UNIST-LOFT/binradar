/* Runtime contract harness for benchmarks/loftix/brpatch-cached.c. */

#define TAOSC_DEST 0x1234
#include "../benchmarks/loftix/brpatch-cached.c"

static int forward_pipe(int fd)
{
	char buf[8192];
	for (;;) {
		const ssize_t n = read(fd, buf, sizeof(buf));
		if (n == 0)
			return 0;
		if (n < 0 || write_all(1, buf, (size_t)n) < 0)
			return -1;
	}
}

int main(void)
{
	uint8_t stack[8] = {0};
	struct STATE state = {0};
	state.rsp = (int64_t)(uintptr_t)stack;
	int fds[2];
	if (pipe(fds) < 0)
		return 1;
	patch_fd = fds[1];

#ifdef BRPATCH_CWE805
	cache_stack_size = sizeof(stack);
	memset(buffers, 0, sizeof(buffers));
	buffers[0].begin = 0x1000;
	buffers[0].end = 0x2000;

	env_patch_id = 1;
	state.rax = 0x1500;
	if (dest(&state) != NULL)
		return 2;

	env_patch_id = 2;
	state.rbx = 0x3000;
	if (dest(&state) != (const void *)TAOSC_DEST)
		return 3;
#else
	env_patch_id = 1;
	if (dest(&state) != (const void *)TAOSC_DEST)
		return 4;

	env_patch_id = 2;
	if (dest(&state) != NULL)
		return 5;
#endif

	close(fds[1]);
	const int result = forward_pipe(fds[0]);
	close(fds[0]);
	return result < 0 ? 6 : 0;
}
