/*
 * Patch prefilter: capture the runtime STATE at the patch site.
 *
 * A sibling of brpatch.c that, instead of evaluating a predicate at the
 * patch site, dumps the 16 STATE slots (the values brpatch.c::eval can
 * reference as v0..v15) to PATCH_FD as one sbsv line per patch-site hit.
 * The captured states are later evaluated offline (fuzzolic/binradar-setup.py
 * `prefilter` subcommand) so that predicates that never branch on the POC can
 * be discarded before the expensive binradar pipeline runs.
 *
 * dest() always returns NULL: the program follows the original (buggy)
 * path, so the POC must still reach the patch site and crash as expected.
 * The TAOSC_DEST macro is not referenced but is defined at compile time
 * (-DTAOSC_DEST=0) to satisfy e9compile.
 *
 * Copyright (C) 2024-2025  Nguyễn Gia Phong
 *
 * This file is part of taosc.
 *
 * Taosc is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Taosc is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with taosc.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "stdlib.c"

static int patch_fd = 2;
#define PREFILTER_DEFAULT_MAX_HITS 65536
#define PREFILTER_DEFAULT_MAX_BYTES (8 * 1024 * 1024)
static uint64_t hit_count = 0;
static uint64_t prefilter_max_hits = PREFILTER_DEFAULT_MAX_HITS;
static uint64_t prefilter_max_bytes = PREFILTER_DEFAULT_MAX_BYTES;

/*
 * Get an environment variable and parse as a number.
 * Return 0 on error.
 */
static uint64_t getenvull(const char *name)
{
	const char *const str = getenv(name);
	if (str == NULL)
		return 0ULL;
	errno = 0;
	const uint64_t ull = strtoull(str, NULL, 0);
	if (errno)
		return 0ULL;
	return ull;
}

static uint32_t getenvul(const char *name)
{
	const char *const str = getenv(name);
	if (str == NULL)
		return 0UL;
	errno = 0;
	const uint32_t ull = strtoul(str, NULL, 0);
	if (errno)
		return 0UL;
	return ull;
}

void init(int argc, const char *const *argv, char **envp)
{
	environ = envp;
	uint32_t s = getenvul("PATCH_FD");
	if (s > 2)
		patch_fd = (int)s;
	uint64_t h = getenvull("PREFILTER_MAX_HITS");
	if (h > 0)
		prefilter_max_hits = h;
	uint64_t b = getenvull("PREFILTER_MAX_BYTES");
	if (b > 0)
		prefilter_max_bytes = b;
}

#ifdef BRPATCH_CWE805
#if !defined(BRPATCH_ALLOC_MALLOC) && !defined(BRPATCH_ALLOC_CALLOC) \
		&& !defined(BRPATCH_ALLOC_REALLOC)
#error "BRPATCH_CWE805 requires one of BRPATCH_ALLOC_MALLOC/CALLOC/REALLOC"
#endif

/*
 * CWE-805 allocation tracker (port of utils/taosc/CWE805/common.c): the
 * allocator call chain is instrumented with mark/set_size/set_base hooks
 * before the patch site, so the 256 clamps are history-dependent and
 * cannot be reconstructed from patch-site registers.
 */
static uint64_t trace;

struct clamp {
	uint64_t begin, end;
};

static struct clamp buffers[256];
static uint8_t next;

void mark(uint8_t bit)
{
	const uint64_t mask = 1ULL << bit;
	trace &= ~mask;                        /* unset bit */
	trace |= mask - 1ULL;                  /* set lower bits */
}

void set_base(uint64_t rax)
{
	if (trace == 1) {
		buffers[next].begin = rax;
		buffers[next++].end += rax;
	}
}

#ifdef BRPATCH_ALLOC_MALLOC
void set_size(uint64_t rdi, uint64_t rsi)
{
	(void)rsi;
	if (trace == 1)
		buffers[next].end = rdi;
}
#elif defined(BRPATCH_ALLOC_CALLOC)
void set_size(uint64_t rdi, uint64_t rsi)
{
	if (trace == 1)
		buffers[next].end = rdi * rsi;
}
#elif defined(BRPATCH_ALLOC_REALLOC)
void set_size(uint64_t rdi, uint64_t rsi)
{
	(void)rdi;
	if (trace == 1)
		buffers[next].end = rsi;
}
#endif

/*
 * Binary full-context snapshot record (plan §8): a versioned fixed header,
 * all 256 {begin,end} clamps, the 16 register bit patterns, then exactly
 * stack-size bytes starting at state->rsp.  Written as one length-checked
 * record under a mutex with a full-write loop so concurrent hits cannot
 * interleave records.  Total captured bytes are bounded; when the hit or
 * byte limit is reached the truncation flag is set and Python fails open
 * rather than evaluating partial history as complete evidence.
 */
#define PREFILTER_SNAPSHOT_VERSION 1
#define PREFILTER_SNAPSHOT_MAGIC 0x42525046u /* "BRPF" */

struct prefilter_snapshot_header {
	uint32_t magic;
	uint32_t version;
	uint64_t stack_size;
	uint64_t flags; /* bit 0: truncated */
};

static uint64_t captured_bytes = 0;
static int truncated = 0;
static mutex_t snapshot_mutex = MUTEX_INITIALIZER;

static void write_all(int fd, const void *buf, size_t count)
{
	const char *p = buf;
	while (count > 0) {
		ssize_t n = write(fd, p, count);
		if (n <= 0)
			return; /* pipe closed: drop the rest of the record */
		p += n;
		count -= (size_t)n;
	}
}

static void capture_snapshot(const struct STATE *state, uint64_t stack_size)
{
	if (truncated)
		return;
	const uint64_t record_size = sizeof(struct prefilter_snapshot_header)
		+ sizeof(buffers) + 16 * sizeof(uint64_t) + stack_size;
	if (hit_count >= prefilter_max_hits
			|| captured_bytes + record_size > prefilter_max_bytes) {
		/* Emit a header-only marker with the truncation flag so the
		 * offline evaluator fails open instead of treating partial
		 * history as complete evidence. */
		truncated = 1;
		struct prefilter_snapshot_header marker = {
			.magic = PREFILTER_SNAPSHOT_MAGIC,
			.version = PREFILTER_SNAPSHOT_VERSION,
			.stack_size = 0,
			.flags = 1,
		};
		write_all(patch_fd, &marker, sizeof(marker));
		return;
	}
	while (mutex_lock(&snapshot_mutex) < 0);
	struct prefilter_snapshot_header header = {
		.magic = PREFILTER_SNAPSHOT_MAGIC,
		.version = PREFILTER_SNAPSHOT_VERSION,
		.stack_size = stack_size,
		.flags = 0,
	};
	write_all(patch_fd, &header, sizeof(header));
	write_all(patch_fd, buffers, sizeof(buffers));
	const uint64_t regs[16] = {
		(uint64_t)state->rax, (uint64_t)state->rbx,
		(uint64_t)state->rcx, (uint64_t)state->rdx,
		(uint64_t)state->rsi, (uint64_t)state->rdi,
		(uint64_t)state->rsp, (uint64_t)state->rbp,
		(uint64_t)state->r8, (uint64_t)state->r9,
		(uint64_t)state->r10, (uint64_t)state->r11,
		(uint64_t)state->r12, (uint64_t)state->r13,
		(uint64_t)state->r14, (uint64_t)state->r15,
	};
	write_all(patch_fd, regs, sizeof(regs));
	write_all(patch_fd, (const void *)state->rsp, stack_size);
	captured_bytes += record_size;
	hit_count++;
	mutex_unlock(&snapshot_mutex);
}
#endif /* BRPATCH_CWE805 */

/*
 * Capture registers in taosc's Variables.RegisterEnum order so the offline
 * evaluator and brpatch.c use the same v0..v15 mapping.
 */
const void *dest(const struct STATE *state)
{
#ifdef BRPATCH_CWE805
	uint64_t stack_size = getenvull("PREFILTER_STACK_SIZE");
	if (stack_size > 0 && stack_size <= 0x100000)
		capture_snapshot(state, stack_size);
	else
#endif
	if (hit_count < prefilter_max_hits) {
		const int64_t v[] = {
			state->rax, state->rbx, state->rcx, state->rdx,
			state->rsi, state->rdi, state->rsp, state->rbp,
			state->r8, state->r9, state->r10, state->r11,
			state->r12, state->r13, state->r14, state->r15,
		};
		char buf[256];
		int n = snprintf(buf, sizeof(buf),
			"[prefilter-state] [v0 %lld] [v1 %lld] [v2 %lld] [v3 %lld] "
			"[v4 %lld] [v5 %lld] [v6 %lld] [v7 %lld] "
			"[v8 %lld] [v9 %lld] [v10 %lld] [v11 %lld] "
			"[v12 %lld] [v13 %lld] [v14 %lld] [v15 %lld]\n",
			(long long)v[0], (long long)v[1], (long long)v[2],
			(long long)v[3], (long long)v[4], (long long)v[5],
			(long long)v[6], (long long)v[7], (long long)v[8],
			(long long)v[9], (long long)v[10], (long long)v[11],
			(long long)v[12], (long long)v[13], (long long)v[14],
			(long long)v[15]);
		write(patch_fd, buf, n);
		hit_count++;
	}
	return NULL; /* keep the original buggy path */
}
