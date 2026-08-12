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
#define PREFILTER_MAX_HITS 65536
static uint64_t hit_count = 0;

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
}

/*
 * Capture the patch-site STATE. The struct STATE layout (see
 * utils/e9patch/examples/stdlib.c) is: slot 0 = flags, slot 1 = r15,
 * slot 2 = r14, ..., slot 15 = rax.  brpatch.c::eval reads the same
 * slots as ((const int64_t *)state)[i] for v{i}, so we dump them
 * verbatim -- no remapping.
 */
const void *dest(const struct STATE *state)
{
	if (hit_count < PREFILTER_MAX_HITS) {
		const int64_t *v = (const int64_t *) state;
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
