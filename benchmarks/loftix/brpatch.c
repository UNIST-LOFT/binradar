/*
 * Dynamic patch
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

static const char *predicate;
#define MAGIC_VALUE_PATCH 123456
// patch_shm size is 8 bytes: patch_shm[0] is patch_id, patch_shm[1] is for index
static const uint32_t *patch_shm = NULL;
static uint32_t env_patch_id = 0;
static int patch_fd = 2;

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
	predicate = getenv("TAOSC_PRED");
	if (predicate == NULL)
		predicate = "p0"; /* false */
	
	env_patch_id = getenvul("PATCH_ID");
	uint32_t s = getenvul("PATCH_FD");
	if (s > 2) {
		patch_fd = (int)s;
	}
	if (env_patch_id != MAGIC_VALUE_PATCH) {
		return;
	}
	const key_t patch_shm_key = getenvul("BINRADAR_PATCH_SHM_KEY");
	if (patch_shm_key) {
		const int patch_shm_id = shmget(patch_shm_key, 8, 0666);
		if (patch_shm_id >= 0)
			patch_shm = shmat(patch_shm_id, NULL, 0);
	}
}

/* Parse *p as an integer. */
int64_t scani(const char **p)
{
	int64_t i = 0;
	for (; **p >= '0' && **p <= '9'; ++*p)
		i = i * 10 + **p - '0';
	return i;
}

/* Parse and evaluate *ptr in a prefix Polish notation, recursively. */
int64_t eval(const char **ptr, const int64_t *env)
{
	const char op = *(*ptr)++;
	switch (op) {
	case 'n': /* negative integer */
		return -scani(ptr);
	case 'p': /* positive integer */
		return scani(ptr);
	case 'v': /* variable look up */
		return env[scani(ptr)];
	case '~': /* bitwise not */
		return ~eval(ptr, env);
	}

	const bool eq = (**ptr == '=' && (op == '>' || op == '<'));
	*ptr += eq;

	const int64_t a = eval(ptr, env);
	const int64_t b = eval(ptr, env);

	switch (op) {
	case '=':
		return a == b;
	case '!':
		return a != b;
	case '>':
		return eq ? (a >= b) : (a > b);
	case '<':
		return eq ? (a <= b) : (a < b);
	case '+':
		return a + b;
	case '-':
		return a - b;
	case '*':
		return a * b;
	case '/':
		return a / b;
	case '%':
		return a % b;
	case '&':
		return a & b;
	case '|':
		return a | b;
	case '^':
		return a ^ b;
	case 'l': /* << */
		return a << b;
	case 'r': /* >> */
		return a >> b;
	default:
		__builtin_unreachable();
	}
}

const char *get_patch_str(int id) {
	switch (id) {
#include "brpatches.inc"
	}
}

const void *dest(const struct STATE *state)
{
	uint32_t patch_id = env_patch_id;
	uint32_t v = 0;
	if (patch_id == MAGIC_VALUE_PATCH) {
		patch_id = patch_shm ? *patch_shm : 0;
		v = patch_shm ? *(patch_shm + 1) : 0;
	}
	const char *tmp = get_patch_str(patch_id);
	int branch_taken = eval(&tmp, (const int64_t *) state) != 0;
	char buf[64];
	int n = snprintf(buf, sizeof(buf), "[patch] [id %u] [br %d] [v %u]\n", patch_id, branch_taken, v);
	write(patch_fd, buf, n);
	return branch_taken ? NULL : (const void *)TAOSC_DEST;
}
