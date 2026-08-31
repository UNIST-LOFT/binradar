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
static int hit_count = 0;

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
	
	uint32_t s = getenvul("PATCH_FD");
	if (s > 2) {
		patch_fd = (int)s;
	}
}

static int64_t i64_from_bits(uint64_t bits)
{
	int64_t value;
	memcpy(&value, &bits, sizeof(value));
	return value;
}

/* Parse *p as an unsigned bit pattern. */
uint64_t scani(const char **p)
{
	uint64_t i = 0;
	for (; **p >= '0' && **p <= '9'; ++*p)
		i = i * 10 + **p - '0';
	return i;
}

static int64_t shift_right_arithmetic(int64_t value, uint64_t amount)
{
	if (amount == 0)
		return value;
	uint64_t bits = (uint64_t)value >> amount;
	if (value < 0)
		bits |= ~(uint64_t)0 << (64 - amount);
	return i64_from_bits(bits);
}

/* Match std.math.shl(i64): negative counts shift right, large counts saturate. */
static int64_t shift_left(int64_t value, int64_t amount)
{
	if (amount >= 64)
		return 0;
	if (amount <= -64)
		return value < 0 ? -1 : 0;
	if (amount >= 0)
		return i64_from_bits((uint64_t)value << (uint64_t)amount);
	return shift_right_arithmetic(value, (uint64_t)-amount);
}

/* Match std.math.shr(i64): negative counts shift left, large counts saturate. */
static int64_t shift_right(int64_t value, int64_t amount)
{
	if (amount >= 64)
		return value < 0 ? -1 : 0;
	if (amount <= -64)
		return 0;
	if (amount >= 0)
		return shift_right_arithmetic(value, (uint64_t)amount);
	return i64_from_bits((uint64_t)value << (uint64_t)-amount);
}

/* Parse and evaluate *ptr in a prefix Polish notation, recursively. */
int64_t eval(const char **ptr, const int64_t *env, int *crashed)
{
	const char op = *(*ptr)++;
	switch (op) {
	case 'n': /* negative integer */
		return i64_from_bits(0 - scani(ptr));
	case 'p': /* positive integer */
		return i64_from_bits(scani(ptr));
	case 'v': /* variable look up */
		return env[scani(ptr)];
	case '~': /* bitwise not */
		return ~eval(ptr, env, crashed);
	}

	const bool eq = (**ptr == '=' && (op == '>' || op == '<'));
	*ptr += eq;

	const int64_t a = eval(ptr, env, crashed);
	const int64_t b = eval(ptr, env, crashed);

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
		return i64_from_bits((uint64_t)a + (uint64_t)b);
	case '-':
		return i64_from_bits((uint64_t)a - (uint64_t)b);
	case '*':
		return i64_from_bits((uint64_t)a * (uint64_t)b);
	case '/':
		if (b == 0 || (a == INT64_MIN && b == -1)) {
			*crashed = 1;
			return 0;
		}
		return a / b;
	case '%':
		if (b == 0 || (a == INT64_MIN && b == -1)) {
			*crashed = 1;
			return 0;
		}
		return a % b;
	case '&':
		return a & b;
	case '|':
		return a | b;
	case '^':
		return a ^ b;
	case 'l': /* << */
		return shift_left(a, b);
	case 'r': /* >> */
		return shift_right(a, b);
	default:
		__builtin_unreachable();
	}
}

static void state_to_env(const struct STATE *state, int64_t env[16])
{
	const int64_t values[] = {
		state->rax, state->rbx, state->rcx, state->rdx,
		state->rsi, state->rdi, state->rsp, state->rbp,
		state->r8, state->r9, state->r10, state->r11,
		state->r12, state->r13, state->r14, state->r15,
	};
	memcpy(env, values, sizeof(values));
}

const void *dest(const struct STATE *state)
{
	int64_t env[16];
	state_to_env(state, env);
	int patch_crashed = 0;
	char *tmp = predicate;
	int branch_taken = eval(&tmp, env, &patch_crashed) != 0;
	if (patch_crashed) {
		/* The patch itself would crash (div/mod by zero, INT64_MIN / -1).
		 * Report `br 2` and follow the original path (no jump) so the
		 * patch is rejected downstream. */
		branch_taken = 2;
	}
	char buf[1024];
	int n = snprintf(buf, sizeof(buf),
		"[snapshot] [predicate %s] [hit-count %d] [br %d] "
		"[v0 %lld] [v1 %lld] [v2 %lld] [v3 %lld] "
		"[v4 %lld] [v5 %lld] [v6 %lld] [v7 %lld] "
		"[v8 %lld] [v9 %lld] [v10 %lld] [v11 %lld] "
		"[v12 %lld] [v13 %lld] [v14 %lld] [v15 %lld]\n",
		predicate ? predicate : "NULL", hit_count, branch_taken, 
		(long long)env[0], (long long)env[1], (long long)env[2],
		(long long)env[3], (long long)env[4], (long long)env[5],
		(long long)env[6], (long long)env[7], (long long)env[8],
		(long long)env[9], (long long)env[10], (long long)env[11],
		(long long)env[12], (long long)env[13], (long long)env[14],
		(long long)env[15]);
	write(patch_fd, buf, n);
	return branch_taken == 1 ? (const void *)TAOSC_DEST : NULL;
}
