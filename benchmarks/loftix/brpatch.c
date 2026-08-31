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

/*
 * Typed predicate table (generated in brpatches.inc by
 * fuzzolic/binradar-setup.py).  Entry 0 is BR_PRED_FALSE ("p0").  Generic
 * entries are the encoded ``predicate == 0`` prefix strings; CWE-119
 * entries are compact descriptors containing only validated enum/integer
 * fields, never source text:
 *
 *   c1p<reg>          pointer predicate, register cell
 *   c1s<w>i<idx>      pointer predicate, stack cell of width w at index idx
 *   c2p<reg>q<scale>  size predicate, register cell, scale 1/2/4/8
 *   c2s<w>i<idx>q<scale>  size predicate, stack cell, scale 1/2/4/8
 */
enum br_predicate_kind {
	BR_PRED_FALSE,
	BR_PRED_GENERIC,
	BR_PRED_CWE119_POINTER,
	BR_PRED_CWE119_SIZE,
};

enum br_cell_kind {
	BR_CELL_REGISTER,
	BR_CELL_STACK8,
	BR_CELL_STACK16,
	BR_CELL_STACK32,
	BR_CELL_STACK64,
};

struct br_predicate {
	enum br_predicate_kind kind;
	enum br_cell_kind cell_kind;
	uint16_t cell_index;
	uint8_t scale;
	const char *generic_branch_expression;
};

static int parse_num(const char **p)
{
	int value = 0;
	while (**p >= '0' && **p <= '9') {
		value = value * 10 + (**p - '0');
		++*p;
	}
	return value;
}

static int parse_predicate(const char *s, struct br_predicate *out)
{
	if (s[0] == 'c') {
		if (s[1] == '1')
			out->kind = BR_PRED_CWE119_POINTER;
		else if (s[1] == '2')
			out->kind = BR_PRED_CWE119_SIZE;
		else
			return -1;
		const char *p = s + 2;
		if (*p == 'p') {
			++p;
			out->cell_kind = BR_CELL_REGISTER;
			out->cell_index = (uint16_t)parse_num(&p);
			if (out->cell_index > 15)
				return -1;
		} else if (*p == 's') {
			++p;
			const int width = parse_num(&p);
			if (*p != 'i')
				return -1;
			++p;
			switch (width) {
			case 8: out->cell_kind = BR_CELL_STACK8; break;
			case 16: out->cell_kind = BR_CELL_STACK16; break;
			case 32: out->cell_kind = BR_CELL_STACK32; break;
			case 64: out->cell_kind = BR_CELL_STACK64; break;
			default: return -1;
			}
			out->cell_index = (uint16_t)parse_num(&p);
		} else {
			return -1;
		}
		if (out->kind == BR_PRED_CWE119_POINTER
				&& out->cell_kind != BR_CELL_REGISTER
				&& out->cell_kind != BR_CELL_STACK64)
			return -1; /* pointer cells are registers or uint64_t stack */
		if (out->kind == BR_PRED_CWE119_SIZE
				&& out->cell_kind == BR_CELL_STACK64)
			return -1; /* size cells are registers or uint{8,16,32}_t */
		if (out->kind == BR_PRED_CWE119_SIZE) {
			if (*p != 'q')
				return -1;
			++p;
			out->scale = (uint8_t)parse_num(&p);
			if (out->scale != 1 && out->scale != 2
					&& out->scale != 4 && out->scale != 8)
				return -1;
		}
		return *p == '\0' ? 0 : -1;
	}
	out->kind = BR_PRED_GENERIC;
	out->cell_kind = BR_CELL_REGISTER;
	out->cell_index = 0;
	out->scale = 0;
	out->generic_branch_expression = s;
	return 0;
}

/*
 * Shared patch selection and logging (used by dest and jnz): ordinary
 * execution reads PATCH_ID; PATCH_ID=123456 reads patch id and iteration
 * from patch_shm on every call; missing shared memory falls back to id 0.
 */
static uint32_t select_patch_id(uint32_t *v_out)
{
	uint32_t patch_id = env_patch_id;
	uint32_t v = 0;
	if (patch_id == MAGIC_VALUE_PATCH) {
		patch_id = patch_shm ? *patch_shm : 0;
		v = patch_shm ? *(patch_shm + 1) : 0;
	}
	if (v_out != NULL)
		*v_out = v;
	return patch_id;
}

static void log_patch(uint32_t patch_id, int branch_taken, uint32_t v)
{
	char buf[64];
	int n = snprintf(buf, sizeof(buf),
		"[patch] [id %u] [br %d] [v %u]\n",
		patch_id, branch_taken, v);
	write(patch_fd, buf, n);
}

#ifdef BRPATCH_CWE119
#if !defined(BRPATCH_ALLOC_MALLOC) && !defined(BRPATCH_ALLOC_CALLOC) \
		&& !defined(BRPATCH_ALLOC_REALLOC)
#error "BRPATCH_CWE119 requires one of BRPATCH_ALLOC_MALLOC/CALLOC/REALLOC"
#endif

/*
 * CWE-119 allocation tracker (port of utils/taosc/cwe119/common.c): the
 * allocator call chain is instrumented with mark/set_size/set_base hooks
 * before the patch site, so the 256 clamps are history-dependent and cannot
 * be reconstructed from patch-site registers.
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

static uint64_t read_cell(const struct STATE *state,
                          enum br_cell_kind kind, uint16_t index)
{
	switch (kind) {
	case BR_CELL_REGISTER: {
		int64_t env[16];
		state_to_env(state, env);
		return (uint64_t)env[index];
	}
	case BR_CELL_STACK8:
		return ((const uint8_t *)state->rsp)[index];
	case BR_CELL_STACK16:
		return ((const uint16_t *)state->rsp)[index];
	case BR_CELL_STACK32:
		return ((const uint32_t *)state->rsp)[index];
	case BR_CELL_STACK64:
		return ((const uint64_t *)state->rsp)[index];
	}
	return 0;
}

/*
 * Evaluate one CWE-119 descriptor against the tracked clamps.
 * Returns 0 (no jump: some clamp matches), 1 (jump: no clamp matches) or
 * 2 (checked-multiply overflow: conservative no-jump, reported as br 2).
 * Zero-initialized clamps never match.
 */
static int cwe119_branch_taken(const struct STATE *state,
                               const struct br_predicate *pred)
{
	const uint64_t value = read_cell(state, pred->cell_kind,
	                                 pred->cell_index);
	struct clamp *i = buffers + 256;
	if (pred->kind == BR_PRED_CWE119_POINTER) {
		while (i-- > buffers)
			if (value >= i->begin && value < i->end)
				return 0;
		return 1;
	}
	uint64_t size;
	if (__builtin_mul_overflow(value, pred->scale, &size))
		return 2;
	while (i-- > buffers)
		if (size < i->end - i->begin)
			return 0;
	return 1;
}

/*
 * CWE-119 direct call-site decision: branch only when the computed
 * effective address lies outside every tracked clamp, and only for
 * candidate id 1.  Patch id 0 returns NULL and logs br 0.
 */
const void *jnz(uint64_t base, uint64_t index, uint8_t size, uint32_t disp,
                const void *dest)
{
	uint32_t v = 0;
	const uint32_t patch_id = select_patch_id(&v);
	const uint64_t address = base + index * size + disp;
	int branch_taken = 0;
	if (patch_id == 1) {
		struct clamp *i = buffers + 256;
		while (i-- > buffers)
			if (address >= i->begin && address < i->end)
				break;
		if (i < buffers) /* no clamp matched */
			branch_taken = 1;
	}
	log_patch(patch_id, branch_taken, v);
	return branch_taken ? dest : NULL;
}
#endif /* BRPATCH_CWE119 */

#ifndef BINRADAR_EVAL_ONLY
const char *get_patch_str(int id) {
	switch (id) {
#include "brpatches.inc"
	}
}

const void *dest(const struct STATE *state)
{
	uint32_t v = 0;
	const uint32_t patch_id = select_patch_id(&v);
	const char *tmp = get_patch_str(patch_id);
	struct br_predicate pred = {0};
	int branch_taken;
	if (parse_predicate(tmp, &pred) < 0) {
		/* Unknown descriptor: BR_PRED_FALSE, follow the original path. */
		branch_taken = 0;
	} else if (pred.kind == BR_PRED_GENERIC) {
		int64_t env[16];
		state_to_env(state, env);
		int patch_crashed = 0;
		const char *cursor = pred.generic_branch_expression;
		branch_taken = eval(&cursor, env, &patch_crashed) != 0;
		if (patch_crashed) {
			/* The patch itself would crash (div/mod by zero,
			 * INT64_MIN / -1).  Report `br 2` and follow the
			 * original path (no jump) so the patch is rejected
			 * downstream. */
			branch_taken = 2;
		}
	} else {
#ifdef BRPATCH_CWE119
		branch_taken = cwe119_branch_taken(state, &pred);
#else
		/* A CWE-119 descriptor cannot occur without the tracker. */
		branch_taken = 0;
#endif
	}
	log_patch(patch_id, branch_taken, v);
	return branch_taken == 1 ? (const void *)TAOSC_DEST : NULL;
}
#endif
