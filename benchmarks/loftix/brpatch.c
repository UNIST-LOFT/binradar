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

/* Shared immutable execution ABI, also emitted by binradar_setup.py. */
#define BR_MAX_DESCRIPTOR_BYTES 4095u
#define BR_MAX_EXPR_DEPTH 256u
/* Every node consumes at least one descriptor byte. */
#define BR_MAX_NODES BR_MAX_DESCRIPTOR_BYTES

enum br_predicate_kind { BR_PRED_FALSE, BR_PRED_GENERIC, BR_PRED_CWE805 };
enum br_cell_kind {
	BR_CELL_REGISTER, BR_CELL_STACK8, BR_CELL_STACK16,
	BR_CELL_STACK32, BR_CELL_STACK64,
};
struct br_node {
	uint8_t op, cell_kind, scale;
	uint16_t left, right, cell_index;
	uint64_t literal;
};
struct br_predicate {
	enum br_predicate_kind kind;
	const struct br_node *nodes;
	uint16_t count, root;
	uint32_t stack_bytes;
};
struct br_parser {
	const char *cursor;
	struct br_node *nodes;
	uint16_t count, capacity;
	uint32_t stack_bytes;
};

/* Bounds are checked before arithmetic, including skipped operands. */
static int br_number(const char **cursor, uint64_t bound, uint64_t *out)
{
	const char *p = *cursor;
	uint64_t value = 0;
	if (*p < '0' || *p > '9')
		return -1;
	do {
		const unsigned digit = *p++ - '0';
		if (value > bound / 10 || (value == bound / 10 && digit > bound % 10))
			return -1;
		value = value * 10 + digit;
	} while (*p >= '0' && *p <= '9');
	*cursor = p;
	*out = value;
	return 0;
}

static int br_parse_node(struct br_parser *p, unsigned depth, int cwe,
                         uint16_t *index)
{
	if (depth > BR_MAX_EXPR_DEPTH || p->count >= p->capacity)
		return -1;
	struct br_node node = {0};
	char op = *p->cursor;
	if (!op)
		return -1;
	++p->cursor;
	uint64_t value;
	if (cwe && op == 'c') {
		char family = *p->cursor++;
		if (family != '1' && family != '2')
			return -1;
		node.op = family == '1' ? 'P' : 'S';
		char cell = *p->cursor;
		if (!cell)
			return -1;
		++p->cursor;
		if (cell == 'p') {
			if (br_number(&p->cursor, 15, &value) < 0)
				return -1;
			node.cell_index = value;
		} else if (cell == 's') {
			if (br_number(&p->cursor, 64, &value) < 0 || *p->cursor != 'i')
				return -1;
			++p->cursor;
			unsigned width = value;
			switch (width) {
			case 8: node.cell_kind = BR_CELL_STACK8; break;
			case 16: node.cell_kind = BR_CELL_STACK16; break;
			case 32: node.cell_kind = BR_CELL_STACK32; break;
			case 64: node.cell_kind = BR_CELL_STACK64; break;
			default: return -1;
			}
			if (br_number(&p->cursor, 65535, &value) < 0)
				return -1;
			node.cell_index = value;
			uint32_t extent = (value + 1) * (width / 8);
			if (extent > p->stack_bytes)
				p->stack_bytes = extent;
		} else {
			return -1;
		}
		if (node.op == 'P' && node.cell_kind != BR_CELL_REGISTER
		    && node.cell_kind != BR_CELL_STACK64)
			return -1;
		if (node.op == 'S') {
			if (node.cell_kind == BR_CELL_STACK64 || *p->cursor != 'q')
				return -1;
			++p->cursor;
			if (br_number(&p->cursor, 8, &value) < 0
			    || (value != 1 && value != 2 && value != 4 && value != 8))
				return -1;
			node.scale = value;
		}
	} else if (!cwe && (op == 'p' || op == 'n' || op == 'v')) {
		if (br_number(&p->cursor, op == 'v' ? 15 : UINT64_MAX, &value) < 0)
			return -1;
		node.op = op == 'n' ? 'p' : op;
		if (op == 'v') node.cell_index = value;
		else node.literal = op == 'n' ? 0 - value : value;
	} else {
		if (cwe ? (op != 'A' && op != 'O')
		        : (strchr("~=!><+-*/%&|^lrAO", op) == NULL))
			return -1;
		node.op = op;
		if (!cwe && (op == '>' || op == '<') && *p->cursor == '=') {
			++p->cursor;
			node.op = op == '>' ? 'G' : 'L';
		}
		if (br_parse_node(p, depth + 1, cwe, &node.left) < 0)
			return -1;
		if (op != '~' && br_parse_node(p, depth + 1, cwe, &node.right) < 0)
			return -1;
	}
	if (p->count >= p->capacity)
		return -1;
	*index = p->count;
	p->nodes[p->count++] = node;
	return 0;
}

static int parse_predicate(const char *s, struct br_predicate *out,
                           struct br_node *arena, uint16_t capacity)
{
	*out = (struct br_predicate){0};
	if (s == NULL)
		return -1;
	unsigned length = 0;
	while (length <= BR_MAX_DESCRIPTOR_BYTES && s[length]) ++length;
	if (!length || length > BR_MAX_DESCRIPTOR_BYTES)
		return -1;
	if (strcmp(s, "p0") == 0)
		return 0;
	int cwe = s[0] == 'c';
	const char *cursor = s;
	if (cwe && s[1] == '3') {
		cursor += 2;
		if (*cursor != 'A' && *cursor != 'O')
			return -1;
	}
	struct br_parser parser = {
		.cursor = cursor, .nodes = arena, .capacity = capacity,
	};
	uint16_t root;
	if (br_parse_node(&parser, 1, cwe, &root) < 0 || *parser.cursor)
		return -1;
	*out = (struct br_predicate){
		.kind = cwe ? BR_PRED_CWE805 : BR_PRED_GENERIC,
		.nodes = arena, .count = parser.count, .root = root,
		.stack_bytes = parser.stack_bytes,
	};
	return 0;
}

static int64_t br_eval_node(const struct br_predicate *pred, uint16_t index,
                           const int64_t env[16], int *crashed)
{
	if (*crashed) return 0;
	if (index >= pred->count) { *crashed = 1; return 0; }
	const struct br_node *node = &pred->nodes[index];
	if (node->op == 'p') return i64_from_bits(node->literal);
	if (node->op == 'v') {
		if (node->cell_index > 15) { *crashed = 1; return 0; }
		return env[node->cell_index];
	}
	int64_t a = br_eval_node(pred, node->left, env, crashed);
	if (*crashed) return 0;
	if (node->op == '~') return ~a;
	if (node->op == 'A' && !a) return 0;
	if (node->op == 'O' && a) return 1;
	int64_t b = br_eval_node(pred, node->right, env, crashed);
	if (*crashed) return 0;
	switch (node->op) {
	case 'A': case 'O': return b != 0;
	case '=': return a == b;
	case '!': return a != b;
	case '>': return a > b;
	case '<': return a < b;
	case 'G': return a >= b;
	case 'L': return a <= b;
	case '+': return i64_from_bits((uint64_t)a + (uint64_t)b);
	case '-': return i64_from_bits((uint64_t)a - (uint64_t)b);
	case '*': return i64_from_bits((uint64_t)a * (uint64_t)b);
	case '/': case '%':
		if (!b || (a == INT64_MIN && b == -1)) {
			*crashed = 1;
			return 0;
		}
		return node->op == '/' ? a / b : a % b;
	case '&': return a & b;
	case '|': return a | b;
	case '^': return a ^ b;
	case 'l': return shift_left(a, b);
	case 'r': return shift_right(a, b);
	default: *crashed = 1; return 0;
	}
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

/* Call only after logging/capture: zero is Taosc's exit(128) action. */
static const void *repair_action(int branch, const void *destination)
{
	if (branch != 1)
		return NULL;
	if (destination == NULL)
		exit(128);
	return destination;
}

#ifdef BRPATCH_CWE805
#if !defined(BRPATCH_ALLOC_MALLOC) && !defined(BRPATCH_ALLOC_CALLOC) \
		&& !defined(BRPATCH_ALLOC_REALLOC)
#error "BRPATCH_CWE805 requires one of BRPATCH_ALLOC_MALLOC/CALLOC/REALLOC"
#endif

/*
 * CWE-805 allocation tracker (port of utils/taosc/CWE805/common.c): the
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
	case BR_CELL_REGISTER:
		switch (index) {
		case 0: return (uint64_t)state->rax;
		case 1: return (uint64_t)state->rbx;
		case 2: return (uint64_t)state->rcx;
		case 3: return (uint64_t)state->rdx;
		case 4: return (uint64_t)state->rsi;
		case 5: return (uint64_t)state->rdi;
		case 6: return (uint64_t)state->rsp;
		case 7: return (uint64_t)state->rbp;
		case 8: return (uint64_t)state->r8;
		case 9: return (uint64_t)state->r9;
		case 10: return (uint64_t)state->r10;
		case 11: return (uint64_t)state->r11;
		case 12: return (uint64_t)state->r12;
		case 13: return (uint64_t)state->r13;
		case 14: return (uint64_t)state->r14;
		case 15: return (uint64_t)state->r15;
		}
		return 0;
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

/* Values are cached only after first visit, and only for this hit. */
static int br_cwe_node(const struct STATE *state, const struct br_predicate *pred,
                       uint16_t index, const struct clamp *clamp,
                       uint64_t *values, uint8_t *visited, int *crashed)
{
	if (*crashed) return 0;
	if (index >= pred->count) { *crashed = 1; return 0; }
	const struct br_node *node = &pred->nodes[index];
	if (node->op == 'A' || node->op == 'O') {
		int left = br_cwe_node(state, pred, node->left, clamp, values,
		                       visited, crashed);
		if (*crashed) return 0;
		if (node->op == 'A' && !left) return 0;
		if (node->op == 'O' && left) return 1;
		return br_cwe_node(state, pred, node->right, clamp, values,
		                   visited, crashed);
	}
	if (node->op != 'P' && node->op != 'S') {
		*crashed = 1;
		return 0;
	}
	if (!visited[index]) {
		if (node->cell_kind > BR_CELL_STACK64
		    || (node->cell_kind == BR_CELL_REGISTER && node->cell_index > 15)
		    || (node->op == 'P' && node->cell_kind != BR_CELL_REGISTER
		        && node->cell_kind != BR_CELL_STACK64)
		    || (node->op == 'S' && (node->cell_kind == BR_CELL_STACK64
		        || (node->scale != 1 && node->scale != 2
		            && node->scale != 4 && node->scale != 8)))) {
			*crashed = 1;
			return 0;
		}
		uint64_t value = read_cell(state, node->cell_kind, node->cell_index);
		if (node->op == 'S' && __builtin_mul_overflow(value,
		                                            node->scale, &value)) {
			*crashed = 1;
			return 0;
		}
		values[index] = value;
		visited[index] = 1;
	}
	uint64_t value = values[index];
	return node->op == 'P' ? value >= clamp->begin && value < clamp->end
	                       : value < clamp->end - clamp->begin;
}

static int CWE805_branch_taken(const struct STATE *state,
                               const struct br_predicate *pred)
{
	if (!pred->count || pred->count > BR_MAX_NODES || pred->root >= pred->count)
		return 2;
	/* Actual-node scratch only; never a maximum generic arena per hit. */
	uint64_t values[pred->count];
	uint8_t visited[pred->count];
	memset(visited, 0, sizeof(visited));
	int crashed = 0;
	for (int i = 255; i >= 0; --i) {
		int safe = br_cwe_node(state, pred, pred->root, &buffers[i],
		                       values, visited, &crashed);
		if (crashed) return 2;
		if (safe) return 0;
	}
	return 1;
}

/*
 * CWE-805 direct call-site decision: match Taosc's joob($mem0,
 * mem[0].size,dest).  A clamp accepts the complete memory access only when
 * address >= begin and address + access_size < end. Candidate id 1 repairs
 * when no clamp accepts it (zero dest exits 128); patch id 0 preserves flow.
 */
const void *jnz(uint64_t base, uint64_t index, uint8_t scale, uint32_t disp,
                uint64_t access_size, const void *dest)
{
	uint32_t v = 0;
	const uint32_t patch_id = select_patch_id(&v);
	const uint64_t address = base + index * scale + disp;
	const uint64_t access_end = address + access_size;
	int branch_taken = 0;
	if (patch_id == 1) {
		struct clamp *i = buffers + 256;
		while (i-- > buffers)
			if (address >= i->begin && access_end < i->end)
				break;
		if (i < buffers) /* no clamp matched */
			branch_taken = 1;
	}
	log_patch(patch_id, branch_taken, v);
	return repair_action(branch_taken, dest);
}
#endif /* BRPATCH_CWE805 */

static int evaluate_predicate(const struct STATE *state,
                              const struct br_predicate *pred, int *invalid)
{
	if (pred == NULL) { *invalid = 1; return 2; }
	if (pred->kind == BR_PRED_FALSE) return 0;
	if (!pred->nodes || !pred->count || pred->count > BR_MAX_NODES
	    || pred->root >= pred->count) {
		*invalid = 1;
		return 2;
	}
	if (pred->kind == BR_PRED_GENERIC) {
		int64_t env[16];
		state_to_env(state, env);
		int crashed = 0;
		int branch = br_eval_node(pred, pred->root, env, &crashed) != 0;
		return crashed ? 2 : branch;
	}
#ifdef BRPATCH_CWE805
	if (pred->kind == BR_PRED_CWE805)
		return CWE805_branch_taken(state, pred);
#endif
	*invalid = 1;
	return 2;
}

#ifndef BINRADAR_EVAL_ONLY
#include "brpatches.inc"

const void *dest(const struct STATE *state)
{
	uint32_t v = 0;
	const uint32_t patch_id = select_patch_id(&v);
	int invalid = 0;
	struct br_predicate predicate;
	get_patch_pred(patch_id, &predicate);
	const int branch_taken = evaluate_predicate(state, &predicate, &invalid);
	log_patch(patch_id, branch_taken, v);
	return repair_action(branch_taken, (const void *)TAOSC_DEST);
}
#endif
