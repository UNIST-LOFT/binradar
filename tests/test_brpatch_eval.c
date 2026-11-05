#define BINRADAR_EVAL_ONLY
#define TAOSC_DEST 0
#include "../benchmarks/loftix/brpatch.c"

static bool check_eval(const char *expression, const int64_t env[16],
                       int64_t expected, int expected_crash)
{
	struct br_node nodes[BR_MAX_NODES];
	struct br_predicate pred;
	if (parse_predicate(expression, &pred, nodes, BR_MAX_NODES) < 0)
		return false;
	int crashed = 0;
	const int64_t actual = pred.kind == BR_PRED_FALSE ? 0
		: br_eval_node(&pred, pred.root, env, &crashed);
	return actual == expected && crashed == expected_crash;
}

int main(void)
{
	const struct STATE state = {
		.rax = 100, .rbx = 101, .rcx = 102, .rdx = 103,
		.rsi = 104, .rdi = 105, .rsp = 106, .rbp = 107,
		.r8 = 108, .r9 = 109, .r10 = 110, .r11 = 111,
		.r12 = 112, .r13 = 113, .r14 = 114, .r15 = 115,
	};
	int64_t env[16];
	state_to_env(&state, env);
	for (int i = 0; i < 16; i++)
		if (env[i] != 100 + i)
			return 1;

	if (!check_eval("v0", env, 100, 0)
			|| !check_eval("v15", env, 115, 0)
			|| !check_eval("n9223372036854775808", env, INT64_MIN, 0)
			|| !check_eval("+p9223372036854775807p1", env, INT64_MIN, 0)
			|| !check_eval("-n9223372036854775808p1", env, INT64_MAX, 0)
			|| !check_eval("*p9223372036854775807p2", env, -2, 0))
		return 2;

	if (!check_eval("lp1p64", env, 0, 0)
			|| !check_eval("lp8n1", env, 4, 0)
			|| !check_eval("ln1n64", env, -1, 0)
			|| !check_eval("rp1p64", env, 0, 0)
			|| !check_eval("rn1p64", env, -1, 0)
			|| !check_eval("rp1n1", env, 2, 0))
		return 3;

	if (!check_eval("/n7p3", env, -2, 0)
			|| !check_eval("%n7p3", env, -1, 0)
			|| !check_eval("/p1p0", env, 0, 1)
			|| !check_eval("%n9223372036854775808n1", env, 0, 1))
		return 4;

	if (!check_eval("=>p1p0p0", env, 0, 0)
			|| !check_eval("=<p1p0p0", env, 1, 0))
		return 5;
	if (!check_eval("Ap0/p1p0", env, 0, 0)
			|| !check_eval("On1/p1p0", env, 1, 0)
			|| !check_eval("+Ap0/p1p0p7", env, 7, 0)
			|| !check_eval("Ap2n3", env, 1, 0)
			|| !check_eval("Op0n3", env, 1, 0)
			|| !check_eval("A/p1p0p0", env, 0, 1)
			|| !check_eval("&p0/p1p0", env, 0, 1)
			|| !check_eval("|p1/p1p0", env, 0, 1))
		return 6;

	struct br_node nodes[BR_MAX_NODES];
	struct br_predicate pred;
	const char *bad[] = {"", "p", "v16", "v65536", "p18446744073709551616",
		"Ap0/p1", "Op1v16", "Ap0?", "p0p1", "~", "c3p0",
		"c1p", "c1s64i65536", "c2s64i0q1", "c2p0q256", "c3Ac1p0p0"};
	for (unsigned i = 0; i < sizeof(bad) / sizeof(*bad); ++i)
		if (parse_predicate(bad[i], &pred, nodes, BR_MAX_NODES) == 0)
			return 7;
	char deep[BR_MAX_EXPR_DEPTH + 3];
	memset(deep, '~', BR_MAX_EXPR_DEPTH - 1);
	strcpy(deep + BR_MAX_EXPR_DEPTH - 1, "p1");
	if (parse_predicate(deep, &pred, nodes, BR_MAX_NODES) < 0)
		return 8;
	memset(deep, '~', BR_MAX_EXPR_DEPTH);
	strcpy(deep + BR_MAX_EXPR_DEPTH, "p1");
	if (parse_predicate(deep, &pred, nodes, BR_MAX_NODES) == 0)
		return 9;
	char long_descriptor[BR_MAX_DESCRIPTOR_BYTES + 2];
	memset(long_descriptor, '1', sizeof(long_descriptor) - 1);
	long_descriptor[0] = 'p';
	long_descriptor[sizeof(long_descriptor) - 1] = 0;
	if (parse_predicate(long_descriptor, &pred, nodes, BR_MAX_NODES) == 0)
		return 10;
	return 0;
}
