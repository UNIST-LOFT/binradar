#define BINRADAR_EVAL_ONLY
#define TAOSC_DEST 0
#include "../benchmarks/loftix/brpatch.c"

static bool check_eval(const char *expression, const int64_t env[16],
                       int64_t expected, int expected_crash)
{
	const char *cursor = expression;
	int crashed = 0;
	const int64_t actual = eval(&cursor, env, &crashed);
	return *cursor == '\0' && actual == expected
		&& crashed == expected_crash;
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
	return 0;
}
