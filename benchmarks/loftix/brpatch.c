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

static const void *destination;
static const char *predicate;

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

void init(int argc, const char *const *argv, char **envp)
{
	environ = envp;
	destination = (void *) getenvull("TAOSC_DEST");
	predicate = getenv("TAOSC_PRED");
	if (predicate == NULL)
		predicate = "p0"; /* false */
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
	}
	const bool eq = **ptr == '=';
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
	default:
		__builtin_unreachable();
	}
}

const void *dest(const struct STATE *state)
{
	const char *tmp = predicate;
	return eval(&tmp, (const int64_t *) state) ? NULL : destination;
}
