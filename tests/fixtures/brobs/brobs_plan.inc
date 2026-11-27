/* Fixed generated-plan fixture; the C harness provides an image-relative page. */
#define BROBS_COUNT 14
#define BROBS_PLAN_CRC32 0x12345678u
#define BROBS_PLAN_SHA256 "1111111111111111111111111111111111111111111111111111111111111111"
#define BROBS_PATCH_LOCATION 0x1000ull
#define BROBS_GLOBAL_BEGIN 0ull
#define BROBS_GLOBAL_END 128ull
#define BROBS_STACK_SIZE 8ull
#define BROBS_ALLOC_SITE_COUNT 4
static const uint64_t brobs_alloc_sites[4] = {0x1010, 0x1020, 0x1030, 0x1040};
static const struct brobs_slot brobs_slots[BROBS_COUNT] = {
	{.kind=0,.width=1,.is_signed=1,.root_index=0},
	{.kind=1,.width=4,.is_signed=1,.root_rva=0},
	{.kind=2,.root_kind=0,.width=4,.depth=1,.root_index=5,.offsets={8}},
	{.kind=2,.root_kind=2,.width=4,.depth=1,.root_rva=8,.offsets={8}},
	{.kind=2,.root_kind=1,.width=4,.depth=1,.root_rva=0,.offsets={8}},
	{.kind=2,.root_kind=3,.width=4,.depth=1,.root_index=0,.offsets={8}},
	{.kind=2,.root_kind=0,.width=4,.depth=2,.root_index=5,.offsets={0,8}},
	{.kind=3,.root_kind=0,.width=8,.root_index=5,.meta_op=0},
	{.kind=3,.root_kind=0,.width=8,.root_index=4,.meta_op=1},
	{.kind=3,.root_kind=0,.width=8,.root_index=5,.meta_op=2},
	{.kind=3,.root_kind=0,.width=8,.root_index=4,.meta_op=3},
	{.kind=3,.root_kind=0,.width=8,.depth=1,.root_index=5,.meta_op=0,.offsets={0}},
	{.kind=1,.width=8,.root_rva=16},
	{.kind=0,.width=4,.root_index=1},
};
