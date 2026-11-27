/* Shared, allocation-free observation runtime for both E9 patch plugins. */
#ifndef BINRADAR_BR_OBSERVATION_H
#define BINRADAR_BR_OBSERVATION_H

enum brobs_status { BR_OBS_OK, BR_OBS_NULL, BR_OBS_UNMAPPED, BR_OBS_FREED, BR_OBS_OOB };
enum brobs_kind { BROBS_REG, BROBS_GLOBAL, BROBS_DEREF_CHAIN, BROBS_HEAP_META };
enum brobs_root { BROBS_ROOT_REG, BROBS_ROOT_STACK, BROBS_ROOT_GLOBAL, BROBS_ROOT_ALLOC_SITE };
enum brobs_meta { BROBS_OBJ_SIZE, BROBS_OBJ_REMAINING, BROBS_IS_LIVE, BROBS_OBJ_OFFSET };
struct brobs_slot {
	uint8_t kind, root_kind, width, is_signed, depth, meta_op;
	uint16_t root_index;
	uint64_t root_rva;
	int32_t offsets[4];
};

/* Setup emits this even for the canonical empty plan. */
#include "brobs_plan.inc"
_Static_assert(BROBS_COUNT <= 64, "too many observation slots");
#define BROBS_STATUS_BYTES ((BROBS_COUNT + 7u) & ~7u)
struct brobs_capture {
#if BROBS_COUNT > 0
	uint8_t status[BROBS_STATUS_BYTES];
	uint64_t values[BROBS_COUNT];
#endif
};

#if BROBS_COUNT > 0
/* SysV args: nr,rdi,rsi,rdx. Raw Linux result (-errno on failure).
 * The unique legal eight-byte NOP marks the syscall PC at marker+8.
 * No ambient-FD or broad E9 authorization is used. */
extern long brobs_probe_syscall(long, long, long, long);
__asm__(".text\n.globl brobs_probe_syscall\n.hidden brobs_probe_syscall\n"
	".type brobs_probe_syscall,@function\nbrobs_probe_syscall:\n"
	"mov %rdi,%rax\nmov %rsi,%rdi\nmov %rdx,%rsi\nmov %rcx,%rdx\n"
	".byte 0x0f,0x1f,0x84,0x00,0x42,0x52,0x4f,0x42\n"
	"syscall\nret\n.size brobs_probe_syscall,.-brobs_probe_syscall\n");
#define BROBS_F_GETFD 1
#define BROBS_F_GETFL 3
#define BROBS_FD_CLOEXEC 1
#define BROBS_OBJECT_CAPACITY 4096u
#define BROBS_CALL_DEPTH 32u
struct brobs_object {
	uint64_t begin, size, extent;
	uint32_t site;
	uint8_t state; /* 0 empty, 1 live, 2 freed; no tombstone eviction. */
};
struct brobs_call {
	uint64_t old, size, stack_pointer;
	uint32_t site, kind;
	uint8_t invalid;
};
static struct brobs_object brobs_objects[BROBS_OBJECT_CAPACITY];
static struct brobs_call brobs_calls[BROBS_CALL_DEPTH];
static uint64_t brobs_last[BROBS_ALLOC_SITE_COUNT ? BROBS_ALLOC_SITE_COUNT : 1];
static unsigned brobs_call_depth, brobs_call_overflow;
static int brobs_tracker_failed;
static int brobs_pipe[2] = {-1, -1};
static struct stat brobs_pipe_identity;
static long brobs_pipe_flags[2];
static int brobs_channel_live, brobs_init_attempted;
static mutex_t brobs_mutex = MUTEX_INITIALIZER;

static void brobs_lock(void)
{
	while (mutex_lock(&brobs_mutex) < 0);
}

static struct brobs_object *brobs_exact(uint64_t begin)
{
	unsigned bucket = (unsigned)((begin >> 4) ^ (begin >> 20)) & (BROBS_OBJECT_CAPACITY - 1);
	for (unsigned n = 0; n < BROBS_OBJECT_CAPACITY; ++n) {
		struct brobs_object *object = &brobs_objects[(bucket + n) & (BROBS_OBJECT_CAPACITY - 1)];
		if (!object->state || object->begin == begin) return object;
	}
	return NULL;
}

static int brobs_site_valid(uint32_t site)
{
#if BROBS_ALLOC_SITE_COUNT > 0
	return site < BROBS_ALLOC_SITE_COUNT;
#else
	(void)site;
	return 0;
#endif
}

static void brobs_retire(uint64_t begin)
{
	if (!begin) return;
	struct brobs_object *object = brobs_exact(begin);
	if (object && object->state) object->state = 2;
}

/* Supported execution model: single guest thread, bounded nested calls.
 * Lost capacity/nesting poisons tracking, never evicts lifetime evidence. */
void brobs_alloc_enter(uint32_t site, uint32_t kind, uint64_t rdi, uint64_t rsi,
                       uint64_t stack_pointer)
{
	brobs_lock();
	if (brobs_call_depth == BROBS_CALL_DEPTH || brobs_call_overflow) {
		++brobs_call_overflow;
		brobs_tracker_failed = 1;
		mutex_unlock(&brobs_mutex);
		return;
	}
	struct brobs_call call = {.site = site, .kind = kind, .stack_pointer = stack_pointer};
	call.invalid = !brobs_site_valid(site) || kind > 3;
	switch (kind) {
	case 0: call.size = rdi; break;
	case 1: call.invalid |= __builtin_mul_overflow(rdi, rsi, &call.size); break;
	case 2: call.old = rdi; call.size = rsi; break;
	case 3: brobs_retire(rdi); break;
	}
	brobs_calls[brobs_call_depth++] = call;
	if (!brobs_site_valid(site) || kind > 3) brobs_tracker_failed = 1;
	mutex_unlock(&brobs_mutex);
}

void brobs_alloc_leave(uint32_t site, uint64_t rax, uint64_t stack_pointer)
{
	brobs_lock();
	if (brobs_call_overflow) {
		--brobs_call_overflow;
		mutex_unlock(&brobs_mutex);
		return;
	}
	/* A return PC can also be a branch join that skipped this call. Match
	 * both the call site and its original SP, including recursive frames. */
	if (!brobs_call_depth || brobs_calls[brobs_call_depth - 1].site != site
	    || brobs_calls[brobs_call_depth - 1].stack_pointer != stack_pointer) {
		mutex_unlock(&brobs_mutex);
		return;
	}
	const struct brobs_call call = brobs_calls[--brobs_call_depth];
	if (call.invalid || call.kind == 3) goto done;
	/* Linux/glibc realloc(p,0) retires p on NULL too. Positive-size failure
	 * preserves the old object, prefix and last successful site pointer. */
	if (call.kind == 2 && (rax || !call.size)) brobs_retire(call.old);
	if (!rax) goto done;
	if (rax > UINT64_MAX - call.size) {
		brobs_tracker_failed = 1;
		goto done;
	}
	struct brobs_object *object = brobs_exact(rax);
	if (!object) {
		brobs_tracker_failed = 1;
		goto done;
	}
	uint64_t extent = call.size;
	/* Retain an in-place shrink's previous extent as OOB evidence. */
	if (call.kind == 2 && call.old == rax && object->state && object->extent > extent)
		extent = object->extent;
	*object = (struct brobs_object){rax, call.size, extent, call.site, 1};
	brobs_last[call.site] = rax;
 done:
	mutex_unlock(&brobs_mutex);
}

static int brobs_validate_channel(void)
{
	if (!brobs_channel_live) return 0;
	for (unsigned i = 0; i < 2; ++i) {
		struct stat info;
		long flags = brobs_probe_syscall(SYS_fcntl, brobs_pipe[i], BROBS_F_GETFL, 0);
		long fdflags = brobs_probe_syscall(SYS_fcntl, brobs_pipe[i], BROBS_F_GETFD, 0);
		if (flags != brobs_pipe_flags[i] || fdflags != BROBS_FD_CLOEXEC
		    || brobs_probe_syscall(SYS_fstat, brobs_pipe[i], (long)&info, 0) != 0
		    || (info.st_mode & S_IFMT) != S_IFIFO
		    || info.st_dev != brobs_pipe_identity.st_dev
		    || info.st_ino != brobs_pipe_identity.st_ino
		    || info.st_rdev != brobs_pipe_identity.st_rdev) {
			brobs_channel_live = 0;
			return 0;
		}
	}
	return 1;
}

/* Bounded drain; the tracer also drains before fork and after child reap. */
static int brobs_drain(void)
{
	uint64_t discard;
	for (unsigned n = 0; n < 8193; ++n) {
		long got = brobs_probe_syscall(SYS_read, brobs_pipe[0], (long)&discard, 8);
		if (got == -EAGAIN) return 1;
		if (got <= 0) break;
	}
	brobs_channel_live = 0;
	return 0;
}

static void brobs_init(void)
{
	if (brobs_init_attempted) return;
	brobs_init_attempted = 1;
	if (brobs_probe_syscall(SYS_pipe2, (long)brobs_pipe, O_NONBLOCK | O_CLOEXEC, 0)) return;
	struct stat other;
	if (brobs_probe_syscall(SYS_fstat, brobs_pipe[0], (long)&brobs_pipe_identity, 0)
	    || brobs_probe_syscall(SYS_fstat, brobs_pipe[1], (long)&other, 0)) return;
	if ((brobs_pipe_identity.st_mode & S_IFMT) != S_IFIFO
	    || (other.st_mode & S_IFMT) != S_IFIFO
	    || other.st_dev != brobs_pipe_identity.st_dev
	    || other.st_ino != brobs_pipe_identity.st_ino) return;
	for (unsigned i = 0; i < 2; ++i) {
		long flags = brobs_probe_syscall(SYS_fcntl, brobs_pipe[i], BROBS_F_GETFL, 0);
		if (flags < 0 || !(flags & O_NONBLOCK)
		    || (flags & O_ACCMODE) != (i ? O_WRONLY : O_RDONLY)) return;
		brobs_pipe_flags[i] = flags;
	}
	brobs_channel_live = 1;
	(void)brobs_validate_channel();
}

static uint64_t brobs_register(const struct STATE *state, unsigned index)
{
	switch (index) {
	case 0: return state->rax; case 1: return state->rbx;
	case 2: return state->rcx; case 3: return state->rdx;
	case 4: return state->rsi; case 5: return state->rdi;
	case 6: return state->rsp; case 7: return state->rbp;
	case 8: return state->r8; case 9: return state->r9;
	case 10: return state->r10; case 11: return state->r11;
	case 12: return state->r12; case 13: return state->r13;
	case 14: return state->r14; case 15: return state->r15;
	default: return 0;
	}
}

static int brobs_address(uint64_t address, size_t width)
{
	if (address < 0x10000) return BR_OBS_NULL;
	if (address >= 0x0000800000000000ULL || width > 0x0000800000000000ULL - address)
		return BR_OBS_UNMAPPED;
	return BR_OBS_OK;
}

static int brobs_add(uint64_t base, int64_t offset, uint64_t *out)
{
	if (offset >= 0) {
		if (base > UINT64_MAX - (uint64_t)offset) return BR_OBS_UNMAPPED;
		*out = base + (uint64_t)offset;
	} else {
		uint64_t distance = 0 - (uint64_t)offset;
		if (base < distance) return BR_OBS_UNMAPPED;
		*out = base - distance;
	}
	return BR_OBS_OK;
}

static struct brobs_object *brobs_containing(uint64_t address)
{
	struct brobs_object *exact = brobs_exact(address);
	if (exact && exact->state == 1) return exact;
	struct brobs_object *retired = exact && exact->state ? exact : NULL;
	for (unsigned i = 0; i < BROBS_OBJECT_CAPACITY; ++i) {
		struct brobs_object *object = &brobs_objects[i];
		if (!object->state || address < object->begin || address - object->begin > object->extent)
			continue;
		/* Live reused/split allocations supersede old overlapping tombstones. */
		if (object->state == 1 && address - object->begin < object->size) return object;
		retired = object;
	}
	return retired;
}

static int brobs_object_range(const struct brobs_object *object, uint64_t address, size_t width)
{
	if (object->state == 2) return BR_OBS_FREED;
	if (address < object->begin || address - object->begin > object->size
	    || width > object->size - (address - object->begin)) return BR_OBS_OOB;
	return BR_OBS_OK;
}

static int brobs_global_range(uint64_t bias, uint64_t address, size_t width)
{
	if (bias > UINT64_MAX - BROBS_GLOBAL_END) return 0;
	uint64_t begin = bias + BROBS_GLOBAL_BEGIN, end = bias + BROBS_GLOBAL_END;
	return address >= begin && address <= end && width <= end - address;
}

/* All actual loads use the kernel, including ELF globals and stack roots. */
static int brobs_read(uint64_t address, unsigned width, uint64_t *value)
{
	int status = brobs_address(address, width);
	if (status) return status;
	if (!brobs_validate_channel() || !brobs_drain()) return BR_OBS_UNMAPPED;
	long sent = brobs_probe_syscall(SYS_write, brobs_pipe[1], (long)address, width);
	if (sent != (long)width) {
		(void)brobs_drain();
		return BR_OBS_UNMAPPED;
	}
	uint64_t bits = 0;
	long got = brobs_probe_syscall(SYS_read, brobs_pipe[0], (long)&bits, width);
	if (got != (long)width) {
		(void)brobs_drain();
		brobs_channel_live = 0;
		return BR_OBS_UNMAPPED;
	}
	*value = bits;
	return BR_OBS_OK;
}

static int brobs_checked_read(uint64_t bias, uint64_t address, unsigned width, uint64_t *value)
{
	int status = brobs_address(address, width);
	if (status) return status;
	if (!brobs_global_range(bias, address, width)) {
		if (brobs_tracker_failed || brobs_call_depth || brobs_call_overflow)
			return BR_OBS_UNMAPPED;
		struct brobs_object *object = brobs_containing(address);
		if (!object) return BR_OBS_UNMAPPED;
		status = brobs_object_range(object, address, width);
		if (status) return status;
	}
	return brobs_read(address, width, value);
}

static int brobs_root_pointer(const struct STATE *state, uint64_t bias,
                              const struct brobs_slot *slot, uint64_t *out)
{
	uint64_t address;
	switch (slot->root_kind) {
	case BROBS_ROOT_REG:
		if (slot->root_index > 15) return BR_OBS_UNMAPPED;
		*out = brobs_register(state, slot->root_index);
		return BR_OBS_OK;
	case BROBS_ROOT_STACK:
		if (slot->root_rva > BROBS_STACK_SIZE || 8 > BROBS_STACK_SIZE - slot->root_rva
		    || (uint64_t)state->rsp > UINT64_MAX - slot->root_rva) return BR_OBS_OOB;
		return brobs_read((uint64_t)state->rsp + slot->root_rva, 8, out);
	case BROBS_ROOT_GLOBAL:
		if (bias > UINT64_MAX - slot->root_rva) return BR_OBS_UNMAPPED;
		address = bias + slot->root_rva;
		if (!brobs_global_range(bias, address, 8)) return BR_OBS_OOB;
		return brobs_read(address, 8, out);
	case BROBS_ROOT_ALLOC_SITE:
		if (!brobs_site_valid(slot->root_index) || brobs_tracker_failed)
			return BR_OBS_UNMAPPED;
		*out = brobs_last[slot->root_index];
		return BR_OBS_OK;
	default: return BR_OBS_UNMAPPED;
	}
}

static int brobs_hop(uint64_t bias, uint64_t base, int32_t offset, unsigned width, uint64_t *out)
{
	int status = brobs_address(base, 1);
	if (status) return status;
	uint64_t address;
	if (brobs_add(base, offset, &address)) return BR_OBS_UNMAPPED;
	/* Preserve the source object's bounds across negative prefix offsets. */
	struct brobs_object *object = brobs_containing(base);
	if (object) {
		if (brobs_tracker_failed || brobs_call_depth || brobs_call_overflow)
			return BR_OBS_UNMAPPED;
		status = brobs_object_range(object, address, width);
		if (status) return status;
		return brobs_read(address, width, out);
	}
	return brobs_checked_read(bias, address, width, out);
}

static int brobs_slot_value(const struct STATE *state, uint64_t bias,
                            const struct brobs_slot *slot, uint64_t *out)
{
	if ((slot->width != 1 && slot->width != 2 && slot->width != 4 && slot->width != 8)
	    || slot->is_signed > 1 || slot->depth > 4) return BR_OBS_UNMAPPED;
	uint64_t value = 0;
	int status;
	if (slot->kind == BROBS_REG) {
		if (slot->root_index > 15) return BR_OBS_UNMAPPED;
		value = brobs_register(state, slot->root_index);
	} else if (slot->kind == BROBS_GLOBAL) {
		if (bias > UINT64_MAX - slot->root_rva) return BR_OBS_UNMAPPED;
		uint64_t address = bias + slot->root_rva;
		if (!brobs_global_range(bias, address, slot->width)) return BR_OBS_OOB;
		status = brobs_read(address, slot->width, &value);
		if (status) return status;
	} else {
		if (slot->kind != BROBS_DEREF_CHAIN && slot->kind != BROBS_HEAP_META)
			return BR_OBS_UNMAPPED;
		status = brobs_root_pointer(state, bias, slot, &value);
		if (status) return status;
		if (slot->kind == BROBS_DEREF_CHAIN && !slot->depth) return BR_OBS_UNMAPPED;
		for (unsigned i = 0; i < slot->depth; ++i) {
			unsigned width = slot->kind == BROBS_DEREF_CHAIN && i + 1 == slot->depth ? slot->width : 8;
			status = brobs_hop(bias, value, slot->offsets[i], width, &value);
			if (status) return status;
		}
		if (slot->kind == BROBS_HEAP_META) {
			status = brobs_address(value, 1);
			if (status) return status;
			if (brobs_tracker_failed || brobs_call_depth || brobs_call_overflow)
				return BR_OBS_UNMAPPED;
			struct brobs_object *object = brobs_containing(value);
			if (!object) return BR_OBS_UNMAPPED;
			status = brobs_object_range(object, value, 1);
			if (status) return status;
			switch (slot->meta_op) {
			case BROBS_OBJ_SIZE: value = object->size; break;
			case BROBS_OBJ_REMAINING: value = object->size - (value - object->begin); break;
			case BROBS_IS_LIVE: value = 1; break;
			case BROBS_OBJ_OFFSET: value -= object->begin; break;
			default: return BR_OBS_UNMAPPED;
			}
		}
	}
	if (slot->width < 8) {
		unsigned bits = slot->width * 8;
		value &= (1ULL << bits) - 1;
		if (slot->is_signed && (value & (1ULL << (bits - 1)))) value |= UINT64_MAX << bits;
	}
	*out = value;
	return BR_OBS_OK;
}

static void brobs_capture(const struct STATE *state, struct brobs_capture *capture)
{
	brobs_lock();
	memset(capture, 0, sizeof(*capture));
	uint64_t bias = (uint64_t)state->rip - BROBS_PATCH_LOCATION;
	for (unsigned i = 0; i < BROBS_COUNT; ++i) {
		uint64_t value = 0;
		int status = brobs_slot_value(state, bias, &brobs_slots[i], &value);
		capture->status[i] = status;
		if (!status) capture->values[i] = value;
	}
	mutex_unlock(&brobs_mutex);
}
#else
/* Empty plans compile out even the calls, not just their implementation. */
#define brobs_init() ((void)0)
#define brobs_capture(state, capture) ((void)0)
#endif

static int brobs_cell(const struct brobs_capture *capture, unsigned index, int validity, uint64_t *out)
{
#if BROBS_COUNT > 0
	if (!capture || index >= BROBS_COUNT) return -1;
	if (validity) {
		*out = capture->status[index] == BR_OBS_OK;
		return 0;
	}
	if (capture->status[index] != BR_OBS_OK) return -1;
	*out = capture->values[index];
	return 0;
#else
	(void)capture; (void)index; (void)validity; (void)out;
	return -1;
#endif
}
#endif
