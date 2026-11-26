"""Standalone synthetic traces; no tracer, target ELF, or guest memory access."""
from copy import deepcopy
import json

import pytest

from binradar.observation_analysis import plan_observations


PATCH = 0x401000
FAULT = 0x402000
SHA = "12" * 32
BASE = 0x100000


def _region(base=BASE, *, size=64, fields=(), initialized=True, kind="heap",
            site=0x403000, object_id=1, generation=1, pointer_offsets=(), state="live"):
    data = bytearray(size)
    for off, width, value in fields:
        data[off:off + width] = value.to_bytes(width, "little", signed=value < 0)
    init = bytearray([255 if initialized else 0] * ((size + 7) // 8))
    return {"kind": kind, "base": base, "size": size,
            "data": data.hex() if state == "live" else "",
            "init": init.hex() if state == "live" else "", "alloc_pc": site,
            "object_id": object_id, "generation": generation,
            "pointer_offsets": list(pointer_offsets), "state": state}


def _patch(regions, *, hit=0, regs=None, bias=0):
    if regs is None:
        regs = [0] * 16
        regs[7] = BASE
        regs[4] = 0x800000
    return {"kind": "patch", "hit_id": hit, "pc": PATCH, "load_bias": bias,
            "regs": regs, "regions": regions}


def _load(addr=BASE + 8, *, dst=16, size=4, addr_regs=(7,), signed=False):
    return {"kind": "load", "pc": PATCH + 8, "addr": addr, "size": size,
            "dst": dst, "addr_regs": list(addr_regs), "signed": signed}


def _fault(*, regs=(16,), mem=(), **extra):
    return {"kind": "fault", "pc": FAULT, "fault_kind": "div-by-zero",
            "regs": list(regs), "mem": list(mem), **extra}


def _run(case, outcome, perturb, patch, events):
    return {"case_id": case, "outcome": outcome, "perturb": perturb,
            "records": [{"kind": "header", "schema_version": 1}, patch,
                        *events, {"kind": "end", "status": "ok"}]}


def _corpus(builder=None):
    if builder is None:
        def builder(crash, perturb):
            return _patch([_region(fields=[(8, 4, 0 if crash else 9)])]), [_load()]
    result = []
    for crash in (True, False):
        for perturb in (85, 170):
            patch, events = builder(crash, perturb)
            if crash:
                events = [*events, _fault()]
            result.append(_run("crash" if crash else "normal",
                               "target_crash" if crash else "normal", perturb,
                               patch, events))
    return result


def _plan(runs=None, **kwargs):
    return plan_observations(_corpus() if runs is None else runs,
                             artifact_orig_sha256=SHA, patch_location=PATCH,
                             fault_reference=FAULT, **kwargs)


def _scalars(plan):
    return [slot for slot in plan["slots"] if slot["kind"] != "heap_meta"]


def _reasons(plan):
    return {candidate["reason"] for candidate in plan["rejected_candidates"]}


def test_schema_and_scalar_consumer_path_are_deterministic():
    runs = _corpus()
    before = deepcopy(runs)
    plan = _plan(runs)
    assert plan["analysis_status"] == "ok"
    assert plan["schema_version"] == 1
    assert plan["artifact_orig_sha256"] == SHA
    assert plan["patch_location"] == hex(PATCH)
    scalar, = _scalars(plan)
    assert scalar["kind"] == "deref_chain"
    assert scalar["root"] == {"kind": "reg", "reg": "rdi"}
    assert scalar["offsets"] == [8]
    assert scalar["width"] == 4
    assert scalar["slice_role"] == "direct_fault"
    assert scalar["separated_pair_count"] == 2
    assert "pointer_value_not_scalar" in _reasons(plan)
    assert "canonical_duplicate" in _reasons(plan)
    assert _plan(list(reversed(runs))) == plan
    assert runs == before
    assert str(BASE) not in json.dumps(plan["slots"])


def test_partial_store_retains_exact_unwritten_consumer_bytes():
    def builder(crash, perturb):
        patch = _patch([_region(fields=[(8, 8, 0 if crash else 0x1122334455667788)])])
        store = {"kind": "store", "pc": PATCH + 4, "addr": BASE + 10,
                 "size": 2, "src": [2], "addr_regs": [7]}
        return patch, [store, _load(size=8)]
    slots = _scalars(_plan(_corpus(builder)))
    assert {(tuple(slot["offsets"]), slot["width"]) for slot in slots} == {((8,), 2), ((12,), 4)}


def test_copy_and_overlapping_memmove_follow_pre_event_source_bytes():
    def builder(crash, perturb):
        value = 0 if crash else 0x1122334455667788
        patch = _patch([_region(fields=[(8, 8, value)])])
        copy = {"kind": "copy", "pc": PATCH + 4, "src_addr": BASE + 8,
                "dst_addr": BASE + 10, "size": 8}
        return patch, [copy, _load(BASE + 10, size=8)]
    plan = _plan(_corpus(builder))
    scalar, = _scalars(plan)
    assert scalar["offsets"] == [8]
    assert scalar["width"] == 8


def test_copy_of_partially_overwritten_consumer_preserves_source_fragments():
    def builder(crash, perturb):
        patch = _patch([_region(fields=[(8, 8, 0 if crash else 0x1122334455667788)])])
        copy = {"kind": "copy", "pc": PATCH + 2, "src_addr": BASE + 8,
                "dst_addr": BASE + 32, "size": 8}
        overwrite = {"kind": "overwrite", "pc": PATCH + 4, "addr": BASE + 34,
                     "size": 2, "src": []}
        return patch, [copy, overwrite, _load(BASE + 32, size=8)]
    slots = _scalars(_plan(_corpus(builder)))
    assert {(tuple(slot["offsets"]), slot["width"]) for slot in slots} == {((8,), 2), ((12,), 4)}


def test_two_hop_pointer_chain_wins_over_allocator_fallback():
    def builder(crash, perturb):
        first = _region(fields=[(0, 8, BASE + 0x100)], pointer_offsets=[0])
        second = _region(BASE + 0x100, fields=[(8, 8, BASE + 0x200)],
                         site=0x403100, object_id=2, pointer_offsets=[8])
        third = _region(BASE + 0x200, fields=[(12, 4, 0 if crash else 23)],
                        site=0x403200, object_id=3)
        return _patch([first, second, third]), [
            _load(BASE, size=8, dst=18),
            _load(BASE + 0x108, size=8, dst=19, addr_regs=[18]),
            _load(BASE + 0x20c, dst=16, addr_regs=[19])]
    plan = _plan(_corpus(builder))
    scalar, = _scalars(plan)
    assert scalar["root"] == {"kind": "reg", "reg": "rdi"}
    assert scalar["offsets"] == [0, 8, 12]


def test_global_pointer_root_is_rva_based_across_aslr_perturbations():
    def builder(crash, perturb):
        bias = 0x4000000 if perturb == 85 else 0x5000000
        heap = BASE if perturb == 85 else BASE + 0x20000
        global_ = _region(bias + 0x2000, fields=[(0, 8, heap)], kind="global",
                          pointer_offsets=[0])
        leaf = _region(heap, fields=[(8, 4, 0 if crash else 7)])
        regs = [0] * 16
        return _patch([global_, leaf], regs=regs, bias=bias), [
            _load(bias + 0x2000, size=8, dst=18, addr_regs=[]),
            _load(heap + 8, addr_regs=[18])]
    scalar, = _scalars(_plan(_corpus(builder)))
    assert scalar["root"] == {"kind": "global", "rva": "0x2000"}
    assert scalar["offsets"] == [8]
    assert "base" not in scalar


def test_zero_hop_global_preferred_and_signedness_preserved():
    def builder(crash, perturb):
        region = _region(0x2000, fields=[(4, 4, -2 if crash else 3)], kind="global")
        return _patch([region], regs=[0] * 16), [_load(0x2004, addr_regs=[], signed=True)]
    scalar, = _scalars(_plan(_corpus(builder)))
    assert scalar["kind"] == "global"
    assert scalar["rva"] == "0x2004"
    assert scalar["signed"] is True


def test_stack_pointer_root_and_allocator_last_resort():
    def stack_builder(crash, perturb):
        stack = _region(0x800000, fields=[(24, 8, BASE)], kind="stack", pointer_offsets=[24])
        leaf = _region(fields=[(8, 4, 0 if crash else 7)])
        regs = [0] * 16
        regs[4] = 0x800000
        return _patch([stack, leaf], regs=regs), [_load(addr_regs=[])]
    scalar, = _scalars(_plan(_corpus(stack_builder)))
    assert scalar["root"] == {"kind": "stack", "rsp_offset": 24}

    def alloc_builder(crash, perturb):
        return _patch([_region(fields=[(8, 4, 0 if crash else 7)])], regs=[0] * 16), [_load(addr_regs=[])]
    plan = _plan(_corpus(alloc_builder))
    scalar, = _scalars(plan)
    assert scalar["root"] == {"kind": "alloc_site", "site_pc": "0x403000", "selection": "last"}
    assert plan["alloc_hooks"] == [{"site_id": 0, "kind": "tracked_allocator", "call_pc": "0x403000"}]


def test_initialized_bytes_required_for_every_scalar_byte():
    runs = _corpus()
    region = runs[0]["records"][1]["regions"][0]
    bitmap = bytearray.fromhex(region["init"])
    bitmap[1] &= ~(1 << 2)
    region["init"] = bitmap.hex()
    plan = _plan(runs)
    assert plan["slots"] == []
    assert "uninitialized_byte_or_pointer" in _reasons(plan)


def test_uninitialized_intermediate_pointer_rejected_without_dereference():
    def builder(crash, perturb):
        first = _region(fields=[(0, 8, BASE + 0x100)], pointer_offsets=[0])
        if not crash:
            bitmap = bytearray.fromhex(first["init"])
            bitmap[0] &= ~1
            first["init"] = bitmap.hex()
        # No allocation site fallback for the leaf: no invented roots.
        leaf = _region(BASE + 0x100, fields=[(8, 4, 0 if crash else 7)], site=None, object_id=2)
        return _patch([first, leaf]), [_load(BASE, size=8, dst=18),
                                        _load(BASE + 0x108, addr_regs=[18])]
    plan = _plan(_corpus(builder))
    assert _scalars(plan) == []
    assert "uninitialized_byte_or_pointer" in _reasons(plan)


def test_pointer_addresses_are_not_scalar_discriminators():
    def builder(crash, perturb):
        pointed = BASE + (0x100 if crash else 0x200)
        first = _region(fields=[(8, 8, pointed)], pointer_offsets=[8])
        second = _region(pointed, size=64, object_id=2, site=0x403100)
        return _patch([first, second]), [_load(size=8)]
    plan = _plan(_corpus(builder))
    assert plan["slots"] == []
    assert "pointer_value_not_scalar" in _reasons(plan)


@pytest.mark.parametrize("pointer_offsets", [[8], []])
def test_crash_only_null_pointer_availability_is_kept(pointer_offsets):
    def builder(crash, perturb):
        pointer = 0 if crash else BASE + 0x100
        first = _region(fields=[(8, 8, pointer)], pointer_offsets=pointer_offsets)
        leaf = _region(BASE + 0x100, object_id=2, site=0x403100)
        return _patch([first, leaf]), [_load(size=8)]
    plan = _plan(_corpus(builder))
    assert plan["analysis_status"] == "ok"
    assert any(slot["availability_discriminating"] and slot["nullable_observed"]
               and slot["kind"] == "heap_meta" and slot["offsets"] == [8]
               for slot in plan["slots"])
    assert _scalars(plan) == []


def test_crash_only_freed_object_availability_is_kept():
    def builder(crash, perturb):
        first = _region(fields=[(8, 8, BASE + 0x100)], pointer_offsets=[8])
        leaf = _region(BASE + 0x100, state="freed" if crash else "live",
                       object_id=2, site=0x403100)
        return _patch([first, leaf]), [_load(size=8)]
    plan = _plan(_corpus(builder))
    assert any(slot["availability_discriminating"] for slot in plan["slots"])


def test_post_patch_input_only_is_explicitly_unobservable():
    runs = _corpus()
    for run in runs:
        run["records"].insert(2, {"kind": "sys_read", "pc": PATCH + 2,
                                  "addr": BASE + 8, "size": 4, "src": []})
    plan = _plan(runs)
    assert plan["analysis_status"] == "post_patch_input_read"
    assert plan["unobservable_reason"] == "post-patch-input-read"
    assert plan["slots"] == []
    assert {"code": "ORIGIN_POST_PATCH_SYSCALL"} in plan["diagnostics"]


def test_mixed_post_read_and_patch_live_in_retains_only_preexisting_scalar():
    def builder(crash, perturb):
        patch = _patch([_region(fields=[(8, 4, 0 if crash else 7), (16, 4, 0)])])
        read = {"kind": "sys_read", "pc": PATCH + 2, "addr": BASE + 16,
                "size": 4, "src": []}
        events = [read, _load(), _load(BASE + 16, dst=18)]
        return patch, events
    runs = _corpus(builder)
    for run in runs:
        if run["outcome"] == "target_crash":
            run["records"][-2]["regs"] = [16, 18]
    plan = _plan(runs)
    scalar, = _scalars(plan)
    assert scalar["offsets"] == [8]
    assert plan["analysis_status"] == "ok"
    assert {"code": "ORIGIN_POST_PATCH_SYSCALL"} in plan["diagnostics"]


def test_post_patch_allocation_bounds_link_to_size_operand_live_in():
    def builder(crash, perturb):
        patch = _patch([_region(fields=[(8, 4, 8 if crash else 64)])])
        alloc = {"kind": "alloc", "pc": 0x403200, "addr": BASE + 0x100,
                 "size": 8 if crash else 64, "object_id": 3, "generation": 1,
                 "src": [16], "dst": 18}
        return patch, [_load(), alloc]
    runs = _corpus(builder)
    for run in runs:
        if run["outcome"] == "target_crash":
            run["records"][-2] = _fault(regs=[18], object_id=3, generation=1,
                                          fault_kind="heap-oob")
    scalar, = _scalars(_plan(runs))
    assert scalar["offsets"] == [8]
    assert scalar["slice_role"] == "direct_fault"


def test_first_normal_divergence_precedes_bounded_recent_control_fallback():
    def builder(crash, perturb):
        patch = _patch([_region(fields=[(8, 4, 0 if crash else 7)])])
        branch = {"kind": "branch", "pc": PATCH + 12, "src": [16], "taken": crash}
        recent = [{"kind": "branch", "pc": PATCH + 32 + i, "src": [], "taken": True}
                  for i in range(24)]
        return patch, [_load(), branch, *recent]
    runs = _corpus(builder)
    for run in runs:
        if run["outcome"] == "target_crash":
            run["records"][-2]["regs"] = []
    scalar, = _scalars(_plan(runs))
    assert scalar["slice_role"] == "control_dep"
    assert scalar["offsets"] == [8]


def test_address_dependency_is_sliced_at_the_correct_event_time():
    def builder(crash, perturb):
        patch = _patch([_region(fields=[(8, 4, 4 if crash else 8)])])
        definition = {"kind": "def", "pc": PATCH + 9, "dst": 18,
                      "src": [16], "width": 4}
        return patch, [_load(), definition,
                       _load(BASE + 32, dst=19, addr_regs=[7, 18])]
    runs = _corpus(builder)
    for run in runs:
        if run["outcome"] == "target_crash":
            run["records"][-2]["regs"] = [19]
    scalar, = _scalars(_plan(runs))
    assert scalar["offsets"] == [8]
    assert scalar["slice_role"] == "addr_dep"


def test_exact_full_gpr_and_hit_id_pairs_required():
    runs = _corpus()
    for run in runs:
        if run["outcome"] == "normal":
            run["records"][1]["regs"][15] = 1
    assert _plan(runs)["analysis_status"] == "no_contrastive_pairs"
    runs = _corpus()
    for run in runs:
        if run["outcome"] == "normal":
            run["records"][1]["hit_id"] = 1
    assert _plan(runs)["analysis_status"] == "no_contrastive_pairs"


def test_all_visits_are_checked_even_if_only_last_window_reaches_fault():
    runs = _corpus()
    for run in runs:
        last = run["records"][1]
        first = deepcopy(last)
        first["regions"][0]["init"] = "00" * 8
        # Earlier visits do not form exact-GPR pairs, but are still checked.
        first["regs"][0] = 1 if run["outcome"] == "normal" else 2
        last["hit_id"] = 1
        run["records"].insert(1, first)
    plan = _plan(runs)
    assert plan["slots"] == []
    assert "uninitialized_byte_or_pointer" in _reasons(plan)


def test_last_retained_hit_need_not_start_at_zero():
    runs = _corpus()
    for run in runs:
        run["records"][1]["hit_id"] = 27
    assert _plan(runs)["analysis_status"] == "ok"


def test_perturbation_rejects_initialized_but_inconsistent_values():
    runs = _corpus()
    region = runs[1]["records"][1]["regions"][0]
    data = bytearray.fromhex(region["data"])
    data[8:12] = (33).to_bytes(4, "little")
    region["data"] = data.hex()
    plan = _plan(runs)
    assert plan["slots"] == []
    assert "malloc_perturbation_inconsistent" in _reasons(plan)


@pytest.mark.parametrize("mutation,reason", [
    (lambda runs: runs.pop(1), "missing_perturbation_run"),
    (lambda runs: runs[0]["records"].pop(), "incomplete_capture"),
    (lambda runs: runs[0]["records"][-1].update(status="window_overflow"), "window_overflow"),
    (lambda runs: runs[0]["records"].insert(2, {"kind": "unknown", "pc": PATCH}), "unsupported_event"),
    (lambda runs: runs[0]["records"][-2].update(regs=[65000]), "undefined_scratch_dependency"),
    (lambda runs: runs[0]["records"][1]["regions"][0].update(data=""), "incomplete_snapshot"),
    (lambda runs: runs[0]["records"][-2].update(pc=FAULT + 1), "fault_reference_mismatch"),
    (lambda runs: runs[0]["records"][1].update(pc=PATCH + 1), "patch_location_mismatch"),
])
def test_incomplete_or_unsupported_evidence_never_emits_partial_plan(mutation, reason):
    runs = _corpus()
    mutation(runs)
    plan = _plan(runs)
    assert plan["analysis_status"] == reason
    assert plan["slots"] == []
    assert {"code": reason} in plan["diagnostics"]


def test_slots_cap_and_expression_cooccurrence_are_deterministic():
    def builder(crash, perturb):
        patch = _patch([_region(fields=[(8, 4, 0 if crash else 7), (16, 4, 1 if crash else 9)])])
        return patch, [_load(), _load(BASE + 16, dst=18)]
    runs = _corpus(builder)
    for run in runs:
        if run["outcome"] == "target_crash":
            run["records"][-2]["regs"] = [16, 18]
    plan = _plan(runs)
    assert len(plan["slots"]) == 2
    assert plan["cooccurrence_groups"] == [[0, 1]]
    capped = _plan(runs, max_slots=1)
    assert len(capped["slots"]) == 1
    assert capped["cooccurrence_groups"] == []
    assert "slot_cap" in _reasons(capped)
    assert capped == _plan(list(reversed(runs)), max_slots=1)


def test_no_separating_slot_does_not_invent_observations():
    runs = _corpus(lambda crash, perturb: (_patch([_region(fields=[(8, 4, 5)])]), [_load()]))
    plan = _plan(runs)
    assert plan["analysis_status"] == "no_additional_separating_slot"
    assert plan["slots"] == []
    assert "non_separating_exact_gpr_pairs" in _reasons(plan)


def test_no_pointer_root_or_allocator_site_reports_unreachable():
    def builder(crash, perturb):
        return _patch([_region(fields=[(8, 4, 0 if crash else 7)], site=None)], regs=[0] * 16), [_load(addr_regs=[])]
    plan = _plan(_corpus(builder))
    assert plan["analysis_status"] == "unreachable_from_patch_roots"
    assert plan["slots"] == []


def test_allocator_reuse_generation_is_not_a_scalar_identity():
    runs = _corpus()
    for run in runs:
        if run["perturb"] == 170:
            run["records"][1]["regions"][0]["generation"] = 12
            run["records"][1]["regions"][0]["object_id"] = 45
    assert _plan(runs)["analysis_status"] == "ok"


def test_corpus_capacity_and_outcome_identity_are_fail_closed():
    runs = _corpus()
    runs[0]["outcome"] = "normal"
    assert _plan(runs)["slots"] == []
    runs = _corpus() * 33
    assert _plan(runs)["analysis_status"] == "corpus_capacity"


def test_heap_remaining_accepts_variable_interior_pointer_without_address_slots():
    def builder(crash, perturb):
        first = _region(fields=[(8, 8, BASE + 0x100 + (60 if crash else 8))],
                        pointer_offsets=[8])
        target = _region(BASE + 0x100, site=0x403100, object_id=2)
        return _patch([first, target]), [_load(size=8)]
    plan = _plan(_corpus(builder))
    assert plan["analysis_status"] == "ok"
    assert any(slot["kind"] == "heap_meta" and slot["meta_op"] == "obj_remaining"
               and slot["offsets"] == [8] for slot in plan["slots"])
    assert _scalars(plan) == []


def test_fault_is_terminal_even_before_a_later_patch_visit():
    runs = _corpus()
    patch = deepcopy(runs[0]["records"][1])
    patch["hit_id"] = 1
    runs[0]["records"].insert(-1, patch)
    plan = _plan(runs)
    assert plan["analysis_status"] == "malformed_event_order"
    assert plan["slots"] == []


def test_invalid_trace_scalar_types_and_ranges_are_rejected():
    runs = _corpus()
    runs[0]["records"][2]["addr"] = True
    assert _plan(runs)["analysis_status"] == "malformed_trace"
    runs = _corpus()
    runs[0]["records"][2]["addr"] = (1 << 64) - 1
    assert _plan(runs)["analysis_status"] == "malformed_trace"
