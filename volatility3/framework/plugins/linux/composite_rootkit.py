from __future__ import annotations

import dataclasses
import logging
from typing import Iterable, Iterator, List, Optional, Sequence, Set, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.linux import lsmod, pslist

vollog = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class Region:
    base: int
    size: int
    source: str
    detail: str

    @property
    def end(self) -> int:
        return self.base + self.size


@dataclasses.dataclass(frozen=True)
class HookRecord:
    hook_type: str
    pointer: int
    target: str


@dataclasses.dataclass(frozen=True)
class HiddenTask:
    pid: int
    task_addr: int
    comm: str
    source: str


@dataclasses.dataclass(frozen=True)
class Correlation:
    pointer: int
    region_base: int
    region_end: int
    hook_type: str
    target: str


@dataclasses.dataclass(frozen=True)
class SubsystemAResult:
    anomalous_regions: Set[Region]
    hidden_modules: Set[int]
    orphan_modules: Set[int]
    symbols_missing: Set[str]


@dataclasses.dataclass(frozen=True)
class SubsystemBResult:
    hooks: Set[HookRecord]
    invalid_idt_scan: bool


@dataclasses.dataclass(frozen=True)
class SubsystemCResult:
    hidden_tasks: Set[HiddenTask]


@dataclasses.dataclass(frozen=True)
class AggregationResult:
    detection_type: str
    correlations: Set[Correlation]


class SubsystemA:
    """Hidden Module Detection (Body)."""

    def __init__(self, plugin: "CompositeRootkit"):
        self.plugin = plugin

    def run(self) -> SubsystemAResult:
        vmlinux = self.plugin.vmlinux
        missing: Set[str] = set()

        M_raw = self._collect_modules_raw()
        K_raw, k_missing = self._collect_module_kset_raw()
        V_raw, v_missing = self._collect_vmap_raw()
        missing |= k_missing | v_missing

        M = {self.plugin.normalize_ptr("module", ptr) for ptr in M_raw}
        K = {self.plugin.normalize_ptr("kobj", ptr) for ptr in K_raw}
        V = {self.plugin.normalize_ptr("vmap", ptr) for ptr in V_raw}

        self.plugin.invariant(len(M) > 0, "|M| must be > 0 on valid system")
        if "module_kset" not in missing:
            self.plugin.invariant(
                len(K) > 0, "K must not be empty when module_kset exists"
            )
        if "vmap_area_list" not in missing:
            self.plugin.invariant(
                len(V) > 0, "V must be non-trivial when vmap_area_list exists"
            )

        S_all = M | K | V
        S_common = M & K & V
        hidden_modules = (K | V) - M
        orphan_modules = M - (K | V)

        vollog.info(
            "SubsystemA set cardinalities: |M|=%d |K|=%d |V|=%d |S_all|=%d |S_common|=%d |Hidden|=%d |Orphan|=%d",
            len(M),
            len(K),
            len(V),
            len(S_all),
            len(S_common),
            len(hidden_modules),
            len(orphan_modules),
        )

        carved = self._page_aligned_carving()
        filters = self._collect_dynamic_code_filters()
        self._assert_filter_safety(filters)

        region_candidates: Set[Region] = set()
        for addr in hidden_modules:
            if self.plugin.is_canonical(addr) and self.plugin.page_aligned(addr):
                region_candidates.add(Region(addr, 0x1000, "cross-view", "(K∪V)\\M"))

        for base, size, detail in carved:
            if self.plugin.is_canonical(base) and self.plugin.page_aligned(base):
                region_candidates.add(Region(base, size, "carving", detail))

        filtered = {
            region
            for region in region_candidates
            if not any(
                self.plugin.overlap(region.base, region.end, f.base, f.end)
                for f in filters
            )
        }

        for region in filtered:
            self.plugin.invariant(
                self.plugin.page_aligned(region.base),
                "AnomalousRegions base must be page-aligned",
            )
            self.plugin.invariant(
                self.plugin.is_canonical(region.base),
                "AnomalousRegions base must be canonical",
            )

        return SubsystemAResult(
            anomalous_regions=filtered,
            hidden_modules=hidden_modules,
            orphan_modules=orphan_modules,
            symbols_missing=missing,
        )

    def _collect_modules_raw(self) -> Set[int]:
        raw: Set[int] = set()
        for module in lsmod.Lsmod.list_modules(
            self.plugin.context, self.plugin.config["kernel"]
        ):
            raw.add(int(module.vol.offset))
        vollog.info("SubsystemA M_raw entries: %d", len(raw))
        return raw

    def _collect_module_kset_raw(self) -> Tuple[Set[int], Set[str]]:
        raw: Set[int] = set()
        missing: Set[str] = set()
        try:
            module_kset = self.plugin.vmlinux.object_from_symbol(
                symbol_name="module_kset"
            )
            for kobj in module_kset.list.to_list(
                self.plugin.vmlinux.symbol_table_name + "!kobject", "entry"
            ):
                raw.add(int(kobj.vol.offset))
        except Exception as exc:
            missing.add("module_kset")
            vollog.warning("SubsystemA: cannot enumerate module_kset: %s", exc)
        vollog.info("SubsystemA K_raw entries: %d", len(raw))
        return raw, missing

    def _collect_vmap_raw(self) -> Tuple[Set[int], Set[str]]:
        raw: Set[int] = set()
        missing: Set[str] = set()
        try:
            vmap_area_list = self.plugin.vmlinux.object_from_symbol(
                symbol_name="vmap_area_list"
            )
            list_off = self.plugin.get_offset("vmap_area", "list")
            for node in vmap_area_list.to_list(
                self.plugin.vmlinux.symbol_table_name + "!list_head", "next"
            ):
                if int(node.vol.offset) == int(vmap_area_list.vol.offset):
                    continue
                raw.add(int(node.vol.offset) - list_off)
        except Exception as exc:
            missing.add("vmap_area_list")
            vollog.warning("SubsystemA: cannot enumerate vmap_area_list: %s", exc)
        vollog.info("SubsystemA V_raw entries: %d", len(raw))
        return raw, missing

    def _page_aligned_carving(self) -> Set[Tuple[int, int, str]]:
        start, end = self.plugin.get_modules_range()
        layer = self.plugin.layer
        results: Set[Tuple[int, int, str]] = set()

        vollog.info("SubsystemA carving range: 0x%x-0x%x", start, end)
        for A in range(start, end, 0x1000):
            try:
                _ = layer.read(A, 0x100, pad=False)
            except Exception:
                continue

            try:
                mod = self.plugin.vmlinux.object(
                    object_type="module", offset=A, absolute=True
                )
            except Exception:
                continue

            try:
                state = int(mod.state)
                if state not in {0, 1, 2, 3}:
                    continue

                name = utility.array_to_string(mod.name) or ""
                if not self.plugin.valid_ascii_name(name):
                    continue

                init_ptr = self.plugin.get_module_init_base(mod)
                if not (start <= init_ptr < end):
                    continue

                base = self.plugin.get_module_core_base(mod)
                size = self.plugin.get_module_core_size(mod)
                if base == 0 or size <= 0:
                    continue
                if not (A >= base and A < base + size):
                    continue

                self.plugin.invariant(
                    self.plugin.is_canonical(base), "carving base must be canonical"
                )
                self.plugin.invariant(
                    size < 100 * 1024 * 1024, "carving size must be <100MB"
                )
                self.plugin.invariant(
                    self.plugin.page_aligned(base), "carving base must be page-aligned"
                )

                results.add((base, size, f"carved:{name}"))
            except Exception:
                continue

        vollog.info("SubsystemA carved candidates: %d", len(results))
        return results

    def _collect_dynamic_code_filters(self) -> Set[Region]:
        filters: Set[Region] = set()
        filters |= self._collect_bpf_jit_regions()
        filters |= self._collect_ftrace_tramp_regions()
        filters |= self._collect_kprobe_tramp_regions()
        vollog.info("SubsystemA filter regions collected: %d", len(filters))
        return filters

    def _collect_bpf_jit_regions(self) -> Set[Region]:
        regions: Set[Region] = set()
        try:
            prog_idr = self.plugin.vmlinux.object_from_symbol(symbol_name="prog_idr")
            for bucket in prog_idr.idr_rt.to_list(
                self.plugin.vmlinux.symbol_table_name + "!radix_tree_node", "parent"
            ):
                try:
                    prog = self.plugin.vmlinux.object(
                        object_type="bpf_prog",
                        offset=int(bucket.vol.offset),
                        absolute=True,
                    )
                    jited = int(getattr(prog, "bpf_func", 0) or 0)
                    jited_len = int(getattr(prog, "jited_len", 0) or 0)
                    if jited and jited_len:
                        regions.add(
                            Region(
                                self.plugin.canonicalize(jited),
                                jited_len,
                                "filter",
                                "eBPF-JIT",
                            )
                        )
                except Exception:
                    continue
        except Exception as exc:
            vollog.warning("SubsystemA: BPF filter enumeration unavailable: %s", exc)
        return regions

    def _collect_ftrace_tramp_regions(self) -> Set[Region]:
        regions: Set[Region] = set()
        try:
            ftrace_ops_list = self.plugin.vmlinux.object_from_symbol(
                symbol_name="ftrace_ops_list"
            )
            list_off = self.plugin.get_offset("ftrace_ops", "list")
            for node in ftrace_ops_list.to_list(
                self.plugin.vmlinux.symbol_table_name + "!list_head", "next"
            ):
                try:
                    ops = self.plugin.vmlinux.object(
                        object_type="ftrace_ops",
                        offset=int(node.vol.offset) - list_off,
                        absolute=True,
                    )
                    callback = int(getattr(ops, "func", 0) or 0)
                    if callback:
                        regions.add(
                            Region(
                                self.plugin.canonicalize(callback),
                                0x1000,
                                "filter",
                                "ftrace-callback",
                            )
                        )
                except Exception:
                    continue
        except Exception as exc:
            vollog.warning("SubsystemA: ftrace filter enumeration unavailable: %s", exc)
        return regions

    def _collect_kprobe_tramp_regions(self) -> Set[Region]:
        regions: Set[Region] = set()
        try:
            kprobe_table = self.plugin.vmlinux.object_from_symbol(
                symbol_name="kprobe_table"
            )
            hlist_off = self.plugin.get_offset("kprobe", "hlist")
            for bucket in kprobe_table:
                for node in bucket.to_list(
                    self.plugin.vmlinux.symbol_table_name + "!hlist_node", "next"
                ):
                    try:
                        kp = self.plugin.vmlinux.object(
                            object_type="kprobe",
                            offset=int(node.vol.offset) - hlist_off,
                            absolute=True,
                        )
                        for field in (
                            "pre_handler",
                            "post_handler",
                            "fault_handler",
                            "break_handler",
                        ):
                            ptr = int(getattr(kp, field, 0) or 0)
                            if ptr:
                                regions.add(
                                    Region(
                                        self.plugin.canonicalize(ptr),
                                        0x1000,
                                        "filter",
                                        f"kprobe-{field}",
                                    )
                                )
                    except Exception:
                        continue
        except Exception as exc:
            vollog.warning("SubsystemA: kprobe filter enumeration unavailable: %s", exc)
        return regions

    def _assert_filter_safety(self, filters: Set[Region]) -> None:
        legit = self.plugin.build_whitelist()
        for region in filters:
            overlaps_legit = any(
                self.plugin.overlap(region.base, region.end, s, e) for s, e in legit
            )
            self.plugin.invariant(
                not overlaps_legit,
                f"FilteredRegions must not overlap known kernel/module text ({region.detail})",
            )


class SubsystemB:
    """Control Flow Integrity (Hooks)."""

    def __init__(self, plugin: "CompositeRootkit"):
        self.plugin = plugin

    def run(self) -> SubsystemBResult:
        whitelist = self.plugin.build_whitelist()
        self.plugin.invariant(
            len(whitelist) > 0, "Whitelist must contain at least kernel text"
        )

        hooks: Set[HookRecord] = set()
        hooks |= self._check_syscalls(whitelist)
        idt_hooks, invalid_idt = self._check_idt(whitelist)
        hooks |= idt_hooks
        hooks |= self._check_vfs(whitelist)
        hooks |= self._check_netfilter(whitelist)
        hooks |= self._check_ftrace(whitelist)
        hooks |= self._check_kprobes(whitelist)

        hooks = {h for h in hooks if self.plugin.is_canonical(h.pointer)}
        return SubsystemBResult(hooks=hooks, invalid_idt_scan=invalid_idt)

    def _check_syscalls(self, whitelist: Sequence[Tuple[int, int]]) -> Set[HookRecord]:
        findings: Set[HookRecord] = set()
        try:
            table = self.plugin.vmlinux.object_from_symbol(symbol_name="sys_call_table")
            for idx, ptr_obj in enumerate(table):
                p = self.plugin.canonicalize(int(ptr_obj))
                self.plugin.invariant(
                    self.plugin.is_canonical(p), "syscall pointer must be canonical"
                )
                if p and not self.plugin.in_whitelist(p, whitelist):
                    findings.add(HookRecord("syscall", p, f"sys_call_table[{idx}]"))
        except Exception as exc:
            vollog.warning("SubsystemB syscall check failed: %s", exc)
        return findings

    def _check_idt(
        self, whitelist: Sequence[Tuple[int, int]]
    ) -> Tuple[Set[HookRecord], bool]:
        findings: Set[HookRecord] = set()
        flagged = 0
        total = 0
        try:
            idt = self.plugin.vmlinux.object_from_symbol(symbol_name="idt_table")
            for idx, gate in enumerate(idt):
                if idx >= 256:
                    break
                total += 1
                p = self.plugin.decode_idt_gate(gate)
                if p == 0:
                    continue
                self.plugin.invariant(
                    self.plugin.is_canonical(p), "IDT pointer must be canonical"
                )
                if self.plugin.in_whitelist(
                    p, whitelist
                ) or self.plugin.in_entry_regions(p):
                    continue
                flagged += 1
                findings.add(HookRecord("idt", p, f"idt[{idx}]"))
        except Exception as exc:
            vollog.warning("SubsystemB IDT check failed: %s", exc)
            return set(), True

        if total > 0 and flagged > total // 2:
            vollog.error(
                "SubsystemB IDT invalid detection: %d/%d entries flagged",
                flagged,
                total,
            )
            return set(), True
        return findings, False

    def _check_vfs(self, whitelist: Sequence[Tuple[int, int]]) -> Set[HookRecord]:
        findings: Set[HookRecord] = set()
        try:
            proc_root_sym = self.plugin.vmlinux.object_from_symbol(
                symbol_name="proc_root"
            )
            proc_root = (
                proc_root_sym.dereference()
                if hasattr(proc_root_sym, "dereference")
                else proc_root_sym
            )
            fops = getattr(
                proc_root, "proc_dir_operations", getattr(proc_root, "proc_fops", None)
            )
            if fops is None:
                return findings
            fops = fops.dereference() if hasattr(fops, "dereference") else fops
            for name in (
                "open",
                "read",
                "write",
                "iterate",
                "iterate_shared",
                "readdir",
            ):
                if not hasattr(fops, name):
                    continue
                p = self.plugin.canonicalize(int(getattr(fops, name) or 0))
                if p and not self.plugin.in_whitelist(p, whitelist):
                    findings.add(HookRecord("vfs", p, f"proc_root.fops.{name}"))
        except Exception as exc:
            vollog.warning("SubsystemB VFS check failed: %s", exc)
        return findings

    def _check_netfilter(self, whitelist: Sequence[Tuple[int, int]]) -> Set[HookRecord]:
        findings: Set[HookRecord] = set()
        try:
            nf_hooks = self.plugin.vmlinux.object_from_symbol(symbol_name="nf_hooks")
            for proto_idx, hook_arr in enumerate(nf_hooks):
                for hook_idx, list_head in enumerate(hook_arr):
                    for hook in list_head.to_list(
                        self.plugin.vmlinux.symbol_table_name + "!nf_hook_ops", "list"
                    ):
                        p = self.plugin.canonicalize(int(getattr(hook, "hook", 0) or 0))
                        if p and not self.plugin.in_whitelist(p, whitelist):
                            findings.add(
                                HookRecord(
                                    "netfilter", p, f"nf_hooks[{proto_idx}][{hook_idx}]"
                                )
                            )
        except Exception as exc:
            vollog.warning("SubsystemB netfilter check failed: %s", exc)
        return findings

    def _check_ftrace(self, whitelist: Sequence[Tuple[int, int]]) -> Set[HookRecord]:
        findings: Set[HookRecord] = set()
        try:
            ftrace_ops_list = self.plugin.vmlinux.object_from_symbol(
                symbol_name="ftrace_ops_list"
            )
            list_off = self.plugin.get_offset("ftrace_ops", "list")
            for node in ftrace_ops_list.to_list(
                self.plugin.vmlinux.symbol_table_name + "!list_head", "next"
            ):
                ops = self.plugin.vmlinux.object(
                    object_type="ftrace_ops",
                    offset=int(node.vol.offset) - list_off,
                    absolute=True,
                )
                p = self.plugin.canonicalize(int(getattr(ops, "func", 0) or 0))
                if p and not self.plugin.in_whitelist(p, whitelist):
                    findings.add(HookRecord("ftrace", p, "ftrace_ops.func"))
        except Exception as exc:
            vollog.warning("SubsystemB ftrace check failed: %s", exc)
        return findings

    def _check_kprobes(self, whitelist: Sequence[Tuple[int, int]]) -> Set[HookRecord]:
        findings: Set[HookRecord] = set()
        try:
            kprobe_table = self.plugin.vmlinux.object_from_symbol(
                symbol_name="kprobe_table"
            )
            hlist_off = self.plugin.get_offset("kprobe", "hlist")
            for bidx, bucket in enumerate(kprobe_table):
                for node in bucket.to_list(
                    self.plugin.vmlinux.symbol_table_name + "!hlist_node", "next"
                ):
                    kp = self.plugin.vmlinux.object(
                        object_type="kprobe",
                        offset=int(node.vol.offset) - hlist_off,
                        absolute=True,
                    )
                    for field in (
                        "pre_handler",
                        "post_handler",
                        "fault_handler",
                        "break_handler",
                    ):
                        p = self.plugin.canonicalize(int(getattr(kp, field, 0) or 0))
                        if p and not self.plugin.in_whitelist(p, whitelist):
                            findings.add(
                                HookRecord("kprobe", p, f"kprobe[{bidx}].{field}")
                            )
        except Exception as exc:
            vollog.warning("SubsystemB kprobe check failed: %s", exc)
        return findings


class SubsystemC:
    """DKOM Detection (Processes)."""

    def __init__(self, plugin: "CompositeRootkit"):
        self.plugin = plugin

    def run(self) -> SubsystemCResult:
        T_list = self._collect_task_set_from_list()
        T_runq = self._collect_task_set_from_runqueues()
        T_pid = self._collect_task_set_from_pid_hash()

        hidden_ptrs = (T_runq | T_pid) - T_list
        hidden: Set[HiddenTask] = set()

        for task_addr in hidden_ptrs:
            task = self._safe_task(task_addr)
            if task is None:
                continue
            try:
                pid = int(task.pid)
                comm = utility.array_to_string(task.comm) or ""
            except Exception:
                continue

            if pid <= 0:
                continue
            if not self.plugin.valid_ascii_name(comm, min_len=1, max_len=16):
                continue
            hidden.add(
                HiddenTask(
                    pid=pid, task_addr=task_addr, comm=comm, source="runq/pidhash"
                )
            )

        vollog.info("SubsystemC hidden tasks: %d", len(hidden))
        return SubsystemCResult(hidden_tasks=hidden)

    def _collect_task_set_from_list(self) -> Set[int]:
        out: Set[int] = set()
        try:
            for task in pslist.PsList.list_tasks(
                self.plugin.context, self.plugin.config["kernel"]
            ):
                out.add(self.plugin.canonicalize(int(task.vol.offset)))
        except Exception as exc:
            vollog.warning("SubsystemC task list collection failed: %s", exc)
        return out

    def _collect_task_set_from_runqueues(self) -> Set[int]:
        out: Set[int] = set()
        try:
            runqueues = self.plugin.vmlinux.object_from_symbol(symbol_name="runqueues")
            nr_cpu_ids = int(
                self.plugin.vmlinux.object_from_symbol(symbol_name="nr_cpu_ids")
            )
            for cpu in range(nr_cpu_ids):
                try:
                    rq = runqueues[cpu]
                    curr = getattr(rq, "curr", None)
                    if curr:
                        out.add(self.plugin.canonicalize(int(curr.vol.offset)))
                except Exception:
                    continue
        except Exception as exc:
            vollog.warning("SubsystemC runqueue collection failed: %s", exc)
        return out

    def _collect_task_set_from_pid_hash(self) -> Set[int]:
        out: Set[int] = set()
        try:
            pidhash = self.plugin.vmlinux.object_from_symbol(symbol_name="pid_hash")
            for bucket in pidhash:
                for upid in bucket.to_list(
                    self.plugin.vmlinux.symbol_table_name + "!upid", "pid_chain"
                ):
                    try:
                        pid_obj = upid.pid
                        task = pid_obj.tasks[0].first
                        if task:
                            out.add(self.plugin.canonicalize(int(task.vol.offset)))
                    except Exception:
                        continue
        except Exception as exc:
            vollog.warning("SubsystemC pid hash collection failed: %s", exc)
        return out

    def _safe_task(self, task_addr: int):
        try:
            return self.plugin.vmlinux.object(
                object_type="task_struct", offset=task_addr, absolute=True
            )
        except Exception:
            return None


class Aggregator:
    def __init__(self, plugin: "CompositeRootkit"):
        self.plugin = plugin

    def run(
        self,
        a_result: SubsystemAResult,
        b_result: SubsystemBResult,
        c_result: SubsystemCResult,
    ) -> AggregationResult:
        correlations: Set[Correlation] = set()

        for hook in b_result.hooks:
            for region in a_result.anomalous_regions:
                if region.base <= hook.pointer < region.end:
                    correlations.add(
                        Correlation(
                            pointer=hook.pointer,
                            region_base=region.base,
                            region_end=region.end,
                            hook_type=hook.hook_type,
                            target=hook.target,
                        )
                    )

        has_hooks = len(b_result.hooks) > 0
        has_hidden_tasks = len(c_result.hidden_tasks) > 0
        has_regions = len(a_result.anomalous_regions) > 0
        has_correlated = len(correlations) > 0

        if has_correlated and has_hidden_tasks:
            detection = "Hybrid Rootkit"
        elif has_correlated:
            detection = "Confirmed LKM Rootkit"
        elif has_hidden_tasks and not has_hooks:
            detection = "DKOM Rootkit"
        elif has_regions:
            detection = "Suspicious"
        elif has_hooks:
            detection = "Confirmed LKM Rootkit"
        else:
            detection = "Suspicious"

        return AggregationResult(detection_type=detection, correlations=correlations)


class CompositeRootkit(interfaces.plugins.PluginInterface):
    """Composite Linux Rootkit Detector (Subsystem A/B/C + Aggregation)."""

    _required_framework_version = (2, 0, 0)
    _version = (13, 0, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.vmlinux = self.context.modules[self.config["kernel"]]
        self.layer = self.context.layers[self.vmlinux.layer_name]

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64", "Amd64"],
            )
        ]

    def run(self) -> renderers.TreeGrid:
        rows = list(self._generator())
        return renderers.TreeGrid(
            [
                ("DetectionType", str),
                ("Category", str),
                ("Subject", str),
                ("Pointer", format_hints.Hex),
                ("Details", str),
            ],
            iter(rows),
        )

    def _generator(self) -> Iterator[Tuple[int, Tuple[object, ...]]]:
        try:
            a_result = SubsystemA(self).run()
        except Exception as exc:
            vollog.exception("Subsystem A failed: %s", exc)
            a_result = SubsystemAResult(set(), set(), set(), {"subsystem_a_failed"})

        try:
            b_result = SubsystemB(self).run()
        except Exception as exc:
            vollog.exception("Subsystem B failed: %s", exc)
            b_result = SubsystemBResult(set(), True)

        try:
            c_result = SubsystemC(self).run()
        except Exception as exc:
            vollog.exception("Subsystem C failed: %s", exc)
            c_result = SubsystemCResult(set())

        agg = Aggregator(self).run(a_result, b_result, c_result)

        header = agg.detection_type

        if a_result.anomalous_regions:
            for region in sorted(a_result.anomalous_regions, key=lambda x: x.base):
                yield (
                    0,
                    (
                        header,
                        "AnomalousRegion",
                        region.source,
                        format_hints.Hex(region.base),
                        f"size=0x{region.size:x};{region.detail}",
                    ),
                )
                header = ""

        if b_result.hooks:
            for hook in sorted(b_result.hooks, key=lambda x: x.pointer):
                yield (
                    0,
                    (
                        header,
                        "Hook",
                        hook.hook_type,
                        format_hints.Hex(hook.pointer),
                        hook.target,
                    ),
                )
                header = ""

        if c_result.hidden_tasks:
            for task in sorted(c_result.hidden_tasks, key=lambda x: x.pid):
                yield (
                    0,
                    (
                        header,
                        "HiddenTask",
                        task.comm,
                        format_hints.Hex(task.task_addr),
                        f"pid={task.pid};source={task.source}",
                    ),
                )
                header = ""

        if agg.correlations:
            for corr in sorted(agg.correlations, key=lambda x: x.pointer):
                yield (
                    0,
                    (
                        header,
                        "Correlation",
                        corr.hook_type,
                        format_hints.Hex(corr.pointer),
                        f"{corr.target} -> [0x{corr.region_base:x},0x{corr.region_end:x})",
                    ),
                )
                header = ""

        if not any(
            [
                a_result.anomalous_regions,
                b_result.hooks,
                c_result.hidden_tasks,
                agg.correlations,
            ]
        ):
            yield (
                0,
                (
                    agg.detection_type,
                    "Info",
                    "NoFindings",
                    format_hints.Hex(0),
                    "No anomalies found",
                ),
            )

    # ===== shared utilities =====
    def canonicalize(self, ptr: int) -> int:
        if ptr <= 0:
            return 0
        if ptr & (1 << 47):
            return ptr | 0xFFFF000000000000
        return ptr & 0x0000FFFFFFFFFFFF

    def is_canonical(self, ptr: int) -> bool:
        p = self.canonicalize(ptr)
        return p != 0 and ((p >> 47) == 0x1FFFF or (p >> 47) == 0)

    def page_aligned(self, ptr: int) -> bool:
        return (ptr & 0xFFF) == 0

    def normalize_ptr(self, kind: str, ptr: int) -> int:
        """f(x): normalize list/kobject/vmap pointers to allocation base."""
        p = self.canonicalize(ptr)
        if kind == "module":
            return p
        if kind == "kobj":
            off = self.get_offset("module_kobject", "kobj")
            p = self.canonicalize(p - off)
        elif kind == "vmap":
            try:
                va = self.vmlinux.object(
                    object_type="vmap_area", offset=p, absolute=True
                )
                p = self.canonicalize(
                    int(getattr(va, "va_start", getattr(va, "addr", p)))
                )
            except Exception:
                p = self.canonicalize(p)

        self.invariant(
            self.is_canonical(p), "f(x) must produce canonical kernel pointer"
        )
        near_alignment = self.page_aligned(p) or self.page_aligned(p & ~0x1FF)
        self.invariant(near_alignment, "f(x) must be page-aligned or near module base")
        return p

    def get_kaslr_shift(self) -> int:
        try:
            sym = self.context.symbol_space.get_symbol(
                self.vmlinux.symbol_table_name + "!init_task"
            ).address
            runtime = int(
                self.vmlinux.object_from_symbol(symbol_name="init_task").vol.offset
            )
            return runtime - sym
        except Exception:
            return 0

    def get_offset(self, struct_name: str, member_name: str) -> int:
        try:
            return self.context.symbol_space.get_type(
                self.vmlinux.symbol_table_name + "!" + struct_name
            ).relative_child_offset(member_name)
        except Exception:
            return 0

    def get_modules_range(self) -> Tuple[int, int]:
        try:
            start = int(
                self.vmlinux.object_from_symbol(symbol_name="module_alloc_base")
            )
            end = int(self.vmlinux.object_from_symbol(symbol_name="module_alloc_end"))
            if start < end:
                return self.canonicalize(start), self.canonicalize(end)
        except Exception:
            pass

        ranges = []
        for mod in lsmod.Lsmod.list_modules(self.context, self.config["kernel"]):
            try:
                b = self.get_module_core_base(mod)
                s = self.get_module_core_size(mod)
                if b and s:
                    ranges.append((b, b + s))
            except Exception:
                continue

        if not ranges:
            return 0xFFFFFFFFA0000000, 0xFFFFFFFFFE000000

        return min(x[0] for x in ranges) - 0x8000000, max(
            x[1] for x in ranges
        ) + 0x8000000

    def get_module_core_base(self, mod) -> int:
        if hasattr(mod, "core_layout"):
            return self.canonicalize(int(mod.core_layout.base))
        return self.canonicalize(int(getattr(mod, "module_core", 0) or 0))

    def get_module_core_size(self, mod) -> int:
        if hasattr(mod, "core_layout"):
            return int(mod.core_layout.size)
        return int(getattr(mod, "core_size", 0) or 0)

    def get_module_init_base(self, mod) -> int:
        if hasattr(mod, "init_layout"):
            return self.canonicalize(int(mod.init_layout.base))
        if hasattr(mod, "module_init"):
            return self.canonicalize(int(mod.module_init))
        return 0

    def valid_ascii_name(self, name: str, min_len: int = 2, max_len: int = 55) -> bool:
        if not (min_len <= len(name) <= max_len):
            return False
        return all(32 <= ord(c) < 127 for c in name)

    def overlap(self, a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
        return a_start < b_end and b_start < a_end

    def build_whitelist(self) -> List[Tuple[int, int]]:
        whitelist: List[Tuple[int, int]] = []
        kaslr = self.get_kaslr_shift()

        def sym_range(start_sym: str, end_sym: str) -> Optional[Tuple[int, int]]:
            try:
                s = (
                    self.context.symbol_space.get_symbol(
                        self.vmlinux.symbol_table_name + "!" + start_sym
                    ).address
                    + kaslr
                )
                e = (
                    self.context.symbol_space.get_symbol(
                        self.vmlinux.symbol_table_name + "!" + end_sym
                    ).address
                    + kaslr
                )
                s = self.canonicalize(s)
                e = self.canonicalize(e)
                if s < e:
                    return s, e
            except Exception:
                return None
            return None

        text = sym_range("_stext", "_etext") or sym_range("_text", "_end")
        if text:
            whitelist.append(text)

        for sym in (
            "__entry_text_start",
            "__entry_text_end",
            "entry_trampoline",
            "cpu_entry_area",
        ):
            try:
                addr = int(self.vmlinux.object_from_symbol(symbol_name=sym).vol.offset)
                addr = self.canonicalize(addr)
                whitelist.append((addr, addr + 0x4000))
            except Exception:
                continue

        for mod in lsmod.Lsmod.list_modules(self.context, self.config["kernel"]):
            try:
                b = self.get_module_core_base(mod)
                s = self.get_module_core_size(mod)
                if b and s > 0:
                    whitelist.append((b, b + s))
            except Exception:
                continue

        for opt in ("__fix_to_virt", "vsyscall_page"):
            try:
                addr = int(self.vmlinux.object_from_symbol(symbol_name=opt).vol.offset)
                addr = self.canonicalize(addr)
                whitelist.append((addr, addr + 0x1000))
            except Exception:
                continue

        if not whitelist:
            raise exceptions.VolatilityException("Whitelist construction failed")

        return whitelist

    def in_whitelist(self, ptr: int, whitelist: Sequence[Tuple[int, int]]) -> bool:
        p = self.canonicalize(ptr)
        return any(start <= p < end for start, end in whitelist)

    def in_entry_regions(self, ptr: int) -> bool:
        p = self.canonicalize(ptr)
        for sym in ("__entry_text_start", "entry_trampoline", "cpu_entry_area"):
            try:
                base = self.canonicalize(
                    int(self.vmlinux.object_from_symbol(symbol_name=sym).vol.offset)
                )
                if base <= p < base + 0x4000:
                    return True
            except Exception:
                continue
        return False

    def decode_idt_gate(self, gate) -> int:
        low = int(getattr(gate, "offset_low", 0) or 0)
        mid = int(getattr(gate, "offset_middle", 0) or 0)
        high = int(getattr(gate, "offset_high", 0) or 0)
        return self.canonicalize(low | (mid << 16) | (high << 32))

    def invariant(self, condition: bool, message: str) -> None:
        if not condition:
            raise exceptions.VolatilityException("Invariant violation: " + message)
