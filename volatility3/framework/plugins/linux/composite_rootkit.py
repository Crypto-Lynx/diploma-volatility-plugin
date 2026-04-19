from __future__ import annotations

import dataclasses
import enum
import logging
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.linux import lsmod, pslist

vollog = logging.getLogger(__name__)


class RootkitClassification(enum.Enum):
    CONFIRMED_LKM = "Confirmed LKM Rootkit"
    DATA_ONLY = "Data-only Rootkit"
    HYBRID = "Hybrid rootkit (code + DKOM)"
    SUSPICIOUS = "Suspicious, not confirmed"
    CLEAN = "No rootkit indicators"


@dataclasses.dataclass(frozen=True)
class MemoryRegion:
    base: int
    size: int
    source: str

    @property
    def end(self) -> int:
        return self.base + self.size


@dataclasses.dataclass(frozen=True)
class HookAnomaly:
    subsystem: str
    location: str
    pointer: int


@dataclasses.dataclass(frozen=True)
class DetectionResult:
    classification: RootkitClassification
    anomalous_regions: Sequence[MemoryRegion]
    hooks: Sequence[HookAnomaly]
    hidden_tasks: Sequence[int]


class CompositeRootkit(interfaces.plugins.PluginInterface):
    """Composite rootkit detector based on allocation, hook and DKOM checks."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.BooleanRequirement(
                name="enable_syscall_check",
                description="Enable sys_call_table hook validation",
                default=True,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="enable_idt_check",
                description="Enable IDT hook validation",
                default=True,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="enable_vfs_check",
                description="Enable VFS hook validation",
                default=True,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="enable_netfilter_check",
                description="Enable Netfilter hook validation",
                default=True,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="enable_carving",
                description="Enable page-aligned module carving",
                default=True,
                optional=True,
            ),
        ]

    def run(self) -> renderers.TreeGrid:
        result = self._detect()

        return renderers.TreeGrid(
            [
                ("Classification", str),
                ("RegionBase", format_hints.Hex),
                ("RegionSize", format_hints.Hex),
                ("RegionSource", str),
                ("HookSubsystem", str),
                ("HookLocation", str),
                ("HookPointer", format_hints.Hex),
                ("HiddenTaskPID", int),
            ],
            self._generator(result),
        )

    def _generator(self, result: DetectionResult) -> Iterator[Tuple[int, Tuple[object, ...]]]:
        region_rows = list(result.anomalous_regions) or [MemoryRegion(0, 0, "-")]
        hook_rows = list(result.hooks) or [HookAnomaly("-", "-", 0)]
        task_rows = list(result.hidden_tasks) or [0]

        total = max(len(region_rows), len(hook_rows), len(task_rows))
        for idx in range(total):
            region = region_rows[idx] if idx < len(region_rows) else MemoryRegion(0, 0, "-")
            hook = hook_rows[idx] if idx < len(hook_rows) else HookAnomaly("-", "-", 0)
            pid = task_rows[idx] if idx < len(task_rows) else 0
            yield (
                0,
                (
                    result.classification.value if idx == 0 else "",
                    format_hints.Hex(region.base),
                    format_hints.Hex(region.size),
                    region.source,
                    hook.subsystem,
                    hook.location,
                    format_hints.Hex(hook.pointer),
                    pid,
                ),
            )

    def _detect(self) -> DetectionResult:
        anomalous_regions = self._subsystem_a()
        hooks = self._subsystem_b(anomalous_regions)
        hidden_tasks = self._subsystem_c()
        classification = self._classify(anomalous_regions, hooks, hidden_tasks)

        return DetectionResult(
            classification=classification,
            anomalous_regions=sorted(anomalous_regions, key=lambda r: r.base),
            hooks=sorted(hooks, key=lambda h: h.pointer),
            hidden_tasks=sorted(hidden_tasks),
        )

    def _classify(
        self,
        anomalous_regions: Sequence[MemoryRegion],
        hooks: Sequence[HookAnomaly],
        hidden_tasks: Sequence[int],
    ) -> RootkitClassification:
        if hidden_tasks and hooks:
            return RootkitClassification.HYBRID

        if hidden_tasks and not hooks:
            return RootkitClassification.DATA_ONLY

        if hooks:
            return RootkitClassification.CONFIRMED_LKM

        if anomalous_regions:
            return RootkitClassification.SUSPICIOUS

        return RootkitClassification.CLEAN

    # ===== Subsystem A =====
    def _subsystem_a(self) -> Set[MemoryRegion]:
        module_view = self._collect_module_view()
        kobj_view = self._collect_module_kset_view()
        vmap_view = self._collect_vmap_view()

        hidden = (kobj_view | vmap_view) - module_view
        carved = self._carve_candidate_modules() if self.config.get("enable_carving", True) else set()
        filtered = self._collect_false_positive_regions()

        candidates = {MemoryRegion(base=addr, size=0x1000, source="cross-view") for addr in hidden}
        candidates |= {MemoryRegion(base=addr, size=0x1000, source="carving") for addr in carved}

        return {region for region in candidates if not self._overlaps(region, filtered)}

    def _collect_module_view(self) -> Set[int]:
        view: Set[int] = set()
        try:
            for module in lsmod.Lsmod.list_modules(self.context, self.config["kernel"]):
                view.add(int(module.vol.offset))
        except Exception as exc:  # pragma: no cover - defensive for malformed symbols
            vollog.debug("Unable to collect module list view: %s", exc)
        return view

    def _collect_module_kset_view(self) -> Set[int]:
        """Collect module addresses from module_kset kobjects and normalize pointers."""
        module = self.context.modules[self.config["kernel"]]
        view: Set[int] = set()

        try:
            module_kset = module.object_from_symbol(symbol_name="module_kset")
            list_head = module_kset.list
            offset = module.get_type("module_kobject").relative_child_offset("kobj")
            for kobj in list_head.to_list("kobject", "entry"):
                view.add(int(kobj.vol.offset) - int(offset))
        except Exception as exc:
            vollog.debug("Unable to collect module_kset view: %s", exc)

        return view

    def _collect_vmap_view(self) -> Set[int]:
        """Collect module addresses from vmap_area list; normalize to va->addr."""
        module = self.context.modules[self.config["kernel"]]
        view: Set[int] = set()

        try:
            vmap_area_list = module.object_from_symbol(symbol_name="vmap_area_list")
            for vmap_area in vmap_area_list.to_list("vmap_area", "list"):
                view.add(int(vmap_area.va_start))
        except Exception as exc:
            vollog.debug("Unable to collect vmap view: %s", exc)

        return view

    def _carve_candidate_modules(self) -> Set[int]:
        """Perform page-aligned carving for module-like allocations."""
        module = self.context.modules[self.config["kernel"]]
        layer = self.context.layers[module.layer_name]

        try:
            modules_start = int(module.object_from_symbol("module_alloc_base"))
        except Exception:
            modules_start = int(getattr(module, "offset", 0))

        try:
            modules_end = int(module.object_from_symbol("module_alloc_end"))
        except Exception:
            modules_end = modules_start + 0x4000000

        candidates: Set[int] = set()
        for base in range(modules_start, modules_end, 0x1000):
            try:
                mod_obj = module.object(object_type="module", offset=base, absolute=True)
                if not self._is_valid_module_candidate(mod_obj, modules_start, modules_end):
                    continue
                candidates.add(base)
            except exceptions.InvalidAddressException:
                continue
            except Exception:
                continue

        return candidates

    def _is_valid_module_candidate(self, mod_obj, modules_start: int, modules_end: int) -> bool:
        valid_states = {0, 1, 2, 3}
        try:
            state = int(mod_obj.state)
            name = utility.array_to_string(mod_obj.name)
            init_addr = int(mod_obj.init_layout.base)
        except Exception:
            return False

        if state not in valid_states:
            return False

        if not self._is_ascii_nul_terminated(name):
            return False

        return modules_start <= init_addr < modules_end

    def _is_ascii_nul_terminated(self, text: str) -> bool:
        if not text:
            return False
        if any(ord(ch) > 127 for ch in text):
            return False
        return "\x00" not in text

    def _collect_false_positive_regions(self) -> Set[MemoryRegion]:
        """Best-effort exclusion set: eBPF/ftrace/kprobe trampolines.

        These symbols are kernel-version dependent; the code intentionally degrades gracefully
        when symbols are absent.
        """
        regions: Set[MemoryRegion] = set()
        module = self.context.modules[self.config["kernel"]]

        for symbol in ("bpf_prog_active", "ftrace_ops_list", "kprobe_table"):
            try:
                obj = module.object_from_symbol(symbol)
                regions.add(MemoryRegion(base=int(obj.vol.offset), size=0x1000, source=f"filter:{symbol}"))
            except Exception:
                continue

        return regions

    def _overlaps(self, region: MemoryRegion, filters: Set[MemoryRegion]) -> bool:
        for flt in filters:
            if region.base < flt.end and flt.base < region.end:
                return True
        return False

    # ===== Subsystem B =====
    def _subsystem_b(self, regions: Set[MemoryRegion]) -> Set[HookAnomaly]:
        hooks: Set[HookAnomaly] = set()

        if self.config.get("enable_syscall_check", True):
            hooks |= self._check_syscall_table()
        if self.config.get("enable_idt_check", True):
            hooks |= self._check_idt()
        if self.config.get("enable_vfs_check", True):
            hooks |= self._check_vfs()
        if self.config.get("enable_netfilter_check", True):
            hooks |= self._check_netfilter()

        return hooks

    def _check_syscall_table(self) -> Set[HookAnomaly]:
        anomalies: Set[HookAnomaly] = set()
        module = self.context.modules[self.config["kernel"]]

        try:
            table = module.object_from_symbol("sys_call_table")
            kernel_ranges = self._kernel_text_ranges()
            module_ranges = self._module_text_ranges()

            for index, entry in enumerate(table):
                pointer = int(entry)
                if self._is_legitimate_text(pointer, kernel_ranges, module_ranges):
                    continue
                anomalies.add(HookAnomaly("syscall", f"sys_call_table[{index}]", pointer))
        except Exception as exc:
            vollog.debug("Syscall check failed: %s", exc)

        return anomalies

    def _check_idt(self) -> Set[HookAnomaly]:
        anomalies: Set[HookAnomaly] = set()
        module = self.context.modules[self.config["kernel"]]

        try:
            idt_table = module.object_from_symbol("idt_table")
            kernel_ranges = self._kernel_text_ranges()
            module_ranges = self._module_text_ranges()

            for index, gate in enumerate(idt_table):
                pointer = self._decode_idt_gate(gate)
                if self._is_legitimate_text(pointer, kernel_ranges, module_ranges):
                    continue
                anomalies.add(HookAnomaly("idt", f"idt[{index}]", pointer))
        except Exception as exc:
            vollog.debug("IDT check failed: %s", exc)

        return anomalies

    def _decode_idt_gate(self, gate) -> int:
        try:
            return int(gate.offset_low | (gate.offset_middle << 16) | (gate.offset_high << 32))
        except Exception:
            return 0

    def _check_vfs(self) -> Set[HookAnomaly]:
        anomalies: Set[HookAnomaly] = set()
        module = self.context.modules[self.config["kernel"]]
        kernel_ranges = self._kernel_text_ranges()
        module_ranges = self._module_text_ranges()

        try:
            mounts = module.object_from_symbol("mount_hashtable")
            for bucket in mounts:
                for mount in bucket.to_list("mount", "mnt_hash"):
                    fops = mount.mnt.mnt_root.d_inode.i_fop
                    for field_name in ("open", "read", "write", "iterate_shared"):
                        pointer = int(getattr(fops, field_name, 0) or 0)
                        if pointer == 0:
                            continue
                        if self._is_legitimate_text(pointer, kernel_ranges, module_ranges):
                            continue
                        anomalies.add(HookAnomaly("vfs", f"fops.{field_name}", pointer))
        except Exception as exc:
            vollog.debug("VFS check failed: %s", exc)

        return anomalies

    def _check_netfilter(self) -> Set[HookAnomaly]:
        anomalies: Set[HookAnomaly] = set()
        module = self.context.modules[self.config["kernel"]]
        kernel_ranges = self._kernel_text_ranges()
        module_ranges = self._module_text_ranges()

        try:
            nf_hooks = module.object_from_symbol("nf_hooks")
            for proto_idx, hook_array in enumerate(nf_hooks):
                for hook_idx, hook_head in enumerate(hook_array):
                    for hook in hook_head.to_list("nf_hook_ops", "list"):
                        pointer = int(hook.hook)
                        if self._is_legitimate_text(pointer, kernel_ranges, module_ranges):
                            continue
                        anomalies.add(HookAnomaly("netfilter", f"nf_hooks[{proto_idx}][{hook_idx}]", pointer))
        except Exception as exc:
            vollog.debug("Netfilter check failed: %s", exc)

        return anomalies

    def _kernel_text_ranges(self) -> List[Tuple[int, int]]:
        module = self.context.modules[self.config["kernel"]]
        ranges: List[Tuple[int, int]] = []
        for start_sym, end_sym in (("_stext", "_etext"), ("_text", "_end")):
            try:
                start = int(module.object_from_symbol(start_sym))
                end = int(module.object_from_symbol(end_sym))
                if start < end:
                    ranges.append((start, end))
            except Exception:
                continue
        return ranges

    def _module_text_ranges(self) -> List[Tuple[int, int]]:
        ranges: List[Tuple[int, int]] = []
        try:
            for mod in lsmod.Lsmod.list_modules(self.context, self.config["kernel"]):
                base = int(mod.core_layout.base)
                size = int(mod.core_layout.size)
                if size > 0:
                    ranges.append((base, base + size))
        except Exception:
            pass
        return ranges

    def _is_legitimate_text(
        self,
        pointer: int,
        kernel_ranges: Sequence[Tuple[int, int]],
        module_ranges: Sequence[Tuple[int, int]],
    ) -> bool:
        if pointer <= 0:
            return True

        for start, end in list(kernel_ranges) + list(module_ranges):
            if start <= pointer < end:
                return True

        return False

    # ===== Subsystem C =====
    def _subsystem_c(self) -> Set[int]:
        t_list = self._collect_tasks_from_list()
        t_runq = self._collect_tasks_from_runqueues()
        t_pid = self._collect_tasks_from_pid_hash()
        return (t_runq | t_pid) - t_list

    def _collect_tasks_from_list(self) -> Set[int]:
        pids: Set[int] = set()
        try:
            for task in pslist.PsList.list_tasks(self.context, self.config["kernel"]):
                pids.add(int(task.pid))
        except Exception as exc:
            vollog.debug("Failed to collect task list: %s", exc)
        return pids

    def _collect_tasks_from_runqueues(self) -> Set[int]:
        module = self.context.modules[self.config["kernel"]]
        pids: Set[int] = set()

        try:
            runqueues = module.object_from_symbol("runqueues")
            for rq in runqueues:
                cfs_rq = rq.cfs
                current = rq.curr
                if current:
                    pids.add(int(current.pid))
                for se in cfs_rq.tasks_timeline.to_list("sched_entity", "run_node"):
                    task = se.v() if hasattr(se, "v") else None
                    if task and hasattr(task, "pid"):
                        pids.add(int(task.pid))
        except Exception as exc:
            vollog.debug("Failed to collect runqueues: %s", exc)

        return pids

    def _collect_tasks_from_pid_hash(self) -> Set[int]:
        module = self.context.modules[self.config["kernel"]]
        pids: Set[int] = set()

        try:
            pidhash = module.object_from_symbol("pid_hash")
            for bucket in pidhash:
                for upid in bucket.to_list("upid", "pid_chain"):
                    if hasattr(upid, "pid") and upid.pid:
                        task = upid.pid.tasks[0].first
                        if task and hasattr(task, "pid"):
                            pids.add(int(task.pid))
        except Exception as exc:
            vollog.debug("Failed to collect pid hash: %s", exc)

        return pids
