from __future__ import annotations

import dataclasses
import logging
import struct
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.linux import lsmod

vollog = logging.getLogger(__name__)

LIST_POISON1 = 0xDEAD000000000100
CHUNK_SIZE = 0x1000000  # 16 MB
PAGE_SIZE = 0x1000
NEAR_MODULE_WINDOW = 0x8000000  # 128 MB


@dataclasses.dataclass(frozen=True)
class ModuleRegion:
    name: str
    base: int
    size: int

    @property
    def end(self) -> int:
        return self.base + self.size


@dataclasses.dataclass(frozen=True)
class EvidenceRow:
    subsystem: str
    object_type: str
    object_name: str
    field_name: str
    address: int
    region_class: str
    confidence: str
    note: str
    raw_pointer: int
    resolved_region: str
    source_structure: str


class CompositeRootkit(interfaces.plugins.PluginInterface):
    """Version 1 evidence-based Linux rootkit detector (Subsystem A + B1)."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

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
            ),
            requirements.BooleanRequirement(
                name="debug",
                description="Include debug details in rows",
                default=False,
                optional=True,
            ),
        ]

    def run(self) -> renderers.TreeGrid:
        rows = list(self._generator())
        return renderers.TreeGrid(
            [
                ("subsystem", str),
                ("object_type", str),
                ("object_name", str),
                ("field_name", str),
                ("address", format_hints.Hex),
                ("region_class", str),
                ("confidence", str),
                ("note", str),
                ("raw_pointer", format_hints.Hex),
                ("resolved_region", str),
                ("source_structure", str),
            ],
            rows,
        )

    def _generator(self) -> Iterator[Tuple[int, Tuple[object, ...]]]:
        known_modules = self._collect_known_modules()
        module_regions = [(m.base, m.end) for m in known_modules]

        kernel_start, kernel_end = self._kernel_text_range()
        modules_vaddr, modules_end = self._module_space_bounds(known_modules)

        evidence: List[EvidenceRow] = []
        evidence.extend(self._subsystem_a(known_modules, modules_vaddr, modules_end))
        evidence.extend(
            self._subsystem_b1(
                known_modules,
                module_regions,
                kernel_start,
                kernel_end,
                modules_vaddr,
                modules_end,
            )
        )

        classification = self._interpretation(evidence, known_modules)
        evidence.append(
            EvidenceRow(
                subsystem="A",
                object_type="interpretation",
                object_name="summary",
                field_name="rule",
                address=0,
                region_class="n/a",
                confidence="medium",
                note=classification,
                raw_pointer=0,
                resolved_region="n/a",
                source_structure="interpretation-layer",
            )
        )

        for row in evidence:
            yield (
                0,
                (
                    row.subsystem,
                    row.object_type,
                    row.object_name,
                    row.field_name,
                    format_hints.Hex(row.address),
                    row.region_class,
                    row.confidence,
                    row.note,
                    format_hints.Hex(row.raw_pointer),
                    row.resolved_region,
                    row.source_structure,
                ),
            )

    # ---------------------------- Subsystem A ----------------------------

    def _subsystem_a(
        self,
        known_modules: Sequence[ModuleRegion],
        modules_vaddr: int,
        modules_end: int,
    ) -> List[EvidenceRow]:
        evidence: List[EvidenceRow] = []
        known_keys = {(m.name, m.base) for m in known_modules}

        for addr in self._find_list_poison_pages(modules_vaddr, modules_end):
            mod = self._reconstruct_module(addr)
            if mod is None:
                evidence.append(
                    EvidenceRow(
                        subsystem="A",
                        object_type="orphan_region",
                        object_name="unknown",
                        field_name="module",
                        address=addr,
                        region_class="suspicious_executable",
                        confidence="low",
                        note="LIST_POISON signature hit; module reconstruction failed",
                        raw_pointer=addr,
                        resolved_region="module-space",
                        source_structure="page-carving",
                    )
                )
                continue

            name, base, size, completeness = mod
            if (name, base) in known_keys:
                continue

            if completeness == "strong":
                otype = "hidden_module_candidate"
                conf = "high"
            else:
                otype = "carved_module"
                conf = "medium"

            evidence.append(
                EvidenceRow(
                    subsystem="A",
                    object_type=otype,
                    object_name=name,
                    field_name="core_layout.base",
                    address=base,
                    region_class="known_module_text" if size > 0 else "unknown_mapped",
                    confidence=conf,
                    note=f"carved from module space page 0x{addr:x}",
                    raw_pointer=addr,
                    resolved_region=f"base=0x{base:x},size=0x{size:x}",
                    source_structure="struct module",
                )
            )

        return evidence

    def _find_list_poison_pages(self, start: int, end: int) -> Set[int]:
        sig = struct.pack("<Q", LIST_POISON1)
        hits: Set[int] = set()

        cur = start
        while cur < end:
            size = min(CHUNK_SIZE, end - cur)
            try:
                data = self.layer.read(cur, size, pad=True)
            except Exception:
                cur += size
                continue

            pos = data.find(sig)
            while pos != -1:
                va = cur + pos
                hits.add(va & ~(PAGE_SIZE - 1))
                pos = data.find(sig, pos + 1)

            cur += size

        return hits

    def _reconstruct_module(
        self, page_addr: int
    ) -> Optional[Tuple[str, int, int, str]]:
        try:
            mod = self.vmlinux.object(
                object_type="module", offset=page_addr, absolute=True
            )
        except Exception:
            return None

        name = self._safe_module_name(mod)
        if not self._valid_ascii_name(name):
            return None

        base = self._module_base(mod)
        size = self._module_size(mod)
        if base == 0:
            base = page_addr

        if size > 0 and base <= page_addr < base + size:
            return (name, base, size, "strong")
        return (name, base, max(size, PAGE_SIZE), "partial")

    # ---------------------------- Subsystem B1 ----------------------------

    def _subsystem_b1(
        self,
        known_modules: Sequence[ModuleRegion],
        module_regions: Sequence[Tuple[int, int]],
        kernel_start: int,
        kernel_end: int,
        modules_vaddr: int,
        modules_end: int,
    ) -> List[EvidenceRow]:
        evidence: List[EvidenceRow] = []

        table = self._locate_sys_call_table(kernel_start, kernel_end)
        if table is None:
            evidence.append(
                EvidenceRow(
                    subsystem="B1",
                    object_type="syscall_table",
                    object_name="sys_call_table",
                    field_name="base",
                    address=0,
                    region_class="invalid",
                    confidence="low",
                    note="sys_call_table unresolved (symbol + heuristic failed)",
                    raw_pointer=0,
                    resolved_region="unresolved",
                    source_structure="symbol+heuristic",
                )
            )
            return evidence

        for idx in range(0, 301):
            ptr_addr = table + (idx * self._ptr_size())
            raw_ptr = self._read_pointer(ptr_addr)
            p = self._canonicalize(raw_ptr)
            region = self._classify_region(
                p,
                kernel_start,
                kernel_end,
                module_regions,
                modules_vaddr,
                modules_end,
            )
            if region not in {"suspicious_executable", "unknown_mapped", "invalid"}:
                continue

            conf = (
                "high" if region in {"suspicious_executable", "invalid"} else "medium"
            )
            evidence.append(
                EvidenceRow(
                    subsystem="B1",
                    object_type="syscall",
                    object_name=f"sys_call_table[{idx}]",
                    field_name="handler",
                    address=p,
                    region_class=region,
                    confidence=conf,
                    note="syscall entry points outside expected trusted regions",
                    raw_pointer=raw_ptr,
                    resolved_region=self._region_debug(
                        p, known_modules, kernel_start, kernel_end
                    ),
                    source_structure="sys_call_table",
                )
            )

        return evidence

    def _locate_sys_call_table(
        self, kernel_start: int, kernel_end: int
    ) -> Optional[int]:
        try:
            sym = self.vmlinux.object_from_symbol(symbol_name="sys_call_table")
            return self._canonicalize(int(sym.vol.offset))
        except Exception:
            pass

        # Heuristic fallback: scan kernel text for pointer-array-like run.
        # Assumption: table-like region has many canonical kernel pointers.
        ptr_size = self._ptr_size()
        scan_end = min(kernel_start + 0x2000000, kernel_end)
        for addr in range(kernel_start, scan_end, PAGE_SIZE):
            try:
                page = self.layer.read(addr, PAGE_SIZE, pad=False)
            except Exception:
                continue
            good = 0
            for i in range(0, min(300 * ptr_size, len(page) - ptr_size), ptr_size):
                val = struct.unpack(
                    "<Q" if ptr_size == 8 else "<I", page[i : i + ptr_size]
                )[0]
                cval = self._canonicalize(val)
                if kernel_start <= cval < kernel_end:
                    good += 1
            if good >= 128:
                return addr
        return None

    # ---------------------------- Interpretation ----------------------------

    def _interpretation(
        self, evidence: Sequence[EvidenceRow], known_modules: Sequence[ModuleRegion]
    ) -> str:
        strong_a = [
            e
            for e in evidence
            if e.subsystem == "A"
            and e.confidence == "high"
            and e.object_type in {"hidden_module_candidate", "carved_module"}
        ]
        strong_b1 = [
            e for e in evidence if e.subsystem == "B1" and e.confidence == "high"
        ]

        if strong_a and strong_b1:
            for a in strong_a:
                for b in strong_b1:
                    if (
                        a.address != 0
                        and b.address != 0
                        and abs(a.address - b.address) < NEAR_MODULE_WINDOW
                    ):
                        return "Confirmed Hidden-Module Rootkit"

        if strong_b1:
            return "Likely Hook-Based Rootkit"

        if evidence:
            if any(e.confidence in {"low", "medium"} for e in evidence):
                return "Suspicious / Unconfirmed"

        return "Inconclusive"

    # ---------------------------- Helpers ----------------------------

    def _collect_known_modules(self) -> List[ModuleRegion]:
        out: List[ModuleRegion] = []
        for module in lsmod.Lsmod.list_modules(self.context, self.config["kernel"]):
            name = self._safe_module_name(module)
            base = self._module_base(module)
            size = self._module_size(module)
            if base == 0 or size <= 0 or not self._valid_ascii_name(name):
                continue
            out.append(ModuleRegion(name=name, base=base, size=size))
        return out

    def _module_space_bounds(
        self, known_modules: Sequence[ModuleRegion]
    ) -> Tuple[int, int]:
        try:
            start_obj = self.vmlinux.object_from_symbol(symbol_name="MODULES_VADDR")
            end_obj = self.vmlinux.object_from_symbol(symbol_name="MODULES_END")
            start = self._canonicalize(int(start_obj))
            end = self._canonicalize(int(end_obj))
            if start and end and end > start:
                return start, end
        except Exception:
            pass

        if known_modules:
            start = min(m.base for m in known_modules) - NEAR_MODULE_WINDOW
            end = max(m.end for m in known_modules) + NEAR_MODULE_WINDOW
            return max(start, 0), end

        return (0xFFFFFFFFA0000000, 0xFFFFFFFFFF000000)

    def _kernel_text_range(self) -> Tuple[int, int]:
        shift = self._kaslr_shift()
        stext = self._symbol_addr("_stext")
        etext = self._symbol_addr("_etext")
        start = self._canonicalize(stext + shift)
        end = self._canonicalize(etext + shift)
        if end <= start:
            return (0, 0)
        return (start, end)

    def _kaslr_shift(self) -> int:
        try:
            runtime = self.vmlinux.object_from_symbol(symbol_name="init_task")
            runtime_addr = self._canonicalize(int(runtime.vol.offset))
            static_addr = self._canonicalize(self._symbol_addr("init_task"))
            return runtime_addr - static_addr
        except Exception:
            return 0

    def _symbol_addr(self, name: str) -> int:
        try:
            sym = self.vmlinux.get_symbol(name)
            return int(sym.address)
        except Exception:
            return 0

    def _classify_region(
        self,
        ptr: int,
        kernel_start: int,
        kernel_end: int,
        module_regions: Sequence[Tuple[int, int]],
        modules_vaddr: int,
        modules_end: int,
    ) -> str:
        if ptr == 0:
            return "invalid"
        try:
            if not self.layer.is_valid(ptr, 1):
                return "invalid"
        except Exception:
            return "invalid"

        if kernel_start <= ptr < kernel_end:
            return "kernel_text"

        for start, end in module_regions:
            if start <= ptr < end:
                return "known_module_text"

        near_modules = False
        if modules_vaddr <= ptr < modules_end:
            near_modules = True
        else:
            for start, end in module_regions:
                if (start - NEAR_MODULE_WINDOW) <= ptr < (end + NEAR_MODULE_WINDOW):
                    near_modules = True
                    break

        if near_modules:
            return "suspicious_executable"

        return "unknown_mapped"

    def _region_debug(
        self,
        ptr: int,
        known_modules: Sequence[ModuleRegion],
        kernel_start: int,
        kernel_end: int,
    ) -> str:
        if kernel_start <= ptr < kernel_end:
            return "kernel_text"
        for m in known_modules:
            if m.base <= ptr < m.end:
                return f"module:{m.name}"
        return "non-whitelisted"

    def _read_pointer(self, addr: int) -> int:
        try:
            data = self.layer.read(addr, self._ptr_size(), pad=False)
            return struct.unpack("<Q" if self._ptr_size() == 8 else "<I", data)[0]
        except Exception:
            return 0

    def _ptr_size(self) -> int:
        return int(self.layer.bits_per_register // 8)

    def _canonicalize(self, ptr: int) -> int:
        ptr = int(ptr) & 0xFFFFFFFFFFFFFFFF
        if ptr & (1 << 47):
            ptr |= 0xFFFF000000000000
        return ptr & 0xFFFFFFFFFFFFFFFF

    def _safe_module_name(self, module) -> str:
        try:
            return utility.array_to_string(module.name) or ""
        except Exception:
            return ""

    def _module_base(self, module) -> int:
        for path in (
            ("core_layout", "base"),
            ("module_core",),
            ("core",),
        ):
            try:
                value = module
                for p in path:
                    value = getattr(value, p)
                base = self._canonicalize(int(value))
                if base:
                    return base
            except Exception:
                continue
        return 0

    def _module_size(self, module) -> int:
        for path in (
            ("core_layout", "size"),
            ("core_text_size",),
            ("core_size",),
        ):
            try:
                value = module
                for p in path:
                    value = getattr(value, p)
                size = int(value)
                if size > 0:
                    return size
            except Exception:
                continue
        return 0

    def _valid_ascii_name(self, value: str) -> bool:
        if not value or len(value) > 64:
            return False
        for c in value:
            if ord(c) < 32 or ord(c) > 126:
                return False
        return True
