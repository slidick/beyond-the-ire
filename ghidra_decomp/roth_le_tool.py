#!/usr/bin/env python3
"""Inspect and reconstruct the LE payload inside ROTH.EXE.

This is intentionally narrow: it targets the MZ-wrapped 32-bit LE executable
format used by Realms of the Haunting and emits diagnostics we can verify.
"""

from __future__ import annotations

import argparse
import json
import struct
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


SOURCE_MASK = 0x0F
SOURCE_BYTE = 0x00
SOURCE_SEG = 0x02
SOURCE_PTR_32 = 0x03
SOURCE_OFF_16 = 0x05
SOURCE_PTR_48 = 0x06
SOURCE_OFF_32 = 0x07
SOURCE_OFF_32_REL = 0x08
SOURCE_LIST = 0x20

TARGET_MASK = 0x03
TARGET_INTERNAL = 0x00
TARGET_EXT_ORD = 0x01
TARGET_EXT_NAME = 0x02
TARGET_INT_VIA_ENTRY = 0x03
TARGET_ADDITIVE = 0x04
TARGET_CHAIN = 0x08
TARGET_OFF_32 = 0x10
TARGET_ADD_32 = 0x20
TARGET_OBJMOD_16 = 0x40
TARGET_ORDINAL_8 = 0x80

OBJ_READABLE = 0x0001
OBJ_WRITEABLE = 0x0002
OBJ_EXECUTABLE = 0x0004


class LEError(Exception):
    """Raised for malformed or unsupported LE data."""


def u8(data: bytes, offset: int) -> int:
    return data[offset]


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def i16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<h", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def p24_be(data: bytes, offset: int) -> int:
    return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]


def write_u16(buf: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<H", buf, offset, value & 0xFFFF)


def write_u32(buf: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", buf, offset, value & 0xFFFFFFFF)


@dataclass(frozen=True)
class LEHeader:
    mz_offset: int
    signature: str
    byte_order: int
    word_order: int
    level: int
    cpu_type: int
    os_type: int
    version: int
    flags: int
    num_pages: int
    start_obj: int
    eip: int
    stack_obj: int
    esp: int
    page_size: int
    last_page: int
    fixup_size: int
    loader_size: int
    objtab_off: int
    num_objects: int
    objmap_off: int
    rsrc_off: int
    num_rsrcs: int
    resname_off: int
    entry_off: int
    fixpage_off: int
    fixrec_off: int
    impmod_off: int
    num_impmods: int
    impproc_off: int
    page_off: int
    num_preload: int
    nonres_off: int
    nonres_size: int
    autodata_obj: int
    debug_off: int
    debug_len: int
    stacksize: int

    @property
    def entry_va(self) -> int:
        return self.eip

    @property
    def fixrec_size(self) -> int:
        return self.impmod_off - self.fixrec_off


@dataclass(frozen=True)
class ObjectRecord:
    index: int
    size: int
    addr: int
    flags: int
    mapidx: int
    nummaps: int
    reserved: int

    @property
    def end(self) -> int:
        return self.addr + self.size

    @property
    def permissions(self) -> str:
        chars = [
            "r" if self.flags & OBJ_READABLE else "-",
            "w" if self.flags & OBJ_WRITEABLE else "-",
            "x" if self.flags & OBJ_EXECUTABLE else "-",
        ]
        return "".join(chars)


@dataclass(frozen=True)
class PageMapEntry:
    index: int
    page_num: int
    flags: int


@dataclass(frozen=True)
class Target:
    kind: int
    object_index: int | None = None
    offset: int | None = None
    module: int | None = None
    reference: int | None = None
    entry: int | None = None
    additive: int | None = None

    def describe(self) -> str:
        if self.kind == TARGET_INTERNAL:
            return f"obj{self.object_index}:0x{self.offset:x}"
        if self.kind == TARGET_INT_VIA_ENTRY:
            return f"entry:{self.entry}"
        if self.kind == TARGET_EXT_ORD:
            return f"extord mod={self.module} ref={self.reference}"
        if self.kind == TARGET_EXT_NAME:
            return f"extname mod={self.module} ref={self.reference}"
        return f"target-kind-{self.kind}"


@dataclass(frozen=True)
class FixupRecord:
    page_index: int
    record_offset: int
    record_size: int
    source_type: int
    source_flags: int
    target_flags: int
    source_offsets: tuple[int, ...]
    target: Target

    @property
    def target_kind(self) -> int:
        return self.target_flags & TARGET_MASK


class ROTHLinearExecutable:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        self.header = self._parse_header()
        self.objects = self._parse_objects()
        self.page_map = self._parse_page_map()
        self.fixup_page_table = self._parse_fixup_page_table()
        self.fixups = self._parse_fixups()

    def _parse_header(self) -> LEHeader:
        if len(self.data) < 0x40:
            raise LEError("file is too small for an MZ header")
        if self.data[:2] != b"MZ":
            raise LEError("missing MZ signature")
        mz_offset = u32(self.data, 0x3C)
        if self.data[mz_offset : mz_offset + 2] != b"LE":
            sig = self.data[mz_offset : mz_offset + 2]
            raise LEError(f"expected LE signature at 0x{mz_offset:x}, found {sig!r}")

        base = mz_offset
        return LEHeader(
            mz_offset=mz_offset,
            signature="LE",
            byte_order=u8(self.data, base + 0x02),
            word_order=u8(self.data, base + 0x03),
            level=u32(self.data, base + 0x04),
            cpu_type=u16(self.data, base + 0x08),
            os_type=u16(self.data, base + 0x0A),
            version=u32(self.data, base + 0x0C),
            flags=u32(self.data, base + 0x10),
            num_pages=u32(self.data, base + 0x14),
            start_obj=u32(self.data, base + 0x18),
            eip=u32(self.data, base + 0x1C),
            stack_obj=u32(self.data, base + 0x20),
            esp=u32(self.data, base + 0x24),
            page_size=u32(self.data, base + 0x28),
            last_page=u32(self.data, base + 0x2C),
            fixup_size=u32(self.data, base + 0x30),
            loader_size=u32(self.data, base + 0x38),
            objtab_off=u32(self.data, base + 0x40),
            num_objects=u32(self.data, base + 0x44),
            objmap_off=u32(self.data, base + 0x48),
            rsrc_off=u32(self.data, base + 0x50),
            num_rsrcs=u32(self.data, base + 0x54),
            resname_off=u32(self.data, base + 0x58),
            entry_off=u32(self.data, base + 0x5C),
            fixpage_off=u32(self.data, base + 0x68),
            fixrec_off=u32(self.data, base + 0x6C),
            impmod_off=u32(self.data, base + 0x70),
            num_impmods=u32(self.data, base + 0x74),
            impproc_off=u32(self.data, base + 0x78),
            page_off=u32(self.data, base + 0x80),
            num_preload=u32(self.data, base + 0x84),
            nonres_off=u32(self.data, base + 0x88),
            nonres_size=u32(self.data, base + 0x8C),
            autodata_obj=u32(self.data, base + 0x94),
            debug_off=u32(self.data, base + 0x98),
            debug_len=u32(self.data, base + 0x9C),
            stacksize=u32(self.data, base + 0xAC),
        )

    def _parse_objects(self) -> list[ObjectRecord]:
        out = []
        base = self.header.mz_offset + self.header.objtab_off
        for i in range(self.header.num_objects):
            off = base + i * 24
            out.append(
                ObjectRecord(
                    index=i + 1,
                    size=u32(self.data, off + 0x00),
                    addr=u32(self.data, off + 0x04),
                    flags=u32(self.data, off + 0x08),
                    mapidx=u32(self.data, off + 0x0C),
                    nummaps=u32(self.data, off + 0x10),
                    reserved=u32(self.data, off + 0x14),
                )
            )
        return out

    def _parse_page_map(self) -> list[PageMapEntry]:
        out = []
        base = self.header.mz_offset + self.header.objmap_off
        for i in range(self.header.num_pages):
            off = base + i * 4
            out.append(
                PageMapEntry(
                    index=i + 1,
                    page_num=p24_be(self.data, off),
                    flags=u8(self.data, off + 3),
                )
            )
        return out

    def _parse_fixup_page_table(self) -> list[int]:
        base = self.header.mz_offset + self.header.fixpage_off
        return [u32(self.data, base + i * 4) for i in range(self.header.num_pages + 1)]

    def _parse_fixups(self) -> list[FixupRecord]:
        if len(self.fixup_page_table) != self.header.num_pages + 1:
            raise LEError("fixup page table length does not match page count")
        if any(
            self.fixup_page_table[i] > self.fixup_page_table[i + 1]
            for i in range(len(self.fixup_page_table) - 1)
        ):
            raise LEError("fixup page table is not monotonic")
        if self.fixup_page_table[-1] != self.header.fixrec_size:
            raise LEError(
                "fixup record stream length mismatch: "
                f"page table ends at 0x{self.fixup_page_table[-1]:x}, "
                f"header implies 0x{self.header.fixrec_size:x}"
            )

        records = []
        stream_base = self.header.mz_offset + self.header.fixrec_off
        for page_index in range(1, self.header.num_pages + 1):
            page_start = self.fixup_page_table[page_index - 1]
            page_end = self.fixup_page_table[page_index]
            pos = stream_base + page_start
            end = stream_base + page_end
            while pos < end:
                record_start = pos
                record = self._parse_fixup_record(page_index, stream_base, pos)
                pos = record_start + record.record_size
                if pos > end:
                    raise LEError(
                        f"fixup record at page {page_index} offset "
                        f"0x{record.record_offset:x} overruns its page boundary"
                    )
                records.append(record)
            if pos != end:
                raise LEError(f"fixup parser stopped early on page {page_index}")
        return records

    def _parse_fixup_record(
        self, page_index: int, stream_base: int, absolute_offset: int
    ) -> FixupRecord:
        pos = absolute_offset
        source_byte = u8(self.data, pos)
        pos += 1
        target_flags = u8(self.data, pos)
        pos += 1

        source_type = source_byte & SOURCE_MASK
        source_flags = source_byte & ~SOURCE_MASK
        source_offsets: list[int] = []
        if source_flags & SOURCE_LIST:
            count = u8(self.data, pos)
            pos += 1
            for _ in range(count):
                source_offsets.append(i16(self.data, pos))
                pos += 2
        else:
            source_offsets.append(i16(self.data, pos))
            pos += 2

        target_kind = target_flags & TARGET_MASK
        additive = None
        if target_kind == TARGET_INTERNAL:
            if target_flags & TARGET_OBJMOD_16:
                object_index = u16(self.data, pos)
                pos += 2
            else:
                object_index = u8(self.data, pos)
                pos += 1

            if target_flags & TARGET_CHAIN:
                target_offset = None
            elif target_flags & TARGET_OFF_32:
                target_offset = u32(self.data, pos)
                pos += 4
            else:
                target_offset = u16(self.data, pos)
                pos += 2

            if target_flags & TARGET_ADDITIVE:
                additive, pos = self._parse_additive(target_flags, pos)
            target = Target(
                kind=target_kind,
                object_index=object_index,
                offset=target_offset,
                additive=additive,
            )
        elif target_kind == TARGET_INT_VIA_ENTRY:
            if target_flags & TARGET_ORDINAL_8:
                entry = u8(self.data, pos)
                pos += 1
            else:
                entry = u16(self.data, pos)
                pos += 2
            if target_flags & TARGET_ADDITIVE:
                additive, pos = self._parse_additive(target_flags, pos)
            target = Target(kind=target_kind, entry=entry, additive=additive)
        else:
            if target_flags & TARGET_OBJMOD_16:
                module = u16(self.data, pos)
                pos += 2
            else:
                module = u8(self.data, pos)
                pos += 1
            if target_flags & TARGET_ORDINAL_8:
                reference = u8(self.data, pos)
                pos += 1
            else:
                reference = u16(self.data, pos)
                pos += 2
            if target_flags & TARGET_ADDITIVE:
                additive, pos = self._parse_additive(target_flags, pos)
            target = Target(
                kind=target_kind,
                module=module,
                reference=reference,
                additive=additive,
            )

        return FixupRecord(
            page_index=page_index,
            record_offset=absolute_offset - stream_base,
            record_size=pos - absolute_offset,
            source_type=source_type,
            source_flags=source_flags,
            target_flags=target_flags,
            source_offsets=tuple(source_offsets),
            target=target,
        )

    def _parse_additive(self, target_flags: int, pos: int) -> tuple[int, int]:
        if target_flags & TARGET_ADD_32:
            return u32(self.data, pos), pos + 4
        return u16(self.data, pos), pos + 2

    def object_for_index(self, index: int) -> ObjectRecord:
        try:
            return self.objects[index - 1]
        except IndexError as exc:
            raise LEError(f"invalid object index {index}") from exc

    def object_for_page(self, page_index: int) -> ObjectRecord:
        for obj in self.objects:
            first = obj.mapidx
            last = obj.mapidx + obj.nummaps - 1
            if first <= page_index <= last:
                return obj
        raise LEError(f"page {page_index} does not belong to any object")

    def page_file_offset(self, page_entry: PageMapEntry) -> int | None:
        if page_entry.page_num == 0:
            return None
        return self.header.page_off + (page_entry.page_num - 1) * self.header.page_size

    def page_data_size(self, page_entry: PageMapEntry) -> int:
        if page_entry.page_num == 0:
            return 0
        if page_entry.page_num == self.header.num_pages and self.header.last_page:
            return self.header.last_page
        return self.header.page_size

    def build_objects(self, apply_fixups: bool = False) -> dict[int, bytearray]:
        images = {obj.index: bytearray(obj.size) for obj in self.objects}
        for obj in self.objects:
            image = images[obj.index]
            for page_number_in_object in range(obj.nummaps):
                map_index = obj.mapidx + page_number_in_object
                page_entry = self.page_map[map_index - 1]
                file_offset = self.page_file_offset(page_entry)
                if file_offset is None:
                    continue
                object_offset = page_number_in_object * self.header.page_size
                if object_offset >= obj.size:
                    continue
                copy_size = min(
                    self.page_data_size(page_entry),
                    self.header.page_size,
                    obj.size - object_offset,
                    len(self.data) - file_offset,
                )
                if copy_size < 0:
                    raise LEError(f"invalid page copy size for page {map_index}")
                image[object_offset : object_offset + copy_size] = self.data[
                    file_offset : file_offset + copy_size
                ]

        if apply_fixups:
            self.apply_fixups(images)
        return images

    def apply_fixups(self, images: dict[int, bytearray]) -> Counter:
        counts: Counter = Counter()
        for record in self.fixups:
            if record.target_kind != TARGET_INTERNAL:
                counts["skipped_non_internal"] += 1
                continue
            if record.target.object_index is None or record.target.offset is None:
                counts["skipped_unresolved_target"] += 1
                continue
            target_obj = self.object_for_index(record.target.object_index)
            value = target_obj.addr + record.target.offset
            if record.target.additive is not None:
                value += record.target.additive

            source_obj = self.object_for_page(record.page_index)
            source_page_in_object = record.page_index - source_obj.mapidx
            source_page_base = source_page_in_object * self.header.page_size
            source_image = images[source_obj.index]
            for source_offset in record.source_offsets:
                write_offset = source_page_base + source_offset
                if write_offset >= len(source_image):
                    counts["skipped_source_out_of_object"] += 1
                    continue
                if record.source_type == SOURCE_OFF_32:
                    if write_offset + 4 > len(source_image):
                        counts["skipped_source_out_of_object"] += 1
                        continue
                    write_u32(source_image, write_offset, value)
                    counts["applied_off32"] += 1
                elif record.source_type == SOURCE_OFF_16:
                    if write_offset + 2 > len(source_image):
                        counts["skipped_source_out_of_object"] += 1
                        continue
                    write_u16(source_image, write_offset, value)
                    counts["applied_off16"] += 1
                else:
                    counts[f"skipped_source_type_{record.source_type}"] += 1
        return counts

    def flat_image(self, images: dict[int, bytearray]) -> tuple[int, bytearray]:
        min_addr = min(obj.addr for obj in self.objects)
        max_addr = max(obj.end for obj in self.objects)
        image = bytearray(max_addr - min_addr)
        for obj in self.objects:
            object_image = images[obj.index]
            start = obj.addr - min_addr
            image[start : start + len(object_image)] = object_image
        return min_addr, image

    def validate(self) -> list[str]:
        messages = []
        h = self.header
        page_data_bytes = sum(self.page_data_size(page) for page in self.page_map)
        expected_end = h.page_off + page_data_bytes
        if expected_end != len(self.data):
            messages.append(
                "page data does not end at EOF: "
                f"expected 0x{expected_end:x}, file length 0x{len(self.data):x}"
            )
        if h.byte_order != 0 or h.word_order != 0:
            messages.append("non-little-endian LE file")
        if h.page_size != 0x1000:
            messages.append(f"unexpected page size 0x{h.page_size:x}")
        object_pages = sum(obj.nummaps for obj in self.objects)
        if object_pages != h.num_pages:
            messages.append(
                f"object page count {object_pages} != header page count {h.num_pages}"
            )
        return messages

    def fixup_summary(self) -> dict[str, object]:
        source_types = Counter(record.source_type for record in self.fixups)
        source_flags = Counter(record.source_flags for record in self.fixups)
        target_flags = Counter(record.target_flags for record in self.fixups)
        target_objects = Counter(
            record.target.object_index
            for record in self.fixups
            if record.target.object_index is not None
        )
        record_sizes = Counter(record.record_size for record in self.fixups)
        pages_with_fixups = len({record.page_index for record in self.fixups})
        return {
            "records": len(self.fixups),
            "pages_with_fixups": pages_with_fixups,
            "source_types": dict(sorted(source_types.items())),
            "source_flags": dict(sorted(source_flags.items())),
            "target_flags": dict(sorted(target_flags.items())),
            "target_objects": dict(sorted(target_objects.items())),
            "record_sizes": dict(sorted(record_sizes.items())),
        }


def hex_or_none(value: int | None) -> str:
    if value is None:
        return "none"
    return f"0x{value:x}"


def print_summary(exe: ROTHLinearExecutable) -> None:
    h = exe.header
    print(f"path: {exe.path}")
    print(f"file_size: 0x{len(exe.data):x} ({len(exe.data)} bytes)")
    print(f"mz_le_offset: 0x{h.mz_offset:x}")
    print(f"signature: {h.signature}")
    print(f"cpu_type: {h.cpu_type}")
    print(f"os_type: {h.os_type}")
    print(f"flags: 0x{h.flags:x}")
    print(f"num_pages: {h.num_pages}")
    print(f"page_size: 0x{h.page_size:x}")
    print(f"last_page: 0x{h.last_page:x}")
    print(f"page_data_offset: 0x{h.page_off:x}")
    print(f"fixup_size: 0x{h.fixup_size:x}")
    print(f"loader_size: 0x{h.loader_size:x}")
    print(f"fixup_record_bytes: 0x{h.fixrec_size:x}")
    print(
        "entry: "
        f"obj{h.start_obj}:0x{h.eip:x} "
        f"(VA 0x{exe.object_for_index(h.start_obj).addr + h.eip:x})"
    )
    print(
        "stack: "
        f"obj{h.stack_obj}:0x{h.esp:x} "
        f"(VA 0x{exe.object_for_index(h.stack_obj).addr + h.esp:x})"
    )
    print(f"autodata_obj: {h.autodata_obj}")
    print()
    print("objects:")
    for obj in exe.objects:
        print(
            f"  obj{obj.index}: base=0x{obj.addr:x} end=0x{obj.end:x} "
            f"size=0x{obj.size:x} flags=0x{obj.flags:x} perms={obj.permissions} "
            f"mapidx={obj.mapidx} pages={obj.nummaps}"
        )
    print()
    print("validation:")
    problems = exe.validate()
    if problems:
        for problem in problems:
            print(f"  FAIL: {problem}")
    else:
        print("  ok")


def print_fixups(exe: ROTHLinearExecutable, limit: int) -> None:
    summary = exe.fixup_summary()
    print(json.dumps(summary, indent=2, sort_keys=True))
    print()
    print(f"first_{limit}_records:")
    for record in exe.fixups[:limit]:
        source_obj = exe.object_for_page(record.page_index)
        source_page_in_object = record.page_index - source_obj.mapidx
        source_base = source_obj.addr + source_page_in_object * exe.header.page_size
        source_addrs = [source_base + off for off in record.source_offsets]
        print(
            f"  page={record.page_index} rec=0x{record.record_offset:x} "
            f"size={record.record_size} source_type=0x{record.source_type:x} "
            f"target_flags=0x{record.target_flags:x} "
            f"source={','.join(hex(addr) for addr in source_addrs)} "
            f"target={record.target.describe()}"
        )


def write_outputs(
    exe: ROTHLinearExecutable,
    out_dir: Path,
    apply_fixups: bool,
    write_flat: bool,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    images = exe.build_objects(apply_fixups=False)
    fixup_counts: Counter | None = None
    if apply_fixups:
        fixup_counts = exe.apply_fixups(images)
    suffix = "reloc" if apply_fixups else "raw"
    manifest = {
        "input": str(exe.path),
        "apply_fixups": apply_fixups,
        "objects": [],
    }
    for obj in exe.objects:
        filename = f"object{obj.index}_{suffix}.bin"
        path = out_dir / filename
        path.write_bytes(images[obj.index])
        manifest["objects"].append(
            {
                "index": obj.index,
                "base": obj.addr,
                "end": obj.end,
                "size": obj.size,
                "flags": obj.flags,
                "permissions": obj.permissions,
                "file": filename,
            }
        )

    if fixup_counts is not None:
        manifest["fixups"] = dict(sorted(fixup_counts.items()))

    if write_flat:
        base, image = exe.flat_image(images)
        filename = f"flat_{suffix}.bin"
        (out_dir / filename).write_bytes(image)
        manifest["flat"] = {
            "base": base,
            "end": base + len(image),
            "size": len(image),
            "file": filename,
        }

    (out_dir / f"manifest_{suffix}.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="ascii",
    )
    print(f"wrote {out_dir}")
    if fixup_counts is not None:
        print(f"fixups: {dict(sorted(fixup_counts.items()))}")


def command_summary(args: argparse.Namespace) -> None:
    print_summary(ROTHLinearExecutable(args.exe))


def command_fixups(args: argparse.Namespace) -> None:
    print_fixups(ROTHLinearExecutable(args.exe), args.limit)


def command_extract(args: argparse.Namespace) -> None:
    write_outputs(
        ROTHLinearExecutable(args.exe),
        args.out_dir,
        args.apply_fixups,
        args.flat,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "exe",
        nargs="?",
        type=Path,
        default=Path("ROTH.EXE"),
        help="path to ROTH.EXE",
    )
    subparsers = parser.add_subparsers(dest="command")

    summary = subparsers.add_parser("summary", help="print LE header/object summary")
    summary.set_defaults(func=command_summary)

    fixups = subparsers.add_parser("fixups", help="print fixup table summary")
    fixups.add_argument("--limit", type=int, default=12, help="example record count")
    fixups.set_defaults(func=command_fixups)

    extract = subparsers.add_parser("extract", help="extract object images")
    extract.add_argument("--out-dir", type=Path, default=Path("analysis/le_image"))
    extract.add_argument("--apply-fixups", action="store_true")
    extract.add_argument("--flat", action="store_true", help="also write flat image")
    extract.set_defaults(func=command_extract)

    parser.set_defaults(func=command_summary)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
