#!/usr/bin/env python3
"""Patch origin_bin without increasing its file size.

Fixes:
  * bounds checking in delete() and show(): 0 <= idx < 10
  * UAF/double-free in delete(): ptr[idx] is cleared before free()

The new instructions are stored in the zero-filled gap at file offsets
0xCA0..0xCE3.  The existing RX PT_LOAD entry is extended just far enough to
map that gap; no bytes are appended to the ELF file.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import struct
import sys


INPUT = Path("origin_bin")
OUTPUT = Path("patched_bin")

EXPECTED_SHA256 = "d2b310c9f1ebc6663975eb4e62cf2758f70be700efe720409799e01f4e49117a"
IMAGE_BASE = 0x400000

# Hook the first instruction after scanf() in each vulnerable function.
DELETE_HOOK_OFF = 0x936
SHOW_HOOK_OFF = 0x979
DELETE_HOOK_VA = IMAGE_BASE + DELETE_HOOK_OFF
SHOW_HOOK_VA = IMAGE_BASE + SHOW_HOOK_OFF

# Zero-filled file gap immediately after the original RX PT_LOAD image.
DELETE_CAVE_OFF = 0xCA0
SHOW_CAVE_OFF = 0xCD0
DELETE_CAVE_VA = IMAGE_BASE + DELETE_CAVE_OFF
SHOW_CAVE_VA = IMAGE_BASE + SHOW_CAVE_OFF

# Third ELF64 program header (the executable PT_LOAD), p_filesz/p_memsz.
RX_FILESZ_OFF = 0xD0
RX_MEMSZ_OFF = 0xD8
ORIGINAL_RX_SIZE = 0xC9C


def rel32(opcode: int, source_va: int, target_va: int) -> bytes:
    """Encode a five-byte x86-64 rel32 call/jump."""
    displacement = target_va - (source_va + 5)
    if not -(1 << 31) <= displacement < (1 << 31):
        raise ValueError("rel32 target is out of range")
    return bytes([opcode]) + struct.pack("<i", displacement)


def checked_replace(image: bytearray, offset: int, expected: bytes, new: bytes) -> None:
    if len(expected) != len(new):
        raise ValueError("checked replacement must keep the same length")
    actual = bytes(image[offset : offset + len(expected)])
    if actual != expected:
        raise RuntimeError(
            f"unexpected bytes at file offset 0x{offset:x}: "
            f"expected {expected.hex()}, found {actual.hex()}"
        )
    image[offset : offset + len(new)] = new


def build_delete_stub() -> bytes:
    # movsxd rax, dword ptr [rsp+0xc]
    # cmp    eax, 10
    # jae    invalid                 ; unsigned: rejects negative and >= 10
    # mov    rdi, [rax*8+0x6010a0]  ; save ptr[idx] as free() argument
    # mov    qword ptr [rax*8+0x6010a0], 0
    # call   free@plt
    # invalid:
    # jmp    delete epilogue
    stub = bytearray.fromhex(
        "486344240c"
        "83f80a"
        "7319"
        "488b3cc5a0106000"
        "48c704c5a010600000000000"
    )
    stub += rel32(0xE8, DELETE_CAVE_VA + len(stub), 0x400640)
    stub += rel32(0xE9, DELETE_CAVE_VA + len(stub), 0x400948)
    if len(stub) != 40:
        raise AssertionError("unexpected delete stub size")
    return bytes(stub)


def build_show_stub() -> bytes:
    # movsxd rax, dword ptr [rsp+0xc]
    # cmp    eax, 10
    # jae    invalid                 ; unsigned: rejects negative and >= 10
    # jmp    original safe body      ; ptr[idx] access and printf
    # invalid:
    # jmp    show epilogue
    stub = bytearray.fromhex("486344240c83f80a7305")
    stub += rel32(0xE9, SHOW_CAVE_VA + len(stub), 0x40097E)
    stub += rel32(0xE9, SHOW_CAVE_VA + len(stub), 0x40099A)
    if len(stub) != 20:
        raise AssertionError("unexpected show stub size")
    return bytes(stub)


def main() -> int:
    try:
        original = INPUT.read_bytes()
    except FileNotFoundError:
        print(f"error: {INPUT} was not found", file=sys.stderr)
        return 1

    digest = hashlib.sha256(original).hexdigest()
    if digest != EXPECTED_SHA256:
        print(
            f"error: unsupported {INPUT} (sha256 {digest}); refusing to patch",
            file=sys.stderr,
        )
        return 1

    image = bytearray(original)
    if image[:6] != b"\x7fELF\x02\x01":
        print("error: input is not a little-endian ELF64 file", file=sys.stderr)
        return 1

    delete_stub = build_delete_stub()
    show_stub = build_show_stub()
    cave_end = SHOW_CAVE_OFF + len(show_stub)

    # Verify the code cave is genuinely unused before placing code there.
    cave = bytes(image[DELETE_CAVE_OFF:cave_end])
    if cave != bytes(len(cave)):
        print("error: expected code-cave range is not zero-filled", file=sys.stderr)
        return 1

    checked_replace(
        image,
        DELETE_HOOK_OFF,
        bytes.fromhex("486344240c"),
        rel32(0xE9, DELETE_HOOK_VA, DELETE_CAVE_VA),
    )
    checked_replace(
        image,
        SHOW_HOOK_OFF,
        bytes.fromhex("486344240c"),
        rel32(0xE9, SHOW_HOOK_VA, SHOW_CAVE_VA),
    )

    image[DELETE_CAVE_OFF : DELETE_CAVE_OFF + len(delete_stub)] = delete_stub
    image[SHOW_CAVE_OFF : SHOW_CAVE_OFF + len(show_stub)] = show_stub

    # Map the cave as part of the existing executable segment. Only existing
    # ELF-header bytes are changed; the file itself is never enlarged.
    checked_replace(
        image,
        RX_FILESZ_OFF,
        struct.pack("<Q", ORIGINAL_RX_SIZE),
        struct.pack("<Q", cave_end),
    )
    checked_replace(
        image,
        RX_MEMSZ_OFF,
        struct.pack("<Q", ORIGINAL_RX_SIZE),
        struct.pack("<Q", cave_end),
    )

    if len(image) != len(original):
        raise AssertionError("patch unexpectedly changed the ELF file size")

    OUTPUT.write_bytes(image)
    os.chmod(OUTPUT, INPUT.stat().st_mode & 0o777)

    print(f"patched: {INPUT} -> {OUTPUT}")
    print(f"size:    {len(original)} bytes (unchanged)")
    print(f"sha256:  {hashlib.sha256(image).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
