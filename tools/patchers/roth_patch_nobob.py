#!/usr/bin/env python3
"""Patch ROTH.EXE to disable the vertical camera head-bob.

Mechanism: the eye-height routine at flat VA 0x3ed94 does
    cmp [bob_amplitude], 0 ; je skip_bob
The bob amplitude ramps up while walking and decays when still; when it is 0 the engine
already skips the bob and uses the plain standing eye height. Forcing that conditional
jump to be unconditional makes the engine ALWAYS take the no-bob path -> constant eye
height, no head-bob. One byte: je (0x74) -> jmp (0xEB).

This is non-destructive: it reads ROTH.EXE and writes a new ROTH_NOBOB.EXE. It verifies
a unique byte signature first and refuses to patch anything that does not match (wrong
file / wrong version).

Usage:
    python3 tools/roth_patch_nobob.py            # ROTH.EXE -> ROTH_NOBOB.EXE
    python3 tools/roth_patch_nobob.py in.exe out.exe
"""
import sys, os

# Verified location: unique signature in the retail ROTH.EXE (release 1.4; the embedded
# "Version 3.925" string is an internal/engine version, not the release version).
PATCH_OFFSET = 0x51794            # file offset of the `je` opcode byte
# je 0x3edd9 ; lea edi,[edi+edi*2] ; shr edi,1 ; and edi,0x3e  -- non-relocated, unique
SIGNATURE = bytes.fromhex("74438d3c7fd1ef83e73e")
ORIG_BYTE = 0x74                 # je rel8
NEW_BYTE  = 0xEB                 # jmp rel8 (same operand/target)

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(here)
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(repo, "ROTH.EXE")
    dst = sys.argv[2] if len(sys.argv) > 2 else os.path.join(repo, "ROTH_NOBOB.EXE")

    with open(src, "rb") as f:
        data = bytearray(f.read())

    actual = bytes(data[PATCH_OFFSET:PATCH_OFFSET + len(SIGNATURE)])
    if actual == SIGNATURE.replace(bytes([ORIG_BYTE]), bytes([NEW_BYTE]), 1):
        print("Already patched (jmp present at offset). Nothing to do.")
        return 0
    if actual != SIGNATURE:
        print(f"ERROR: signature mismatch at {PATCH_OFFSET:#x}.")
        print(f"  expected {SIGNATURE.hex()}")
        print(f"  found    {actual.hex()}")
        print("Refusing to patch. Is this the expected ROTH.EXE (version 3.925)?")
        return 1

    data[PATCH_OFFSET] = NEW_BYTE
    with open(dst, "wb") as f:
        f.write(data)
    print(f"Patched head-bob disabled: {os.path.basename(src)} -> {os.path.basename(dst)}")
    print(f"  byte at {PATCH_OFFSET:#x}: {ORIG_BYTE:#04x} (je) -> {NEW_BYTE:#04x} (jmp)")
    print("Run the new exe in DOSBox. To revert: just use the original ROTH.EXE.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
