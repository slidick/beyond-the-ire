#!/usr/bin/env python3
"""Patch ROTH.EXE to enable the hidden developer/debug mode on startup.

Mechanism: the shipped game contains a dormant dev mode
gated by the boolean g_dev_mode_flag (VA 0x7f560, bit 0), which lives in BSS and is
never set. The developers' own enable routine enable_dev_mode (VA 0x14464) does
    mov byte [0x7f560],1 ; not byte [0x7f36f] ; ret
but has ZERO cross-references, so it is never called. (0x7f36f is dead: nothing reads
it, so calling enable_dev_mode is functionally just "set the master flag".)

This patch makes startup call enable_dev_mode once, persistently:

  1. Hijack the existing `call 0x10458` inside roth_game_startup (VA 0x10035) and point
     it at a code cave instead.
  2. The code cave (16 bytes of inter-function padding at VA 0x146d8) runs:
         call enable_dev_mode (0x14464)   ; set the dev-mode flag
         call 0x10458                     ; perform the original hijacked call
         ret                              ; return to startup at 0x1003a
     so the original startup subroutine still runs, in order, and control returns
     exactly where it would have. enable_dev_mode touches only memory + flags (no GP
     register clobber), so the hijacked subroutine sees an identical machine state.

Everything injected is RELATIVE (E8 call rel32 / C3 ret) — no absolute operands — so no
LE relocation/fixup is needed. enable_dev_mode's own absolute flag write is already a
relocated instruction in the shipped file; we just reach it via a relative call.

Once enabled, the dev features behave exactly as the developers intended (toggleable):
  - 'W' opens the map-selector menu; '+'/'-' choose a map; RETURN warps there (instant
    any-map teleport — a practice/routing tool).
  - 'L' toggles the maphack overlay (g_dev_flag_0x7f36e; OFF by default, so the screen
    is NOT cluttered until you press L).
  - 'Spacebar' opens the door directly in front of the player (the player must be 
    standing right at the door)

Non-destructive: reads ROTH.EXE, writes a new ROTH_DEVMODE.EXE. Verifies unique byte
signatures first and refuses to patch anything that does not match (wrong file/version).

Usage:
    python3 tools/roth_patch_devmode.py            # ROTH.EXE -> ROTH_DEVMODE.EXE
    python3 tools/roth_patch_devmode.py in.exe out.exe
"""
import sys, os

# --- Hijack site: the `call 0x10458` at flat VA 0x10035 inside roth_game_startup. ---
# Signature is the preceding `mov dword [0x85c34],0x1000` + the call (relative -> the
# file bytes equal the relocated image bytes here). Unique in the retail 1.4 exe.
HIJACK_OFFSET = 0x22a35                              # file offset of the E8 call opcode
HIJACK_SIG    = bytes.fromhex("c705345c010000100000e81e040000")  # mov ...,0x1000 ; call 0x10458
HIJACK_CALL_IDX = HIJACK_SIG.index(bytes.fromhex("e81e040000"))  # call within the signature
HIJACK_ORIG   = bytes.fromhex("e81e040000")          # call 0x10458  (rel32 0x0000041e)
HIJACK_NEW    = bytes.fromhex("e89e460000")          # call 0x146d8  (rel32 0x0000469e -> cave)

# --- Code cave: 16 bytes of inter-function zero padding at flat VA 0x146d8. ---
CAVE_OFFSET = 0x270d8                                # file offset of the padding gap
CAVE_ORIG   = bytes(16)                              # must be all zero (untouched padding)
#   call 0x14464 (enable_dev_mode) ; call 0x10458 ; ret    -- all relative, 11 bytes
CAVE_STUB   = bytes.fromhex("e887fdffff" "e876bdffff" "c3")
assert len(CAVE_STUB) <= len(CAVE_ORIG)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(here)
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(repo, "ROTH.EXE")
    dst = sys.argv[2] if len(sys.argv) > 2 else os.path.join(repo, "ROTH_DEVMODE.EXE")

    with open(src, "rb") as f:
        data = bytearray(f.read())

    hij  = bytes(data[HIJACK_OFFSET:HIJACK_OFFSET + len(HIJACK_ORIG)])
    cave = bytes(data[CAVE_OFFSET:CAVE_OFFSET + len(CAVE_STUB)])

    # Idempotency: already patched?
    if hij == HIJACK_NEW and cave == CAVE_STUB:
        print("Already patched (dev mode enable present). Nothing to do.")
        return 0

    # Verify both sites against pristine signatures before touching anything.
    sig = bytes(data[HIJACK_OFFSET - HIJACK_CALL_IDX:
                     HIJACK_OFFSET - HIJACK_CALL_IDX + len(HIJACK_SIG)])
    if sig != HIJACK_SIG:
        print(f"ERROR: hijack-site signature mismatch at {HIJACK_OFFSET:#x}.")
        print(f"  expected {HIJACK_SIG.hex()}")
        print(f"  found    {sig.hex()}")
        print("Refusing to patch. Is this the expected retail ROTH.EXE (1.4)?")
        return 1
    if bytes(data[CAVE_OFFSET:CAVE_OFFSET + len(CAVE_ORIG)]) != CAVE_ORIG:
        print(f"ERROR: code cave at {CAVE_OFFSET:#x} is not the expected 16 zero bytes.")
        print(f"  found    {bytes(data[CAVE_OFFSET:CAVE_OFFSET+16]).hex()}")
        print("Refusing to patch (cave may be in use in this build).")
        return 1

    # Apply: write the cave stub first, then retarget the call into it.
    data[CAVE_OFFSET:CAVE_OFFSET + len(CAVE_STUB)] = CAVE_STUB
    data[HIJACK_OFFSET:HIJACK_OFFSET + len(HIJACK_NEW)] = HIJACK_NEW

    with open(dst, "wb") as f:
        f.write(data)

    print(f"Patched dev mode enabled: {os.path.basename(src)} -> {os.path.basename(dst)}")
    print(f"  hijack @ {HIJACK_OFFSET:#x}: {HIJACK_ORIG.hex()} -> {HIJACK_NEW.hex()}  (call 0x10458 -> call cave 0x146d8)")
    print(f"  cave   @ {CAVE_OFFSET:#x}: 16x00 -> {CAVE_STUB.hex()}  (call enable_dev_mode; call 0x10458; ret)")
    print("Run the new exe in DOSBox. In game: 'W' = map selector (+/- choose, RETURN warp), 'L' = maphack.")
    print("To revert: just use the original ROTH.EXE.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
