#!/usr/bin/env python3
"""Patch ROTH.EXE to add a toggleable "CREATIVE MODE" cheat (fly + no-clip + dev mode).

Press **T** in-game to toggle creative mode. When ON:
  1. FLY / no-gravity   — hold JUMP (A) to rise, CROUCH (Z) to descend; gravity off.
  2. NO-CLIP (player)   — the player walks through walls (enemies/projectiles unaffected).
  3. NO HEAD-BOB        — the vertical camera bob is suppressed (constant eye height).
  4. DEV MODE           — unlocks the hidden W map-selector, L maphack overlay, Space
                          door skeleton key.
  5. WATERMARK          — "CREATIVE MODE ON" shows top-right while active.

The whole thing hangs off ONE already-present, already-dead piece of the game:
  * The T key (scancode 0x14) is already bound to a vestigial handler at 0x14ca7 whose
    entire body is `xor byte[0x7f370],1 ; mov byte[0x7f570],1 ; ret`. The byte 0x7f370 is
    read by NOTHING else in the binary (a cut feature), so T already toggles a free flag.
    We adopt 0x7f370 (bit 0) as the master "creative mode" flag and leave the T handler
    UNTOUCHED — it already flips it for us.

Everything else is four 5-byte CALL-site hijacks that route through stubs in object 1's
zero-filled tail page (the same cave the watermark patch uses). Each stub reads the flag
and behaves as stock when it is clear, so the default game is byte-for-byte unchanged
until you press T.

  | Feature   | Hijacked call (VA / file)          | Was               | Stub          |
  | --------- | ---------------------------------- | ----------------- | ------------- |
  | fly       | 0x3ed34 / 0x51734 (in view-bob)    | call 0x1c648      | fly_stub      |
  | no-clip   | 0x3e93a / 0x5133a (player substep) | call 0x3ecc0      | substep_wrap  |
  | no-clip   | 0x3ef96 / 0x51996 (wall solver)    | call 0x3f0e0      | gate_stub     |
  | no-bob    | 0x3ed94 / 0x51794 (eye height)     | je 0x3edd9 + lea  | bob_gate      |
  | watermark | 0x1799a / 0x2a39a (per-frame text) | call 0x1f0e8      | wm_stub       |

Why this is relocation-safe (no LE fixups needed, like the other patches):
  * Every hijack replaces a RELATIVE `call rel32` with another relative call into the cave.
    Source and target are both in object 1, so the rel32 is position-independent (the file
    bytes equal the relocated image bytes) — no fixup record required.
  * The cave stubs contain ZERO absolute operands. They reach the game's data globals
    position-independently: a `call/pop` recovers object 1's runtime load delta, and the
    relocated pointer to 0x7f560 living inside `enable_dev_mode` (the operand of its
    `mov byte[0x7f560],1` at file/canon 0x14466) is read to get object 3's runtime base.
    All data is then addressed as `[base + constant]`. This relies only on each LE object
    being loaded contiguously (always true) — never on a fixed inter-object delta.

Player-only no-clip: `collide_substep_track_sector` (0x3ecc0) has exactly ONE caller — the
player mover. `substep_wrap` sets the cave's `noclip_flag = creative` only around that call,
so when the shared wall solver `collide_point_walls_recursive` (0x3f0e0) runs via `gate_stub`
it skips the wall clamp ONLY during the player's substep. Enemies/projectiles still collide.

Dev mode follows creative each frame: `wm_stub` mirrors `g_dev_mode_flag (0x7f560) = creative`
(and clears the map-selector `0x7fe28` when off so it doesn't linger). So W/L/Space light up
with creative mode and go inert when it is off.

Non-destructive: reads ROTH.EXE, writes ROTH_CREATIVE.EXE. Verifies unique byte signatures
at every site and refuses to patch a file that does not match. Idempotent.

  python3 tools/roth_patch_creative.py                 # ROTH.EXE -> ROTH_CREATIVE.EXE
  python3 tools/roth_patch_creative.py in.exe out.exe

Note: this occupies the SAME object-1 tail cave + per-frame text hook as
tools/roth_patch_watermark.py, so the two are mutually exclusive — apply this to a clean
ROTH.EXE, not to a watermarked one.

Maintainers: the cave machine code below is assembled from CAVE_ASM by GNU as/ld/objcopy.
Run `python3 tools/roth_patch_creative.py --rebuild` (needs binutils) to re-derive CAVE_BYTES
and the stub offsets and confirm they still match the embedded copy.
"""
from __future__ import annotations

import os
import struct
import subprocess
import sys
import tempfile

# --- VA <-> file-offset for object 1 (base 0x10000): file = VA + 0x12a00 (proven by the
#     existing devmode/watermark patches). ---
OBJ1_DELTA = 0x12A00

# --- Cave: object 1's zero-filled tail page, VA 0x58cd0 / file 0x6b6d0 (as the watermark
#     patch). Requires object 1's declared size be bumped to the full page (0x49000). ---
CAVE_VA = 0x58CD0
CAVE_OFFSET = 0x6B6D0
CAVE_END_OFFSET = 0x6BA00          # object-1 page end (file)
CAVE_CAPACITY = CAVE_END_OFFSET - CAVE_OFFSET   # 0x330 = 816 bytes

OBJECT1_RECORD_OFFSET = 0x32D4
OBJECT1_RECORD_ORIG = bytes.fromhex("cb8c04000000010045200000010000004900000000000000")
OBJECT1_RECORD_PATCHED = struct.pack("<I", 0x49000) + OBJECT1_RECORD_ORIG[4:]

MARKER = b"ROTHCREATIVE1\x00"

# --- Tunables baked into CAVE_BYTES (change via --rebuild). ---
CREATIVE_TEXT = b"CREATIVE MODE ON"
TEXT_COLOR = 0x20
TEXT_X = 200
TEXT_Y = 4
TEXT_FLAGS = 0
FLY_STEP = 0x10

# --- Pre-assembled cave (GNU as/ld/objcopy of CAVE_ASM, linked at CAVE_VA). 350 bytes. ---
CAVE_BYTES = bytes.fromhex(
    "9c5056e8000000005e81eed88c05008b8666440100f68010feffff0175085e589de9"
    "5239fcff0fb68860240000f6c101740383c310f6c104740383eb10c6806124000000"
    "c680652400000089d85e83c4049dc3509ce800000000582d2a8d0500f6801f8e0500"
    "0175079d58e9a063feff9d58c3509ce8000000005981e94a8d05008b91664401000f"
    "b68210feffff240188811f8e05009d58e8535ffeff509ce8000000005981e9748d05"
    "00c6811f8e0500009d58c3e85e63fcff9c60e8000000005e81ee918d05008bbe6644"
    "01008a8710feffff240188077438684f4e0000684f444520685645204d6845415449"
    "680120435289e08b9f385f000083eb78b904000000ba00000000e89c12fcff83c414"
    "eb07c687c808000000619dc3509ce800000000582df38d05008b8066440100f68010"
    "feffff0174079d58e9ca5ffeff9d580f84c25ffeff8d3c7fe97a5ffeff00524f5448"
    "43524541544956453100"
)
# Stub entry offsets within the cave (verified against `nm` in --rebuild).
STUB_OFFSETS = {
    "fly_stub": 0x00,
    "gate_stub": 0x53,
    "substep_wrap": 0x73,
    "wm_stub": 0xB5,
    "bob_gate": 0x11C,
}

# --- The five hijacks. Each replaces 5 bytes at a known site with a relative branch into
#     a cave stub. `opcode` is 0xE8 (call) for the four call-sites, 0xE9 (jmp) for the
#     no-bob site (which replaces `je 0x3edd9` + the `lea` that follows it).
#     Fields: (name, site file offset, opcode, original 5 bytes, signature offset+bytes, stub). ---
def _call_va(call_off: int) -> int:
    return call_off - OBJ1_DELTA


HOOKS = [
    # name        site     op    orig5                 sig_off  sig_bytes                       stub
    ("fly",       0x51734, 0xE8, "e80fd9fdff",        0x51732, "5052e80fd9fdff",             "fly_stub"),
    ("substep",   0x5133A, 0xE8, "e881030000",        0x51335, "a174c10100e881030000",       "substep_wrap"),
    ("gate",      0x51996, 0xE8, "e845010000",        0x51994, "7507e845010000",             "gate_stub"),
    ("nobob",     0x51794, 0xE9, "74438d3c7f",        0x51794, "74438d3c7fd1ef83e73e",       "bob_gate"),
    ("watermark", 0x2A39A, 0xE8, "e849770000",        0x2A398, "31c0e849770000",             "wm_stub"),
]


def branch_rel32(site_va: int, target_va: int, opcode: int) -> bytes:
    rel = target_va - (site_va + 5)
    if not -(1 << 31) <= rel < (1 << 31):
        raise ValueError(f"branch target out of rel32 range: {target_va:#x}")
    return bytes([opcode]) + struct.pack("<i", rel)


def new_call_bytes(call_off: int, stub_name: str, opcode: int = 0xE8) -> bytes:
    return branch_rel32(_call_va(call_off), CAVE_VA + STUB_OFFSETS[stub_name], opcode)


# ---------------------------------------------------------------------------------------
# Cave source (for reference + --rebuild). Assembled and linked at CAVE_VA.
# ---------------------------------------------------------------------------------------
def build_cave_asm() -> str:
    ctrl = bytes([0x01, TEXT_COLOR]) + CREATIVE_TEXT + b"\x00"
    pad = (len(ctrl) + 3) & ~3
    ctrl_p = ctrl + b"\x00" * (pad - len(ctrl))
    pushes = []
    for pos in range(pad - 4, -1, -4):
        dw = struct.unpack_from("<I", ctrl_p, pos)[0]
        pushes.append(f"    push 0x{dw:08x}")
    push_block = "\n".join(pushes)
    return f""".intel_syntax noprefix
.code32
.text
.set fn_uvp,     0x1c648   /* update_player_vertical_physics */
.set fn_wallrec, 0x3f0e0   /* collide_point_walls_recursive  */
.set fn_substep, 0x3ecc0   /* collide_substep_track_sector   */
.set fn_textui,  0x1f0e8   /* render_text_ui                 */
.set fn_drawtext,0x1a079   /* draw_text_at_screen_xy         */
.set dev_op,     0x14466   /* relocated [0x7f560] operand inside enable_dev_mode */
.set G_dev,      0x7f560   /* g_dev_mode_flag (obj3 anchor)  */
.set G_creat,    0x7f370   /* creative-mode flag (T toggles) */
.set G_loco,     0x819c0   /* g_player_locomotion_flags      */
.set G_air,      0x819c1   /* g_player_airborne              */
.set G_fall,     0x819c5   /* fall-state var                 */
.set G_mapmenu,  0x7fe28   /* g_map_menu_active              */
.set G_pitch,    0x85498   /* g_screen_pitch (live row width, tracks the video mode) */
.set bob_skip,   0x3edd9   /* je target: store eye height with NO bob added */
.set bob_cont,   0x3ed99   /* resume after the displaced lea (shr edi,1)    */
.set FLY_STEP,   0x{FLY_STEP:x}
.set RIGHT_OFFSET, {320 - TEXT_X}   /* x = pitch - RIGHT_OFFSET; pins to the right edge */

/* ===== FLY (replaces `call 0x1c648` @ 0x3ed34, inside update_player_view_bob).
   ABI: EAX=floor, EDX=ceiling, EBX=current Z; returns new Z in EAX; floor/ceiling are
   saved on the caller's stack across the call. Creative OFF => tail-call the original. */
fly_stub:
    pushfd
    push eax
    push esi
    call .Lf
.Lf:
    pop esi
    sub esi, OFFSET .Lf                  /* esi = obj1 load delta */
    mov eax, dword ptr [esi + dev_op]    /* eax = obj3 base (runtime 0x7f560) */
    test byte ptr [eax + (G_creat-G_dev)], 1
    jnz .Lfcr
    pop esi
    pop eax
    popfd
    jmp fn_uvp
.Lfcr:
    movzx ecx, byte ptr [eax + (G_loco-G_dev)]
    test cl, 1                           /* jump pressed -> up */
    jz .Lf1
    add ebx, FLY_STEP
.Lf1:
    test cl, 4                           /* crouch -> down */
    jz .Lf2
    sub ebx, FLY_STEP
.Lf2:
    mov byte ptr [eax + (G_air-G_dev)], 0    /* kill gravity arc */
    mov byte ptr [eax + (G_fall-G_dev)], 0
    mov eax, ebx
    pop esi
    add esp, 4
    popfd
    ret

/* ===== NO-CLIP GATE (replaces `call 0x3f0e0` @ 0x3ef96). Skips the wall solver only when
   the player-substep flag (set by substep_wrap) is up. Preserves all regs/flags so the
   wall solver still sees ES/ESI/EBP. Both paths return to 0x3ef9b. */
gate_stub:
    push eax
    pushfd
    call .Lg
.Lg:
    pop eax
    sub eax, OFFSET .Lg
    test byte ptr [eax + noclip_flag], 1
    jnz .Lgskip
    popfd
    pop eax
    jmp fn_wallrec
.Lgskip:
    popfd
    pop eax
    ret

/* ===== NO-CLIP SUBSTEP WRAP (replaces `call 0x3ecc0` @ 0x3e93a, player-only caller).
   Sets noclip_flag = creative around the substep, then clears it. EAX holds the substep
   argument and must survive into the call. */
substep_wrap:
    push eax
    pushfd
    call .Ls
.Ls:
    pop ecx
    sub ecx, OFFSET .Ls
    mov edx, dword ptr [ecx + dev_op]
    movzx eax, byte ptr [edx + (G_creat-G_dev)]
    and al, 1
    mov byte ptr [ecx + noclip_flag], al
    popfd
    pop eax
    call fn_substep
    push eax
    pushfd
    call .Ls2
.Ls2:
    pop ecx
    sub ecx, OFFSET .Ls2
    mov byte ptr [ecx + noclip_flag], 0
    popfd
    pop eax
    ret

/* ===== WATERMARK + dev-mirror (replaces `call 0x1f0e8` @ 0x1799a, per-frame UI text).
   Runs the original text pass, mirrors g_dev_mode_flag = creative, and (when creative)
   draws "CREATIVE MODE ON" top-right via the game's own positioned text renderer. The
   control-coded string is built on the stack (no absolute data pointer). */
wm_stub:
    call fn_textui
    pushfd
    pushad
    call .Lw
.Lw:
    pop esi
    sub esi, OFFSET .Lw
    mov edi, dword ptr [esi + dev_op]    /* edi = obj3 base (runtime 0x7f560) */
    mov al, byte ptr [edi + (G_creat-G_dev)]
    and al, 1
    mov byte ptr [edi + 0], al           /* g_dev_mode_flag = creative bit */
    jz .Lwoff
{push_block}
    mov eax, esp
    mov ebx, dword ptr [edi + (G_pitch - G_dev)]   /* ebx = current screen pitch/width */
    sub ebx, RIGHT_OFFSET                          /* x = pitch - RIGHT_OFFSET (right-pin) */
    mov ecx, 0x{TEXT_Y:x}
    mov edx, 0x{TEXT_FLAGS:x}
    call fn_drawtext
    add esp, {pad}
    jmp .Lwdone
.Lwoff:
    mov byte ptr [edi + (G_mapmenu-G_dev)], 0
.Lwdone:
    popad
    popfd
    ret

/* ===== NO HEAD-BOB (replaces `je 0x3edd9` + `lea edi,[edi+edi*2]` @ 0x3ed94, just after
   `cmp [bob_amplitude 0x7e8d8],0`). Creative ON => take the no-bob path unconditionally;
   OFF => replay the original conditional + the displaced lea and resume at 0x3ed99. The
   creative test is bracketed by pushfd/popfd so the cmp's ZF survives for the stock je. */
bob_gate:
    push eax
    pushfd
    call .Lbb
.Lbb:
    pop eax
    sub eax, OFFSET .Lbb
    mov eax, dword ptr [eax + dev_op]
    test byte ptr [eax + (G_creat-G_dev)], 1
    jz .Lbbstock
    popfd
    pop eax
    jmp bob_skip
.Lbbstock:
    popfd
    pop eax
    je bob_skip
    lea edi, [edi + edi*2]
    jmp bob_cont

noclip_flag:
    .byte 0
marker:
    .ascii "ROTHCREATIVE1\\0"
"""


def assemble_cave() -> tuple[bytes, dict]:
    """Assemble+link CAVE_ASM at CAVE_VA. Returns (raw bytes, {stub: offset}). Needs binutils."""
    for tool in ("as", "ld", "objcopy", "nm"):
        if subprocess.run(["which", tool], capture_output=True).returncode != 0:
            raise RuntimeError(f"--rebuild needs binutils; '{tool}' not found")
    with tempfile.TemporaryDirectory() as d:
        s = os.path.join(d, "cave.s")
        o = os.path.join(d, "cave.o")
        elf = os.path.join(d, "cave.elf")
        binf = os.path.join(d, "cave.bin")
        with open(s, "w") as f:
            f.write(build_cave_asm())
        subprocess.run(["as", "--32", "-o", o, s], check=True)
        # ld warns about a missing _start entry (harmless: objcopy -j .text dumps the whole
        # section regardless of entry point); the cave is position-independent.
        subprocess.run(["ld", "-m", "elf_i386", f"-Ttext={CAVE_VA:#x}", "-o", elf, o],
                       check=True, capture_output=True)
        subprocess.run(["objcopy", "-O", "binary", "-j", ".text", elf, binf], check=True)
        data = open(binf, "rb").read()
        offs = {}
        nm = subprocess.run(["nm", elf], capture_output=True, text=True).stdout
        for line in nm.splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[2] in STUB_OFFSETS:
                offs[parts[2]] = int(parts[0], 16) - CAVE_VA
    return data, offs


def rebuild_and_check() -> int:
    data, offs = assemble_cave()
    print(f"assembled cave: {len(data)} bytes (capacity {CAVE_CAPACITY})")
    print("stub offsets:", {k: hex(v) for k, v in sorted(offs.items(), key=lambda kv: kv[1])})
    ok = data == CAVE_BYTES and offs == STUB_OFFSETS
    if ok:
        print("MATCH: embedded CAVE_BYTES / STUB_OFFSETS are up to date.")
        return 0
    print("DIFF: embedded copy is stale. Update with:")
    print(f'CAVE_BYTES = bytes.fromhex(\n    "{data.hex()}"\n)')
    print("STUB_OFFSETS =", {k: hex(v) for k, v in offs.items()})
    return 1


# ---------------------------------------------------------------------------------------
def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(here)

    args = [a for a in sys.argv[1:] if a != "--rebuild"]
    if "--rebuild" in sys.argv[1:]:
        return rebuild_and_check()

    src = args[0] if len(args) > 0 else os.path.join(repo, "ROTH.EXE")
    dst = args[1] if len(args) > 1 else os.path.join(repo, "ROTH_CREATIVE.EXE")

    if len(CAVE_BYTES) > CAVE_CAPACITY:
        print(f"ERROR: cave is {len(CAVE_BYTES)} bytes, capacity {CAVE_CAPACITY}.")
        return 1

    with open(src, "rb") as f:
        data = bytearray(f.read())

    # --- Idempotency: already fully patched? ---
    obj1 = bytes(data[OBJECT1_RECORD_OFFSET:OBJECT1_RECORD_OFFSET + len(OBJECT1_RECORD_ORIG)])
    cave_now = bytes(data[CAVE_OFFSET:CAVE_OFFSET + len(CAVE_BYTES)])
    hooks_patched = all(
        bytes(data[off:off + 5]) == new_call_bytes(off, stub, op)
        for _, off, op, _, _, _, stub in HOOKS
    )
    if obj1 == OBJECT1_RECORD_PATCHED and cave_now == CAVE_BYTES and hooks_patched:
        print("Already patched (creative mode present). Nothing to do.")
        return 0

    # --- Verify every site against pristine (or our-own-patched) signatures first. ---
    if obj1 not in (OBJECT1_RECORD_ORIG, OBJECT1_RECORD_PATCHED):
        print(f"ERROR: object-1 record mismatch at {OBJECT1_RECORD_OFFSET:#x}.")
        print(f"  expected {OBJECT1_RECORD_ORIG.hex()} or {OBJECT1_RECORD_PATCHED.hex()}")
        print(f"  found    {obj1.hex()}")
        return 1

    for name, call_off, op, orig_call, sig_off, sig_hex, stub in HOOKS:
        sig = bytes.fromhex(sig_hex)
        cur_sig = bytes(data[sig_off:sig_off + len(sig)])
        cur_call = bytes(data[call_off:call_off + 5])
        patched_call = new_call_bytes(call_off, stub, op)
        if cur_sig == sig and cur_call == bytes.fromhex(orig_call):
            continue                       # pristine, will patch
        if cur_call == patched_call:
            continue                       # already ours, fine
        print(f"ERROR: hook '{name}' signature mismatch at {sig_off:#x}.")
        print(f"  expected {sig.hex()}")
        print(f"  found    {cur_sig.hex()}")
        print("Refusing to patch. Is this the expected retail ROTH.EXE (1.4)?")
        return 1

    # --- Cave must be pristine zeros or already ours. ---
    cave_region = bytes(data[CAVE_OFFSET:CAVE_END_OFFSET])
    if not (cave_region == bytes(len(cave_region)) or MARKER in cave_region):
        print(f"ERROR: object-1 tail cave at {CAVE_OFFSET:#x} is neither empty nor ours.")
        if b"ROTHWATERMARK1" in cave_region:
            print("  It looks like the watermark patch is applied. The watermark patch and")
            print("  this one share the same cave + per-frame hook and are mutually exclusive.")
            print("  Apply this to a CLEAN ROTH.EXE instead.")
        else:
            print("  Refusing to overwrite unknown bytes.")
        return 1

    # --- Apply. Object-1 size, then cave (zero the whole region, then write), then hooks. ---
    data[OBJECT1_RECORD_OFFSET:OBJECT1_RECORD_OFFSET + len(OBJECT1_RECORD_PATCHED)] = \
        OBJECT1_RECORD_PATCHED
    data[CAVE_OFFSET:CAVE_END_OFFSET] = bytes(CAVE_END_OFFSET - CAVE_OFFSET)
    data[CAVE_OFFSET:CAVE_OFFSET + len(CAVE_BYTES)] = CAVE_BYTES
    for _, call_off, op, _, _, _, stub in HOOKS:
        data[call_off:call_off + 5] = new_call_bytes(call_off, stub, op)

    with open(dst, "wb") as f:
        f.write(data)

    print(f"Patched creative mode: {os.path.basename(src)} -> {os.path.basename(dst)}")
    print(f"  object1 size @ {OBJECT1_RECORD_OFFSET:#x}: 0x48ccb -> 0x49000")
    print(f"  cave @ {CAVE_OFFSET:#x} / VA {CAVE_VA:#x}: {len(CAVE_BYTES)} bytes "
          f"(of {CAVE_CAPACITY})")
    for name, call_off, op, orig_call, _, _, stub in HOOKS:
        nb = new_call_bytes(call_off, stub, op)
        print(f"  hook {name:9s} @ {call_off:#x} (VA {_call_va(call_off):#x}): "
              f"{orig_call} -> {nb.hex()}  (-> {stub})")
    print()
    print("In game: press T to toggle CREATIVE MODE (watermark top-right).")
    print("  While ON: A = fly up, Z = fly down (no gravity); walk through walls; no head-bob;")
    print("  W = map selector (+/- choose, RETURN warp), L = maphack, Space = open door.")
    print("To revert: just use the original ROTH.EXE.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
