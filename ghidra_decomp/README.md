# Set up ROTH.EXE in Ghidra

A clean, cross-platform recipe for loading _Realms of the
Haunting_ (`ROTH.EXE`) into Ghidra with the LE relocations applied, this project's
reverse-engineered function **boundaries, names, and types**, and the **correct Watcom
calling conventions** in the decompiler.

Note from Alex:

> This project was heavily assisted by AI (primarily Claude Opus 4.8 and some Fable 5 and GPT 5.5) and
> although I've tried my best to make sure things are accurate and correctly reflect what's in the
> game, there may be some weird function naming that might not make sense. The core of this decomp
> is sound, however, and I've created already several patches to validate random parts of it. Also,
> the majority of the remaining unnamed functions are lib/host/SOS-related and were intentionally
> skipped.

## Legal / scope

This repo does **not** contain or distribute `ROTH.EXE` or any game asset.
You must own the game and supply your own `ROTH.EXE`. For interoperability, preservation,
and study.

## Why these steps (read once)

- `ROTH.EXE` is an **MZ-wrapped LE (Linear Executable)** — the 32-bit DOS/4GW format.
  Ghidra has no LE loader, so you can't open the EXE directly. A small Python tool
  flattens the LE objects to their runtime addresses and applies the relocations,
  producing a flat image Ghidra _can_ load.
- The game was built with **Watcom C/C++**, which passes arguments in **EAX, EDX, EBX,
  ECX**. Ghidra's usual stand-in (`borlandcpp`) drops every EBX argument, mangling the
  decompilation. The included `x86watcom.cspec` teaches the decompiler the real convention.
- **Function boundaries are stamped from data, not guessed by analysis.** ROTH is full of
  Watcom shared-code / multi-entry functions with non-contiguous bodies; Ghidra's
  auto-analysis carves a number of them inconsistently (and the result depends on import
  order, compiler spec, and whether the project is pristine). So instead of relying on
  auto-analysis, `ROTHDefineCanonicalBoundaries` **recreates every function at its exact
  canonical body**. That makes the result deterministic — **it no longer matters which
  compiler spec you import under**, and a re-used project can't drift.

Because of that, the flow is just: install the compiler spec once, flatten, import, run the
single **`ROTHSetup`** script, and commit the Watcom parameters.

## What you need

| Item                     | Where                                                                      |
| ------------------------ | -------------------------------------------------------------------------- |
| Your own `ROTH.EXE`      | (you supply) — expected `sha256 5b0b4dd5…`, 470447 bytes (see `expected/`) |
| Python 3                 | python.org / your package manager                                          |
| The flatten tool         | `roth_le_tool.py`                                                          |
| The Watcom compiler spec | `x86watcom.cspec`                                                          |
| The Ghidra scripts       | `ghidra_scripts/*.java`                                                    |
| Ghidra                   | ghidra-sre.org (developed against **Ghidra 12.1**)                         |

---

## Step 1 — Flatten ROTH.EXE (command line)

From this directory, run the Python tool against your copy of the game:

```sh
python3 roth_le_tool.py /path/to/ROTH.EXE extract --apply-fixups --flat --out-dir analysis/le_image
```

If `ROTH.EXE` is in the current directory you can omit it entirely — it defaults to `ROTH.EXE`.
(The `analysis/le_image` output path matters — the memory-block script looks there by default.)
This writes into `analysis/le_image/`:

- `flat_reloc.bin` — the flat, relocated image (this is what you import into Ghidra)
- `object1_reloc.bin`, `object2_reloc.bin`, `object3_reloc.bin` — the individual LE objects
- `manifest_reloc.json`

(Tip: verify your EXE first — `sha256sum ROTH.EXE` on Linux/macOS, `certutil -hashfile ROTH.EXE SHA256` on Windows — against `expected/ROTH.EXE.sha256`. A different build will have different addresses and the names won't line up.)

## Step 2 — Install the Watcom compiler spec into Ghidra (once, ever)

This is a **one-time Ghidra setup** — you do it once, not per project. Ghidra has no "add
compiler spec" button, so you place one file and add one line. Find your Ghidra language
folder:

```
<GHIDRA_INSTALL>/Ghidra/Processors/x86/data/languages/
```

1. **Copy** `x86watcom.cspec` into that `languages/` folder.
2. **Edit** `x86.ldefs` in that same folder. Find the line:
   ```xml
   <compiler name="Borland C++" spec="x86borland.cspec" id="borlandcpp"/>
   ```
   and add directly beneath it:
   ```xml
   <compiler name="Watcom C/C++" spec="x86watcom.cspec" id="watcom"/>
   ```
3. **Restart Ghidra** so it re-reads the language definitions.

> Linux/macOS shortcut (optional): `GHIDRA_HOME=/opt/ghidra sudo -E ghidra/install_cspec.sh`
> does steps 1–2 idempotently. Windows users do it by hand as above.

## Step 3 — Import the flat image (under Watcom)

In Ghidra, after you have opened a project or started a new one:
**File ▸ Import File…**, select `analysis/le_image/flat_reloc.bin`, then in the import
dialog:

- **Format:** Raw Binary
- **Language:**
  1.  click the `...`, filter for `watcom`, and select the entry with:
      - Processor = `x86`
      - Variant = `default`
      - Size = `32`
      - Endian = `little`
      - Compiler = `Watcom C/C++`
      - **Note:** this is the compiler spec you added in the previous step
  2.  Press OK
- **Options ▸ Base Address:** `0x10000`

Open the imported program. **Decline** auto-analysis if prompted — `ROTHSetup` runs it for you.

## Step 4 — Add the project scripts

Open **Window ▸ Script Manager ▸ Manage Script Directories** (the list icon on the right) and add the `ghidra_scripts/` folder in this repo. The `ROTH*` scripts now appear under the category **ROTH**.

## Step 5 — Run `ROTHSetup` (the one click)

Select **`ROTHSetup.java`** in the Script Manager and click **Run**. It will prompt you for a directory. Select this folder (the folder that contains `analysis/le_image/`).

This script drives the whole pipeline in order:

1. builds the three LE object memory blocks (**prompts once** — point it at the folder that
   contains `analysis/le_image/`);
2. runs auto-analysis;
3. **stamps the canonical function boundaries** (deletes the analysis-carved functions and
   recreates the exact canonical set, including the non-contiguous shared-code bodies);
4. applies the DAS structures/types;
5. applies all engine names, comments, and globals.

Watch the console — it logs the five phases and should end with
**`recreated 1471 functions, 0 failed`** and `[ROTHSetup] DONE`.

> Fallback: if the in-script auto-analysis ever misbehaves, run **ROTHCreateObjectMemory**
> and **Analysis ▸ Auto Analyze** by hand first, then run `ROTHSetup` — it detects both are
> done and skips straight to stamping.

## Step 6 — Commit the Watcom parameters

**Analysis ▸ One Shot ▸ Decompiler Parameter ID.** This re-derives each function's register
arguments under the Watcom spec and commits them. (Use the one-shot analyzer, _not_ a full
re-analyze — the stamped boundaries must not be disturbed.)

Decompiled functions now show their register arguments correctly.

---

## Verify it worked

- Go to `0x2196a` (`dos_write_u16`) and decompile it — with the Watcom spec it should take
  **three** parameters including the `BX`/size argument: `dos_write_u16(param_1, param_2, param_3)`.
  If it only shows two, the compiler spec is still Borland — recheck Steps 2–3.
- Go to `0x1e8cc` (`read_next_dialogue_line`) — it should be a **four**-argument
  `__watcall` function (the `EBX` arg is recovered).
- The Script Manager console for Step 5 should have said **`recreated 1471 functions, 0 failed`**.

## Known differences from the maintainer's corpus

A fresh run was validated against the maintainer's corpus: **identical function set (1471),
zero function-name differences, and 99.4% of all function metadata field-identical** (measured:
55 differing fields out of 8824). Every difference falls in a small, fixed set, and **none of it
affects the engine names or anything that gets lifted**:

- **The `0x385dc` SMC render cluster** (`render_world_col_tint_gs_385dc` and neighbours): a
  self-modifying render-column function whose body contains a 16-bit segment-override op
  (`mov bh, gs:[bx]`) that halts Ghidra's linear decoder mid-body. Its 82-byte non-contiguous
  body carves as 10 bytes + a spurious `0x385e6`, the neighbour `0x385d4` gets auto-flagged as a
  thunk, and one CRT jump-thunk (`0x58624`) isn't recreated. One column-drawing family in the
  (already-complete) renderer.
- **~14 calling conventions and ~34 signatures** — on **interrupt handlers** (conventionless
  by nature) and **CRT library functions** (`printf`/`sprintf`/`memcpy`/`malloc`…). Ghidra's
  parameter-ID is nondeterministic on untyped functions, and the corpus carries some hand
  typing / library detection that a clean rebuild doesn't reconstruct. All of these are
  host-mapped, not engine code.
- **3 comments** on Watcom CRT startup helpers.

These are inherent to Ghidra's analysis (nondeterministic parameter-ID, decoder limits on
SMC), not recipe defects — they can't be byte-reproduced and don't need to be.

## Notes

- **Regenerating the boundary stamper (maintainers only).** `ROTHDefineCanonicalBoundaries.java`
  is generated by `tools/gen_boundary_script.py` from `tools/boundaries.json`, which is dumped
  by running `ROTHExportBoundaries.java` on the canonical project. Regenerate only when the
  canonical function boundaries actually change; end users never touch this.
- The single source of truth for **names** is `ROTHApplyEngineNames.java` (which `ROTHSetup`
  runs last). Boundaries come from the generated stamper. The two are independent.
- All scripts are compile-checked against Ghidra 12.1.
