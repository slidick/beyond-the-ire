# DBASE100 File Format

The DBASE100 file is an index and data container used by Realms of the Haunting for:

- inventory items (definitions, images, and per-item action opcodes)
- global action chains (script-like opcode chains referenced elsewhere)
- cutscene lookup (names and subtitle sequences)
- interface lookup (text strings and UI labels via DBASE400)

Unlike many engines, resources are referenced by offsets within other DBASE files rather than by unique IDs.

## Header

| Offset | Size (bytes) | Field | Description |
| ----------- | ----------- | ----------- | ----------- |
| 0x00 | 8 | DBASE100 | ASCII signature "DBASE100" |
| 0x08 | 4 | FILE_SIZE | Total size of the file in bytes |
| 0x0C | 4 | UNK_0x0C | Unknown DWORD |
| 0x10 | 4 | INVENTORY_COUNT | Number of inventory entries |
| 0x14 | 4 | INVENTORY_SECTION_OFFSET | Offset to [Inventory Lookup Section](#inventory-lookup-section) |
| 0x18 | 4 | ACTIONS_COUNT | Number of action entries |
| 0x1C | 4 | ACTIONS_SECTION_OFFSET | Offset to [Actions Lookup Section](#actions-lookup-section) |
| 0x20 | 4 | CUTSCENES_COUNT | Number of cutscene entries |
| 0x24 | 4 | CUTSCENES_SECTION_OFFSET | Offset to [Cutscenes Section](#cutscenes-section) |
| 0x28 | 4 | INTERFACES_COUNT | Number of interface entries |
| 0x2C | 4 | INTERFACES_SECTION_OFFSET | Offset to [Interfaces Lookup Section](#interfaces-lookup-section) |
| 0x30 | 4 | UNK_0x30 | Unknown DWORD |

All offsets are absolute from the start of the file.

## Sections Overview

DBASE100 organizes most content as lookup tables of 4-byte offsets that point to entries either within this file or into other DBASE files:

- Inventory: offsets to inventory entries within DBASE100.
- Actions: offsets to action chains within DBASE100.
- Cutscenes: fixed-size entries within DBASE100.
- Interfaces: offsets into DBASE400 (text entries). See [Interfaces Lookup Section](#interfaces-lookup-section).

---

## Inventory Lookup Section

Starts at `HEADER.INVENTORY_SECTION_OFFSET`.

| Offset | Size (bytes) | Field | Description |
| ----------- | ----------- | ----------- | ----------- |
| 0x00 | 4 * INVENTORY_COUNT | ENTRIES | Array of 4-byte offsets to [Inventory Entry](#inventory-entry). A value of 0 indicates no entry. |

### Inventory Entry

The inventory entry contains the item's metadata, cross-file references to images and name strings, plus a section of DBASE100 Opcode actions to initialize additional data about the item (such as weapon attributes or enemy characteristics).

| Offset | Size (bytes) | Field | Description |
| ----------- | ----------- | ----------- | ----------- |
| 0x00 | 2 | LENGTH | Total size of this entry, including header and actions |
| 0x02 | 2 | OBJECT_RENDER_LOOKUP | Bits 0-8 represent the index in the DAS's FAT Block 3 to apply to this object. If bit 9 is set, look up the object in `ADEMO.DAS` instead of the current map's `DEMO*.DAS`. |
| 0x04 | 1 | CLOSEUP_TYPE | Type of close-up rendering/asset selection |
| 0x05 | 1 | ITEM_TYPE_FLAGS | Item category (see values below) |
| 0x06 | 1 | UNK_0x06 | Unknown BYTE |
| 0x07 | 1 | UNK_0x07 | Unknown BYTE |
| 0x08 | 4 | CLOSEUP_IMAGE_OFFSET | Offset into DBASE300 (animated close-up) |
| 0x0C | 4 | INVENTORY_IMAGE_OFFSET | Offset into DBASE200 (inventory sprite) |
| 0x10 | 4 | NAME_OFFSET | Offset into DBASE400 to the localized name string |
| 0x14 | LENGTH - 24 | INVENTORY_COMMAND_SECTIONS | Array of inventory command sections |
| LENGTH - 4 | 4 | NULL_COMMAND | A final command presumably to signify the end of the item definition. `00 00 00 00` |

An inventory command section has the following format:

| Offset | Size (bytes) | Field | Description |
| ----------- | ----------- | ----------- | ----------- |
| 0x00 | 3 | LENGTH | size of the section in bytes |
| 0x03 | 1 | TRIGGER_CODE | the code corresponding to what triggers the COMMAND_CHAIN<br>`0x05 = item inspect` |
| 0x04 | LENGTH - 4 | COMMAND_CHAIN | An array of commands (actions) that run when the trigger is activated (via TRIGGER_CODE) |

Here is the list of possible TRIGGER_CODEs:
| Code | Name | Description |
| ----------- |  ----------- | ----------- |
| 0x01 | OnInformation |  |
| 0x02 | ChangeName | this executes whenever the item is hovered over in the inventory and is used to change the name of an item (via the `0x10` command).<br>Like the `0x01` trigger code, it can be controlled via the `0x01` conditional command (when placed after the first command).<br>Note: although only the `0x10` command is used to change the name, other commands can be used.  |
| 0x04 | OnInspect | command chain triggers when item is inspected (right click in the environment or magnifying glass in inventory) |
| 0x05 | WeaponAction | commands initialize data for when the weapon is fired |
| 0x06 | AsBullet | commands initialize data for when the item is used as a projectile |
| 0x07 | Document | allows the inventory item to display a document image (using command code `0x00`) |
| 0x0A | AsMonster | initializes data for the item as a monster (also for Adam) |
| 0x0B | OnUse | commands here initialize callbacks (other command chains) that run when the item is used |

Notes:

- `NAME_OFFSET` points to a DBASE400 entry. DBASE400 entries are strings with a color/font field; see [Interfaces Lookup Section](#interfaces-lookup-section) for a brief on DBASE400 layout.
- See [DBASE100_inventory_examples.md](DBASE100_inventory_examples.md) for examples

ITEM_TYPE_FLAGS values:

ITEM_TYPE_FLAGS & 0x0F => Item category

```text
0x00 - generic
0x01 - weapon
0x02 - characters and important info
0x03 - special items
0x04 - readables
0x12 - Adam Randall
0x20 - coin
0x21 - ammo
0x40 - interactive items
0x43 - consumable or wearable items
```

#### Action Structure

Each action/opcode is 4 bytes:

| Offset | Size (bytes) | Field | Description |
| ----------- | ----------- | ----------- | ----------- |
| 0x00 | 3 | ARGS | Little-endian 24-bit argument payload |
| 0x03 | 1 | COMMAND | Opcode identifier |

For a full list (WIP) of commands, see [DBASE100_commands.md](DBASE100_commands.md)

---

## Actions Lookup Section

Starts at `HEADER.ACTIONS_SECTION_OFFSET`.

| Offset | Size (bytes) | Field | Description |
| ----------- | ----------- | ----------- | ----------- |
| 0x00 | 4 * ACTIONS_COUNT | ENTRIES | Array of 4-byte offsets to [Action Chain](#action-chain). |

### Action Chain

An action chain is a sequence of 4-byte [Action](#action-structure) entries. The first action is the entry action. If the entry action's `COMMAND == 0x03`, its `ARGS` encodes the total byte length of the chain, allowing the number of remaining actions to be computed as `(ARGS / 4) - 1`.

Practical reading pattern:

- Read the first 4-byte action.
- If `COMMAND != 0x03`, treat it as a single-action chain.
- If `COMMAND == 0x03` and `ARGS > 0`, read `(ARGS / 4) - 1` additional actions.
The same [Action](#action-structure) layout is used here as in inventory entries.

---

## Interfaces Lookup Section

Starts at `HEADER.INTERFACES_SECTION_OFFSET`.

| Offset | Size (bytes) | Field | Description |
| ----------- | ----------- | ----------- | ----------- |
| 0x00 | 4 * INTERFACES_COUNT | ENTRIES | Array of 4-byte offsets into DBASE400. Each offset is a standard DBASE400 string entry (UI text, labels, messages). |

DBASE400 entry (for reference):

| Offset | Size | Field | Description |
| ----------- | ----------- | ----------- | ----------- |
| 0x00 | 4 | DBASE500_OFFSET | Pointer into DBASE500 (font/related) |
| 0x04 | 2 | STRING_LENGTH | Length of ASCII string |
| 0x06 | 2 | FONT_COLOR | Palette index |
| 0x08 | N | TEXT | ASCII text (not null-terminated; use length) |

---

## Cutscenes Section

Starts at `HEADER.CUTSCENES_SECTION_OFFSET`.

| Offset | Size (bytes) | Field | Description |
| ----------- | ----------- | ----------- | ----------- |
| 0x00 | 0x14 * CUTSCENES_COUNT | ENTRIES | Array of [Cutscene Entry](#cutscene-entry) |

### Cutscene Entry

Size: 0x14 bytes per entry. Fields below match observed data and align to 0x14 bytes; unknowns remain WIP.

| Offset | Size (bytes) | Field | Description |
| ----------- | ----------- | ----------- | ----------- |
| 0x00 | 8 | FILE_NAME | ASCII name of the GDV file (from `GDV/`), without extension |
| 0x08 | 2 | UNK_0x08 | Unknown WORD (often 0) |
| 0x0A | 2 | SUBTITLES_LENGTH | Length of the subtitle sequence entry; 0 if none |
| 0x0C | 4 | NAME_OFFSET | Offset into DBASE400 for the in-game name (standard entry) |
| 0x10 | 4 | SUBTITLE_SEQ_OFFSET | Offset into DBASE400 for the start of the subtitle sequence |

---

## Cross-file references

- `CLOSEUP_IMAGE_OFFSET` → DBASE300 (animated inventory closeup)
- `INVENTORY_IMAGE_OFFSET` → DBASE200 (inventory icon sprite)
- `NAME_OFFSET`, interface lookups, cutscene fields → DBASE400 (strings)
- Some DBASE400 entries reference DBASE500 for font/formatting

## Notes

- All multi-byte fields are little-endian.
- Offsets in lookup tables are absolute from the start of the file unless otherwise noted.
- The [Action](#action-structure) opcodes and semantics are still being mapped.
