# .DAS File Format (WIP)

## Overview

DAS files are texture archives containing collections of textures including floors, ceilings, walls, skyboxes, in-game objects, enemies, projectiles, and items.

The DAS format supports multiple image types, compression schemes, and animation sequences.

Although the same file format, ADEMO.DAS differs slightly than the other *.DAS files. Since ADEMO is accessible by every map (defined by ROTH.RES), it contains game-wide object mapping information (such as inventory items and enemies). I will attempt to document which sections are only present or only missing in ADEMO.

## General File Structure

The large majority of the file is made up of sections relating to object/image data entities, loosely inspired by a File Allocation Format. Here we will nevertheless refer to these data blocks as FAT (File Allocation Table) Data Blocks for consistency with previous reverse-engineering attempts/documentation.  


```
DAS File Structure (WIP):
├── Header (68 bytes)
├── File Allocation Table
├── Palette System (optional)
├── Unk_0x10 Section
├── FAT Data Blocks (bulk of the file)
├── Directional Object Table (optional)
├── Object Collision Section
├── Monster Mapping Section
├── Unk_0x38 Section (small, found in ADEMO)
├── Unk_0x40 Section (small, found in ADEMO)
└── Filename Block
```

## To investigate (TODO)
- How to specify whether a texture has full transparency or partial (potions, crystal texture)


## Main Header (68 bytes)

The DAS file header contains metadata about the file structure and offsets to various sections.

| Offset | Size | Field Name | Description |
|--------|------|------------|-------------|
| 0x00 | 4 | DAS_ID_STR | File signature: "DASP" |
| 0x04 | 2 | DAS_ID_NUM | Always 5 |
| 0x06 | 2 | SIZE_FAT | Total size of the FAT. To retrieve the amount of FAT slots, do `SIZE_FAT / 8` |
| 0x08 | 4 | IMG_FAT_OFFSET | Offset to image FAT (usually 0x44) |
| 0x0C | 4 | PALETTE_SYSTEM_OFFSET | Offset to the [section containing the palette and palette remaps](#palette-system). (0 = use ADEMO.DAS palette) |
| 0x10 | 4 | UNK_0x10_SECTION_OFFSET | Offset to [Unk_0x10 Section](#unknown-section-0x10) |
| 0x14 | 4 | FILE_NAMES_SECTION | Offset to filename section |
| 0x18 | 2 | FILE_NAMES_SECTION_SIZE | Size of filename section |
| 0x1A | 2 | DIRECTIONAL_OBJECT_TABLE_SIZE | Size of the directional object table |
| 0x1C | 4 | DIRECTIONAL_OBJECT_TABLE | Offset to the [directional object table](#directional-object-table) |
| 0x20 | 2 | UNK_0x20 | Unknown field |
| 0x22 | 2 | SKY_INDEX | Index that maps using this das should use for their empty/transparent 'sky' texture |
| 0x24 | 4 | OBJECT_COLLISION_SECTION_OFFSET | Offset to the [section that defines collision boxes for objects](#object-collision-section) |
| 0x28 | 4 | MONSTER_MAPPING_SECTION | Offset to the [section for mapping animations to monsters](#monster-mapping-section) |
| 0x2C | 4 | MONSTER_MAPPING_SECTION_SIZE | Size of MONSTER_MAPPING_SECTION |
| 0x30 | 2 | FAT_BLOCK_1_COUNT | Number of entries in the first FAT page/block (wall/floor textures) |
| 0x32 | 2 | FAT_BLOCK_2_COUNT | Number of entries in the second FAT page/block (always empty?) |
| 0x34 | 2 | FAT_BLOCK_3_COUNT | Number of entries in the third FAT page/block (object-mappable textures/data) |
| 0x36 | 2 | FAT_BLOCK_4_COUNT | Number of entries in the fourth FAT page/block (directional billboard sprites) |
| 0x38 | 4 | UNK_0x38 | `0x00` in `DEMO*.DAS` files. |
| 0x3C | 2 | UNK_0x38_SIZE | `0x00` in `DEMO*.DAS` files. |
| 0x3E | 2 | UNK_0x40_SIZE | `0x00` in `DEMO*.DAS` files. |
| 0x40 | 4 | UNK_0x40 | `0x00` in `DEMO*.DAS` files. |

## Palette System

The Realms of the Haunting engine uses a single palette alongside 322 palette remap tables to handle not only 32 levels of shading, but also transparency blending allowing any color to be partially transparent.

The palette system data starts at HEADER.PALETTE_SYSTEM_OFFSET and has the following structure:

| Offset | Size | Field Name | Description |
|--------|------|------------|-------------|
| 0x0000 | 768 | PALETTE | 256 3-byte values representing all colors used |
| 0x0300 | 2 | PADDING | `00 00` |
| 0x0302 | 82432 | PALETTE_REMAP_ARRAY | The array of 322 PALETTE_REMAP_TABLE's |

`ADEMO.DAS` does not contain a palette.

This section goes all the way to HEADER.UNK_0x10_SECTION_OFFSET.

### Palette

The palette itself is VGA and made up of 256 6-bit colors. Each color is represented in 3 bytes, where each byte is a 6 bit value corresponding to R, G, and B respectively. 

| Offset | Size | Field Name | Description |
|--------|------|------------|-------------|
| 0x00 | 1 | R6 | 6-bit red |
| 0x01 | 1 | G6 | 6-bit green |
| 0x02 | 1 | B6 | 6-bit blue |

To convert each value to a standard 8 bit color:
```
Option 1: Close approximation
R = R6 * 4
G = G6 * 4
B = B6 * 4

Option 2: Mathematically correct
R = round(R6 * 255 / 63)
G = rount(G6 * 255 / 63)
B = rount(B6 * 255 / 63)
```
Here is an image of the original palette:  

<img src="images/palette.png" alt="Description" max-height="500">

### Palette Remap Tables

Following the palette are 322 palette remap tables. A palette remap table is a 256 byte array where the value of each byte is an index to a color in the original palette. The array (or table) then represents a new or remapped palette. This is used to efficiently render shading, allow each color to be partially transparent, and allow other effects using the original colors.

As noted, there are 322 tables. Here is the breakdown of the tables:

| Table | Count | Purpose |
|-------|-------|---------|
| 0-31 | 32 | Standard shading. First table starts bright and progressively gets near pitch black |
| 32-63 | 32 | Some sort of tinted shading. Starts slightly dark and purple, brightens, then darkens to black |
| 64-319 | 256 | Transparency blending. One table per original palette color, for translucent overlay rendering. This allows textures to have partial colored transparency (such as the shimmering portals) |
| 320 | 1 | Very slightly darker than original palette |
| 321 | 1 | Very slightly brighter than original palette |

Aside from the standard shading maps, the most notable portion here are the transparency blending tables. Any color can be partially transparent, allowing textures behind it to still render, but with a tint from the original color.

Here is an example of the transparency blending table for color at index 134 (`0x86`):  

<img src="images/remapped_palette.png" alt="Description" max-height="500">

To fully explore each of the tables, you can use this [tool](../tools/das-analysis/palette-shading-examiner.html).

## Unknown Section 0x10

This section is still unknown and starts at HEADER.UNK_0x10_SECTION_OFFSET.

The section only appears in the `DEMO*.DAS` files and not in `ADEMO.DAS`. Due to it following the [palette system](#palette-system) as well as the fact that there is no palette defined in `ADEMO.DAS`, it's possible that this section somehow relates to the palette. Zeroing out this section or filling it with garbage data yielded no noticeable difference in the game.

This section has a fixed size of 4096 bytes. If it is related to the palette, it may represent either a 256-element array with 16-byte elements or a 16-element array with 256-byte elements.


## File Allocation Table

This section directly follows the header and provides a list of 8 byte elements that point to a FAT Data Block. Whenever a FAT entry or FAT index is referenced, it is in regards to the index within this array. The total amount of slots available in the FAT can be calculated with the sum of `HEADER.FAT_BLOCK_*_COUNT` or `HEADER.SIZE_FAT / 8`. Although in most `.DAS` files there are many empty entries.

| Offset | Size | Field Name | Description |
|--------|------|------------|-------------|
| 0x00 | HEADER.SIZE_FAT | FAT_ENTRY_ARRAY | Array of FAT_ENTRY objects |

The entire section itself is categorized into 4 separate blocks or pages of FAT entry types.

| Block | Size | Purpose |
|-------|------|---------|
| 1 | 3840 (`ADEMO.DAS` = 0) | Wall and floor textures |
| 2 | 256 (`ADEMO.DAS` = 0) | Always empty |
| 3 | 256 (`ADEMO.DAS` = 293) | Object-mappable sprites (3D object textures, items, etc.) |
| 4 | variable | Directional sprites |

And here is the `FAT_ENTRY` itself:

| Offset | Size | Field Name | Description |
|--------|------|------------|-------------|
| 0x00 | 4 | DATA_BLOCK_OFFSET | when image, this is absolute offset to data block within file<br>when enemy or directional object, the value, although set, is unused (can be zeroed out with no effect) |
| 0x04 | 2 | DATA_SIZE_BASE | This value is used to calculate the total size of the data block pointed to by DATA_BLOCK_OFFSET. The standard operation to be done is multiply by 2. For animations, the value must instead be shifted to the left 4 bits (or multiplying it by `0x10`). When the type is monster or directional object the size value is unused but still must be greater than 0. Size 4 is typically used |
| 0x06 | 1 | FLAG_1 | Flags or type. (0x24 is monster) |
| 0x07 | 1 | FLAG_2 | when FLAG_1 is 0x24, this is the index within the monster mapping section to apply to the object |

#### FLAG_1 Bit Flags

| Bit | Name | Description |
|-----|------|-------------|
| 0   | Unknown | Unused? |
| 1   | Sky | Set this bit to use the texture in the skybox. The texture's modifier value becomes a shift upward value for the skybox. Attempting to use a texture in the skybox without this bit set will cause minor rendering issues as well as having the skybox's draw height be dependent on the player's starting rotation |
| 2   | Monster | Must also set bit 5 (directional object); FLAG_2 becomes index within monster mapping section |
| 3   | Shift Origin | With this bit checked, an additional two 2-byte signed integers are added before the data block's offset. The first byte is an x-offset, the second a y-offset. Not included in the data size. These values will shift the draw origin of the texture. Can only be used on fat3 objects and fat4 directional/monster textures. Allows the alignment of different sized animations to a unified origin point. |
| 4   | No Effect | Seems to be set only when the texture's BLOCK_TYPE_MODIFIER bit 4 is set (draw downward). No effect on its own |
| 5   | Directional Object | Sprites with multiple viewing angles. FLAG_2 becomes index within directional object table |
| 6   | No Effect | Again seems to be set only when the texture's BLOCK_TYPE_MODIFIER bit 6 is set (image pack). No effect on its own |
| 7   | No Effect | Again seems to be set only when the texture's BLOCK_TYPE_MODIFIER bit 7 is set (half size). No effect on its own |

#### FLAG_2 Bit Flags

| Bit | Name | Description |
|-----|------|-------------|
| 0   | Delta Animation | Must be set for delta encoded animation textures |
| 1   | Sub-image Animation | Must be set for sub-image encoded animation textures |
| 2   | Unknown | Unused? |
| 3   | Unknown | Unused? |
| 4   | No Effect | Seems to be set only when the texture's BLOCK_TYPE bit 4 is set (unknown). No actual effect on its own |
| 5   | Unknown | Unused? |
| 6   | Unknown | Unused? |
| 7   | No Effect | Again seems to be set only when the texture's BLOCK_TYPE bit 7 is set (3d object). No effect on its own |

Again FLAG_2 instead becomes an index into the directional object mapping table or monster mapping table when the corresponding FLAG_1 bits are set.


## FAT Data Blocks Section (WIP)

Each block within the FAT Data Blocks section begins with two bytes of data identifying what structure the data is. 

The majority of the data contained here is image/texture data. 

**Note:** Realms of the Haunting transposes its textures. Textures displayed on floors and ceilings will be displayed as stored in the DAS file. Textures displayed on walls or as objects will be rotated 90 degrees clockwise then mirrored horizontally.

The second byte is considered the data block_type and the first byte is considered the block_type_modifier. The naming is likely not completely accurate, because both bytes include type information. Generally, however the block_type is "what is the data and how is it read" and the block_type_modifier is "how does the engine use or place this".

| Offset | Size | Field Name | Description |
|--------|------|------------|-------------|
| 0x00 | 1 | BLOCK_TYPE_MODIFIER |  | 
| 0x01 | 1 | BLOCK_TYPE |  |
| 0x02 | ~ | DATA_BLOCK_DATA | The remaining data dependent on the BLOCK_TYPE and BLOCK_TYPE_MODIFIER combination |

Here are the main data block types and their associated BLOCK_TYPE and BLOCK_TYPE_MODIFIER:

| Description | BLOCK_TYPE_MODIFIER | BLOCK_TYPE |
| --- | --- | --- |
| [Plain Texture](#plain-texture) | `0x80` - `0x9F` | Even-numbered under `0x40` (ex: `0x10`) |
| Plain Texture Transposed |  |  |
| [Animated Texture (Compressed)](#animated-texture-compressed) |  | Odd-numbered under `0x40` (ex: `0x11`) |
| [Directional Billboard Object](#directional-billboard-object) | `0xC0` - `0xDF` |  |
| [Graphics Folder](#graphics-folder) | `0x40` only |  |
| [3D Object](#3d-object) |  | `0x80` only |


#### BLOCK_TYPE Bit Flags

| Bit | Name | Description |
|-----|------|-------------|
| 0   | Animation | Set when the data is either a delta or sub-image animation |
| 1   | Disable Pixel 0 Transparency | This only applies to textures when used on mid double-sided faces. Stops pixels with value zero from being fully transparent. Single sided faces will always have pixel zero be opaque while objects will always have pixel zero be transparent |
| 2   | Enable Semi-transparency | Causes pixel values 128-255 to become semi-transparent |
| 3   | Turn into Mirror | If bit 2 is set only transparent parts of the texture become a mirror |
| 4   | Unknown | This flag is set all over the place but doesn't seem to do anything. Seems to be mostly set on wall and other vertical textures. Might be an old no longer used method of determining floor/ceiling vs wall textures |
| 5   | Large Size | Can only be used on objects with the half-size modifier set. Causes objects to render at a large size |
| 6   | Even Larger Size | Can only be used on objects with the half-size modifier set. Causes objects to render at an even larger size. Can be combined with bit 5 for a super large size object |
| 7   | 3D Object | Set when the data is 3d object data |


#### BLOCK_TYPE_MODIFIER Bit Flags

| Bit | Name | Description |
|-----|------|-------------|
| 0-3 | Shift Downward | Value as 0-15. Shift fat3 objects and fat4 directional textures downward this many pixels |
| 4   | Draw Downward/Pin Ceiling | Works only on objects and directional textures. Used to move the origin from the bottom center to the top center |
| 5   | Unknown | Hides Object? Collision still works |
| 6   | Image Pack | Used for both 3D object graphics folders as well as directional billboard objects |
| 7   | Half Size | Works on objects and directional textures. Causes the texture to render at half-size |

*Block Type Animation, Block Type 3D Object, and Block Type Modifier Image Pack are mutually exclusive.*

### Data formats for all data block types

#### Plain Texture

| Offset | Size | Field Name | Description |
|--------|------|------------|-------------|
| 0x00 | 1 | BLOCK_TYPE_MODIFIER | High nibble is `0x8` or `0x9` (representing this type of object) and the low nibble encodes vertical displacement in the world (not exactly sure on the specifics).<br>When the high nibble is `0x8`, the image's bottom is positioned at the object. When the high nibble is `0x9` the image's top is positioned at the object. | 
| 0x01 | 1 | BLOCK_TYPE | This is an even value, indicating it is a plain texture (such as `0x10`). Bits 4-6 represent scaling (`0x1*` for standard scaling, `0x2*` for large scaling, and `0x4*` for extra large scaling) |
| 0x02 | 2 | IMAGE_WIDTH | Number of pixels wide the image is (prior to any transposing) |
| 0x04 | 2 | IMAGE_HEIGHT | Number of pixels tall the image is (prior to any transposing) |
| 0x06 | IMAGE_WIDTH<br>* IMAGE_HEIGHT | PIXEL_DATA | Raw pixels in the image. Each byte is an index reference to the palette. 


#### Animated Texture (Compressed)

This data block contains animation data and the frames are stored in one of two compression formats: 
- Delta Compression
- RLE with Sub-Image Headers

| Offset | Size | Field Name | Description |
|--------|------|------------|-------------|
| 0x00 | 1 | BLOCK_TYPE_MODIFIER | The low nibble encodes vertical displacement in the world (not exactly sure on the specifics).<br>When the high nibble is `0x8`, the image's bottom is positioned at the object. When the high nibble is `0x9` the image's top is positioned at the object. | 
| 0x01 | 1 | BLOCK_TYPE | This is an odd value, indicating it is a compressed animation (such as `0x11`). Bits 4-6 represent scaling (`0x1*` for standard scaling, `0x2*` for large scaling, and `0x4*` for extra large scaling) |
| 0x02 | 2 | BUFFER_WIDTH | Number of pixels wide the buffer should be |
| 0x04 | 2 | BUFFER_HEIGHT | Number of pixels tall the buffer should be |
| 0x06 | 4 | TOTAL_BLOCK_SIZE | Total size of the data block IF Delta Compression, otherwise just `0x00` |
| 0x0A | 2 | BASE_IMAGE_OFFSET | Offset from data block start to the first image, which is stored as [Plain Data Format](#plain-texture) |
| 0x0C | 2 | NUM_DELTA_FRAMES | Number of delta frames IF Delta Compression, otherwise `0xFFFE` |
| 0x0E | ~ | COMPRESSION_DATA | The rest of the data block is dependent on the type of compression that is used |

<b>Delta Compression</b>  
TODO

<b>RLE with Sub-Image Headers</b>  
TODO

#### Directional Billboard Object

<b>Summary:</b> The Directional Billboard Object renders an object in the world with billboarding. Depending on the angle the player is in relation to the direction the object is pointing, a different texture will be displayed, simulating a basic 3D object. There are 8 total directions that such an object renders. Direction 1 is the back and incrementing clockwise, with direction 5 being the front.

The data has a header followed by an array of raw texture images.

| Offset | Size | Field Name | Description |
|--------|------|------------|-------------|
| 0x00 | 1 | BLOCK_TYPE_MODIFIER | High nibble is `0xC` or `0xD` (representing this type of object) and the low nibble encodes vertical displacement in the world (not exactly sure on the specifics) | 
| 0x01 | 1 | BLOCK_TYPE | `0x10` for standard scaling, `0x20` for large scaling, and `0x40` for extra large scaling |
| 0x02 | 2 | MAX_WIDTH | The max width of the textures |
| 0x04 | 2 | MAX_HEIGHT | The max height of the textures |
| 0x06 | 1 | OFFSETS_SIZE | For directional billboard objects this will always be 16 |
| 0x07 | 1 | PACK_TYPE | For directional billboard objects bit 7 will be set. Other bits are unused |
| 0x08 | 2 | DIR_1_IMG_REF | Packed image reference for first direction. Bit 15 is the horizontal mirror flag (1 = flipped). Bits 0-14 store the image data offset in units of 16 bytes. The actual byte offset is (value & `0x7FFF`) << 4, relative to the start of the data block. |
| 0x0A | 2 | DIR_2_IMG_REF | Same as DIR_1_IMG_REF, but for direction 2 |
| 0x0C | 2 | DIR_3_IMG_REF | Same as DIR_1_IMG_REF, but for direction 3 |
| 0x0E | 2 | DIR_4_IMG_REF | Same as DIR_1_IMG_REF, but for direction 4 |
| 0x10 | 2 | DIR_5_IMG_REF | Same as DIR_1_IMG_REF, but for direction 5 |
| 0x12 | 2 | DIR_6_IMG_REF | Same as DIR_1_IMG_REF, but for direction 6 |
| 0x14 | 2 | DIR_7_IMG_REF | Same as DIR_1_IMG_REF, but for direction 7 |
| 0x16 | 2 | DIR_8_IMG_REF | Same as DIR_1_IMG_REF, but for direction 8 |
| 0x18 | 8 | PADDING | appears to always be 8 bytes |
| 0x1E | ~ | IMAGE_DATA_ARRAY | Array of raw pixel data for texture images |

<b>`IMAGE_DATA_ARRAY` Entry</b>  
The images can take the form of any of the texture formats as listed in [FAT Data Blocks Section](#fat-data-blocks-section-wip). Most common is the [Plain Texture](#plain-texture)

#### Graphics Folder

This special data type contains a grouping of related textures. Most commonly these represent graphics to be applied to a 3D Object. There is a small header which contains modified offsets to each of the contained textures.  

| Offset | Size | Field Name | Description |
|--------|------|------------|-------------|
| 0x00 | 1 | BLOCK_TYPE_MODIFIER | `0x40` |
| 0x01 | 1 | BLOCK_TYPE | either `0x10` or `0x12` TODO |
| 0x02 | 2 | MAX_WIDTH | The max width of the textures |
| 0x04 | 2 | MAX_HEIGHT | The max height of the textures |
| 0x06 | 1 | OFFSETS_SIZE | Size of the offsets array |
| 0x07 | 1 | PACK_TYPE | For graphics folders bit 7 will **not** be set. Other bits are unused |
| 0x08 | ~ | SHIFTED_IMAGE_OFFSET_ARRAY | This is an array of 2-byte size values representing an offset to each of the contained images. This value must be shifted left 4 bits to get the offset. The offset is relative to the start of the data block.<br>The array is terminated by a 4 byte null value (`00 00 00 00`) and further aligned to 16 bytes. |
| ~ | ~ | IMAGES | The remainder of the data block is the raw image data. Each image pointed to by the entries in SHIFTED_IMAGE_OFFSET_ARRAY is one of the Plain Texture formats (including the header). Each image is also aligned to 16 bytes. |

#### 3D Object

This data type renders fully meshed 3D objects in the world.

The data object is made up of an array of 3D vertices and then an array of face mapping objects which create a face by referencing 3 or 4 vertices. It's also possible to pin an object texture to a single vertex, although this is only used once in the base game on the object `CHAND2` which is the chandelier in the starting room of the game (map: `STUDY1`).

| Offset | Size | Field Name | Description |
|--------|------|------------|-------------|
| 0x00 | 1 | BLOCK_TYPE_MODIFIER | `0x10` or `0x00` |
| 0x01 | 1 | BLOCK_TYPE | `0x80` |
| 0x02 | 2 | MAX_BOUND_X | The maximum X distance (in both negative and positive directions) |
| 0x04 | 2 | MAX_BOUND_Y | The maximum Y distance (in both negative and positive directions) |
| 0x06 | 2 | UNK_0x06 | Only `0x08` |
| 0x08 | 2 | UNK_0x08 | Always seems to be the amount of vertices plus or minus a couple |
| 0x0A | 4 | UNK_0x0A | Only `0x1E` |
| 0x0E | 2 | MAX_BOUND_Z | The maximum Z distance (in both negative and positive directions) |
| 0x10 | 4 | UNK_0x10 | Only `0x00` |
| 0x14 | 2 | NUM_VERTICES | The number of vertices that makes up the 3D object |
| 0x16 | 0x10 * NUM_VERTICES | VERTICES_ARRAY | An array containing the vertices of type VERTEX that make up the 3D object |
| 0x16 + (0x10 * NUM_VERTICES) | ~ | FACE_MAPPING_SECTION | The rest of the data block contains information for constructing faces and mapping textures to them |

Here is the format for the VERTEX type. Each vertex is 16 bytes in size.
| Offset | Size | Field Name | Description |
|--------|------|------------|-------------|
| 0x00 | 2 | POS_X | X-coordinate of the vertex |
| 0x02 | 2 | POS_Y | Y-coordinate of the vertex |
| 0x04 | 2 | POS_Z | Z-coordinate of the vertex |
| 0x06 | 0x0A | PADDING | The remaining 10 bytes is padding |

Here is the format for FACE_MAPPING_SECTION:
| Offset | Size | Field Name | Description |
|--------|------|------------|-------------|
| 0x00 | 4 | EXP2 | ASCII string "EXP2" |
| 0x04 | 2 | UNK_0x04 | Likely padding. Only `0x00` |
| 0x06 | 2 (big-endian) | FACES_ARRAY_SIZE | Size of the face mapping array in bytes. NOTE: this value is big-endian byte order. |
| 0x08 | FACES_ARRAY_SIZE | FACES_ARRAY | An array of FACE objects, which determine how to build and map a face on the 3D object |

And below is the format for a FACE.  

<b>Note:</b> the object contains a lot of seemingly really specific rendering information (like altering pixel projections on the face). In most faces, however, it is fairly straightforward how the texture is mapped: by default the texture fills the face and then applies things like mirroring or transparency using the RENDER_FLAG_1 and RENDER_FLAG_2 combination. 
| Offset | Size | Field Name | Description |
|--------|------|------------|-------------|
| 0x00 | 2 | SIZE | The size in bytes of this data element |
| 0x02 | 4 | UNK_0x02 | Only `0x00` |
| 0x06 | 2 | UNK_0x06 | Only `0x00` |
| 0x08 | 2 | UNK_0x08 | `0x00`, `0x08`, or `0x0E` |
| 0x0A | 2 | UNK_0x0A | `0x00`, `0x03`, or `0x04` |
| 0x0C | 2 (big-endian) | TEXTURE_FAT_INDEX_BASE | This number is used to calculate the texture index (FAT_INDEX) within the File Allocation Table. That means this is the texture to use on this face. It can either be a [Plain Texture](#plain-texture), [Compressed Animation](#animated-texture-compressed), or a [Graphics Folder](#graphics-folder). It could also be a solid color from the palette if the first byte is `0xFF`. NOTE: this value is big-endian byte order.<br>Most of the time this is just the raw index to the FAT, but when EDGE_COUNT is 0, `0x1000` needs to be added to the value. |
| 0x0E | 2 | UNK_0x0E | This seems to be some flag. Either `0x00` or `0x80` |
| 0x10 | 6 | UNK_0x10 | Only `0x00` |
| 0x16 | 1 | RENDER_FLAG_1 | TODO This is a bit packed flag.<br>0 = transparency (see RENDER_FLAG_2) <br>1 = mirror<br>2 = mirror (when rendered as floor)<br>3 = visible<br>4 = ?<br>5 = render as floor<br>6 = ?<br>7 = ? |
| 0x17 | 1 | RENDER_FLAG_2 | TODO Maybe another bit packed flag, but not as consistent.<br>`0x00` - automatically transparent and RENDER_FLAG_2 bit 0 has no effect<br>`0x01` - repeating texture<br>`0x02` - mirrored<br>`0x03` - mirrored<br>`0x12` - solid color |
| 0x18 | 4 | UNK_0x18 |  |
| 0x1C | 1 | SUB_TEXTURE_INDEX | Which image within a [Graphics Folder](#graphics-folder) to display.<br>Note: the object `CROSS` in the base game (FAT index 4237) seems to use this field in another way, but this object is not used in the game, so this field may have previously had other functionality | 
| 0x1D | 1 | UNK_0x1D |  |
| 0x1E | 1 | UNK_0x1E |  |
| 0x1F | 1 | UNK_0x1F | render-related |
| 0x20 | 4 | UNK_0x20 | render-related. 3-4 `0xFF` bytes seemingly. This can be modified with UNK_0x1F to  |  |
| 0x24 | 2 | UNK_0x24 | render-related. Likely another bit flag. Bit 0 is never set. |
| 0x26 | 2 | UNK_0x26 | render-related |
| 0x28 | 4 | UNK_0x28 | `0x00` except for every face in `CHAIR3` which is `0x01010101` (but this object doesn't render properly, it's likely unfinished or scrapped) |
| 0x2C | 4 | UNK_0x2C | `0x00` except for every face in `CHAIR3` which is `0xFFFFFFFF` (but this object doesn't render properly, it's likely unfinished or scrapped) |
| 0x30 | 2 | UNK_0x30 | Only `0x32` |
| 0x32 | 2 | UNK_0x32 | Only `0x00` |
| 0x34 | 2 | EDGE_COUNT | How many edges the face should be made up of. The following is an array of vertex indices that make the face. The vertices must make a closed loop, resulting in the array size being EDGE_COUNT + 1. If EDGE_COUNT is 0, the texture will be pinned and rendered right at the point of the vertex<br>Only values used in base game are `0x00`, `0x03`, and `0x04`. The only time  |
| 0x36 | (EDGE_COUNT + 1) * 0x02 | EDGE_ARRAY | An array of `0x02` size vertex indices indicating the points that make up the face. Note: the vertex is a little weird, appears to be encoded << 4 (so to reference vertex index 1 the value used is `0x10` not `0x01`) |

## Directional Object Table

Located at HEADER.DIRECTIONAL_OBJECT_TABLE.

Very similar to the [Directional Billboard Object](#directional-billboard-object), this section simply maps directional textures to an object. In `ADEMO.DAS`, this is primarily used to apply textures to the bullets (projectiles) of the game.

Unlike Directional Billboard Objects, the texture data is not stored in this object, but are references to other FAT entries. 

Each object has 8 angles from which it can be viewed. Direction 1 is the back and incrementing clockwise, with direction 5 being the front.

| Offset | Size | Field Name | Description |
|--------|------|------------|-------------|
| 0x00 | ~ | OFFSET_ARRAY | An array of 2-byte offsets from start of the section to the associated DIRECTIONAL_OBJECT_MAPPING |
| ~ | (OFFSET_ARRAY / 2) * 0x12 | DIRECTIONAL_OBJECT_MAPPING_ARRAY | An array of DIRECTIONAL_OBJECT_MAPPING's |

`DIRECTIONAL_OBJECT_MAPPING`:
| Offset | Size | Field Name | Description |
|--------|------|------------|-------------|
| 0x00 | 2 | HEADER | Always `10 80` |
| 0x02 | 2 | DIR_1_FAT_IDX | Packed data containing the index to the FAT entry that should be mapped to the first direction.<br>If the top bit is set (bit 15), the texture will be mirrored.<br>If the file is `ADEMO.DAS`, `fat_index = first_byte \| (((second_byte & 0x7F) - 0x12) << 8)`<br>For every other `*.DAS` file, `fat_index = DIR_1_FAT_IDX & 0x7FFF` (this just retrieves the lower 15 bits) |
| 0x02 | 2 | DIR_2_FAT_IDX | Same as DIR_1_FAT_IDX, but for direction 2 |
| 0x02 | 2 | DIR_3_FAT_IDX | Same as DIR_1_FAT_IDX, but for direction 3 |
| 0x02 | 2 | DIR_4_FAT_IDX | Same as DIR_1_FAT_IDX, but for direction 4 |
| 0x02 | 2 | DIR_5_FAT_IDX | Same as DIR_1_FAT_IDX, but for direction 5 |
| 0x02 | 2 | DIR_6_FAT_IDX | Same as DIR_1_FAT_IDX, but for direction 6 |
| 0x02 | 2 | DIR_7_FAT_IDX | Same as DIR_1_FAT_IDX, but for direction 7 |
| 0x02 | 2 | DIR_8_FAT_IDX | Same as DIR_1_FAT_IDX, but for direction 8 |

## Object Collision Section

Starts at HEADER.OBJECT_COLLISION_SECTION_OFFSET.

This section defines the collision box for the objects in the world. These are the FAT entries corresponding with [FAT block 3](#file-allocation-table). As a result, the size of this section is `HEADER.FAT_BLOCK_3_COUNT * 4`.

| Offset | Size | Field Name | Description |
|--------|------|------------|-------------|
| 0x00 | HEADER.FAT_BLOCK_3_COUNT * 4 | COLLISION_BOX_ARRAY | array of collision box definitions |

Each element in the array corresponds directly to the same index within FAT block 3 in the FAT entries. For example, in `DEMO.DAS` the second entry in FAT block 3 is the object `SOFA` and its corresponding collision box information is therefore the second entry in the COLLISION_BOX_ARRAY. 

The collision box definition can take one of two forms:
- standard objects
- [3D objects](#3d-object)

<b>Standard Objects</b>
| Offset | Size | Field Name | Description |
|--------|------|------------|-------------|
| 0x00 | 2 | HEIGHT | height of the collision box |
| 0x02 | 2 | WIDTH | width of the collision box (in both x and y directions) |

<b>3D Objects</b>
| Offset | Size | Field Name | Description |
|--------|------|------------|-------------|
| 0x00 | 1 | ? | seems to be always 0 |
| 0x01 | 1 | HEIGHT | height of the collision box |
| 0x02 | 1 | WIDTH_PERPENDICULAR | width perpendicular to the rotation direction |
| 0x03 | 1 | WIDTH_PARALLEL | width parallel to the rotation direction |

## Monster Mapping Section

Starts at HEADER.MONSTER_MAPPING_SECTION.

This section is an array of monster texture mapping entries, which assigns textures to various monster-related states, such as flying, walking, attacking, and dying. A monster texture mapping entry is referred to by its index in this array.

| Offset | Size | Field Name | Description |
|--------|------|------------|-------------|
| 0x00 | 0x68 | monster_mapping_entry_array  | array of monster mapping entries |

#### Monster mapping entry

Each monster state can have a texture/animation assigned to it. Flying, walking, primary attack, secondary attack, and receiving damage are all directional and can have a texture/animation assigned to any of 8 directions.

Notes: 
- If the monster has flying animations assigned, the game automatically makes it able to fly
- Primary and secondary attacks and receiving damage only ever have the "front" position that's differently defined; the other positions are just the walking textures.
- The receiving damage state only randomly occurs when the monster receives damage

| Offset | Size | Field Name | Description |
|--------|------|------------|-------------|
| 0x00 | 4 | unk_0x00               |  |
| 0x04 | 2 | flying_back            | Flying textures |
| 0x06 | 2 | flying_back_right      |  |
| 0x08 | 2 | flying_right           |  |
| 0x0A | 2 | flying_front_right     |  |
| 0x0C | 2 | flying_front           |  |
| 0x0E | 2 | flying_front_left      |  |
| 0x10 | 2 | flying_left            |  |
| 0x12 | 2 | flying_back_left       |  |
| 0x14 | 2 | walking_back           | Walking textures |
| 0x16 | 2 | walking_back_right     |  |
| 0x18 | 2 | walking_right          |  |
| 0x1A | 2 | walking_front_right    |  |
| 0x1C | 2 | walking_front          |  |
| 0x1E | 2 | walking_front_left     |  |
| 0x20 | 2 | walking_left           |  |
| 0x22 | 2 | walking_back_left      |  |
| 0x24 | 2 | attack1_back           | Primary attack textures |
| 0x26 | 2 | attack1_back_right     |  |
| 0x28 | 2 | attack1_right          |  |
| 0x2A | 2 | attack1_front_right    |  |
| 0x2C | 2 | attack1_front          |  |
| 0x2E | 2 | attack1_front_left     |  |
| 0x30 | 2 | attack1_left           |  |
| 0x32 | 2 | attack1_back_left      |  |
| 0x34 | 2 | attack2_back           | Secondary attack textures |
| 0x36 | 2 | attack2_back_right     |  |
| 0x38 | 2 | attack2_right          |  |
| 0x3A | 2 | attack2_front_right    |  |
| 0x3C | 2 | attack2_front          |  |
| 0x3E | 2 | attack2_front_left     |  |
| 0x40 | 2 | attack2_left           |  |
| 0x42 | 2 | attack2_back_left      |  |
| 0x44 | 2 | on_damage_back         | Receiving damage textures (only a small chance) |
| 0x46 | 2 | on_damage_back_right   |  |
| 0x48 | 2 | on_damage_right        |  |
| 0x4A | 2 | on_damage_front_right  |  |
| 0x4C | 2 | on_damage_front        |  |
| 0x4E | 2 | on_damage_front_left   |  |
| 0x50 | 2 | on_damage_left         |  |
| 0x52 | 2 | on_damage_back_left    |  |
| 0x54 | 2 | dying_normal           | Death animation |
| 0x56 | 2 | dead_normal            | Dead texture |
| 0x58 | 2 | dying_crit             | Death by massive damage animation |
| 0x5A | 2 | dead_crit              | Dead texture (when death by massive damage) |
| 0x5C | 2 | spawn                  | Spawn animation |
| 0x5E | 2 | unk_0x5e               |  |
| 0x60 | 4 | unk_0x60               |  |
| 0x64 | 4 | unk_0x64               |  |

## File Names Section

| Offset | Size | Field Name | Description |
|--------|------|------------|-------------|
| 0x00 | 2 | section1_element_count  | Count of the elements in the first section |
| 0x02 | 2 | section2_element_count  | Count of the elements in the section section |
| 0x04 | section1_size | section1_array  | First section of file name elements (empty for ADEMO.DAS) |
| section1_size + 0x04 | section2_size | section2_array | Second section of file name elements |

Each element in both sections are a file name element, which has the following format:

| Offset | Size | Field Name | Description |
|--------|------|------------|-------------|
| 0x00 | 2 | element_size  | Size in bytes of the file name element |
| 0x02 | 2 | index         | The index of the FAT entry to link this file to |
| 0x04 | title_size | title       | Null-terminated ASCII string representing the title of the file |
| 0x04 + title_size | description_size | description | Null-terminated ASCII string representing the description of the file |