/* ###
 * ROTH
 */
// Applies confirmed ROTH .DAS loader names and the 68-byte DASHeader structure.
//@category ROTH

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class ROTHApplyDasTypes extends GhidraScript {

	private static final CategoryPath ROTH_DAS_CATEGORY =
		new CategoryPath(CategoryPath.ROOT, "ROTH", "DAS");
	private static final long DAS_HEADER_ADDR = 0x85c58L;
	private static final long CURRENT_DAS_FAT_ENTRY_ADDR = 0x8c70cL;

	private static class NamedFunction {
		final long address;
		final String name;
		final String comment;

		NamedFunction(long address, String name, String comment) {
			this.address = address;
			this.name = name;
			this.comment = comment;
		}
	}

	private static class NamedAddress {
		final long address;
		final String name;
		final String comment;

		NamedAddress(long address, String name, String comment) {
			this.address = address;
			this.name = name;
			this.comment = comment;
		}
	}

	private final NamedFunction[] dasFunctions = new NamedFunction[] {
		new NamedFunction(0x10c32L, "load_das_file_wrapper",
			"Builds a path and dispatches to load_map_das_file."),
		new NamedFunction(0x10c70L, "load_ademo_das_wrapper",
			"Builds a path and dispatches to load_ademo_das_file."),
		new NamedFunction(0x2effbL, "load_ademo_das_file",
			"Loads ADEMO.DAS sections; expects DAS version 5 and zero palette offset."),
		new NamedFunction(0x2f1a1L, "dos_seek_file_start",
			"DOS int 21h AH=42h, origin 0: seeks current file handle from start."),
		new NamedFunction(0x2f1b4L, "load_map_das_file",
			"Loads a map DAS file; validates DASP magic/version 5 and reads FAT/palette sections."),
		new NamedFunction(0x2f379L, "read_das_palette",
			"Reads the 0x300-byte VGA palette from the DAS palette section and remaps it."),
		new NamedFunction(0x2f163L, "close_das_handles_and_buffers",
			"Clears DAS globals, frees loaded buffers, and closes the open DAS handle."),
		new NamedFunction(0x2fb7fL, "build_game_path",
			"Combines configured base path and filename unless the filename is drive-qualified."),
		new NamedFunction(0x1517dL, "game_heap_alloc",
			"Allocates from the game heap handle in g_game_heap_handle; byte count in EAX."),
		new NamedFunction(0x15191L, "game_heap_free",
			"Frees a block through the game heap handle in g_game_heap_handle; pointer in EAX."),
		new NamedFunction(0x40a2aL, "game_free_if_not_null",
			"Null-safe wrapper around game_heap_free."),
		new NamedFunction(0x411e0L, "select_das_fat_entry",
			"Selects a DAS FAT entry from map or ADEMO FAT buffers and copies it to g_current_das_fat_entry."),
		new NamedFunction(0x40d7cL, "load_das_block_for_fat_index",
			"Loads or resolves the DAS data block for the FAT index in AX/EAX."),
		new NamedFunction(0x4134aL, "reserve_das_cache_slot",
			"Scans 240 DAS cache slots for a zero allocation pointer or starts eviction."),
		new NamedFunction(0x41317L, "read_das_block_payload",
			"Reads a selected DAS data block payload into the allocated cache block."),
		new NamedFunction(0x41331L, "read_das_block_with_size_prefix",
			"Reads payload_size+4 at cache+0x06 and preserves the 4-byte prefix at cache+0x04."),
		new NamedFunction(0x41385L, "evict_das_cache_slot",
			"Chooses the oldest occupied DAS cache slot by tick delta and releases it."),
		new NamedFunction(0x413eaL, "evict_one_das_cache_slot",
			"Evicts one DAS cache slot, preserving registers; returns -1 on success or 0 on failure."),
		new NamedFunction(0x413fdL, "release_das_cache_slot_resources",
			"Marks the DAS cache status entry unloaded and frees selectors/allocations for the slot."),
		new NamedFunction(0x414d2L, "ensure_das_cache_heap_space",
			"Evicts DAS cache slots until the DAS cache heap reports enough space."),
		new NamedFunction(0x414f4L, "get_loaded_das_block_for_index",
			"Returns the loaded DAS cache block for a FAT index, lazy-loading it when needed."),
		// NOTE: 0x38d6c (name conflict) + the DAS delta-stream codecs (0x4eda1/0x4ee1f/0x4eeae) moved to
		// ROTHApplyEngineNames 2026-06-30 — that script is the single authoritative source of function
		// names. 0x38d6c is render_parallax_sky_columns there (NOT render_special_das_sprite_columns).
		new NamedFunction(0x38fecL, "advance_das_sprite_animation_frame",
			"Updates animated DAS sprite frame state for the loaded block in ESI."),
		new NamedFunction(0x214b9L, "read_raw_state_stream",
			"Reads a RAW/state stream, applies full or literal/skip delta chunks, and checks EXIT."),
		new NamedFunction(0x41b41L, "dos_close_handle",
			"Closes the DOS file handle in EAX through int 21h AH=3eh."),
		new NamedFunction(0x41b53L, "dos_read_items",
			"Reads EDX items of EBX bytes from handle ECX into EAX; returns item count."),
		new NamedFunction(0x41b7aL, "dos_write_items",
			"Writes EDX items of EBX bytes from EAX to handle ECX; returns item count."),
		new NamedFunction(0x41250L, "refresh_moved_das_cache_block",
			"Clears moved-block state and refreshes DAS selectors or internal pointers."),
		new NamedFunction(0x412edL, "refresh_das_block_selector_base",
			"Updates a loaded DAS block selector base through DPMI function 0007h."),
		new NamedFunction(0x41554L, "initialize_das_block_internal_pointers",
			"Converts shifted offsets and initializes node pointers for runtime flag 0x8000 blocks."),
		new NamedFunction(0x41616L, "zero_memory",
			"Zeros EDX bytes at EAX using dword stores followed by byte tail cleanup."),
		new NamedFunction(0x41051L, "postprocess_loaded_das_block",
			"Post-processes a loaded DAS data block after it has been read into cache."),
		new NamedFunction(0x41191L, "setup_das_block_selector",
			"Allocates a DPMI selector and sets base/limit for a loaded DAS block."),
		new NamedFunction(0x41631L, "repair_das_rle_frame_count",
			"Validates and repairs the frame count for RLE/sub-image compressed DAS blocks.")
	};

	private final NamedAddress[] dasGlobals = new NamedAddress[] {
		new NamedAddress(0x7f374L, "g_game_heap_handle",
			"Heap/context handle used by game_heap_alloc and game_heap_free."),
		new NamedAddress(0x89f0cL, "g_roth_error_code",
			"Global ROTH error/status code; DAS loader sets values 9 and 14."),
		new NamedAddress(0x85d00L, "g_das_file_handle",
			"Open DOS file handle for the active DAS file."),
		new NamedAddress(0x90cbeL, "g_das_unk_0x22",
			"Copy of DASHeader.unk_0x22 from the active map DAS header."),
		new NamedAddress(0x85ce8L, "g_map_das_dir_table_buffer",
			"Allocated base buffer for the map DAS directional object table."),
		new NamedAddress(0x90a38L, "g_map_das_fat_buffer",
			"Pointer to the map DAS FAT entries inside the directional/FAT allocation."),
		new NamedAddress(0x89f3fL, "g_das_skip_palette_load_flag",
			"Nonzero skips reading palette/remap data from the current map DAS."),
		new NamedAddress(0x89f10L, "g_das_palette_remap_prefix",
			"Two bytes read after the 0x300-byte palette and before remap chunks."),
		new NamedAddress(0x86d14L, "g_das_remap_chunk_4000_ptr",
			"Pointer receiving the first 0x4000-byte palette remap chunk."),
		new NamedAddress(0x85d08L, "g_das_remap_chunk_10000_ptr",
			"Pointer receiving the 0x10000-byte palette remap chunk."),
		new NamedAddress(0x85d10L, "g_das_remap_chunk_100_a_ptr",
			"Pointer receiving a 0x100-byte palette remap chunk."),
		new NamedAddress(0x86d20L, "g_das_remap_chunk_100_b_ptr",
			"Pointer receiving a second 0x100-byte palette remap chunk."),
		new NamedAddress(0x85c50L, "g_das_collision_buffer",
			"Buffer that receives 0x800 bytes from DASHeader.object_collision_section_offset."),
		new NamedAddress(0x85d14L, "g_das_unk_0x10_buffer",
			"Buffer that receives 0x1000 bytes from DASHeader.unk_0x10_section_offset."),
		new NamedAddress(0x85cf0L, "g_ademo_das_fat_buffer",
			"Pointer to ADEMO.DAS FAT entries loaded by load_ademo_das_file."),
		new NamedAddress(0x85c3cL, "g_das_cache_heap_handle",
			"Heap/context handle used for DAS cache block allocations."),
		new NamedAddress(0x85400L, "g_das_eviction_protected_allocation",
			"Allocation pointer protected from zero-age DAS cache eviction."),
		new NamedAddress(0x8c70cL, "g_current_das_fat_entry",
			"Static copy of the selected 8-byte DAS FAT entry."),
		new NamedAddress(0x8c72cL, "g_current_das_block_size_bytes",
			"Computed byte size for the selected DAS FAT data block."),
		new NamedAddress(0x8c730L, "g_current_das_fat_index_x2",
			"Current DAS FAT index multiplied by 2; also used as an offset into 16-bit tables."),
		new NamedAddress(0x86d30L, "g_das_entry_status_table",
			"0x1600-entry word table tracking DAS FAT cache/status markers."),
		new NamedAddress(0x8c740L, "g_das_low_index_bitset",
			"Bitset used by low-index DAS entries before loading/cache resolution."),
		new NamedAddress(0x89930L, "g_das_cache_slots",
			"0xf0 cache slot records; each record is 4-byte pointer plus 2-byte age/tick."),
		new NamedAddress(0x8c734L, "g_current_das_cache_slot",
			"Pointer to the selected 6-byte DAS cache slot record."),
		new NamedAddress(0x8c738L, "g_current_das_block_allocation",
			"Pointer to the allocation backing the current loaded DAS block."),
		new NamedAddress(0x8c73cL, "g_current_das_alloc_size",
			"Allocation size requested for the current DAS block cache allocation."),
		new NamedAddress(0x8c940L, "g_current_das_cache_slot_index",
			"Index of the selected DAS cache slot."),
		new NamedAddress(0x8c942L, "g_das_special_index_load_flag",
			"Set when loading the special DAS FAT index stored at g_das_special_fat_index."),
		new NamedAddress(0x89f34L, "g_das_special_fat_index",
			"Special FAT index handled separately by load_das_block_for_fat_index."),
		new NamedAddress(0x90c0aL, "g_das_cache_tick",
			"16-bit DAS cache age/tick copied into cache slots when blocks are loaded."),
		new NamedAddress(0x90cc4L, "g_das_force_low_index_status_flag",
			"Forces low-index entries down the 0xfd status-table path."),
		new NamedAddress(0x90c06L, "g_render_target_selector",
			"Segment selector loaded into ES by column renderers for the active render target."),
		new NamedAddress(0x8a310L, "g_render_double_scanline_flag",
			"Nonzero column renderer path writes two screen rows per source sample."),
		new NamedAddress(0x8a356L, "g_render_x_flip_flag",
			"Nonzero makes column renderers step the destination pointer backwards."),
		new NamedAddress(0x84980L, "g_render_source_base_ptr",
			"Current render source base pointer; DAS animation helper updates this for frames."),
		new NamedAddress(0x8c484L, "g_render_column_source_table",
			"Column lookup table used by render_parallax_sky_columns for source coordinates."),
		new NamedAddress(0x90aa8L, "g_raw_state_primary_buffer",
			"Primary buffer serialized by the RAW/state stream read/write path."),
		new NamedAddress(0x90aa4L, "g_raw_state_secondary_buffer",
			"Secondary buffer serialized immediately after the primary RAW/state stream chunk.")
	};

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			printerr("Open the ROTH program before running this script.");
			return;
		}

		Structure dasHeader = defineDasHeader();
		Structure dasFatEntry = defineDasFatEntry();
		applyDasHeader(dasHeader);
		applyCurrentDasFatEntry(dasFatEntry);
		applyDasGlobals();
		applyDasNames();

		println("Applied DASHeader at 0x" + Long.toHexString(DAS_HEADER_ADDR) +
			" and refreshed DAS loader names/globals.");
		println("DAS labels are refreshed; continue with the next address from the project notes/chat.");
	}

	private Structure defineDasHeader() {
		StructureDataType header = new StructureDataType(ROTH_DAS_CATEGORY, "DASHeader", 0);
		DataType char4 = new ArrayDataType(CharDataType.dataType, 4, 1);
		DataType u16 = UnsignedShortDataType.dataType;
		DataType u32 = UnsignedIntegerDataType.dataType;

		header.add(char4, 4, "signature", "File signature: DASP.");
		header.add(u16, 2, "version", "Always 5 for known ROTH DAS files.");
		header.add(u16, 2, "size_fat", "Total FAT byte size; FAT entries are 8 bytes each.");
		header.add(u32, 4, "img_fat_offset", "File offset to image FAT.");
		header.add(u32, 4, "palette_system_offset", "File offset to palette/remap data; zero for ADEMO.DAS.");
		header.add(u32, 4, "unk_0x10_section_offset", "File offset to the unknown 0x10 section.");
		header.add(u32, 4, "file_names_section_offset", "File offset to filename section.");
		header.add(u16, 2, "file_names_section_size", "Filename section size in bytes.");
		header.add(u16, 2, "directional_object_table_size", "Directional object table size in bytes.");
		header.add(u32, 4, "directional_object_table_offset", "File offset to directional object table.");
		header.add(u16, 2, "unk_0x20", "Unknown field, low word of documented 0x20 value.");
		header.add(u16, 2, "unk_0x22",
			"Unknown field copied to DAT_00090cbe by load_map_das_file.");
		header.add(u32, 4, "object_collision_section_offset", "File offset to object collision section.");
		header.add(u32, 4, "monster_mapping_section_offset", "File offset to monster mapping section.");
		header.add(u32, 4, "monster_mapping_section_size", "Monster mapping section size in bytes.");
		header.add(u16, 2, "fat_block_1_count", "Wall/floor texture FAT entry count.");
		header.add(u16, 2, "fat_block_2_count", "Second FAT block entry count, usually empty.");
		header.add(u16, 2, "fat_block_3_count", "Object-mappable texture/data FAT entry count.");
		header.add(u16, 2, "fat_block_4_count", "Directional billboard sprite FAT entry count.");
		header.add(u32, 4, "unk_0x38_offset", "File offset to ADEMO-only unknown 0x38 section.");
		header.add(u16, 2, "unk_0x38_size", "Size of unknown 0x38 section.");
		header.add(u16, 2, "unk_0x40_size", "Size of unknown 0x40 section.");
		header.add(u32, 4, "unk_0x40_offset", "File offset to ADEMO-only unknown 0x40 section.");

		if (header.getLength() != 0x44) {
			throw new IllegalStateException("DASHeader length is 0x" +
				Integer.toHexString(header.getLength()) + ", expected 0x44.");
		}

		DataTypeManager dtm = currentProgram.getDataTypeManager();
		return (Structure) dtm.addDataType(header, DataTypeConflictHandler.REPLACE_HANDLER);
	}

	private Structure defineDasFatEntry() {
		StructureDataType entry = new StructureDataType(ROTH_DAS_CATEGORY, "DASFatEntry", 0);
		DataType u8 = ByteDataType.dataType;
		DataType u16 = UnsignedShortDataType.dataType;
		DataType u32 = UnsignedIntegerDataType.dataType;

		entry.add(u32, 4, "data_block_offset", "Absolute file offset to the FAT data block.");
		entry.add(u16, 2, "data_size_base",
			"Base size value; commonly multiplied by 2, sometimes shifted by type flags.");
		entry.add(u8, 1, "flag_1", "DAS FAT type/flag byte.");
		entry.add(u8, 1, "flag_2", "Secondary DAS FAT flag or mapping index.");

		if (entry.getLength() != 8) {
			throw new IllegalStateException("DASFatEntry length is 0x" +
				Integer.toHexString(entry.getLength()) + ", expected 0x8.");
		}

		DataTypeManager dtm = currentProgram.getDataTypeManager();
		return (Structure) dtm.addDataType(entry, DataTypeConflictHandler.REPLACE_HANDLER);
	}

	private void applyDasHeader(Structure dasHeader) throws Exception {
		Address addr = toAddr(DAS_HEADER_ADDR);
		DataUtilities.createData(currentProgram, addr, dasHeader, dasHeader.getLength(),
			DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
		createUserLabel(DAS_HEADER_ADDR, "g_das_header");
		setPlateComment(addr,
			"Global 68-byte DAS header buffer. Used by load_map_das_file and load_ademo_das_file.");
	}

	private void applyCurrentDasFatEntry(Structure dasFatEntry) throws Exception {
		Address addr = toAddr(CURRENT_DAS_FAT_ENTRY_ADDR);
		DataUtilities.createData(currentProgram, addr, dasFatEntry, dasFatEntry.getLength(),
			DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
		createUserLabel(CURRENT_DAS_FAT_ENTRY_ADDR, "g_current_das_fat_entry");
		setPlateComment(addr,
			"Static copy of the selected 8-byte DAS FAT entry populated by select_das_fat_entry.");
	}

	private void applyDasNames() throws Exception {
		for (NamedFunction item : dasFunctions) {
			monitor.checkCancelled();
			Address addr = toAddr(item.address);
			disassemble(addr);
			Function function = currentProgram.getFunctionManager().getFunctionAt(addr);
			if (function == null) {
				function = createFunction(addr, item.name);
			}
			if (function != null) {
				function.setName(item.name, SourceType.USER_DEFINED);
				function.setComment(item.comment);
			}
			else {
				createUserLabel(item.address, item.name);
			}
			setPlateComment(addr, item.comment);
		}
	}

	private void applyDasGlobals() throws Exception {
		for (NamedAddress item : dasGlobals) {
			monitor.checkCancelled();
			Address addr = toAddr(item.address);
			createUserLabel(item.address, item.name);
			setPlateComment(addr, item.comment);
		}
	}

	private void createUserLabel(long offset, String name) throws Exception {
		Address addr = toAddr(offset);
		Namespace global = currentProgram.getGlobalNamespace();
		Symbol existing = currentProgram.getSymbolTable().getSymbol(name, addr, global);
		if (existing != null) {
			return;
		}
		currentProgram.getSymbolTable().createLabel(addr, name, global, SourceType.USER_DEFINED);
	}
}
