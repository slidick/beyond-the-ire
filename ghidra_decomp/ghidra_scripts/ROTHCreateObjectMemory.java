/* ###
 * ROTH
 */
// Creates the relocated ROTH.EXE LE object memory blocks from analysis/le_image.
//@category ROTH

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

import java.io.File;
import java.io.FileInputStream;

public class ROTHCreateObjectMemory extends GhidraScript {

	private static final String IMAGE_DIR = "analysis/le_image";

	private static class RothObject {
		final String blockName;
		final String fileName;
		final long base;
		final long size;
		final boolean read;
		final boolean write;
		final boolean execute;
		final String comment;

		RothObject(String blockName, String fileName, long base, long size, boolean read,
				boolean write, boolean execute, String comment) {
			this.blockName = blockName;
			this.fileName = fileName;
			this.base = base;
			this.size = size;
			this.read = read;
			this.write = write;
			this.execute = execute;
			this.comment = comment;
		}
	}

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

	private final RothObject[] objects = new RothObject[] {
		new RothObject("ROTH_OBJ1_CODE", "object1_reloc.bin", 0x10000L, 0x48ccbL, true, false,
			true, "LE object 1: executable/readable relocated code and read-only data."),
		new RothObject("ROTH_OBJ2_STUB", "object2_reloc.bin", 0x60000L, 0x13L, true, false,
			true, "LE object 2: tiny executable/readable helper object."),
		new RothObject("ROTH_OBJ3_DATA", "object3_reloc.bin", 0x70000L, 0x38170L, true, true,
			false, "LE object 3: writable auto-data/stack object.")
	};

	private final NamedFunction[] functions = new NamedFunction[] {
		new NamedFunction(0x43854L, "watcom_runtime_startup",
			"Runtime entry after LE entry jump over the Watcom C/C++32 string."),
		new NamedFunction(0x4f626L, "watcom_run_init_table",
			"Walks 6-byte Watcom initializer entries and calls function pointers by priority."),
		new NamedFunction(0x4f671L, "watcom_run_fini_table",
			"Likely Watcom shutdown/finalizer table walker."),
		new NamedFunction(0x4f5d6L, "watcom_call_program_entry",
			"Watcom runtime bridge to the program entry wrapper."),
		new NamedFunction(0x15110L, "roth_program_entry_wrapper",
			"Memory/setup wrapper that calls roth_game_startup."),
		new NamedFunction(0x10010L, "roth_game_startup",
			"ROTH startup wrapper; saves registers and prints startup messages."),
		new NamedFunction(0x100e4L, "dos_print_dollar_string",
			"DOS int 21h AH=09h; prints DS:EDX dollar-terminated string unless disabled."),
		new NamedFunction(0x100f6L, "roth_main_sequence",
			"Main ROTH startup sequence; RAW/DAS/SFX/sound/video setup."),
		new NamedFunction(0x10c13L, "load_raw_file_wrapper",
			"Builds a path and dispatches to the RAW loading path."),
		new NamedFunction(0x10c32L, "load_das_file_wrapper",
			"Builds a path and dispatches to the map DAS loader; deeper code checks DASP/version 5."),
		new NamedFunction(0x10c51L, "load_sfx_file_wrapper",
			"Builds a path and dispatches to SFX loading."),
		new NamedFunction(0x10c70L, "load_ademo_das_wrapper",
			"Builds a path and dispatches to the ADEMO.DAS-specific loading path."),
		new NamedFunction(0x2effbL, "load_ademo_das_file",
			"Loads ADEMO.DAS sections; expects DAS version 5 and zero palette offset."),
		new NamedFunction(0x2f1a1L, "dos_seek_file_start",
			"DOS int 21h AH=42h, origin 0: seeks current file handle from start."),
		new NamedFunction(0x2f1b4L, "load_map_das_file",
			"Loads a map DAS file; validates DASP magic/version 5 and reads FAT/palette sections."),
		new NamedFunction(0x2f379L, "read_das_palette",
			"Reads the 0x300-byte VGA palette from the DAS palette section and remaps it."),
		new NamedFunction(0x2fb7fL, "build_game_path",
			"Combines configured base path and filename unless the filename is drive-qualified."),
		new NamedFunction(0x2f163L, "close_das_handles_and_buffers",
			"Clears DAS globals, frees loaded buffers, and closes the open DAS handle."),
		new NamedFunction(0x2fa29L, "allocate_das_work_buffers",
			"Allocates DPMI/linear buffers used before DAS loading.")
	};

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			printerr("Open or create an x86:LE:32 program before running this script.");
			return;
		}

		ScriptOptions options = parseArgs();
		File repoRoot = options.repoRoot;
		File imageDir = new File(repoRoot, IMAGE_DIR);
		validateInputs(imageDir);

		Memory memory = currentProgram.getMemory();
		MemoryBlock[] existingBlocks = memory.getBlocks();
		if (existingBlocks.length != 0) {
			boolean replace = options.replaceExisting;
			if (!replace) {
				replace = askYesNo("Replace memory blocks?",
					"This will remove all current memory blocks in this program and recreate " +
						"ROTH LE object blocks. Run this on a fresh import or copied program.");
			}
			if (!replace) {
				println("Cancelled; no memory blocks were changed.");
				return;
			}
			removeMemoryBlocks(memory, existingBlocks);
		}

		createObjectBlocks(memory, imageDir);
		applyEntryLabels();
		applyKnownFunctions();
		fixKnownDecodeAt10100();

		println("ROTH object memory setup complete.");
		println("Entry check: 0x437dc should be JMP 0x43854.");
		println("Next target: inspect roth_main_sequence at 0x100f6.");
	}

	private static class ScriptOptions {
		File repoRoot;
		boolean replaceExisting;
	}

	private ScriptOptions parseArgs() throws Exception {
		ScriptOptions options = new ScriptOptions();
		String[] args = getScriptArgs();
		for (String arg : args) {
			if ("--replace".equals(arg) || "replace".equals(arg)) {
				options.replaceExisting = true;
			}
			else if (options.repoRoot == null) {
				options.repoRoot = new File(arg);
			}
			else {
				printerr("Ignoring extra script argument: " + arg);
			}
		}
		if (options.repoRoot == null) {
			options.repoRoot = askDirectory("Select roth-exe-RE repository root", "Select");
		}
		options.repoRoot = options.repoRoot.getCanonicalFile();
		return options;
	}

	private void validateInputs(File imageDir) throws Exception {
		if (!imageDir.isDirectory()) {
			throw new IllegalArgumentException("Missing image directory: " + imageDir);
		}
		for (RothObject obj : objects) {
			File file = new File(imageDir, obj.fileName);
			if (!file.isFile()) {
				throw new IllegalArgumentException("Missing object image: " + file);
			}
			if (file.length() != obj.size) {
				throw new IllegalArgumentException("Unexpected size for " + file + ": got 0x" +
					Long.toHexString(file.length()) + ", expected 0x" + Long.toHexString(obj.size));
			}
		}
	}

	private void removeMemoryBlocks(Memory memory, MemoryBlock[] existingBlocks) throws Exception {
		for (MemoryBlock block : existingBlocks) {
			monitor.checkCancelled();
			println("Removing memory block " + block.getName());
			memory.removeBlock(block, monitor);
		}
	}

	private void createObjectBlocks(Memory memory, File imageDir) throws Exception {
		for (RothObject obj : objects) {
			monitor.checkCancelled();
			File file = new File(imageDir, obj.fileName);
			Address start = toAddr(obj.base);
			try (FileInputStream stream = new FileInputStream(file)) {
				MemoryBlock block =
					memory.createInitializedBlock(obj.blockName, start, stream, obj.size, monitor, false);
				block.setRead(obj.read);
				block.setWrite(obj.write);
				block.setExecute(obj.execute);
				block.setSourceName(file.getPath());
				block.setComment(obj.comment);
				println("Created " + obj.blockName + " at 0x" + Long.toHexString(obj.base) +
					", size 0x" + Long.toHexString(obj.size));
			}
		}
	}

	private void applyEntryLabels() throws Exception {
		createUserLabel(0x437dcL, "le_entry_jump");
		setPlateComment(toAddr(0x437dcL),
			"LE entry point: object 1 offset 0x337dc. Jumps over Watcom runtime string.");
		currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(0x437dcL));
	}

	private void applyKnownFunctions() throws Exception {
		for (NamedFunction item : functions) {
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

	private void fixKnownDecodeAt10100() throws Exception {
		Address start = toAddr(0x10100L);
		Address end = toAddr(0x10104L);
		clearListing(start, end);
		disassemble(start);
		setPlateComment(start,
			"Known raw-import artifact fixed here: bytes are CALL allocate_das_work_buffers.");
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
