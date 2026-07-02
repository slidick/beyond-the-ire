/* ###
 * ROTH
 */
// Applies confirmed ROTH engine names: RAW map loader, player-state globals,
// trig/math helpers, and entity movement/collision/proximity functions.
// This script is additive and idempotent: it only sets function names, plate
// comments, and global labels. It never replaces memory blocks. Safe to re-run.
//
// Confidence is noted in each comment as [HIGH]/[MED]. Names are provisional
// where marked [MED]; refine them in the GUI and copy improvements back here so
// the script stays the source of truth for the Ghidra database.
//@category ROTH

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class ROTHApplyEngineNames extends GhidraScript {

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

	// All function addresses below are confirmed call targets reached from the
	// disassembly, so creating functions at them is safe.
	private final NamedFunction[] engineFunctions = new NamedFunction[] {
		new NamedFunction(0x4355aL, "aim_enemy_at_player",
			"[enemy combat AI — ROTH_TRACE-confirmed (fires when an enemy is engaging) 2026-06-16] Per-tick targeting: advances g_ai_wander_rng, computes the bearing from the enemy to the PLAYER (atan2_bearing on g_player_x vs the entity position), and turns the entity to face the player clamped to the max turn rate param_1 (1000/10000 passed by tick_dynamic_entities). Bails if g_player_health<1. When aligned/in-range it calls begin_enemy_attack(0x434d8). The 'face + shoot the player' half of monster AI (locomotion is update_actor_movement_ai 0x43326)."),
		new NamedFunction(0x434d8L, "begin_enemy_attack",
			"[enemy combat AI — the attack initiator; runtime CONSUMER of the DBASE100 AsMonster attack config] Selects and launches an enemy attack: RANDOMLY picks PRIMARY vs SECONDARY attack (gated on a secondary existing at entity-def +0x12, chosen by g_ai_wander_rng&1) — reads PrimAttackDelay (def+6) / SecondAttackDelay (def+7) into the entity's attack timer +0x1e, the Bullet/SecondBullet (def+0x10/+0x12) into the entity's pending-attack field +7, and plays PrimAttackSFX/SecondAttackSFX (def+0x14/+0x16) via play_entity_sound — exactly the fields build_entity_def_record fills from the 0x0A AsMonster block. Sets the attacking state (+8 bit8). This is HOW an enemy with two attacks chooses between them. The bullet then drives the ranged attack (spawn_object_projectile_at_player). Caller: aim_enemy_at_player."),
		new NamedFunction(0x33ac4L, "cmd_change_lighting",
			"[.RAW command EXECUTE, base 0x1d 'Change Lighting'] (Ghidra-undefined.) Registers a type-0x1d active effect (find/alloc_active_effect) that ramps a sector/face brightness by cmd+7 per tick toward a target (delta at effect+6, direction from cmd+2 bit1); ticked by table[0x60]. Animated dim/brighten. VERIFIED."),
		new NamedFunction(0x32626L, "cmd_change_floor_texture",
			"[.RAW command EXECUTE, base 0x0a/0x0b 'Change Floor Texture'] (Ghidra-undefined.) Registers a 0xc-byte active effect (alloc_active_effect, target cmd+8) then swaps the sector's floor/ceiling texture (tail at 0x32668). VERIFIED (registration pattern)."),
		new NamedFunction(0x32473L, "cmd_scroll_sector_texture",
			"[.RAW command EXECUTE, base 0x0e 'Scroll Sector Texture'] (Ghidra-undefined.) Registers an active effect (alloc_active_effect, target cmd+9) that continuously scrolls a sector's texture; ticked per frame. VERIFIED (registration pattern)."),
		new NamedFunction(0x324a7L, "cmd_scroll_face_texture",
			"[.RAW command EXECUTE, base 0x0f 'Scroll Face Texture'] (Ghidra-undefined; per dispatch table 0x30780 + BTI RAW.md.) Face-texture scroll counterpart of cmd_scroll_sector_texture."),
		new NamedFunction(0x3179cL, "cmd_cycle_texture",
			"[.RAW command EXECUTE, base 0x1c 'Cycle Texture'] (Ghidra-undefined.) Resolves the target sector (0x4f2e0) and cycles its texture through an animation sequence (animated texture). VERIFIED."),
		new NamedFunction(0x32738L, "cmd_change_face_texture",
			"[.RAW command EXECUTE, base 0x34 'Change Face Tex Simple'] (Ghidra-undefined; per dispatch table + BTI RAW.md.) Sets a face's texture (simple, non-animated swap)."),
		new NamedFunction(0x32645L, "cmd_change_face_texture_adv",
			"[.RAW command EXECUTE, base 0x0c 'Change Face Texture Adv'] (Ghidra-undefined; per dispatch table + BTI RAW.md.) Advanced face-texture change (more parameters than the 0x34 simple variant)."),
		new NamedFunction(0x327f8L, "cmd_change_object_texture",
			"[.RAW command EXECUTE, base 0x0d 'Change Object Texture'] (Ghidra-undefined; per dispatch table + BTI RAW.md.) Swaps the texture on a placed object/sprite. Apply step = apply_object_state_to_group (0x328aa)."),
		// ---- Geometry/object STATE-SWAP effect-apply family (register-context EDI=effect record, EBP=match query;
		//      each is the tail-apply of an effect-tick parent; targets a linked group of cells/records. disasm-verified.) ----
		new NamedFunction(0x33072L, "collect_secondary_matches_into_struct",
			"[effect helper — disasm-verified; called from 0x330ac/0x331a3/0x33244 (state-swap setup)] Thin wrapper: "
			+ "collect_secondary_state_records_by_key(key=struct+2, out=struct+2) and stores the match count into "
			+ "struct+0. Register/ptr arg."),
		new NamedFunction(0x328aaL, "apply_object_state_to_group",
			"[effect-apply — disasm-verified; tail of cmd_change_object_texture 0x327f8 (call @0x3289a); register-context "
			+ "EDI=command record, ESI=query] Propagates the command's value (EDI+0xc) and flag bit 0x10 to a linked "
			+ "group of secondary-state records: writes EDI+0xc into each g_raw_state_secondary_buffer record+4 over the "
			+ "list at ESI+0x14 (count ESI+0x10), mirroring record+7 bit0x10 between source and group. (Was provisionally "
			+ "sync_linked_secondary_records.)"),
		new NamedFunction(0x33255L, "swap_cell_state_group_v1",
			"[effect-apply — disasm-verified; tail-called @0x33244 from its effect-tick parent; register-context "
			+ "EDI=effect record, EBP=match query {count@+0, firstcell@+4, offsets@+6}] Exchanges the effect's two stored "
			+ "state words (EDI+10/+0xc) with a primary-buffer cell, then propagates the new values across the whole "
			+ "matched group. Two field sets by EDI+6 bit4: bit4-clear swaps cell+8/+0x12 (+ packs flags cell+10/+0x17 "
			+ "<-> EDI+7, mask 0xccf); bit4-set follows cell+0x18 indirection and swaps cell+6/+10. The EDI+6 bit8 gate "
			+ "decides whether the effect side is updated (one-way vs swap). One of the moving/toggling-cell effect cores."),
		new NamedFunction(0x333ecL, "swap_cell_state_group_v2",
			"[effect-apply — disasm-verified; tail-called @0x333db; twin of swap_cell_state_group_v1 with a DIFFERENT "
			+ "field set] Same structure (effect EDI <-> primary cell, propagate to the EBP group) but swaps cell+6/+0x10 "
			+ "(bit4-clear) or, via cell+0x18 indirection, cell+0/+4 (bit4-set); flag pack uses mask 0xf3f3 and the "
			+ "<<2/>>2 nibble layout (vs v1's <<4/>>4). The second moving/toggling-cell effect core (different geometry/"
			+ "surface attribute pair than v1)."),
		new NamedFunction(0x33571L, "swap_cell_state_linked_pair",
			"[effect-apply — disasm-verified; called @0x33561 and @0x340ec; register-context EDI=effect record] Toggles "
			+ "a flag byte on the primary cell (cell = g_raw_state_primary_buffer+word[EDI+8]; atomic swap with EDI+0x14, "
			+ "masks 0xff7c/0x83ff) then EXCHANGES five fields between the effect record and a second linked cell "
			+ "(g_raw_state_primary_buffer+word[cell+4]): word EDI+10<->cell+2, EDI+0x10<->cell+4, EDI+0x12<->cell+6, "
			+ "byte EDI+7<->cell+8, word EDI+0xc<->cell+10. A single-pair (no group loop) state-swap effect tick."),
		new NamedFunction(0x31700L, "cmd_cycle_object_texture",
			"[.RAW command EXECUTE, base 0x20 'Cycle Object Texture'] (Ghidra-undefined; per dispatch table + BTI RAW.md.) Animated-texture cycle on an object (object counterpart of cmd_cycle_texture)."),
		new NamedFunction(0x3198eL, "cmd_texture_change_count",
			"[.RAW command EXECUTE, base 0x1f 'Texture Change Count'] (Ghidra-undefined; per dispatch table + BTI RAW.md.) Counted texture-change step (advances a stored counter then repaints), in the animated-texture family."),
		new NamedFunction(0x31676L, "cmd_smash_face_texture",
			"[.RAW command EXECUTE, base 0x2e 'Smash Face Texture'] (Ghidra-undefined.) Resolves target faces (0x34c38) and changes each face's texture to a 'smashed'/broken variant, selecting by a direction-byte table (0x31672, indexed by cmd+6 & 3) over g_map_geometry_buffer. VERIFIED. (E.g. breaking a window/wall.)"),
		new NamedFunction(0x312a1L, "cmd_modify_sector",
			"[.RAW command EXECUTE, base 0x03 'Modify Sector'] (Ghidra-undefined; per dispatch table + BTI RAW.md.) Modifies sector properties (flags/attributes)."),
		new NamedFunction(0x3121cL, "cmd_change_height",
			"[.RAW command EXECUTE, base 0x07 'Change Floor/Ceil Height'] (Ghidra-undefined; per dispatch table + BTI RAW.md.) Changes a sector's floor/ceiling height (often registers a moving-height effect, cf. cmd_move_sector)."),
		new NamedFunction(0x3146dL, "cmd_rotate_object",
			"[.RAW command EXECUTE, base 0x24 'Rotate Object'] (Ghidra-undefined.) Resolves objects by id (resolve_command_objects 0x34c19) and rotates them, toggling/setting orientation per cmd+6 bits (object counterpart of cmd_spawn_object's flag toggling). VERIFIED."),
		new NamedFunction(0x31fb0L, "fire_trigger_on_contact",
			"[trigger ENTRY: contact/hit] Fires a sector/object trigger's .RAW command chain (walk_command_chain_flow on trigger+4), reached from the COLLISION/damage path (0x3520b<-0x35303, 0x351cd<-0x3534b) — i.e. when a projectile/contact strikes a triggerable target. On a chain that wants to persist (trigger+6 bit0x20) sets the g_state_link_* re-fire state (object 0x8a124, sector). Sibling of fire_sector_trigger."),
		new NamedFunction(0x31ffeL, "fire_trigger_on_interact",
			"[trigger ENTRY: use/dialogue] Sector/object trigger fired from the input/dialogue path (0x35235<-0x10cb3<-mouse handler 0x1691c). Gates on trigger+2 bits 0x29 (not done/active), runs walk_command_chain_flow(trigger+4), and arms the g_state_link_* re-fire state on persistent chains. Sibling of fire_sector_trigger / fire_trigger_on_contact."),
		new NamedFunction(0x34d75L, "dispatch_entry_command_trigger",
			"[trigger ENTRY: sector entry-command, category A] For a type-3 target (player position) in a sector flagged (raw+9 bit1), scans the object-table header's entry-command category at header+0x18/+0x1a ({offset,count}, ~category index 4): finds the ref whose sector matches (+0xc) and whose direction mask (header+6 & dir_mask[target+0x1a & 3], table 0x34d6d) admits the approach, then fires its command chain (walk_command_chain_flow). Seeds g_active_object/g_command_source_object. The directional floor/face entry trigger. (Companion: dispatch_entry_command_trigger_b.)"),
		new NamedFunction(0x34f5aL, "dispatch_entry_command_trigger_b",
			"[trigger ENTRY: sector entry-command, category B] Twin of dispatch_entry_command_trigger but for sector flag raw+9 bit4 and the entry-command category at header+0x30/+0x32 (~category index 10). Same match-by-sector + approach-direction-mask gating, then fires the matched command chain."),
		new NamedFunction(0x30b7cL, "fire_queued_command",
			"[trigger: delayed/timer] Fires a command chain (walk_command_chain_flow on rec+4) and, on success, appends it to the per-frame active/timer queue at PTR_DAT_00071f40 (max 0x10 entries, 8 bytes each: {chain idx, 0}) then calls FUN_00030b45. Driven each frame by 0x345e2 <- tick_world_effects. The mechanism behind Delay Timer (0x12) / re-firing chains."),
		new NamedFunction(0x320e6L, "cmd_apply_damage",
			"[.RAW command EXECUTE handler, base 0x33 'Apply Damage' — area/blast damage] (Ghidra-undefined.) Damages the PLAYER with radius falloff: radius = cmd+0xa; from the source point (g_command_source_object 0x8a100, else the current-interaction object 0x8a0fc via dist helper point_to_wall_distance_sq 0x3e03f) computes distance^2 to the player (g_player_x/y 0x90a8e/0x90a96); if within radius^2, the damage is attenuated by falloff = 0x100*dist^2/radius^2 (0..0x100) and applied via apply_damage_to_player. The explosion/blast-radius damage trigger."),
		new NamedFunction(0x30f83L, "cmd_face_emits_damage",
			"[.RAW command EXECUTE handler, base 0x35 'Face Emits Damage' — damaging walls/faces] (Ghidra-undefined.) Resolves the target faces by id (cmd+8, via 0x34c38) and for each face within range of the player (dist helper 0x3e03f vs 0x7ff00) applies cmd+7 damage via apply_damage_to_player. Used for hazard faces (e.g. a damaging force-field / energy wall). Distinct from the per-frame sector hazard emitter (register_damage_emitter/damage_player_from_emitter)."),
		new NamedFunction(0x164c9L, "activate_targeted_object",
			"[trigger ENTRY: player use/interact] Dispatched from the mouse-mode handler (0x1691c) on the object the player is pointing at (param_1 = cursor-target: type byte +1, object ptr +0xe, within range +0x20<600). Routes by target type: type 4 = object trigger -> run_leftclick_object_trigger (its .RAW command chain), or pickup (destroy_dynamic_entity) / examine (0x1dcef); type 6 = DOOR -> 0x3d93f (open swing); else generic 0x10d1e. Returns a mouse-mode result code (0x240/0x268). The 'press use on what you're looking at' entry into the command system."),
		new NamedFunction(0x31e8fL, "fire_sector_trigger",
			"[trigger ENTRY: floor/sector entry] Fires a sector/face trigger's .RAW command chain (walk_command_chain_flow on trigger+4, then process_deferred_command_queue) when the player enters it (called from tick_world_effects 0x3464c via the special-sector link detection). DIRECTIONAL: builds a quadrant bit from g_player_angle (>>7) and only fires if the trigger's +6 hasn't already fired for that approach direction. Seeds the command context (g_command_source_object/g_active_object = 0). The 'walk onto a trigger' entry."),
		new NamedFunction(0x311adL, "cmd_particle_effect",
			"[.RAW command EXECUTE handler, base 0x2d 'Particle Effect'] (Ghidra-undefined.) Spawns cmd+7 particles of type cmd+8 at the source object's position (g_active_object 0x8a0f8, else g_command_source_object 0x8a100; pos x=obj+0, y=obj+2, z=obj+0xa), looping spawn_particle. The blood/spark/debris burst trigger."),
		new NamedFunction(0x4b4e9L, "spawn_particle",
			"Allocates a particle (alloc_particle 0x4b485 from g_particle_pool) and inits it at a position with a RANDOM burst velocity: random angle via rng_next -> g_sincos_table gives horizontal vx/vy (+0x1c/+0x20), upward z-velocity +0x18 = rng*4+190000, 16.16 position +0x24/+0x28/+0x2c, sector (+4 via locate_sector_at_position), lifetime +0x32=300. The explosion/blood spray particle."),
		new NamedFunction(0x4b485L, "alloc_particle",
			"Allocates+links a particle record from g_particle_pool (0x91864 linked list), zero-fills it (mem_fill). Returns the record or 0 if the pool is full. Used by spawn_particle / spawn_particle_on_edge (0x4b5b4)."),
		new NamedFunction(0x4b396L, "tick_particles",
			"[per-frame, from tick_world_effects 0x3464c] Advances every particle in g_particle_pool with 16.16 physics scaled by g_frame_time_scale: decrements lifetime (+0x32) and unlinks dead ones; integrates position by velocity; applies GRAVITY (z-velocity +0x18 -= 0x1900*frametime) and FLOOR BOUNCE (on hitting the sector floor, reflect+halve the z-velocity); re-resolves the sector. So particles fall, bounce, and expire."),
		new NamedFunction(0x313b4L, "cmd_spawn_object",
			"[.RAW command EXECUTE handler, base 0x16 'Spawn Object Simple'] (Ghidra-undefined.) Does NOT create objects from scratch — it ACTIVATES/REVEALS objects that are already placed in the map. Resolves the target object set by id (cmd+8) via resolve_command_objects(0x34c19) into a local buffer, sets g_command_source_object (0x8a100) to the first, then for each matched object in g_map_objects_buffer toggles/sets/clears its +7 bit 0x80 (the active/visible flag) per the cmd+6 mode bits (bit-pair 6 present -> set(bit4)/clear, else toggle), and wakes its actor (object+0xc pool-A index -> slot +9|=1) so a revealed monster starts ticking. So scripted objects/enemies are pre-placed but hidden, then 'spawned' (un-hidden + activated) by a trigger. Returns -1."),
		new NamedFunction(0x34c19L, "resolve_command_objects",
			"Shared command-target object resolver: target id (EAX) -> list of object offsets (into g_map_objects_buffer) + count, written to the caller's buffer (EDX, cap EBX). id==0 uses the current g_command_source_object (0x8a100); else finds matching objects by id (0x34c97). Used by cmd_spawn_object and other object-acting command handlers."),
		new NamedFunction(0x35437L, "cmd_give_item",
			"[.RAW command EXECUTE handler, base 0x29 'Give Item' — adventure-puzzle bridge] (Ghidra-undefined.) Adds item id (cmd+8) to the player inventory via give_item (0x1cedc, resolves the item's DBASE100 template + finds/stacks a slot); stores the resulting item record in g_last_item_record (0x89fa8). When [0x8a134]==0 and a current object (0x8a0fc) exists, first computes a world drop position (edge-midpoint of the object from g_sector_geom_base/g_map_geometry_buffer) for the spawned item. On inventory-full failure sets g_command_chain_interrupt=2. Returns 0/-1."),
		new NamedFunction(0x354d3L, "cmd_remove_item",
			"[.RAW command EXECUTE handler, base 0x2a 'Remove Item'] (Ghidra-undefined.) Removes item id (cmd+8, or g_last_item_record 0x89fa8 when 0) from the player inventory via remove_item (0x1d077). The consume half of item puzzles (e.g. use-key removes the key). Returns 0/-1."),
		new NamedFunction(0x35544L, "cmd_if_not_item",
			"[.RAW command EXECUTE handler, base 0x27 'If Not Item' — puzzle CONDITION] (Ghidra-undefined.) Gates the command chain on inventory: tests whether the player has item id (cmd+8) via query_player_inventory (0x1ccf7), or (cmd+6 bit4) compares against g_last_item_record. Per the cmd+6 mode bits (1=negate, 2/0x20/8 variants) it either continues the chain (-> 0x355ba) or stops it (-> 0x355ef), and can raise g_command_chain_interrupt. The 'do X only if (not) holding item Y' primitive."),
		new NamedFunction(0x355a7L, "cmd_if_not_flag",
			"[.RAW command EXECUTE handler, base 0x28 'If Not Flag' — puzzle CONDITION] (Ghidra-undefined.) Branches the command chain on a game progress flag: tests flag id (cmd+8) in g_dbase100_record_bitmap (0x81e28) via test_dbase100_record_flag, continuing or stopping the chain per the cmd+6 negate/mode bits. The story/puzzle-state gate (companion to cmd_set_flag)."),
		new NamedFunction(0x35617L, "cmd_set_flag",
			"[.RAW command EXECUTE handler, base 0x26 'Set/Unset Flag'] (Ghidra-undefined.) Sets or clears a game progress flag id (cmd+8) in g_dbase100_record_bitmap (0x81e28) via dbase100_bitmap_test_set/_clear (set vs unset chosen by cmd+6 bits 1/2). How map scripts record story/puzzle progress (paired with cmd_if_not_flag)."),
		new NamedFunction(0x1d077L, "remove_item",
			"Removes an item from the player inventory by id (AX); inventory-remove counterpart of give_item "
			+ "(0x1cedc). Checks the two active slots g_selected_item_primary (0x81044) / g_selected_item_secondary "
			+ "(0x81038) then scans g_inventory_slots (0x80c30, count g_inventory_count); first match -> "
			+ "remove_inventory_item (0x1ce6b), returns -1. If absent/empty -> rebuild_weapon_inventory_list "
			+ "(0x2245c), returns 0. Called by cmd_remove_item and the weapon/ammo-consume paths."),
		new NamedFunction(0x1cab7L, "dbase100_bitmap_test_set",
			"[recomp-lifted, oracle-verified; was 'access_game_flag'] Test-AND-SET a bit in the game "
			+ "progress-flag bitmap g_dbase100_record_bitmap (0x81e28): EAX=flag id -> byte[id>>3], mask "
			+ "g_bit_mask_lut (0x71366)[id&7]; if already set ret 0, else set it and ret -1 (no bitmap -> -1). "
			+ "Backs cmd_set_flag / cmd_if_not_flag (story & puzzle state); 'game flags' = a bitmap over "
			+ "DBASE100 record ids. Sibling: dbase100_bitmap_test_clear (0x1caf4)."),
		new NamedFunction(0x1caf4L, "dbase100_bitmap_test_clear",
			"[recomp-lifted, oracle-verified] Test-AND-CLEAR sibling of dbase100_bitmap_test_set (0x1cab7): if "
			+ "the bit in g_dbase100_record_bitmap (0x81e28) is already clear ret 0, else clear it and ret -1."),
		new NamedFunction(0x3de31L, "update_door_swing",
			"[DOOR subsystem, per-frame swing tick — ROTH_TRACE-confirmed door-only 2026-06-16] Advances one door's swing: calls rotate_quad to rotate the 4 hinge-relative corners (record+0x2e) to the current angle (record+3), computes the swept bounding box (min/max of the 4 rotated corners), and tests the PLAYER position (g_player_x/y 0x90a8c/0x90a94) against it +/-0x1a so the swinging face can block/interact with the player. (The other rotate_quad caller 0x3db8d runs every frame regardless = a general rotation, NOT the door tick.)"),
		new NamedFunction(0x3d54bL, "register_door_swing",
			"[DOOR subsystem] Called by cmd_open_door: latches the swing target vector (0x8b3cc..0x8b3d0) + target id (EAX), looks for an existing door record (0x3d4da), and if none and the door pool isn't full (g_door_count<6) registers a new one via setup_door_swing_geometry(0x3d147)/alloc_door_record(0x3d6c3). A door is a SECTOR FACE (quad) that swings on a hinge corner."),
		new NamedFunction(0x3d6c3L, "alloc_door_record",
			"[DOOR subsystem] Allocates a slot in g_door_pool (0x8b3f8, max 6 records of 0x1f6=502 bytes) and initialises the swing state: target vector at rec+0x26/+0x28, swing-range fields rec+0x1c=0x80 / rec+0x24=0x40 (0x40=64=90deg in the 256-unit angle system), a unique id, and (if a sound id is set) the open SFX via FUN_00027207 with timer rec+0x1e=1000. Returns the record."),
		new NamedFunction(0x3d147L, "setup_door_swing_geometry",
			"[DOOR subsystem] Snapshots the door's geometry for the swing: finds the door sector's quad (FS-segment, face-type 4), captures its FOUR corner vertices as offsets RELATIVE TO THE HINGE PIVOT (pivot X/Y = ESI[10]/ESI[0xb] from one corner; stores vertex.x-pivot.x, vertex.y-pivot.y per corner into the record at +0x2e), marks the sector dirty (+0x16 bit0), then calls rotate_quad to compute the rotated corner positions. Confirms the in-game behaviour: the wall/face pivots about a corner. Increments g_door_count."),
		new NamedFunction(0x3d03cL, "is_door_open",
			"[DOOR subsystem] Query: walks g_door_pool (stride 0x1f6) for the record matching a sector id (DI), returns its open-state bit (record+2 & 2). 0 if no door / closed."),
		new NamedFunction(0x3cfccL, "find_door_by_sector",
			"[DOOR subsystem] Query: returns when a g_door_pool record matches a sector id (SI) on either the door sector (+0) or the paired sector (+0x10); used to test whether a sector is part of an active door."),
		new NamedFunction(0x3d433L, "init_door_pool",
			"[DOOR subsystem] Map-load init of the door system: zeroes g_door_count + the second table (0x8bfc0) and all 6 g_door_pool records (0x2f1 dwords), then pre-builds each record's quad/vertex sub-structures (linked vertex lists seeded from the template at 0x724c8). Prepares the 6 reusable door slots."),
		new NamedFunction(0x32ac5L, "cmd_move_sector",
			"[.RAW command EXECUTE handler, base 0x09 'Move Sector' = doors/lifts/platforms] (Ghidra-undefined; reached via g_command_dispatch_table[0x09].) Guards on the command's +2 bit 0x20 (already-registered); resolves the target sector (cmd+8 via 0x4f2e0); alloc_effect_record(0x16 bytes); snapshots the sector's FOUR geometry-slot indices (from g_map_geometry_buffer 0x90aa8 / g_sector_geom_base 0x90aac, offsets +0/+0xc/+0x18/+0x24, min/max-ordered) into the effect record +0xe/+0x10/+0x12/+0x14; sets direction bit (+5 bit 0x80 from cmd +2 bit1), stores COMMAND_BASE (cmd+3) at effect+4 and back-ptr at +8, marks cmd registered (+2|=0x20). tick_moving_sector (0x32c05, tick[0x09]) then translates those slots each frame. Returns -1 (done)."),
		new NamedFunction(0x32269L, "cmd_flash_lights",
			"[.RAW command EXECUTE handler, base 0x11 'Flash Lights'] (Ghidra-undefined.) Guards on cmd +2 bits 0x21; resolves target (cmd+8) and registers a flash effect via alloc_face_effect (0x3296b); sets effect +8=back-ptr, +4=COMMAND_BASE, +6=0 (timer); then walks the effect's snapshotted face list and records each affected face's ORIGINAL brightness (byte[face+0xb] from g_map_geometry_buffer) so the per-frame tick (table[0x54]=0x32324) can flash/restore them. Returns -1."),
		new NamedFunction(0x3104aL, "cmd_map_transition",
			"[.RAW command EXECUTE handler, base 0x3b 'Map Transition/Warp'] (Ghidra-undefined; INSTANT, tick=NOP.) Latches a pending level change: stores cmd+0xa -> g_warp_dest_a (0x8547c), cmd+0xe -> g_warp_dest_b (0x85480), the target map id (cmd+8) -> 0x85484 (the next-map global, currently g_map_first_load_flag), and sets g_pending_game_action (0x7fea8)=1 — the main loop performs the actual map load. If cmd+6 bit0x10, also sets cmd+2 bit3. Returns -1."),
		new NamedFunction(0x33a69L, "cmd_open_door",
			"[.RAW command EXECUTE handler, base 0x2f 'Open Door'] (Ghidra-undefined; INSTANT, tick=NOP.) Resolves the door sector: cmd+8 target (via 0x4f52b/0x4f567), or the current-interaction object (0x8a0fc else 0x8a0f8) when cmd+8==0; reads the swing params (cmd+0xa, +7 byte, +0xc, +0xe/+0x10) and calls register_door_swing(0x3d54b). Doors are their OWN subsystem (NOT a Move-Sector effect): a door is a SECTOR FACE/quad that SWINGS on a hinge corner — registered into g_door_pool (max 6) and rotated by rotate_quad (g_sincos_table) around the pivot, matching the in-game pivoting-wall behaviour. Returns -1 on success."),
		new NamedFunction(0x3296bL, "alloc_face_effect",
			"[world-interaction] alloc_active_effect sibling used by effect handlers that act on a resolved FACE/geometry group (e.g. cmd_flash_lights): finds matching geometry (0x4f3d0/0x4f313) and alloc_effect_record(0x34464)s a record holding the snapshotted face-index list; the caller then fills per-face state."),
		new NamedFunction(0x3464cL, "tick_world_effects",
			"[world-interaction CORE] Per-frame processor for the .RAW command 'active-effect' system (called from tick_dynamic_entities 0x42d74). Three jobs: (1) ticks the sector-damage emitters (damage_player_from_emitter if g_damage_emitter_ptr 0x8a120 set) + the special-sector link state (g_state_link_*: detects the player entering/leaving water/lava/link sectors via sector flag +0x17 bits 0xc0 vs player Z, firing FUN_00031e8f); (2) walks the ACTIVE-EFFECT POOL (g_active_effect_pool 0x8a118 linked list) and dispatches each effect through the per-frame TICK dispatch table g_command_tick_dispatch_table (0x3088c) indexed by the effect's stored COMMAND_BASE (rec+4) — e.g. tick[0x09]=tick_moving_sector; if a tick handler returns nonzero the effect is finished and unlink_finished_effect removes it; (3) flushes process_deferred_command_queue. This is how doors/lifts/lights/texture-cycles animate over time."),
		new NamedFunction(0x343f5L, "free_effect_pools",
			"[world-interaction] Map-unload teardown: frees the three runtime effect lists (g_active_effect_pool 0x8a118, 0x8a11c, g_damage_emitter_ptr 0x8a120) via free_effect_list, and releases the command-index pointer array (g_object_ptr_array -> pool_free_handle on the DAS-cache heap). Called from the map (un)load path 0x2f459."),
		new NamedFunction(0x344f9L, "unlink_finished_effect",
			"[world-interaction] Removes a completed active-effect record from the g_active_effect_pool linked list (its tick handler returned 'done'); returns the predecessor link so tick_world_effects can continue the walk. (param: node, prev-link slot.)"),
		new NamedFunction(0x34464L, "alloc_effect_record",
			"[world-interaction] Allocates an active-effect record of the requested byte size from the effect-pool heap and links it; the shared allocator behind alloc_active_effect and the other effect-registering command handlers (moving sectors, lights, texture cycles)."),
		new NamedFunction(0x34499L, "alloc_effect_record_list_b",
			"[world-interaction — disasm-verified; called by tick_move_floorceil 0x340f3 @0x3414d/0x341be] Allocates a "
			+ "record from the DAS-cache heap (ensure_das_cache_heap_space + pool_alloc_handle on g_das_cache_heap_handle) "
			+ "and pushes it onto the SECOND effect list g_effect_list_b (0x8a11c): clears chunk+5/+6, links via chunk+0 "
			+ "= previous head. Sibling of alloc_effect_record (which uses g_active_effect_pool). Returns the handle."),
		new NamedFunction(0x34434L, "free_effect_list",
			"[world-interaction] Frees one effect linked-list (walks node+0 next-ptrs releasing each record); called 3x by free_effect_pools for the active-effect / b / damage-emitter lists."),
		new NamedFunction(0x4b4cbL, "rng_next",
			"[recomp-lifted, oracle-verified] 16-bit LCG PRNG over g_rng_state(0x7276c): state=(state*0x5e5+0x29)&0xffff; returns it in AX (EAX high half carries from caller)."),
		new NamedFunction(0x4b378L, "clear_list_field30",
			"[recomp-lifted, oracle-verified] if list head g_particle_pool (0x91864)!=0: clear it, then walk the chain (next=node[0]) zeroing byte[node+0x30] of every node."),
		new NamedFunction(0x27e0bL, "bounded_string_copy",
			"[recomp-lifted, oracle-verified] EBP=ptr to src pointer, EDI=dst, CL=max count: copy bytes from *EBP to dst until NUL or CL bytes (count check post-copy, so a non-NUL first byte is copied even when CL==0)."),
		new NamedFunction(0x16d79L, "rng_range",
			"[recomp-lifted, oracle-verified] EAX=range. Advances the 16-bit LCG g_rng_state2(0x7fe08) (state=(state*0x5e5+0x29)&0xffff) then returns (state*range)>>16 = a uniform value in [0,range)."),
		new NamedFunction(0x1c59eL, "clear_dual_array_80afc",
			"[recomp-lifted, oracle-verified] Zeroes 5 dwords at 0x80afc and 5 dwords at 0x80b10 (interleaved)."),
		new NamedFunction(0x3cf86L, "emit_literal_run_3cf86",
			"[recomp-lifted, oracle-verified] ByteRun1/PackBits literal-run emit. EBX=count, ESI=end-of-run ptr, EDI=dst. count==0 no-op; else writes header byte (count-1) then copies the count bytes ending at ESI (src=ESI-count). Returns advanced EDI; ESI restored; EBX=0; EAX preserved. Called by rle_compress_byterun1."),
		new NamedFunction(0x4ee9cL, "emit_literal_run_4ee9c",
			"[recomp-lifted, oracle-verified] Literal-run emit sibling. EBP=count, ESI=end ptr, EDI=dst. Writes header byte (count) then copies count bytes from src=ESI-count-1 (even count==0 writes the 0 header). Returns advanced EDI; ESI restored; EBP=0; EAX=count."),
		new NamedFunction(0x2778dL, "is_in_83ed4_table",
			"[recomp-lifted, oracle-verified] EAX=key. Returns 1 if any of the 16 records at 0x83ed4 (stride 0x9a) has its first dword == key, else 0 (membership test)."),
		new NamedFunction(0x43b0bL, "find_sfx_node_by_key",
			"[recomp-lifted, oracle-verified] AX=key. Scans the [0x85c44] record table (count word[+2], records stride 0x12 from +4) for word[rec+6]==key; returns the record ptr or 0."),
		new NamedFunction(0x1c96fL, "reset_player_locomotion_state",
			"[recomp-lifted, oracle-verified] Zeroes the player locomotion/airborne flags: byte[0x819c0] + dwords at 0x819c1/0x819c5/0x819cd/0x819d1."),
		new NamedFunction(0x3c068L, "isqrt16_bsearch",
			"[recomp-lifted, oracle-verified] EAX=value -> EAX. Pure 16-bit binary-search integer sqrt; the kernel isqrt_fixed (0x3bfe5) calls 0x300x to build its lookup table at 0x8a446. 16-bit math with a wrapping midpoint ((si+di) mod 2^16 >> 1); inputs whose high word is large take a skip path returning the input unchanged."),
		new NamedFunction(0x57422L, "fetch_dbcs_char",
			"[recomp-lifted, oracle-verified] EAX=char ptr -> EAX (ushort). If DBCS enabled ([0x758c8]!=0) and the lead-byte class table bit (byte[0x758cd + *p] & 1) is set, returns the wide char (*p<<8 | p[1]); otherwise the single byte *p. Classic DBCS lead-byte fetch."),
		new NamedFunction(0x1bb12L, "move_cursor_entry_clamped",
			"[recomp-lifted, oracle-verified] EAX=delta. idx=[0x80b38]; new=delta+base[idx] (0x80b10[]). If new>=count(0x80af4, unsigned) or new==cur(0x80afc[idx]) -> no-op; else cur[idx]=new and, unless [0x7f571]&2, add 2 to [0x7f571]. Cursor/selection move on the 0x80afc/0x80b10 arrays (cf. clear_dual_array_80afc 0x1c59e)."),
		new NamedFunction(0x2fd3cL, "recompute_hires_line_doubling",
			"[recomp-lifted, oracle-verified] No args. If g_rawscreen_flag(0x90c08)&1, clamp mode word [0x90be6] to low 2 bits; set g_hires_line_doubling_flag(0x90cbd)=0xff iff [0x90be6]&4 (post-clamp) else 0; clear [0x90be4]. Recomputes the line-doubling state from the video mode flags."),
		new NamedFunction(0x4a28cL, "sos_voice_xchg_w54_if_active",
			"[recomp-lifted, oracle-verified] EAX=voice set, EDX=voice idx, BX=new value. Resolves the SOS voice control block via the far ptr at g_sos_voice_table[set*0xc0 + idx*6] (lgs). If the voice is active (status word [+0x30] bit15), swaps the u16 at [+0x54] with BX and returns the OLD value (sign-extended); else returns 0. Field +0x54 semantic unknown (offset-named) - please refine from SOS voice struct."),
		new NamedFunction(0x49fe9L, "sos_voice_xchg_w32_if_active",
			"[recomp-lifted, oracle-verified] Twin of sos_voice_xchg_w54_if_active (0x4a28c) but the field is [+0x32] instead of [+0x54]. EAX=set, EDX=idx, BX=new; if voice active, swap u16@+0x32 and return old (sign-extended), else 0."),
		new NamedFunction(0x4ac55L, "sos_voice_deactivate_slot",
			"[recomp-lifted, oracle-verified] EAX=voice set, EDX=voice idx. If idx>=0x20 return 10. Else resolve the voice block (g_sos_voice_table far ptr) and, if active (status [+0x30] bit15) and not locked (byte[+0x31]&0x10==0), clear the active bit (byte[+0x31]&=0x7f) and zero u16[+0x34]; return 0. Looks like a voice-stop/free."),
		new NamedFunction(0x4a54aL, "sos_voice_get_w34",
			"[recomp-lifted, oracle-verified] EAX=voice set, EDX=voice idx -> returns the sign-extended u16 at voice block [+0x34] (the field sos_voice_deactivate_slot 0x4ac55 zeroes). Thin getter; has a thunk at 0x15a79. Field +0x34 semantic unknown (offset-named)."),
		new NamedFunction(0x53b01L, "sos_voice_clamp_w38",
			"[recomp-lifted, oracle-verified] cdecl(p1,p2). Clears the flat flag byte [0x73c5c + p2*0x14]; resolves the voice block (set = [0x94b50 + p1*4]) and clamps its u16 [+0x38] down to 1 if it exceeds 1. Returns 0. (+0x38 looks like a remaining-loops/repeat count being capped.)"),
		new NamedFunction(0x303abL, "find_unflagged_object_by_key",
			"[recomp-lifted, oracle-verified] EAX=record. key = u16[rec+0xe]; if key==0 or g_object_table_header(0x85c30)==0 or its count u16[+0xa]==0, return 0. Else scan `count` entry-offsets at u16[hdr+8] stride 2: entry at hdr+off, if flag byte[+2]&8 clear AND key u16[+8]==key return -1 (found). Else 0. Membership test over the object table (skips entries flagged with bit3, likely dead/pending)."),
		new NamedFunction(0x1c06bL, "resolve_reloc_record_fields",
			"[recomp-lifted, oracle-verified] EAX=out1 ptr, EDX=out2 ptr, EBX=offset, CL=flags. base=g_reloc_base(0x7f56c); if 0 ret 0. rec = *(u32*)(base+offset) + base (base-relative reloc); if 0 ret 0. If flags&1: *out1 = -(int16[rec+4]>>1); if flags&2: *out2 = -(int16[rec+6]>>1). Returns rec. Extracts negated half-scale fields (+4,+6 - likely a delta/coordinate pair) from a reloc-table entry."),
		new NamedFunction(0x476fdL, "is_entry_93144_zero",
			"[recomp-lifted, oracle-verified] EAX=index -> 1 if the dword [0x93144 + index*4] is 0, else 0. A dword-array empty-slot test (0x93144 array purpose unknown - offset-named)."),
		new NamedFunction(0x1c9a0L, "rng_next_index_for_count",
			"[recomp-lifted, oracle-verified] EAX=count -> (count*rng)>>16, a count-scaled pseudo-random index (cf. rng_range 0x16d79). A per-call weight (2/4/8/0x10 by count magnitude) decrements the countdown [0x81e3a]; on <=0 the 16-bit LCG [0x71364] (state*0x5e5+0x29) reseeds the rng [0x81e38]. The rng is rotated left by (weight&0xf) afterward; the return uses the PRE-rotate rng."),
		new NamedFunction(0x575e9L, "fetch_dbcs_char_advance",
			"[recomp-lifted, oracle-verified] EAX=char ptr, EDX=out u32. Pointer-advancing sibling of fetch_dbcs_char (0x57422). DBCS off ([0x758c8]==0): *out=*p, ret p+1. Else *out=*p; *p==0 -> ret p; not a lead byte (table[*p]&1==0) -> ret p+1; lead with p[1]==0 -> *p=0, ret p; lead+trail -> *out=(*p<<8)|p[1], ret p+2."),
		new NamedFunction(0x10d87L, "noop_stub_10d87",
			"[recomp-lifted, oracle-verified] push esi/edi/ecx/ebx then pop ebx/ecx/edi/esi; ret - a register-preserving no-op (vestigial/placeholder stub). No observable effect."),
		new NamedFunction(0x3a848L, "set_floorceil_span_value",
			"[recomp-lifted, oracle-verified] EAX=value. Self-modifying-code: patches the operand at the setup_floorceil_span site (0x3ac9b, inside the renderer floor/ceil span routine) with EAX. (Pairs with the named data label setup_floorceil_span @0x3ac9b.)"),
		new NamedFunction(0x34510L, "find_object_list20",
			"[recomp-lifted, oracle-verified] AX=key. Searches the object-table list whose (cursor,count) header pair is at g_object_table_header(0x85c30)+0x20/+0x22: scans `count` u16 entry-offsets from hdr+cursor; if an entry (hdr+off) has flag byte[+2]&8 clear AND key u16[+8]==key, returns hdr+off (absolute ptr), else 0. One of several per-list variants (cf. find_object_list24 0x3451b @+0x24, find_object_list40 0x34526 @+0x40, and the rec-keyed 0x303ab). The object table has multiple (cursor,count) sub-lists; the field base selects which."),
		new NamedFunction(0x3451bL, "find_object_list24",
			"[recomp-lifted, oracle-verified] AX=key. Same object-table search as find_object_list20 (0x34510) but the (cursor,count) header pair is at +0x24/+0x26. Returns hdr+off or 0."),
		new NamedFunction(0x34526L, "find_object_list40",
			"[recomp-lifted, oracle-verified] AX=key. Same object-table search as find_object_list20 (0x34510) but the (cursor,count) header pair is at +0x40/+0x42. Returns hdr+off or 0."),
		new NamedFunction(0x43326L, "update_actor_movement_ai",
			"[actor/monster AI — the moving-actor tick] Default-branch handler in the g_state_pool_a dispatch (tick_dynamic_entities), for actors not in a special state (despawn 0x20 / anim 0x40 / proximity 0x8 / cooldown +0x21). Calls check_entity_player_contact: if NOT touching the player, advances a move-phase counter (+0x1f += g_actor_move_rate); each phase tick it may randomly retarget via the wander LCG (g_ai_wander_rng) and, when its facing-state (+0x18) is active, derives a forward motion vector from the entity facing byte (geom+6) through g_sincos_table and calls entity_apply_vertical_movement(dx,dy) — which runs move_entity_with_collision -> collide_entity_and_steer (wall-avoidance re-bearing). On player CONTACT it stops (entity_apply_vertical_movement(0,0)) and sets the contact flag (+8 bit 0x10). This is the pursue/wander locomotion AI; combat/damage is the separate contact + projectile path. Register-context (EDI=entity record)."),
		new NamedFunction(0x43402L, "tick_entity_vertical_only",
			"[actor] Static-actor tick: entity_apply_vertical_movement(0,0) only — gravity/height settle with no horizontal motion. The non-moving counterpart of update_actor_movement_ai, dispatched for cooldown-state pool-A entities."),
		new NamedFunction(0x1035aL, "update_player_movement",
			"[player tick] Per-frame player movement orchestrator (caller 0x1729c): update_turn_view_scale (0x3e22c) -> move_player_with_collision(0x3e796, _, 0) -> update_view_transform_params (0x3e2ba) -> tick_ambient_render_and_map -> play_nearby_sfx_emitters. Top of the player physics chain. (CORRECTED: 0x3e22c is the turn view-scale, not 'input velocity'.)"),
		new NamedFunction(0x3e22cL, "update_turn_view_scale",
			"[player view — disasm-verified; called by update_player_movement 0x1035a] When the 'blur'/low-detail "
			+ "feature is enabled (g_blur_flag) and the player is turning, toggles the rendered viewport scale by the "
			+ "turn accumulator g_turn_accum: |g_turn_accum| >= 8 -> switch to the SCALED (low-res) viewport "
			+ "(g_view_scale_flags=1, state g_turn_view_scale_state 0x90cc0 = +8/-8, request 0x90bfc=2); back below the "
			+ "threshold -> full-res (flags=0, request=1). Each change re-runs configure_render_viewport + sets the "
			+ "viewport-dirty flag 0x8c1d2. The 'reduce detail while turning' (motion-blur-ish) effect."),
		new NamedFunction(0x3e2baL, "update_view_transform_params",
			"[player view — disasm-verified; called by update_player_movement 0x1035a] Builds the render camera "
			+ "transform from the player state each frame: view yaw = -(g_player_angle + DAT_8c104) -> 0x89f00; view "
			+ "translation = -(player X/Z/Y ints @0x90a8c/0x90a90/0x90a94, with eye height _DAT_8c112) -> 0x89eec/eee/"
			+ "ef0; pitch = g_view_pitch (or g_view_pitch_applied if zero), clamped +/-0x7e -> 0x89ee8; plus a video-mode "
			+ "flag bit (g_video_mode_flags) and 0x90a72 -> 0x89ee6. Feeds the world renderer's vertex transform."),
		new NamedFunction(0x3e796L, "move_player_with_collision",
			"[player mover] Integrates the player position (g_player_x/z/y 16.16 at 0x90a8c/90/94) by the double-buffered input velocity queue (g_vel_queue_a/b, toggled by g_vel_queue_select), substepping each delta through collide_substep_track_sector. Sets the PLAYER's FIXED collision dims (radius 0x1c -> g_collision bound block 0x8c130..0x8c144) and climb (g_max_climb, or 0x10 in a special mode), seeds g_locate_query_* + g_collision_restore_*, resolves the final sector (find_query_sector), reads its light/flags for shading (0x8c1de from sector+0xb + g_max_sector_light), writes the new position back, then update_player_view_bob. Player twin of move_entity_with_collision."),
		new NamedFunction(0x3ecc0L, "collide_substep_track_sector",
			"[player mover] One player move substep: find_sector_and_collide, then caches the resulting sector in g_player_sector_cache (0x8c1d6) when it changes. Returns the sector. __stdcall, carry = not-found."),
		new NamedFunction(0x3ecfeL, "update_player_view_bob",
			"[player view] Per-frame view/camera update scaled by g_frame_time_scale: smoothly returns g_view_pitch_applied toward 0 (clamped +/-3 per tick), resolves the player's vertical position via update_player_vertical_physics (0x1c648), and applies head-bob — DAT_0008c1d4 from the walk-cycle bob table 0x724f0 (indexed by walk phase _DAT_0008c10c) scaled by g_move_speed_accum — clamping eye height _DAT_0008c112 between floor+0x18 and ceiling-0x18."),
		new NamedFunction(0x3e590L, "move_entity_with_collision",
			"[entity/AI mover] Entity-level mover (caller 0x43187, entity tick): pulls the entity's collision RADIUS from its sprite's collision dims (g_das_collision_buffer[sprite*4]) -> g_collision bound block, sets step-height (g_max_step_height 0x80, or 0x260 if flag bit1), reads the entity position from its record (EBX+0x10/0x12/0x14 + sub-record puVar4 high words), adds the move delta (param_1/param_2), stashes the entity in g_collision_move_entity(0x8c0dc)/_geom(0x8c0d8), calls collide_entity_and_steer, writes the resolved position back, and runs a state timer (EBX+0xc -= 10; on underflow resets to 12000 + sets action flags). AI/object twin of move_player_with_collision."),
		new NamedFunction(0x3ea10L, "collide_entity_and_steer",
			"[entity/AI mover] Collides the moving entity (g_collision_move_entity) along its delta via find_sector_and_collide; on a wall hit, if it barely moved sets the 'blocked' flag (entity+9 bit 0x20), else computes a NEW bearing with atan2_bearing and turns the entity (facing entity+6, turn counter +0x1a, flags 8/0x40) so AI navigates around obstacles. param_2/param_3 = the move delta (for the distance-moved test)."),
		new NamedFunction(0x3b1c1L, "rasterize_floorceil_polygon",
			"[renderer: floor/ceiling EDGE-WALKER] Edge-walks a floor/ceiling polygon into the per-scanline span "
			+ "table g_floorceil_span_records (0x8cd0c, stride 0x18; left half +0 / right half +0xc=0x8cd18) "
			+ "(caller draw_floorceil_surface 0x3a84e via rasterize_world_spans_scanline 0x366cb). Frustum-clips the "
			+ "surface bbox (ESI+0x28=minX/+0x2a=minY/+0x2c=maxX/+0x2e=maxY vs view bounds g_view_bound_right/left/"
			+ "bottom/top 0x90968/0x9096a/0x9096c/0x9096e); first runs build_floorceil_vertex_records (0x3bbb0) to "
			+ "produce g_floorceil_vertex_records (0x8c946, stride 0xc) and build_floorceil_clip_edges (0x3b4a2) for "
			+ "clipped sides; then for each edge (consecutive vertex pair) computes the X slope (dx<<16/dy) and fills "
			+ "the edge-X column of each span record, tracking min/max Y (0x90a1a/0x90a1c) and (when textured) calling "
			+ "interp_floorceil_edge_texcoords (0x3b8b7) / store_floorceil_flat_edge_texcoords (0x3b84a) to fill the "
			+ "U/V/W texcoords. Driver then reads span_records[Y] + g_scanline_dest_offset_table[Y] (0x854a8). Full "
			+ "data formats: lift_handoffs/3b1c1_floorceil_edge_walker.md."),
		new NamedFunction(0x3eeb0L, "resolve_collisions_in_sector",
			"[collision dispatcher] Per-sector collision resolver for the swept query (caller find_sector_and_collide 0x3ec5a). Loops: sets up + tests walls via collide_sector_walls(0x3ef21); then in swept-step mode (g_collision_step_active!=0) runs test_ray_reached_target + collide_ray_entities, else the point-test entity pass resolve_collisions_against_objects (0x401cf). On ANY hit restores the query position to g_collision_restore_x/y (0x90ab4/0x90ab8) and returns. Iterates into portal-linked sectors while g_collision_portal_continue (0x8c190) is set, with a hop budget at EBP+0x20. Register-context (EBP=ray state)."),
		new NamedFunction(0x401cfL, "resolve_collisions_against_objects",
			"[collision CORE — disasm-verified; the point-test entity/object pass of resolve_collisions_in_sector 0x3eeb0] "
			+ "Walks the gathered nearby objects/doors (g_door_worklist, g_collision_entity_count entries of {tag, ptr}) "
			+ "and resolves the query (g_locate_query_x/y) against each AABB collision box: box half-dims come from "
			+ "g_das_collision_buffer[sprite*4] (object+7 bit1 selects a simple half-width box vs a 4-byte shifted/rotated "
			+ "box -> scratch 0x8c154/0x8c158/0x8c15c). On a block it SLIDES the query out along the blocking axis, but "
			+ "first allows STEP-OVER if the box's top is within g_max_step_height (0x90bde) of the mover's feet (EBP+0x1e) "
			+ "with at least 0x8c0e8 clearance; otherwise sets g_collision_hit_flags |= 2, records the blocker in "
			+ "g_collision_blocker_object (0x8c16c), and pushes the query to the box edge + g_collision_portal_continue. "
			+ "Fires fire_tracked_object_trigger for touch-triggered objects (obj+9 bit4 && 0x8c1e6). tag!=0 entries go "
			+ "through clip_query_circle_to_edge's quad path (clip_locate_query_to_object). Iterates up to 4 relaxation "
			+ "passes (0x8c1dc) while anything moved (0x8c1da). Register-context (EBP = mover position/extent record)."),
		new NamedFunction(0x3ec5aL, "find_sector_and_collide",
			"[collision dispatcher] Locates the sector containing the current query point then resolves collisions in it. Seeds the ray bounds (EBP[0]=0x8000/EBP[1]=0x7fff, hop count 6); if g_player_sector==0 uses search_sector_global, else search_sector_from_hint -> search_sector_neighbors(0x3f090) -> search_sector_global; sets g_player_sector and calls resolve_collisions_in_sector(0x3eeb0). The in-sector test arm of probe_collision_step. Register-context (EBP=ray state)."),
		new NamedFunction(0x3ec40L, "find_query_sector",
			"[collision] 3-strategy sector search for the current query point (collision-path twin of locate_sector_at_position 0x3ee4b): tries search_sector_from_hint -> search_sector_neighbors(0x3f090) -> search_sector_global, returning the first that succeeds (carry clear) or 0 if none. Used by probe_collision_step to cross a portal into the next sector. __stdcall, carry-flag driven."),
		new NamedFunction(0x3f090L, "search_sector_neighbors",
			"[collision] Searches a sector's neighbouring sectors for the query point by walking its edge/portal list (sector+0xe = edge array, +0xd = count, stride 0xc): for each edge with a valid adjacent-sector id (!=0xffff) calls scan_sector_edges_at_y(0x3efb0) and returns the matching neighbour sector id. Middle strategy of the 3-strategy sector search."),
		new NamedFunction(0x3ef21L, "collide_sector_walls",
			"[collision] Prepares wall-collision bounds for the current sector (reads sector struct via ES: +0/+2 -> EBP[0]/EBP[1] X-bounds, +0x18 = adjacent sector for floor/ceiling height clipping against g_player_height / g_locate_query_z), resets the visited-sector stack (g_collision_sector_stack_count 0x8c192=0), then runs wall collision: collide_ray_walls_recursive(0x3fae0) in swept-step mode, else the point-test variant FUN_0003f0e0. Register-context (EBP=ray state, ES=sector seg)."),
		new NamedFunction(0x1768aL, "trigger_weapon_fire",
			"[trace-confirmed: fire-only] First-person weapon FIRE-BUTTON handler (HUD chain caller 0x1691c). Bails if the fire lock g_weapon_fire_lock(0x7fdd0) is set or the fire-button state 0x812f4 is clear; resolves the active-weapon attribute block (g_active_weapon_attrs / DAT_0007fe00), consumes ammo from g_selected_item_secondary[+2] (burst/multi-shot loops render_weapon_view per pellet), then latches the pending-shot params (g_pending_weapon_def 0x7fdf4 = weapon def, 0x7fde8/0x7fdec/0x7fdf8/0x7fdfc = aim/velocity, g_pending_fire_aim 0x7fe10/0x7fe14 = param_1/param_2), sets the lock g_weapon_fire_lock=-1 and arms the fire state via arm_weapon_fire(0x17629)."),
		new NamedFunction(0x16da2L, "fire_pending_weapon_shot",
			"[trace-confirmed: fire-only] Deferred execution of the shot queued by trigger_weapon_fire: if a pending weapon def g_pending_weapon_def(0x7fdf4) exists, bumps the per-frame max DAT_000853f6, calls spawn_projectile_from_aim(0x42400) with the pending weapon + aim (g_pending_fire_aim 0x7fe10/0x7fe14), then scales the spawned projectile's DAMAGE field [+0x16] (NOT velocity — corrected; compute_projectile_hit_damage reads +0x16 as the hit damage) by g_pending_shot_scale (0x7fe0c) and clears it. The bridge from input-latch to actual projectile entity spawn. Called from the per-frame player tick 0x1729c."),
		new NamedFunction(0x23869L, "redraw_weapon_hud_panel",
			"[weapon HUD] Redraws the first-person weapon/ammo HUD panel: if g_hud_panel_das_handle1 != 0, render_ui_texture_panel(g_hud_panel_das_handle1, 0x83e78). Sole caller = trigger_weapon_fire, on the ammo-depleted branch (right after g_pending_weapon_def=0). RENAMED from resolve_weapon_projectile_def (consistency audit 2026-06-21): it does NOT resolve a projectile def — g_pending_weapon_def (0x7fdf4) is set INLINE in trigger_weapon_fire (= g_active_weapon_attrs[2])."),
		new NamedFunction(0x27270L, "play_sound_effect",
			"[AUDIO/SFX — CORRECTED 2026-06-17; was mislabeled 'compute_player_fire_aim'] Plays a one-shot sound "
			+ "effect. EAX/CX = sound id (masked 0x7fff), EDX/ESI = an emitter/param stored at handle+0x22. Gated "
			+ "on g_sound_enabled (0x7f550) and 0x71d84. Allocates a sound handle (find_free_slot_83ed4 -> "
			+ "g_active_sound_handles 0x83ed4 + slot*0x9a), fills it (name ptr 0x84907, id @+4, vol @+4=0x20), "
			+ "resolves+loads the sample via resolve_sound_sample (0x27951 -> handle+5 = voice slot), then starts "
			+ "the SOS digital voice via start_sound_voice (0x276a2). Returns the handle ptr. Callers = "
			+ "trigger_weapon_fire (the FIRE sound), execute_dbase100_chain (script sound ops), "
			+ "run_leftclick_object_trigger (object SFX), the RAW command executor. NOTE: the player's fire AIM is "
			+ "computed inline in trigger_weapon_fire (0x1768a, the 0x7fe10 write @0x17921), NOT here."),

		// --- SFX / digital sound-effect engine (2026-06-17 audio deep-dive) ---
		// Game-facing sound effects. A "sound handle" = g_active_sound_handles (0x83ed4) + slot*0x9a.
		// play* fns allocate a handle, resolve+load the sample, compute positional vol/pan, and submit a
		// digital voice to the SOS mixer (device g_sos_digital_device 0x7f4dc) via sos_submit_voice.
		new NamedFunction(0x270caL, "play_object_sound",
			"[SFX] Plays a positional sound tied to an emitter/object. EAX=sound id (masked 0x7fff), "
			+ "[ebp+0x10]=emitter ptr (stored at handle+0). Allocates a handle (find_free_slot_83ed4), computes "
			+ "distance vol/pan via compute_sound_volume_pan (0x26f48) from the player origin, then submits the "
			+ "voice via start_sound_voice_vol (0x275cc). Reached from RAW/dbase command sounds (via 0x2730b)."),
		new NamedFunction(0x271e8L, "play_entity_object_sound",
			"[SFX — disasm-verified; called by tick_dynamic_entities 0x42d74] Thin wrapper: if g_sound_enabled, sets "
			+ "g_pending_sound_param=0x20 and plays the entity's sound via play_object_sound (emitter DAT_83ec2). The "
			+ "monster ambient/idle sound trigger in the AI tick."),
		new NamedFunction(0x273f0L, "play_sound_unique",
			"[SFX] Plays a sound only if that emitter's sound isn't already active (dedup via is_in_83ed4_table "
			+ "0x2778d) — used for looping/ambient emitters so they don't restart each frame. Else same path as "
			+ "play_object_sound: alloc handle, compute_sound_volume_pan, start_sound_voice_vol."),
		new NamedFunction(0x2730bL, "play_command_sound",
			"[SFX] Thin wrapper that plays a sound from a RAW/dbase command (-> 0x271e2 -> play_object_sound "
			+ "0x270ca). Called from the command executor's post-effects (finalize_command_chain 0x3065e)."),
		new NamedFunction(0x276a2L, "start_sound_voice",
			"[SFX] Submits a set-up sound handle to the SOS digital mixer at default volume. EAX=handle; reads "
			+ "handle+5 (voice/sample slot) -> g_sound_voice_descriptors (0x84874)[slot*4], fills the voice "
			+ "struct at handle+0x26 and calls sos_submit_voice (0x15a4a). Used by play_sound_effect."),
		new NamedFunction(0x275ccL, "start_sound_voice_vol",
			"[SFX] Like start_sound_voice but takes a caller-supplied volume/pan (ECX) from "
			+ "compute_sound_volume_pan — the positional submit path used by play_object_sound/play_sound_unique. "
			+ "Skips samples longer than 0x100000 (those stream instead). -> sos_submit_voice (0x15a4a)."),
		new NamedFunction(0x26f48L, "compute_sound_volume_pan",
			"[SFX] Positional attenuation: from the emitter position + the player/listener origin (0x90a94, "
			+ "0x85c48) computes a distance-scaled volume (0..0x7fff) and L/R pan for a sound handle (handle+6 = "
			+ "pan side). Helper 0x3bfd6 = distance/angle. Called before submitting + by update_active_sounds."),
		new NamedFunction(0x27b05L, "update_active_sounds",
			"[SFX] Per-frame update of all active positional sound handles: recomputes vol/pan via "
			+ "compute_sound_volume_pan (0x26f48) as the player moves and pushes them to the SOS voices "
			+ "(0x15a9c/0x15ab2 set volume/pan); reaps finished handles."),
		new NamedFunction(0x27951L, "resolve_sound_sample",
			"[SFX] Resolves a sound id to its loaded mixer-sample slot. EAX=id; bounds-checks vs "
			+ "g_sound_sample_count (0x848fc), indexes g_sound_sample_table (0x848f4, stride 0xc) at +0xb; if not "
			+ "yet loaded triggers load_sound_sample (0x277db). Returns the slot in AL (0xff = unavailable)."),
		new NamedFunction(0x277dbL, "load_sound_sample",
			"[SFX] Loads a sound-effect PCM sample into a mixer-sample slot on demand: reads sample bytes from the "
			+ "sound bank (g_sound_bank_file_handle) via dos_read_items (0x41b53), optionally up-samples via "
			+ "interpolate_words_43dd8, and registers it in g_sound_sample_table. Called by resolve_sound_sample. "
			+ "(NOT a DAS-cache resource — it's the SFX sound bank.)"),
		new NamedFunction(0x15a4aL, "sos_submit_voice",
			"[AUDIO/SFX] Game->SOS bridge: stores voice params (word@+0x20, dword@+0x1c) into the voice struct "
			+ "(EAX) and submits it to the SOS digital device g_sos_digital_device (0x7f4dc) via the SOS voice "
			+ "primitive 0x4a641 (sosDIGIStartSample-equivalent). CX/EBX = rate/flags."),
		new NamedFunction(0x15a65L, "sos_stop_voice",
			"[AUDIO/SFX] Stops a digital voice: EAX=voice -> sos_voice_deactivate_slot (0x4ac55) on the digital "
			+ "device (0x7f4dc). Used by the sound-handle stop/flush paths."),
		new NamedFunction(0x10c51L, "load_sfx_file_wrapper",
			"[SFX] Loads the sound-effect bank file at init (filename @0x763b0) — called by roth_main_sequence."),

		// --- recomp proposed_names backlog applied (oracle-verified lifts, 2026-06-17) ---
		new NamedFunction(0x557e7L, "noop_ret_stub",
			"[recomp-lifted] 1-byte bare `ret` — vestigial no-op stub (no observable effect). One of four "
			+ "identical stubs (also 0x15804, 0x3cc01, 0x55e7b)."),
		new NamedFunction(0x15804L, "noop_ret_stub_15804",
			"[recomp-lifted] 1-byte `ret` no-op stub. Cf. noop_ret_stub (0x557e7)."),
		new NamedFunction(0x3cc01L, "noop_ret_stub_3cc01",
			"[recomp-lifted] 1-byte `ret` no-op stub. Cf. noop_ret_stub (0x557e7)."),
		new NamedFunction(0x55e7bL, "noop_ret_stub_55e7b",
			"[recomp-lifted] 1-byte `ret` no-op stub. Cf. noop_ret_stub (0x557e7)."),
		new NamedFunction(0x4f36dL, "collect_raw_state_matches",
			"[recomp-lifted, oracle-verified] EAX=key, EDX=out (u16[]), EBX=max. Scans the raw-state primary "
			+ "buffer records (g_map_geometry_buffer 0x90aa8 (raw-state records are a keyed sub-table within it, at +word[+8]); start=u16[buf+8], count=u16[buf+start-2]; "
			+ "valid records (byte[+1]&0x80) 14B / invalid 10B) and writes the buf-relative offset of each "
			+ "record with key u16[+0xc]==key into out[2..] (up to max-2). out[0]=count, out[1]=key; returns count."),
		new NamedFunction(0x4f52bL, "find_raw_state_record",
			"[recomp-lifted, oracle-verified] AX=key. Single-match sibling of collect_raw_state_matches "
			+ "(0x4f36d): returns the buf-relative offset of the first valid raw-state record "
			+ "(g_map_geometry_buffer 0x90aa8 (raw-state records are a keyed sub-table within it, at +word[+8])) whose key u16[+0xc]==key, else 0."),
		new NamedFunction(0x50e35L, "ring_push",
			"[recomp-lifted, oracle-verified] stdcall(ret 4). Push a 16-byte entry onto event ring EAX "
			+ "(32 slots @0x931c0+idx*0x200; count 0x93bfc, cap 0x93be8, head 0x93bc0). EDX/EBX/ECX = first 3 "
			+ "dwords, stack[0] = 4th. Full (count>=cap) -> -1, else writes slot[head], count++, head=(head+1)&0x1f, "
			+ "returns the OLD head. Consumer 0x53d16; init ring_init (0x50d51)."),
		new NamedFunction(0x26f02L, "clamp_diff_200",
			"[recomp-lifted, oracle-verified] EAX=value, EDX=center; clamps value to within +/-0x200 of center "
			+ "(signed). SFX-cluster helper."),
		new NamedFunction(0x302b3L, "compute_mode_bytes",
			"[recomp-lifted, oracle-verified] EAX=out1, EDX=out2 (byte ptrs). Writes two pixel step/size bytes "
			+ "derived from the video-mode flags (g_90bd4 & g_hires_line_doubling_flag 0x90cbd)."),
		new NamedFunction(0x26a6cL, "set_7049a_from_71988",
			"[recomp-lifted, oracle-verified] byte[0x7049a] = 0x10 - min((u32[0x71988]&0x1ff)>>4, 0x10). Derives "
			+ "a 0..0x10 value from a position/scroll register (offset-named)."),
		new NamedFunction(0x3c1c9L, "build_atan_table",
			"[recomp-lifted, oracle-verified] Builds g_atan_table (0x8aa46): atan[i] = 0x4000*sincos[i]/"
			+ "sincos[i+0x80] for i in 0..0x3f — a ratio->angle (arctangent) LUT from g_sincos_table (0x72080). "
			+ "Pairs with atan2_bearing (0x3c201)."),
		new NamedFunction(0x10711L, "basename_strip_ext",
			"[recomp-lifted, oracle-verified] EAX=path, EDX=out. Copies the basename (after the last path "
			+ "separator) up to but excluding the first '.' into out, NUL-terminated."),
		new NamedFunction(0x13154L, "decode_byterun1",
			"[recomp-lifted, oracle-verified] EAX=src, EDX=dst, EBX=output length. ByteRun1 RLE decode: bytes "
			+ "<=0xf0 copy literally; a marker 0xf1..0xff repeats the next byte (marker-0xf0 = 1..15) times; "
			+ "stops when the output length is exhausted."),
		new NamedFunction(0x1e792L, "init_freelist_820c1",
			"[recomp-lifted, oracle-verified] Builds a 32-node free list: head [0x820c1] -> first node 0x820c5; "
			+ "each node 0x20 bytes, *node=next (last=0), node[+4]=0."),
		new NamedFunction(0x27374L, "find_sound_sample_index",
			"[recomp-lifted, oracle-verified; recomp proposed 'find_index_848f4'] AX=sound id. If g_sound_enabled "
			+ "(0x7f550)!=0, scans g_sound_sample_table (0x848f4, count g_sound_sample_count 0x848fc, stride 0xc) "
			+ "for an entry whose key u16[+8]==id; returns its 1-based index, else 0. The SFX sample-by-id lookup."),
		new NamedFunction(0x203fdL, "expand_rgb",
			"[recomp-lifted, oracle-verified] EAX=src (bytes), EDX=dst (u16[]), EBX=count. Per RGB triple: "
			+ "dst[0]=src[0]<<5, dst[1]=src[1]*0x30, dst[2]=src[2]<<4. A palette/color component expansion."),
		new NamedFunction(0x34a5fL, "adjust_records_z_carry",
			"[recomp-lifted, oracle-verified; recomp proposed 'adjust_records_34a5f'] EAX=center, ESI=record "
			+ "array, CL=count. For each 0x10-byte record whose word[+0xa] lies in [center-delta, center] "
			+ "(delta=g_player_move_delta_z 0x8a12c), adds delta to it. Moving-sector/entity Z carry-along."),
		new NamedFunction(0x50d51L, "ring_init",
			"[recomp-lifted, oracle-verified] Init counterpart to ring_push (0x50e35): fills all 32 slots of "
			+ "ring EAX (0x931c0+idx*0x200) with 0xffffffff, zeroes head/count, sets capacity [0x93be8+idx*4]=EDX."),
		new NamedFunction(0x130d4L, "blit_save_region",
			"[recomp-lifted, oracle-verified] EAX = ptr to a descriptor ptr. Copies a strided 2D framebuffer "
			+ "block from desc[0] (src row pitch g_screen_pitch 0x85498) into desc+0xc (contiguous): desc[1]/4 "
			+ "dwords/row x desc[2] rows. Saves a screen region into the descriptor's own buffer."),
		new NamedFunction(0x13ecbL, "shade_remap_blit",
			"[recomp-lifted, oracle-verified] EAX=descriptor. In-place 2D pixel remap through a 256-entry shade "
			+ "row: row byte[desc+0x10] selects g_world_shading_table_ptr (0x86d28) or g_das_remap_chunk_4000_ptr "
			+ "(0x86d14); pixel p -> table[(row<<8)|p] (low-byte REPLACE, not add). w=desc[1],h=desc[2],"
			+ "stride=desc[3],buf=desc[0]."),
		new NamedFunction(0x4c296L, "compute_ratio_4c296",
			"[recomp-lifted, oracle-verified] EAX=out (u32[2]). div=[0x91874] (x2 if byte[0x91dcf]&0x80); if 0 "
			+ "ret 0. out[1]=[0x91870]/div; out[0]=([0x91ce8]*([0x91870]%div))/div (64-bit). Fixed-point "
			+ "integer.fraction split; returns -1."),
		// --- GDV streaming media codec (FMV: RLE/LZ video + DPCM audio + VGA palette; file magic
		//     0x29111994). One shared decoder driven open->decode_frame*->close by play_gdv_cutscene
		//     (.GDV cutscenes) and by the INSPECT-window close-up branch of load_dbase300_resource_at_offset,
		//     which reads its resource from dbase300.dat (g_dbase300_filename) at a byte offset and GDV-
		//     decodes it ONLY when that resource is actually GDV (gdv_decoder_open validates the magic).
		//     NOT used by plain dbase300.dat resource loading (that's seek+read into the DAS cache).
		//     Decoder state lives in the g_gdv_* globals (0x91d00-0x91df0). Named 2026-06-20; the deeper
		//     per-frame video/audio bit-decoders (0x4c2d1/0x4c3ba/0x4c59d/0x4c7a5/0x4e0xx) are a follow-on.
		new NamedFunction(0x4b710L, "gdv_decoder_open",
			"[GDV codec API] Opens/initialises the decoder from the context struct (EAX=param_1): zeroes the "
			+ "g_gdv_* state, reads header/format fields (param+0x10/0x14/0x18-flags/0x1c/0x54/0x64), allocates "
			+ "the decode buffer (gdv_alloc_decode_buffer), reads+validates the file header "
			+ "(gdv_read_file_header), lays out audio/video buffers + DPCM (gdv_setup_decode_buffers), opens "
			+ "audio output (gdv_init_audio_output), builds pixel tables (gdv_init_pixel_tables); sets "
			+ "g_gdv_decoder_active=0xff and returns 0 on success."),
		new NamedFunction(0x4b8c1L, "gdv_decode_frame",
			"[GDV codec API] Decodes the next frame while g_gdv_decoder_active: rebases the 13 working "
			+ "pointers if the input buffer moved (streaming), then runs the video+palette decode path (or the "
			+ "alt path when g_gdv_stream_flags&4). Returns 0 = frame decoded, 1 = idle, 0x100 = end-of-stream "
			+ "(g_gdv_end_of_stream set). Looped by play_gdv_cutscene / load_dbase300_resource_at_offset."),
		new NamedFunction(0x4b95eL, "gdv_decoder_close",
			"[GDV codec API] Tears down the decoder: clears g_gdv_decoder_active, closes the input "
			+ "(gdv_close_input), frees the decode buffer (gdv_free_decode_buffer), and closes the source file "
			+ "(int21h) unless it was embedded (g_gdv_stream_flags&0x1000)."),
		new NamedFunction(0x4b9d4L, "gdv_alloc_decode_buffer",
			"[GDV codec] If the context's buffer ptr (ctx+8) is null, allocates ctx+0xc bytes via "
			+ "game_heap_alloc (flags alloc-owned bit in 0x91d22), zero-fills it, and records the base in "
			+ "g_gdv_decode_buffer (0x91d34) / ctx+0x50."),
		new NamedFunction(0x4b9a6L, "gdv_free_decode_buffer",
			"[GDV codec] If the decoder owns the decode buffer (0x91d22 bit0), frees g_gdv_decode_buffer via "
			+ "game_heap_free and clears ctx+8."),
		new NamedFunction(0x4ba30L, "gdv_setup_decode_buffers",
			"[GDV codec] Partitions the decode buffer into the audio region (0x91d38) and video/work regions "
			+ "(0x91d3c/0x91d40/0x91d50) per the header sizes; if the stream has DPCM audio (0x91dca&8) builds "
			+ "the step table (build_dpcm_step_table) and selects the DPCM decode entry (0x91898)."),
		new NamedFunction(0x4bbb1L, "gdv_read_file_header",
			"[GDV codec] Opens the source (int21h 0x3d00, or LSEEK 0x4200 for an embedded offset), reads the "
			+ "0x18-byte GDV header into 0x91d44, and validates the MAGIC 0x29111994 + version word (+0xe==1); "
			+ "for v1 also reads the 0x300-byte palette."),
		new NamedFunction(0x4bddfL, "gdv_init_audio_output",
			"[GDV codec; CORRECTED 2026-06-20 from gdv_open_input_stream] Sets up AUDIO output for the movie: "
			+ "either installs the PIT timer-sync path (gdv_install_timer_sync 0x4e590, g_gdv_stream_flags&2) "
			+ "or configures the SOS digital audio device (gdv_configure_audio_device 0x4e192) and submits the "
			+ "first audio buffer (0x55440 of ctx+4). Reads the audio sample-rate header (0x9187c = "
			+ "word[0x91d44+8]<<3). (Verified: this is audio-output setup, not input-stream opening.)"),
		new NamedFunction(0x4bef0L, "gdv_init_pixel_tables",
			"[GDV codec] Builds the pixel/colour expansion lookup tables at 0x91d3c (gradient fill, 0x400 or "
			+ "0x200 entries depending on g_palette_dirty) and zero-fills the video work buffer (0x91d40, size "
			+ "0x91d94) used by the frame decoder."),
		new NamedFunction(0x4beb3L, "gdv_close_input",
			"[GDV codec] Close/flush the GDV input source (int21h via 0x4e5db when 0x91dc2&0x20) and return the "
			+ "final status; called from gdv_decoder_close."),
		// === Audio/SOS + GDV-codec internals (2026-06-20, from 2 research subagents, each entry
		//     cross-checked vs the corpus; load-bearing/disputed ones disasm-verified by me). ===
		new NamedFunction(0x4d384L, "gdv_decode_video_chunk",
			"[GDV codec] THE video bitstream decompressor: validates chunk magic 0x1305, runs a bit-reader + 12-bit-distance LZ back-refs + RLE runs; sub-formats 0/1 also write the VGA palette. The only true decoder in the codec."),
		new NamedFunction(0x4c7a5L, "gdv_blit_frame_to_vga",
			"[GDV codec] Scaler/presenter (NOT a decoder): INT10h AX=4F05 VESA bank-switch + out 0x3c4/0x3c5 Mode-X plane masks; copies the decoded buffer to 0xa0000/0xb0000 with 1x/2x pixel-doubling."),
		new NamedFunction(0x4c788L, "gdv_blit_frame_to_vga_alt",
			"[GDV codec] 29-byte alternate entry that falls through into gdv_blit_frame_to_vga (0x4c7a5) = the dirty-flag/alt-path blit entry (Watcom shared-code; the corpus under-measures its size)."),
		new NamedFunction(0x4c2d1L, "gdv_present_streamed_frame",
			"[GDV codec] Single-frame present path (g_gdv_stream_flags&4): write_vga_palette then loops gdv_decode_video_chunk + reads the next chunk per subframe."),
		new NamedFunction(0x4c3baL, "gdv_read_frame_chunk",
			"[GDV codec] Reads the next compressed chunk into the ring via INT21h AH=3F/42 (read/lseek), verifies magic 0x1305, retries up to 8x. Returns bytes-read in ECX (dropped by Ghidra)."),
		new NamedFunction(0x4c59dL, "gdv_clear_display_surface",
			"[GDV codec] First-frame screen clear: zeroes the 0xa0000 VGA / work buffers per video mode (mode bits 0x40/0x01/0x80), VESA bank loop."),
		new NamedFunction(0x4c75cL, "gdv_present_first_frame",
			"[GDV codec] Present-first-frame guard: if no user callback is set, blits via gdv_blit_frame_to_vga (0x4c7a5)."),
		new NamedFunction(0x4e17fL, "gdv_begin_playback",
			"[GDV codec] Begin playback: gdv_setup_video_mode then gdv_init_frame_geometry + present-first-frame. Carry-flag return dropped (caller branches on it)."),
		new NamedFunction(0x4de7aL, "gdv_prime_first_frame",
			"[GDV codec] Primes the chunk ring before the playback loop: seeds the chunk ptrs, decodes one chunk, advances."),
		new NamedFunction(0x4deb5L, "gdv_run_playback_loop",
			"[GDV codec; MED] Main streamed playback loop: write_vga_palette, then per-frame gdv_read_frame_chunk + user-callback + advance; handles loop/seek (flags&8) and audio-sync drift."),
		new NamedFunction(0x4ddddL, "gdv_preload_frame_window",
			"[GDV codec; MED] Pre-decodes frames up to the ring window (d9c/d5c) and sets the loop sentinel; called from gdv_decoder_open."),
		new NamedFunction(0x4dff4L, "gdv_drain_pending_subframes",
			"[GDV codec] Audio catch-up: while audio is active (0x97b6c) loops gdv_decode_subframe while db4>1."),
		new NamedFunction(0x4e00dL, "gdv_decode_subframe",
			"[GDV codec] Decodes one subframe: decrements the subframe/audio counters, gdv_decode_video_chunk + advance-chunk-ptr."),
		new NamedFunction(0x4dcfcL, "gdv_emit_decoded_frame",
			"[GDV codec] Emits a decoded frame: if no user callback blit via 0x4c788, else user-callback(0) then user-callback(1) finalize."),
		new NamedFunction(0x4dd33L, "gdv_advance_chunk_ptr",
			"[GDV codec] 5-byte entry that falls into gdv_advance_chunk_ptr_inner; advances the chunk ring pointer."),
		new NamedFunction(0x4dd38L, "gdv_advance_chunk_ptr_inner",
			"[GDV codec] Advances the chunk ring pointer (d6c += hdr+payload+0xf & ~7, wraps to d50)."),
		new NamedFunction(0x4dd71L, "gdv_invoke_user_callback",
			"[GDV codec] Invokes the user callback (*g_gdv_user_callback 0x91d00)(op,...); returns AL status bits (Ghidra typed void; callers test bit0)."),
		new NamedFunction(0x4e041L, "gdv_callback_frame_boundary",
			"[GDV codec] Invokes the user callback with op=2 at a frame boundary; carry/eax status dropped (caller branches on it)."),
		new NamedFunction(0x4d2e0L, "gdv_settle_palette_fade",
			"[GDV codec] Palette-fade step: decrements the fade counter (de4); intermediate -> fade step (gdv_clear_vga_palette region), final -> write_vga_palette."),
		new NamedFunction(0x4d541L, "gdv_reformat_pixel_buffer",
			"[GDV codec; MED] Reformats the decode buffer on a scale-mode change (de2^de3 bits 4/8): de-interleaves/halves the rows in place."),
		new NamedFunction(0x4e08eL, "gdv_fade_in_palette",
			"[GDV codec] Palette fade-IN: loops gdv_write_scaled_palette with increasing level until full, over state+0x20 frames."),
		new NamedFunction(0x4e0c2L, "gdv_fade_out_palette",
			"[GDV codec] Palette fade-OUT: PIT-timed busy-wait, gdv_write_scaled_palette level 0x40->0, over state+0x22/0x24 frames."),
		new NamedFunction(0x4e11aL, "gdv_write_scaled_palette",
			"[GDV codec] Writes 256 DAC palette entries (out 0x3c8/0x3c9), each RGB scaled by the fade level (EBX arg, dropped by Ghidra); returns last value in AX."),
		new NamedFunction(0x4c392L, "gdv_clear_vga_palette",
			"[GDV codec] Clears the VGA palette: writes all 256 DAC entries to black (out 0x3c8/0x3c9 = 0)."),
		new NamedFunction(0x4e67eL, "gdv_setup_video_mode",
			"[GDV codec] Picks the VGA/VESA mode from frame dims+flags (0x13 / VESA 0x101/0x103/0x105 / Mode-X 0x8000), INT10h AX=4F02 or 0x13; writes mode fields into the context."),
		new NamedFunction(0x4ea34L, "gdv_init_modex_unchained",
			"[GDV codec] Mode-X/unchained setup: INT10h 0x13 then sequencer/GC/CRTC ports (out 0x3c4/0x3ce/0x3d4) to disable chain-4 and set double-scan."),
		new NamedFunction(0x4eba9L, "gdv_probe_vesa_bank_granularity",
			"[GDV codec; MED] Probes VESA bank granularity: writes a ramp into 0xa0000, INT10h 4F05 bank-switch probing; returns the granule in EAX, sets the linear-FB flag (de8)."),
		new NamedFunction(0x4eb03L, "gdv_flip_display_page",
			"[GDV codec] CRTC start-address page flip (out 0x3d4 0xc/0xd) + swaps the double-buffer ptrs (cd8/cdc/ce0/ce4)."),
		new NamedFunction(0x4eb4aL, "gdv_flip_vesa_page",
			"[GDV codec] VESA display-start page flip (INT10h 4F07, gated on flag 0x400000), swaps the double-buffer ptrs."),
		new NamedFunction(0x4bf4cL, "gdv_init_frame_geometry",
			"[GDV codec] Computes per-frame blit geometry: centering offsets, clip rect, scaled w/h, the plane-pointer set (d74..d90), stride deltas. Pure setup, no I/O. (Verified.)"),
		new NamedFunction(0x4e192L, "gdv_configure_audio_device",
			"[GDV codec; MED] Configures the SOS digital audio device: copies the audio-device descriptor (state+0x30..0x40) and registers it via the HMI digital driver (0x552f0/0x55360)."),
		new NamedFunction(0x4e590L, "gdv_install_timer_sync",
			"[GDV codec] Installs the A/V-timing PIT sync: hooks an INT vector (op 8) and reprograms PIT channel 0 (out 0x43 0x3e / 0x40) for the GDV tick rate."),
		// --- GDV audio-output path (cutscene PCM track -> SOS digital mixer) ---
		// Named 2026-06-21. These are the GDV decoder's *audio* glue: game-side code that bridges the
		// cutscene's audio track into the SOS digital voice mixer (sos_voice_*). The SOS layer itself is
		// host-replaced, but THIS glue is real engine code (lifted as part of GDV playback). Evidence =
		// caller context (gdv_* parents) + the sos_voice_*/timer callees + g_gdv_* state (0x91d00-0x91df0).
		new NamedFunction(0x4e066L, "gdv_audio_begin_playback",
			"[GDV audio; MED] If audio is enabled (g_gdv_audio_enabled 0x91dc8): runs the prime/sync hook (*0x91898) then starts the streaming voice via gdv_audio_start_voice(0x55670, buf=0x91d30, base=g_gdv_audio_stream_base 0x91d50). Called from gdv_run_playback_loop once buffers are primed."),
		new NamedFunction(0x4e394L, "gdv_audio_stream_callback",
			"[GDV audio; MED] SOS far buffer-completion callback (installed at 0x97c78 by gdv_audio_start_voice). arg type 0 = a queued DMA half drained -> advance the stream ring cursor (0x91d70 within base 0x91d50 / end 0x91d5c, with wrap) and re-queue via gdv_audio_queue_buffer(0x55620); type 2 = end-of-stream -> sets g_gdv_audio_end 0x91df4. Mirrors the SOS 0/2 message convention used by the speech voice path."),
		new NamedFunction(0x4e4f1L, "gdv_audio_init_silence_buffer",
			"[GDV audio] Called by gdv_decoder_open: installs the prime/sync hook ptr (0x91898 = 0x4e519) and fills the GDV audio output buffer (0x91d38, size g_gdv_audio_buf_size 0x91d2c) with 0x80808080 = 8-bit unsigned-PCM silence."),
		new NamedFunction(0x4e5dbL, "gdv_uninstall_timer_sync",
			"[GDV audio] Teardown counterpart of gdv_install_timer_sync (0x4e590): when g_gdv_stream_flags&2, restores the hooked INT vector (int21h op 8) and reprograms PIT channel 0 back to the default ~18.2 Hz rate (out 0x43 0x3e / out 0x40 0xff x2). Called by gdv_close_input."),
		new NamedFunction(0x552f0L, "gdv_audio_detect_driver",
			"[GDV audio; MED] Resolves the SOS audio driver descriptor for cutscene playback: if a descriptor is already cached (0x91d04) copies it (0x1b dwords) to 0x97b80; otherwise loads the detection driver, runs sos_find_driver_for_device, unloads detection. Stores result/error in 0x91d10. Called by gdv_configure_audio_device."),
		new NamedFunction(0x55360L, "gdv_audio_load_drivers",
			"[GDV audio; MED] Loads the SOS driver image(s) for cutscene audio: loads the detection driver, then the SOS driver-image loaders 0x4910f (-> 0x97b80) and 0x49587 (-> 0x97b70), unloads detection. Stores result/error in 0x91d10. Called by gdv_configure_audio_device."),
		new NamedFunction(0x55440L, "gdv_audio_setup_voices",
			"[GDV audio; MED] Initializes GDV audio playback: enables the audio callback (sos_enable_audio_callback), configures the SOS timer rate, opens the driver voices (sos_driver_open_voices), and registers the per-buffer/per-frame timer events (sos_timer_register_event). Records each step it completed in the g_gdv_audio_init_flags bitmask (0x91dc2) so gdv_audio_shutdown can unwind exactly what was set up. Called by gdv_init_audio_output."),
		new NamedFunction(0x55670L, "gdv_audio_start_voice",
			"[GDV audio; MED] Builds the SOS streaming-voice descriptor (rate 0x7fff, sentinel 0xdead, completion callback = gdv_audio_stream_callback 0x4e394, buffer/selector at 0x97c5c..) honoring the 8/16-bit + stereo flags in g_gdv_audio_format (0x91dca), then calls sos_voice_start and records the voice handle (0x97ce0) + sets g_gdv_audio_init_flags|0x40."),
		new NamedFunction(0x55620L, "gdv_audio_queue_buffer",
			"[GDV audio] Stores the next buffer ptr/selector (0x97c5c/0x97c60) and submits it to the active voice via sos_voice_load_to_slot. Called from the stream callback to ping-pong the DMA halves."),
		new NamedFunction(0x55640L, "gdv_audio_stop_voice",
			"[GDV audio] Per-frame voice stop: if g_gdv_audio_init_flags&0x40 (voice active), deactivates the SOS voice (sos_voice_deactivate_slot 0x97cdc/0x97ce0) and clears the bit. Called by gdv_decode_frame when a frame signals audio stop."),
		new NamedFunction(0x553b0L, "gdv_audio_shutdown",
			"[GDV audio; MED] Full audio teardown, unwound by the g_gdv_audio_init_flags bitmask (0x91dc2) that gdv_audio_setup_voices/start_voice set: deactivate voice (0x40), remove the two timer events (0x10/0x08), close driver voices (0x04), stop the timer service (0x02), disable the audio callback (0x01). Called by gdv_close_input."),
		// --- SOS DPMI descriptor helpers (host-serviced via INT 31h; flagged do-not-lift) ---
		new NamedFunction(0x4fcd3L, "sos_dpmi_create_descriptor",
			"[SOS/DPMI; OS-bound] Allocates and fully initializes an LDT descriptor for a real-mode SOS driver buffer via INT 31h: fn 0x0000 (Allocate Descriptor), 0x0006/0x0007 (get/set segment base), 0x0008 (set limit), 0x0009 (set access rights). Returns 0. NOTE: ROTH_audio_notes.md previously labeled 0x4fcd3 as 'the SOS far-call dispatch the host hooks' — that is INCORRECT; this is DPMI descriptor setup. The real driver-event dispatch is the g_sos_driver_vtable (0x92f9c) method-0 / sos_dispatch_midi_event (0x44e0d). See lift_handoffs/NAME_CORRECTIONS.md."),
		new NamedFunction(0x4fc9dL, "sos_dpmi_free_descriptor",
			"[SOS/DPMI; OS-bound] Frees an LDT descriptor (INT 31h fn 0x0001) allocated by sos_dpmi_create_descriptor; called from the SOS driver close/teardown paths."),
		new NamedFunction(0x47150L, "decode_midi_varlen",
			"[MIDI seq] MIDI variable-length-quantity decoder (byte&0x80 continuation, &0x7f<<7n accumulate); writes the value, returns the byte-count in EAX."),
		new NamedFunction(0x4594dL, "midi_all_notes_off_channels",
			"[MIDI seq] All-notes-off: per channel emits CC 0x7b (all-notes-off) + 0x79 (reset-controllers) + pitch-center via g_sos_driver_vtable; clears the channel-map tables."),
		new NamedFunction(0x45dc5L, "midi_restore_channel_volumes",
			"[MIDI seq] On resume: walks the 0x20 voices and re-sends CC7 channel volume from the stored raw volumes via the SOS MIDI dispatch; sets DAT_93104=1."),
		new NamedFunction(0x45f1dL, "midi_mute_channel_volumes",
			"[MIDI seq] On pause/finalize: sends CC7 stored-volume but clears the active flag (mute); twin of midi_restore_channel_volumes; sets DAT_93104=0."),
		new NamedFunction(0x46cceL, "clear_music_sequence_slot",
			"[MIDI seq; MED] Clears a music-sequence slot (zeroes the slot descriptor for slot<8); returns err 10 if slot>=8."),
		new NamedFunction(0x46da7L, "teardown_music_sequence",
			"[MIDI seq] Tears down a music sequence: removes its timer event, runs all-notes-off (midi_all_notes_off_channels), and tears down the track table."),
		new NamedFunction(0x46eb3L, "parse_music_sequence_tracks",
			"[MIDI seq] Parses the MIDI track table: reads the track pointers, decodes the first delta per track (decode_midi_varlen), populates the voice/track tables. Track-table ptr in EBX (dropped arg)."),
		new NamedFunction(0x45d28L, "sos_driver_dispatch_simple",
			"[SOS audio; MED] Thin generic invoke through the SOS driver vtable (g_sos_driver_vtable[verb*0x48]); shared by driver load + unload."),
		new NamedFunction(0x47daeL, "sos_driver_open_voices",
			"[SOS audio] Driver-open: per-channel populates the driver entrypoint descriptor tables (0x972a4/0x972c4); from sos_audio_init + the driver open thunks."),
		new NamedFunction(0x48666L, "sos_driver_close_voices",
			"[SOS audio] Driver-close (twin of sos_driver_open_voices): frees the real-mode buffer and zeroes the same descriptor tables; from the close thunk + shutdown."),
		new NamedFunction(0x47cf5L, "sos_enable_audio_callback",
			"[SOS audio; MED] Enables the mixer callback: page-locks (sos_lock_audio_buffers), sets the mixer-active flag (0x97b30=1), stores the rate."),
		new NamedFunction(0x47d6eL, "sos_disable_audio_callback",
			"[SOS audio] Disables the mixer callback (twin of sos_enable_audio_callback): unlocks the buffers, clears the mixer-active flag (0x97b30=0)."),
		new NamedFunction(0x47769L, "sos_lock_audio_buffers",
			"[SOS audio] Page-locks the 16 SOS buffers/code regions touched in the timer ISR (16x dpmi_lock_linear_region); returns 0 or err 5."),
		new NamedFunction(0x47a2fL, "sos_unlock_audio_buffers",
			"[SOS audio] Unlocks the 16 SOS buffers (twin of sos_lock_audio_buffers; 16x dpmi_unlock_linear_region)."),
		new NamedFunction(0x48b21L, "sos_load_detection_driver",
			"[SOS audio] Loads the HMIDET.386 detection driver: builds its path, opens + reads the header, page-locks it; sets 0x97aec=1."),
		new NamedFunction(0x48c6bL, "sos_unload_detection_driver",
			"[SOS audio] Unloads the HMIDET.386 detection driver (twin): closes the fd, unlocks, clears 0x97aec."),
		new NamedFunction(0x48f79L, "sos_find_driver_for_device",
			"[SOS audio] Scans the HMIDET device-ID records (0xe000-0xe200 window) for a match (device id + flag 0x80) and loads it; returns err 7 if not found."),
		new NamedFunction(0x4980dL, "sos_configure_timer_rate",
			"[SOS audio] Programs the PIT timer rate (0x1234dc / rate, the 1.193182 MHz clock) and installs the ISR vector (0x49f78)."),
		new NamedFunction(0x498e9L, "sos_stop_timer_service",
			"[SOS audio; MED] Stops the timer service (gated on DAT_755b4): calls the timer-teardown trio."),
		new NamedFunction(0x49e7aL, "sos_program_pit_divisor",
			"[SOS audio] Sets g_sos_timer_base_rate and writes the PIT divisor (shared by the register/remove-event paths)."),
		new NamedFunction(0x4a641L, "sos_voice_start",
			"[SOS audio] Voice-start: scans the 0x20 voice slots for a free one, copies the sample descriptor (EBX) into it, sets the active flag (|0xa000). Returns the slot/status in EAX."),
		new NamedFunction(0x4ad03L, "sos_voice_load_to_slot",
			"[SOS audio] Loads a sample into a caller-given voice slot (twin of sos_voice_start; flag |0x8800 + callback field +0x50); from sos_voice_set_callback."),
		new NamedFunction(0x4a5dfL, "sos_voice_set_rate",
			"[SOS audio; MED] Sets a voice's sample-rate/pitch field (word at voice slot+4)."),
		new NamedFunction(0x4887eL, "sos_alloc_driver_realmode_buf",
			"[SOS audio; MED] DPMI-mode-gated real-mode buffer alloc for the driver image; returns a ptr in EAX plus a second handle via EBX (dropped by Ghidra)."),
		new NamedFunction(0x4895eL, "sos_dpmi_alloc_dos_block",
			"[SOS audio; MED] Allocates a 0x1000-byte DOS/real-mode block and memcpy's the driver into it; returns the segment via out-params; helper of sos_alloc_driver_realmode_buf."),
		new NamedFunction(0x48a7aL, "sos_free_driver_realmode_buf",
			"[SOS audio; MED] Frees the driver real-mode buffer (DPMI free trio); from sos_driver_close_voices."),
		new NamedFunction(0x4b5b4L, "spawn_particle_on_edge",
			"[effects] Spawns a particle at a random point interpolated between two sector vertices (g_sector_geom_base + the two vtx indices in ECX), with a random velocity from g_sincos_table; sibling of spawn_particle, called by cmd_particle_effect. (alloc_particle + rng_next.)"),
		new NamedFunction(0x4ec70L, "init_gdv_video_context",
			"[cutscene] Fills the GDV movie context's video-mode fields (param+0x26 mode / +0x2a pitch / +0x2c height / +0x70 width / +0x74 linear-fb) from the current display state (g_video_linear_flag / g_rawscreen_flag / g_hires_line_doubling_flag / VESA globals). Called by play_gdv_cutscene before gdv_decoder_open."),
		new NamedFunction(0x4ed38L, "swap_cutscene_display_buffers",
			"[cutscene] Double-buffer page swap for the GDV cutscene: swaps the front/back buffer pointer pairs 0x71f04<->0x71f08 and 0x71f06<->0x71f0a (gated on g_rawscreen_flag + the context's +0x2e flag). Called by play_gdv_cutscene."),
		new NamedFunction(0x121a1L, "mouse_edge_latch",
			"[recomp-lifted, oracle-verified] On a rising edge of the mouse-button byte [0x7e93a] (cur!=0, prev "
			+ "[0x7e93b]==0) and only if not already latched ([0x7e930]==0): latch ([0x7e930]=1) + snapshot "
			+ "g_mouse_x/y (0x707b3/0x707b7) -> [0x7e904]/[0x7e908]. Always copies cur->prev. Called by "
			+ "player_movement_tick (0x12520)."),
		new NamedFunction(0x26de4L, "mark_sound_handle_by_id",
			"[recomp-lifted, oracle-verified; recomp proposed 'set_83ed4_flag_by_id'] EAX=sound id. Scans the 16 "
			+ "sound handles g_active_sound_handles (0x83ed4, stride 0x9a); for the first active one whose record "
			+ "u16[+6]==id, sets handle dword[+8]=0x7f00 and ret 1, else 0. Tags a playing SFX by its sound id."),
		new NamedFunction(0x356faL, "find_object_index_by_ptr",
			"[recomp-lifted, oracle-verified] EAX=entry ptr. Walks g_object_table_header's stride-linked "
			+ "world-object entries (first stride u16[hdr+4], count u16[hdr+6]; each step advances by the current "
			+ "stride, reads the next stride at the new position); returns the 1-based index where the address "
			+ "equals EAX, else 0. Address-keyed variant of the object-table search family."),

		// --- Queue-A frontier batch (2026-06-17 post-compact, ranked by inbound-call count) ---
		new NamedFunction(0x26d8aL, "stop_sound_by_id",
			"[SFX] Stop+free counterpart of mark_sound_handle_by_id (0x26de4): EAX=sound id. Scans the 16 "
			+ "sound handles g_active_sound_handles (0x83ed4, stride 0x9a) for the first active one whose record "
			+ "u16[+6]==id, stops its SOS digital voice via sos_stop_voice, decrements the voice descriptor's "
			+ "refcount (g_sound_voice_descriptors[handle+5]+8), and zeroes the handle slot. Returns 1 if a "
			+ "playing voice was stopped, else 0. Callers in the door/animated-object region (0x3d8xx-0x3ddxx)."),
		new NamedFunction(0x33c3eL, "set_state_record_count",
			"[command/state] Sets g_state_record_list_count (0x89f5c) = param, then calls FUN_00033f0e to "
			+ "rebuild/re-index the state-record list. Small setter used by the command/dialogue state layer."),
		new NamedFunction(0x305b6L, "reset_command_chain_state",
			"[command executor] Resets the RAW command-chain executor: zeroes g_command_chain_interrupt and several "
			+ "executor state globals (0x8a138/0x8a10c/0x89f64/0x8a0cc/0x8a134), calls FUN_0003065e, returns -1 (the "
			+ "chain-interrupt sentinel). Called when a command chain is aborted/restarted "
			+ "(0x31f3f/0x33dba/0x33e6b/0x348e2)."),
		new NamedFunction(0x3540bL, "run_command_dbase100_record",
			"[.RAW EXECUTE base 0x2B = BTI 'DBASE100 Command'] Runs the GLOBAL DBASE100 record/action-chain a "
			+ "command record points to: eval_dialogue_record_by_id(ESI+8) where ESI+8 = the command's 'Global Command "
			+ "Index' (Arg2); on first run latches DAT_8a26c/DAT_81e18; if the sticky flag (ESI+6 & 0x10) set, ORs bit3 "
			+ "into the command's state byte (ESI+2); clears the pending flag DAT_8a0dc; returns -1 on success, 0 if eval "
			+ "returned 0. DUAL-PURPOSE: it is BOTH the immediate cmd 0x2B handler (dispatch table[0x2b]) AND the deferred "
			+ "runner for cmd 0x36 cmd_dbase100_if_next_fails — which stages its own record as 'pending' (DAT_8a0dc) so "
			+ "flush_pending_command_record (0x31963) runs it here later if a following conditional fails. So 'pending' "
			+ "only applies to the 0x36 path; for 0x2B it fires immediately. (Was run_command_dbase100_record.)"),
		new NamedFunction(0x31963L, "flush_pending_command_record",
			"[command/dialogue] Tail-called dispatcher (3 jmp sites): if a command/dialogue record is pending "
			+ "(DAT_8a0dc!=0) and not blocked (DAT_89f60==0), runs run_command_dbase100_record (0x3540b) and clears "
			+ "the pending flag; always resets g_anim_step_mode to 0."),
		new NamedFunction(0x408d1L, "configure_render_viewport",
			"[renderer/video] Recomputes the 3D view-window geometry from the current video mode. Sets g_screen_height "
			+ "(x2 if g_hires_line_doubling_flag), then derives the viewport rect globals 0x90bee/0x90bf0/0x90bf2/"
			+ "0x90bf4(=g_render_viewport_height, clamped to 200 scanlines)/0x90bf6 from the mode params "
			+ "(0x8549c/0x85cd8/0x85cdc/0x85ce0/0x85ce4) honoring the g_view_scale_flags (0x90bd4) halve-width(bit0)/"
			+ "halve-height(bit1) bits, then refreshes derived state (0x2e458, conditionally 0x2e140). 9 callers = the "
			+ "video-mode-change + viewport-resize sites (0x11177/0x14xxx/0x2e6xx/0x3e2xx)."),
		// ---- Render viewport SCALE + perspective PROJECTION-TABLE rebuild (runs on every video-mode / view-size
		//      change, via configure_render_viewport). disasm-verified 2026-06-20. ----
		new NamedFunction(0x2e458L, "setup_render_projection_scale",
			"[renderer — disasm-verified; called by configure_render_viewport 0x408d1] Recomputes the perspective SCALE "
			+ "factors and view geometry from the current viewport dims + aspect/FOV constants: view CENTER g_view_center_x/y "
			+ "(0x90a70/0x90a72 = render width/height >> 1), the g_image_surface clip bounds (+0xe=width-1, +0xc=height-1), "
			+ "the world/sprite render scales (0x85410/0x8540c/g_das_render_scale, halved per g_view_scale_flags & "
			+ "doubled per g_hires_line_doubling_flag), the viewport pixel area (0x89f2a/0x89f2c), and the centered "
			+ "g_render_target_buffer (offset into g_framebuffer_ptr) with its DPMI limit. Ends by rebuilding the "
			+ "perspective LUT via rebuild_projection_table (0x409b4)."),
		new NamedFunction(0x409b4L, "rebuild_projection_table",
			"[renderer — disasm-verified] Computes the viewport vertical centering offset g_viewport_top_margin (0x90c0c "
			+ "= (200 - render_height)/2, with g_render_double_scanline_flag set when 0x71eea > 0xbd -> halve height), "
			+ "then drives build_projection_table (0x40bd6) with the pending mode g_render_viewport_reconfig (0x90bfc, "
			+ "0=build / 1=restore / 2=narrow-copy)."),
		new NamedFunction(0x40bd6L, "build_projection_table",
			"[renderer — disasm-verified] Builds the perspective projection LUT g_render_column_source_table (mode 0): "
			+ "inits it to 0x80 (unset), then for each angle/distance step iVar (0x200..1) computes sincos_pair and the "
			+ "projected screen position center - (sin*scale)/iVar, storing iVar there — i.e. a screen-position -> "
			+ "distance map. Built in both directions (g_projection_build_dir +1/-1 = the two horizon halves) with the "
			+ "gaps filled by interpolate_projection_gaps (0x40d1e), then snapshotted to g_projection_table_backup "
			+ "(0x8c204). Modes 1/2 restore/narrow-copy the backup instead of rebuilding."),
		new NamedFunction(0x40d1eL, "interpolate_projection_gaps",
			"[renderer — disasm-verified; called by build_projection_table] Walks the projection LUT in the "
			+ "g_projection_build_dir direction and fills runs of unset (0x80) entries between two known samples by "
			+ "linear interpolation (single-gap inline, longer runs via fill_projection_linear_ramp 0x40cb1)."),
		new NamedFunction(0x40cb1L, "fill_projection_linear_ramp",
			"[renderer — disasm-verified; leaf of interpolate_projection_gaps] Linearly interpolates a run of N entries "
			+ "between two known endpoint samples (step = delta/N), writing the ramp into the projection LUT in the "
			+ "g_projection_build_dir direction. Handles both build directions (0x8c200 sign)."),
		new NamedFunction(0x2e104L, "set_vesa_bank_page2",
			"[video/VESA] Banks the VESA window to g_current_vesa_bank + g_vesa_page_bank_offset (0x71dc4) via "
			+ "set_vesa_bank — i.e. selects the off-screen/second video page that lives that many banks above the "
			+ "current one. Returns its argument. Part of the VESA banked double-buffer present path."),
		new NamedFunction(0x2e36bL, "program_vga_display_mode",
			"[video/VGA] Programs the VGA hardware for the game's display mode: disables Sequencer chain-4 (port "
			+ "0x3c4/0x3c5 idx4), clears GC mode bits (0x3ce/0x3cf idx5/6), tweaks CRTC (0x3d4/0x3d5 idx0x14/0x17 = "
			+ "byte-mode/word-mode + idx9 max-scanline for line doubling), and sets Misc-Output (0x3c2) sync polarity "
			+ "from the table at 0x71dc0[g_video_mode_flags&3]. Stores the unchained page bases (0x71f04=0xa000, "
			+ "0x71f06/0x71f08) and sets the mode-configured flag g_vga_mode_configured (0x90be4). The 0x90be6&4 bit "
			+ "selects the taller (double-height) variant. No-op + returns arg in raw-screen / 0x146d8 modes."),
		// ---- VGA display-LAYOUT toggle (the F4/F6 'display type' keys: key_cycle_display_type[_alt]). disasm-verified ----
		new NamedFunction(0x2e609L, "toggle_video_display_mode",
			"[video/VGA — disasm-verified; called by key_cycle_display_type_alt (F6) and configure_render_viewport] "
			+ "Toggles between the two VGA framebuffer LAYOUTS (g_video_mode_flags bit2): blanks + copies the visible "
			+ "page contents plane-by-plane between the 0xA0000/0xA8000 unchained pages (with line-doubling in the taller "
			+ "variant), flips g_video_mode_flags^4, reprograms CRTC max-scan-line (0x3d4/0x3d5 idx9) for line-doubling, "
			+ "recompute_hires_line_doubling, reconfigures the viewport, reprograms the page bases (0x71f04/0x71f06/"
			+ "0x71f08) + Misc-Output sync (0x3c2), and re-uploads the palette. The 'display type' switch the user sees."),
		new NamedFunction(0x2e896L, "copy_vga_page_planar",
			"[video/VGA — disasm-verified] Copies one full VGA page to another (src/dst = 0x71f04<<4 / 0x71f08<<4, "
			+ "swapped if param_1) plane-by-plane via Sequencer map-mask (0x3c4 idx2) + GC read-map (0x3ce idx4), over "
			+ "all 4 planes x 200/400 rows x 0x50 bytes. Used by toggle_video_display_mode to preserve the image across "
			+ "the layout switch."),
		new NamedFunction(0x2e900L, "vga_screen_off",
			"[video/VGA — disasm-verified] Blanks the display: Sequencer reg 1 (0x3c4/0x3c5 idx1) |= 0x20 (screen-off bit)."),
		new NamedFunction(0x2e90dL, "vga_screen_on",
			"[video/VGA — disasm-verified] Un-blanks the display: Sequencer reg 1 &= ~0x20 (clear screen-off bit)."),
		new NamedFunction(0x2e91aL, "wait_one_timer_tick",
			"[timing — disasm-verified; Ghidra mis-decompiled as an infinite loop] Busy-waits until g_frame_tick_counter "
			+ "(0x90bcc) advances by 1 — paces the mode switch one timer tick. (asm: dx=tick+1; spin while (dx-tick)>=0.)"),
		new NamedFunction(0x2e932L, "vga_blackout_palette",
			"[video/VGA — disasm-verified] Sets all 256 DAC palette entries to black (out 0x3c8 index, 0x3c9 R/G/B = 0) "
			+ "— a fade/blank during the mode switch before the real palette is re-uploaded."),
		new NamedFunction(0x2e140L, "blank_active_video_page",
			"[video] Ensures the VGA mode is programmed (calls program_vga_display_mode if g_vga_mode_configured "
			+ "0x90be4==0) then blanks the display: in buffered mode does the 0x2e18b/flip_video_page(0) page-flip "
			+ "dance, in raw-screen mode zeroes the whole 64000-byte VGA page at 0xa0000. Gated off during "
			+ "cutscene/fade (0x76634/0x146d8). Called by configure_render_viewport."),
		new NamedFunction(0x2d6a8L, "set_render_shade_level",
			"[renderer SMC] Selects the global lighting/shade level (index EAX, stored g_render_shade_level 0x90c1a) "
			+ "by SELF-MODIFYING the span rasterizers: looks up two per-level shade constants (words at 0x71db4[idx] "
			+ "and 0x71dba[idx]) and patches their bytes directly into the immediate operands of the inner span loops "
			+ "(e.g. 0x36d4f = the imm8 of `mov edx,8` in draw_world_surface_spans; also 0x37062/0x399d8/0x3b789/"
			+ "0x3b7bf/0x3b829/0x38c8a... across the wall/sprite/floor drivers). Called from render_world_scene "
			+ "(0x28ad9) and render_world_face_list (0x2ae58). [SMC WRITER — flagged to recomp.]"),
		new NamedFunction(0x2d200L, "project_perspective_coord_0c",
			"[renderer] Perspective-projects one edge/vertex coordinate: depth = max(0x1000, geom_record[FS:BX+0xc]); "
			+ "screen = clamp((coord(param_2) * g_perspective_scale)/depth + g_view_center 0x909a4, -0x3ffe..0x3ffd); "
			+ "passes the 16.16 result to emit_vertex_bbox. Sibling of project_perspective_coord_20 (differs only in "
			+ "the depth field offset 0xc vs 0x20)."),
		new NamedFunction(0x2d24dL, "project_perspective_coord_20",
			"[renderer] As project_perspective_coord_0c but divides by the depth field at geom_record[FS:BX+0x20] "
			+ "(vs +0xc). Perspective-projects the other edge endpoint and feeds emit_vertex_bbox."),
		new NamedFunction(0x42056L, "remove_secondary_state_record",
			"[raw-state/entity] Removes a 0x10-byte record from a group in g_raw_state_secondary_buffer and compacts "
			+ "the array: GS:[param] = the group count byte; shifts every trailing record down one slot, fixing each "
			+ "record's back-reference (byte[+9]&2 -> g_dynamic_entity_count index table, else g_state_pool_a_records) "
			+ "by its u16[+6] index, then decrements the count. Sets the dirty flags 0x911c5/0x911c7. Counterpart of "
			+ "add_secondary_state_record (0x42c72)."),
		new NamedFunction(0x42c72L, "add_secondary_state_record",
			"[raw-state/entity] Inserts a 0x10-byte record into g_raw_state_secondary_buffer: stages the source "
			+ "record (param_2) on the stack, runs FUN_00042014 on it, allocates a free secondary slot (FUN_00042189), "
			+ "sets bit1 (0x2) in the owning primary record's flag byte (g_raw_state_primary_buffer[param_3+0x16]), "
			+ "copies the record in, and links the back-reference (byte[+9]&2 -> g_dynamic_entity_count else "
			+ "g_state_pool_a_records). Counterpart of remove_secondary_state_record (0x42056)."),
		new NamedFunction(0x4269bL, "play_distance_variant_sound",
			"[SFX] Plays one of an object/entity def's sound variants chosen by distance. EBX=def with a variant "
			+ "table at +0x24 (count u16[+0x22], range u32[+8]); param_3=distance scales the variant index down "
			+ "(via DAT_0007272c) when close. Resolves id = table[idx]-1 and plays it: param_1==0 -> FUN_000271fb "
			+ "(positional), else play_entity_sound bound to the entity at param_1+2. Used for impact/footstep-style "
			+ "multi-sample sounds."),
		new NamedFunction(0x43d04L, "project_point_to_screen_column",
			"[renderer] Projects a rotated 2D point to a clamped 16-bit screen column: rotate_point_2d, then "
			+ "(rotatedY>>8)*0x7400 / (depth param_1 + 1) + 0x8000 (screen center), clamped to 0..0xffff. Used for "
			+ "horizontal sprite/billboard placement. [name semantics hedged — confirm sprite-placement caller.]"),
		new NamedFunction(0x40b08L, "ensure_dos_transfer_buffer",
			"[OS/DPMI] Lazily allocates the 64KB conventional-memory DOS transfer buffer used for real-mode "
			+ "INT 21h I/O under DOS/4GW: if not yet allocated (g_dos_transfer_buffer_linear 0x8c1f8 == 0), calls "
			+ "dpmi_alloc_dos_memory(0x1000 paragraphs) and caches the linear address (seg<<4) + the real-mode "
			+ "segment/selector (g_dos_transfer_buffer_selector 0x8c1fc)."),
		new NamedFunction(0x34d14L, "find_secondary_state_record_by_key",
			"[raw-state/entity] First-match lookup over g_raw_state_secondary_buffer: walks every group (via the "
			+ "index region at g_raw_state_primary_buffer+4) and its 0x10-byte sub-records, returning a pointer to "
			+ "the first record whose key u16[+0xe]==param. Returns NULL if none. First-match sibling of "
			+ "collect_secondary_state_records_by_key (0x34c97)."),
		new NamedFunction(0x34c97L, "collect_secondary_state_records_by_key",
			"[raw-state/entity] Collect-all sibling of find_secondary_state_record_by_key (0x34d14): walks the same "
			+ "g_raw_state_secondary_buffer groups and writes the buffer-relative offset of EVERY 0x10-byte record "
			+ "whose key u16[+0xe]==param into the out array (param_2), counting in DAT_8a110; returns the count. "
			+ "(Resolves the previously-deferred 'raw-state secondary-buffer scan'.) Used by 0x32a20 to snapshot "
			+ "keyed records into an effect record."),
		new NamedFunction(0x35303L, "begin_object_command_chain",
			"[command executor] Starts a command chain sourced from a world object: clears g_active_object, sets "
			+ "g_command_source_object = param_1 (the object record) and DAT_8a134, snapshots param_1[0]/[1] into "
			+ "DAT_8a260/8a262, looks up the object's command list via find_object_list24(param_1[7], param_2) and, "
			+ "if found, runs it (FUN_0003520b). Called from the object/entity layer (0x40779/0x427a7)."),
		new NamedFunction(0x2a4d0L, "emit_world_surface",
			"[renderer scene] Per-surface render setup + emit (called by transform_sector_objects_to_view 0x29dcf "
			+ "with the enqueued record). Derives g_world_surface_draw_flags from the surface flags (ESI+7 bit0x10), "
			+ "computes the mip level (from the ESI+0xa flag bits 0x6000/0x80) and texture dims (DAT_90956 = height*2, "
			+ "DAT_90980 = width*2 << mip), stores the dispatch index/flags/das-ptr into the render record, then calls "
			+ "emit_world_face_spans to rasterize it."),
		new NamedFunction(0x2a6d0L, "build_sector_draw_order",
			"[renderer scene] Top of the sector visibility/ordering pass: resets the recursion depth (DAT_85300=0), "
			+ "then for every sector (FS-relative, count DAT_852f0) not yet visited runs traverse_sectors_recursive "
			+ "(0x2a7af) to build the back-to-front visit order; a second pass coalesces overlapping span bboxes "
			+ "(merges Y-extents +4/+6, retires merged nodes with +2=0xffff). Companion driver to "
			+ "traverse_sectors_recursive."),
		new NamedFunction(0x2abfbL, "setup_surface_render_constants",
			"[renderer/perspective] Initializes the perspective + span constants for the current surface/view from "
			+ "the geometry records DAT_85270/DAT_85274: resets g_render_shade_level (0xffff), sets g_world_span_colorkey, "
			+ "g_perspective_scale (= width<<8), the reciprocal divisors DAT_90994/90996 (=0x40000/dim), the view "
			+ "center DAT_909a4, and the texture dims DAT_9099c/90998. Also SMC-patches the colorkey/shade bytes into "
			+ "the span drivers (0x38c94/0x3b794). [SMC writer — flagged for recomp.]"),
		// --- DEV-MODE debug MAP overlay renderer (2026-06-18; entry 0x10dce, draws into g_render_target_buffer) ---
		// DEV-ONLY feature (author-confirmed): only togglable when g_dev_mode_flag (0x7f560) is set — which the
		// SHIPPED game leaves clear, so a normal player never sees it. With dev mode on, the 'L' key handler
		// (0x1444c: tests g_dev_mode_flag&1, then `not g_debug_map_enabled`) toggles g_debug_map_enabled (0x7f36e).
		// The per-frame refresh (0x103bf) calls draw_map_overlay only when g_debug_map_enabled != 0. It draws RAW
		// wireframe lines directly over the full player view (NOT a corner minimap or a separate window).
		new NamedFunction(0x10dceL, "draw_map_overlay",
			"[map / DEV] Entry for the dev-mode wireframe map overlay (toggled by 'L' when g_dev_mode_flag is set; "
			+ "off in the shipped game). Stashes the marker/UI colors (g_map_menu_marker_selected, "
			+ "g_default_message_color), computes the player-orientation step bytes (compute_mode_bytes from player pos "
			+ "0x90a8c/0x90a94 + g_player_angle + viewport width 0x90bf2), then calls render_map_geometry to draw the "
			+ "world wireframe straight onto g_render_target_buffer / g_screen_pitch (over the player's 3D view). "
			+ "Gated by g_debug_map_enabled (0x7f36e)."),
		new NamedFunction(0x2e954L, "render_map_geometry",
			"[map] Renders the overhead map. From the map-view descriptor (EBX: rect w/h +0xc/+0xe, scale +0x10, "
			+ "aspect bytes +0x12/+0x13, player obj +8) computes the world->map scale (g_map_scale_x/y) to fit the "
			+ "world into the rect and the world/screen centers (g_map_world_center_x/y, g_map_screen_center_x/y). "
			+ "Then walks the world walls (g_raw_state_primary_buffer records, flag byte+5 bit0x40), drawing each "
			+ "wall edge between its sector-geometry vertices (g_sector_geom_base) via map_draw_world_edge, and finally "
			+ "the player-position marker (map_draw_player_marker on EBX+8)."),
		new NamedFunction(0x2ec5fL, "map_draw_world_edge",
			"[map] Transforms a world edge (x0,y,x1 args) into map space — rotate (floorceil_rotation_sincos), scale "
			+ "by g_map_scale_x/y, offset by the world/screen centers — and draws it via clip_map_line (0x2ee66), "
			+ "falling back to draw_bresenham_line when not fully clipped."),
		new NamedFunction(0x2ebfdL, "map_draw_marker_edge",
			"[map] Draws one edge of the player-position marker: transforms the marker vertex (from EBP) into map "
			+ "space (same rotate/scale/offset as map_draw_world_edge) and draws it. Called 3x by "
			+ "map_draw_player_marker."),
		new NamedFunction(0x2eba7L, "map_draw_player_marker",
			"[map] Draws the player-position marker on the map as 3 edges (3x map_draw_marker_edge) — the little "
			+ "facing arrow/triangle at the player's location."),
		new NamedFunction(0x2ee66L, "clip_map_line",
			"[map] Clips a map line segment against the map view rect (ESI[0..3] = the clip bounds), sorting the "
			+ "endpoints, then draws the visible part via draw_bresenham_line / the clip helper 0x2eebc."),
		new NamedFunction(0x2eebcL, "map_line_clip_test",
			"[map] Endpoint visibility/clip helper for clip_map_line: tests a line endpoint against the map rect "
			+ "bounds (ESI[0]/ESI[2]) to decide accept/reject."),
		new NamedFunction(0x2ed21L, "draw_bresenham_line",
			"[map/2D] Bresenham line rasterizer into the map buffer (g_map_buffer_base 0x8543c, row pitch "
			+ "g_map_buffer_pitch 0x85438). Color = g_map_draw_color (0x85458 low byte); if its high byte == 0xff the "
			+ "writes are XOR (`*p ^= color`, for the rubber-band/marker) else solid (`*p = color`). Handles both "
			+ "x-major and y-major octants. The pixel-level line draw under the map renderer."),
		new NamedFunction(0x2b3faL, "render_secondary_surface_pass_clipped",
			"[renderer scene — secondary surfaces] Renders g_secondary_surface_list split by the horizon line "
			+ "DAT_853ce with top/bottom span clipping (g_world_span_top<-DAT_84942 above the split, g_world_span_bottom"
			+ "<-DAT_84940 below), marking the subpass (g_secondary_subpass_id/flags 1 or 2). Per record sets "
			+ "g_view_clip_plane/0x85260/0x85268 then render_world_secondary_surface. Gated on g_has_secondary_surfaces. "
			+ "Called by render_world_face_list_subpass (0x2928a) — the span-clipped sibling of the "
			+ "render_secondary_surface_pass1/2 family; DAT_853ce is the likely mirror/reflection split line."),
		new NamedFunction(0x28972L, "shift_wall_nodes_vertical",
			"[renderer scene] Post-projection pass over the sector render arena (FS-relative, size DAT_852ce): for "
			+ "each sector's wall sub-nodes (stride 0x14) subtracts DAT_853c8 from the projected screen-Y top/bottom "
			+ "(+2/+3), i.e. applies a vertical (pitch/look) shift to the whole projected scene. Called from the "
			+ "render_world_face_list_subpass setup (0x2875a/0x28942)."),
		new NamedFunction(0x2a0a0L, "build_scene_draw_list",
			"[renderer scene — draw-list assembler] Builds the per-frame render worklist (g_door_worklist) from the "
			+ "sector visit-order arena + object/door pools. First transforms the global object pools to view "
			+ "(transform_sector_objects_to_view for the entity pool 0x84958, FUN_29f50 for 0x853dc, g_particle_pool). "
			+ "Then walks the visited sectors (FS:[0xfc00] visit list from build_sector_draw_order) and, for each "
			+ "sector with surfaces (flag byte+0x16 bit1), iterates its secondary-buffer object records "
			+ "(g_raw_state_secondary_buffer, stride 0x10): projects each renderable one (flag+7 bit0x80 clear) via "
			+ "rotate_point_2d and, by its type bits, writes a worklist node (advancing 0x26/0x4c) tagged at +0x12 = "
			+ "1 (world surface -> emit_world_surface) / 2 (depth-sorted surface) / 3 (steep/near object) and emits or "
			+ "insert_depth_sorted_surface. Finally walks g_door_pool (count g_door_count, stride 0x1f6) projecting "
			+ "each door (tag 4) into the sorted list. Called from render_world_scene (0x28df1/0x29385)."),
		new NamedFunction(0x29830L, "build_sector_render_tree_recursive",
			"[renderer scene — recursive portal traversal + projection] Builds the per-frame projected sector/wall "
			+ "node arena (FS-relative, alloc cursor DAT_852ee stride 0xa header + 0x14-byte wall sub-nodes; bounded "
			+ "by DAT_852f0 < 0xc65 sectors and DAT_852ce < 0x7cdf bytes). For the current sector (ESI): allocates a "
			+ "node, and for each wall (list ESI[7], count byte[ESI+0xd]) records the wall's GS view-space vertex "
			+ "coords (+8/+0xc), marks portal walls (neighbor u16[wall+4]!=0xffff, within clip X range "
			+ "DAT_852dc/852e0) with flag +0x12 bit0x20, perspective-projects the wall vertices to screen "
			+ "(*g_perspective_scale / depth + center 0x909a4, clamped +/-0x3ffe) into +0/+4/+6, then RECURSES "
			+ "through each portal. This arena is consumed by build_sector_draw_order (0x2a6d0) + build_scene_draw_list "
			+ "(0x2a0a0). Distinct from walk_visible_sectors (0x294c0, the wall-clip pass). Entry = "
			+ "begin_sector_render_tree (0x29812)."),
		new NamedFunction(0x29812L, "begin_sector_render_tree",
			"[renderer scene] Entry wrapper for the recursive sector-tree build: clears DAT_8b3d8 then calls "
			+ "build_sector_render_tree_recursive (0x29830) on the root sector (ESI)."),
		new NamedFunction(0x29f50L, "setup_player_viewmodel_sprite",
			"[renderer scene] Builds the player-anchored first-person viewmodel sprite node (the held weapon/torch "
			+ "drawn over the world). Positions the node at the player origin (0x90a8c/0x90a94/0x90a90), sets the "
			+ "render flags (+0x10=0x80, +0x11=1, +0x14=0x221), runs a walk-bob animation state machine "
			+ "(DAT_9202c/DAT_84920 phases, timer DAT_9203e stepped by g_frame_time_scale, gated on g_move_speed_accum "
			+ "so it only bobs while moving), orients it by -g_player_angle, and enqueues it via "
			+ "transform_sector_objects_to_view. Called by build_scene_draw_list (0x2a0a0) for the DAT_853dc slot."),
		new NamedFunction(0x3d4daL, "lookup_door_record_by_sector",
			"[world/doors] Searches the two runtime door pools for an existing door on a given sector (resolves the "
			+ "sector id via the geometry selector DAT_852c8): first g_door_pool (count g_door_count, stride 0x1f6) "
			+ "then g_secondary_door_pool (count g_secondary_door_count, stride 0x2c), matching record[0]==sector id. "
			+ "Returns the door record or NULL. Distinct from find_door_by_sector (0x3cfcc, the geometry-side "
			+ "enumerator)."),
		new NamedFunction(0x3d749L, "resolve_door_neighbor_sector",
			"[world/doors] Walks a door sector's walls to find the portal wall, follows it to the adjacent sector "
			+ "and stores the linked neighbor in DAT_8c0cc — i.e. resolves the sector on the other side of a door. "
			+ "Geometry helper for spawn_door_instance."),
		new NamedFunction(0x3d7b9L, "alloc_secondary_door_record",
			"[world/doors] Allocates+initializes a door in the SECONDARY door pool (g_secondary_door_pool 0x8bfc0, "
			+ "max 6, stride 0x2c) if one isn't already present for the sector: takes a free slot, sets the sector id, "
			+ "derives the door height from the min wall-vertex Y (-10), copies the sector base coords, sets the door "
			+ "flags (+0xf=0x81/+0x13=0x40), assigns a per-door sound id (DAT_8c0d2++), and on a sound (DAT_8b3cc) "
			+ "plays the open SFX (play_world_sound_at_pos). Increments g_secondary_door_count."),
		new NamedFunction(0x3db20L, "scan_portal_walls_near_query",
			"[collision/proximity — disasm-verified; CORRECTED from 'draw_sector_portal_edges' — this DOES NOT draw] "
			+ "Walks a sector's walls (count byte[+0xd], wall array u16[+0xe], stride 0xc) and for each portal wall "
			+ "(neighbor u16[wall+8]!=0xffff) computes the query point's distance to that wall via point_to_wall_distance_sq "
			+ "(0x3e03f, radius 0x26), short-circuiting (returns) once a portal wall is within 0x311. Skips the sector "
			+ "matching param_2. Used by apply_cell_move_to_player_portalcheck when a moving floor/ceiling gap closes "
			+ "(proximity-to-portal test, NOT rendering). [exact output semantics hedged — register/CL aliasing in the "
			+ "decomp; the load-bearing fact is it is a distance scan, not a draw.]"),
		new NamedFunction(0x3d586L, "spawn_door_instance",
			"[world/doors] Registers an active (animating) door in the door pool when a door is opened/triggered. "
			+ "Resolves the door's sector + neighbor geometry via the geometry selector (DAT_852c8), and (while "
			+ "g_door_count < 5) builds its runtime record(s) — alloc_door_record per leaf + setup_door_swing_geometry "
			+ "for the swing arc — into g_door_pool (stride 0x1f6, base 0x8b3fc) which build_scene_draw_list then "
			+ "projects each frame (tag 4). Callers in the door-trigger path (0x3d545/0x3e027)."),
		new NamedFunction(0x2f772L, "free_dpmi_selector",
			"[OS/DPMI] Frees a DPMI/LDT descriptor (selector) if nonzero: INT 31h AX=0001h (Free Descriptor). "
			+ "Counterpart to alloc_dpmi_selector (0x2f72a). Used to release the selector-backed map geometry "
			+ "sections."),
		new NamedFunction(0x2f72aL, "alloc_dpmi_selector",
			"[OS/DPMI] Allocates a DPMI selector and configures it: INT 31h AX=0000h (Allocate 1 LDT Descriptor), "
			+ "then AX=0007h (Set Segment Base = param_2) and AX=0008h (Set Segment Limit = param_3-1); on any error "
			+ "frees it (AX=0001h). Returns the selector. Used by the map loader to map each carved geometry section."),
		new NamedFunction(0x2f459L, "unload_map_geometry",
			"[map load] Tears down the current map's geometry: atomically zeroes + frees (via free_dpmi_selector) the "
			+ "four section selectors g_geometry_selector / 0x90bec / 0x90bea / 0x90bc4, clears g_player_sector, frees "
			+ "the section buffer 0x85c4c (game_free_if_not_null), and releases the effect pools (free_effect_pools)."),
		new NamedFunction(0x21dc6L, "write_savegame_file",
			"[savegame] Writes a savegame to SAVE\\<slot>.SAV (param_1 = slot). Builds the path (build_game_path + "
			+ "dos_make_directory), sprintf's the filename, and if a file already exists confirms overwrite "
			+ "(FUN_00026349). Then opens for write and emits the chunked save format via dos_write_u16(chunk-id) + "
			+ "dos_write_items: chunk 1 header, the UI/screen snapshot (g_ui_panel_scratch_handle, allocated from "
			+ "g_das_cache_heap_handle), then the game-state chunks (ids 1/0xa/0xb=thumbnail/2/3/0xe/7/4/5/6/0xd/0xc — see ROTH_savegame_format.md chunk table). Write-side "
			+ "counterpart of the savegame loader (chunk reader). Callers in the save-menu/options path (0x1ac56). "
			+ "The 0x30-byte player chunk is built by write_player_state_chunk (0x3e0f0)."),
		new NamedFunction(0x3e0f0L, "write_player_state_chunk",
			"[savegame — disasm-verified; called by write_savegame_file 0x21dc6] Serializes the player into a 0x30-byte "
			+ "record (param_1): position g_player_x/z/y (0x90a8c/90/94), g_player_angle, g_player_sector, g_player_height, "
			+ "g_view_pitch/_applied, g_value_reduction_factor, g_player_health, and the two equipped items "
			+ "(g_selected_item_primary/secondary stored as offsets relative to g_inventory_slots so they survive reloc). "
			+ "Returns 0x30 (the chunk size). Inverse of read_player_state_chunk (0x3e1a0)."),
		new NamedFunction(0x3e1a0L, "read_player_state_chunk",
			"[savegame — disasm-verified; called by load_savegame_file 0x22129] Restores the player from the 0x30-byte "
			+ "record (inverse of write_player_state_chunk): writes back position/angle, height, pitch, "
			+ "g_value_reduction_factor, health, and rebuilds the equipped-item pointers (+ g_inventory_slots). NOTE the "
			+ "asymmetry: the saved sector goes to staging 0x89f36, NOT directly to g_player_sector (the engine "
			+ "re-resolves it) — consistent with the documented type-selective restore."),
		new NamedFunction(0x26eafL, "stop_sounds_for_sample_slot",
			"[SFX] Stops every active sound handle bound to voice/sample slot param_1: scans g_active_sound_handles "
			+ "(16, stride 0x9a) for handles whose slot byte (+5)==param_1, zeroes the handle, sos_stop_voice's its "
			+ "voice, and decrements the sample descriptor's refcount (g_sound_voice_descriptors[param_1]+8). Used "
			+ "when unloading/evicting a sound sample so no voice is left playing it."),
		new NamedFunction(0x1dcefL, "give_item_by_dbase_id",
			"[inventory] Gives the player an item identified by its dbase100 id (param_1, must be >= 0x200): scans "
			+ "g_dbase100_inventory_table for the template whose id (g_dbase100_base[entry+2]) == param_1 and is a "
			+ "valid pickable item (flags +4: bit0x80 clear, type nibble != 2), then give_item(slot index+1, param_2). "
			+ "Returns the give_item result, or 0 if not found. The by-id wrapper over give_item."),
		new NamedFunction(0x26c8cL, "free_resource_buffers",
			"[shutdown/level-unload] Releases the loaded resource buffers: closes the resource file handle "
			+ "(DAT_848f8), frees the SFX sample bank (g_sound_sample_table, via flush_object_das_handles + "
			+ "game_heap_free + free_audio_stream_buffers 0x30162), the voice-stream double-buffers "
			+ "(g_audio_decode_buffer_a/_b/g_audio_silence_buffer 0x8548c/0x85490/0x85494), and g_resource_pool. "
			+ "Run on shutdown / before reloading resources."),
		new NamedFunction(0x27ca6L, "vsprintf_core",
			"[CRT/string] The printf format engine behind sprintf (0x27c53). Walks the format string (ESI) copying "
			+ "literals to the output (EDI) and consuming varargs (EBP); on '%' parses the conversion (flags into "
			+ "g_format_flags, width/precision, then the d/u/x/s/c/etc. conversion), and converts \"\\n\" to CRLF "
			+ "(0x0a0d) for DOS text. Returns the formatted length (EDI - param_4). The shared formatter for "
			+ "sprintf/printf-family calls."),
		new NamedFunction(0x32a20L, "snapshot_keyed_secondary_records",
			"[raw-state/effects] Snapshots all secondary-state records matching a key into an effect record: "
			+ "collect_secondary_state_records_by_key (0x34c97) gathers the matching record offsets into a stack "
			+ "buffer, then alloc_effect_record reserves space and the count + offsets are copied in (at +param_2). "
			+ "Builds a persistent saved copy of a keyed record set (resolves the previously-deferred 0x32a20)."),
		new NamedFunction(0x3fdb0L, "clip_locate_query_to_object",
			"[collision] Tests/clips the locate query point (g_locate_query_x/y) against an object's 4-corner "
			+ "collision quad: reads the 4 corner coords from the object's geometry record (obj+0x2e -> +0x82, stride "
			+ "8) into the scratch 0x8c17c, then stages each edge's endpoints into g_collision_edge_a/b and runs the "
			+ "per-edge clip clip_query_circle_to_edge (0x3fe2d) for each of the 4 edges. Used by the movement/locate "
			+ "query to clip against door/object boxes. [name hedged.]"),
		new NamedFunction(0x3fe2dL, "clip_query_circle_to_edge",
			"[collision CORE — disasm-verified; per-edge worker of clip_locate_query_to_object 0x3fdb0] Swept "
			+ "circle-vs-line-segment resolution: tests the moving query circle (center g_locate_query_x/y, radius from "
			+ "the bound block g_collision_radius/g_collision_radius_sq) against ONE wall/object edge whose endpoints are "
			+ "staged in g_collision_edge_ax/ay (0x8c1ef/0x8c1f1) -> g_collision_edge_bx/by (0x8c1f3/0x8c1f5). Steps: "
			+ "(1) AABB reject vs the box bounds g_collision_box_min/max; (2) project the circle onto the segment "
			+ "(perp-distance^2 vs g_collision_radius_sq), early-out if clear; (3) on penetration, SLIDE the query out "
			+ "to the nearest non-penetrating point along the edge (uses isqrt_fixed; 0x8c13c = radius^2 push numerator), "
			+ "or round it around an endpoint/corner when within g_collision_corner_radius_sq (0x8c140) via atan2_bearing "
			+ "+ g_sincos_table. On a hit sets g_collision_hit_flags |= 4, writes the new g_locate_query_x/y, records the "
			+ "moved-distance^2 (EBP+0x24), and sets g_collision_portal_continue. Register-context (scratch in EBP). "
			+ "This is THE player/entity-vs-wall slide response."),
		new NamedFunction(0x1db98L, "advance_dialogue_action_queue",
			"[dialogue] Per-frame pump of the queued dialogue-action list: if not busy (g_dialogue_busy_flag) "
			+ "and the queue is non-empty (g_dialogue_action_queue_count), runs the next entry via execute_dbase100_chain "
			+ "(DAT_81e42/81e46); on completion (!= -1) decrements the count, calls finish_dialogue_record_eval when "
			+ "drained, else shifts the remaining 0xc-byte queue entries down. Drives queued dialogue commands one per "
			+ "frame."),
		new NamedFunction(0x1dd50L, "is_item_id_pickable",
			"[inventory/dbase100] Predicate: returns 1 if a valid pickable item template with dbase100 id == param_1 "
			+ "(>= 0x200) exists in g_dbase100_inventory_table — i.e. flags+4 bit0x80 clear AND type nibble != 2 — "
			+ "else 0. The query counterpart of give_item_by_dbase_id (0x1dcef)."),
		new NamedFunction(0x1def8L, "resolve_dbase100_sound_ids",
			"[dbase100 load] Load-time pass over every inventory/object template: walks each template's trigger "
			+ "blocks (+0x14) and, for the sound-bearing sub-opcodes (0x19/0x21-0x22/0x29-0x2a/0x31-0x32), rewrites "
			+ "the embedded sound id (low 16 bits) in place to its resolved mixer sample index "
			+ "(find_sound_sample_index). Pre-binds template SFX so playback skips the id lookup."),
		new NamedFunction(0x1e0a9L, "free_dbase100_data",
			"[dbase100 unload] Releases the dbase100 dialogue/command database: game_heap_free's g_dbase100_base and "
			+ "g_dbase100_record_bitmap (then close_dialogue_script), and closes the script file handle "
			+ "(g_dialogue_script_handle). Run on level unload / shutdown."),
		// --- HUD / UI panel + menu rendering (0x23-0x24 region) ---
		new NamedFunction(0x244daL, "render_text_input_field",
			"[menu/text-entry] Renders an editable text input field with a blinking cursor (used by show_message_box "
			+ "0x26078 for the save-name entry): measures + lays out the label (param_1) + current input (the 0x30-char "
			+ "buffer), clear_framebuffer_rect's the field, and draws the text with the cursor (the local_cc/_cb "
			+ "control struct + fill_rect_solid (0x12cd4) fills the cursor/field rect (g_rect_fill_color 0x7f355 = DAT_7675f then 0), colour g_default_message_color), "
			+ "then flushes/flips. The text-entry widget."),
		new NamedFunction(0x235feL, "render_player_health_bar",
			"[HUD] Renders the player status panel's health bar: scales g_player_health against max health "
			+ "(DAT_7fe44) to a proportional fill (panel geometry from param_2[9/0xb/0xc/0xe]), builds the bar into a "
			+ "work buffer and blits it. The status (health) panel drawn by draw_active_ui_panels for DAT_83d6c."),
		new NamedFunction(0x23cffL, "blit_panel_image",
			"[HUD] Transparent blit of a UI panel's content image to the framebuffer: copy_nonzero_bytes each row "
			+ "(skip color 0) from param_1 (source) to g_framebuffer_ptr + param_2[4], stride param_2[6], height "
			+ "param_2[7], honoring g_hires_line_doubling_flag (double rows). The panel-content blitter."),
		new NamedFunction(0x23897L, "render_ui_panel_text",
			"[HUD] Renders the text layer of a UI panel (DAT_83d78): lays out and draws 3 text fields via the font "
			+ "renderer (0x13f2e/0x1426f) at the panel's anchored positions, marking the region dirty. The text "
			+ "content of the main HUD panel (paired with render_ui_texture_panel for its background)."),
		new NamedFunction(0x2491fL, "render_menu_entry_list",
			"[menu] Renders the list of menu entries (param_3+0x14, stride 3 dwords): per entry draws its label via "
			+ "the text path (measure_control_text_width + draw_text_at_screen_xy), formatting numbered items as "
			+ "\"%d: %s\" (s__D___s 0x75ef9), resolving dbase100 labels (resolve_dbase100_text), drawing a settings "
			+ "value bar (draw_menu_value_bar when flag bit0x10), and accumulating the dirty rect. The content "
			+ "of the options/settings/save/load lists."),
		new NamedFunction(0x247bcL, "draw_menu_value_bar",
			"[menu/settings] Draws a horizontal VALUE GAUGE (a settings slider bar — NOT a scrollbar; ROTH has no "
			+ "draggable thumb) for one menu item: fill length = (item value ECX, = item[+8]&0x1ff) * 0x23/256, "
			+ "clamped to the 0x23(35)-px track. Composes a FILLED strip (tile 0x350 if this is the selected item "
			+ "g_map_menu_marker_selected, else 0x340) for the fill px and an EMPTY strip (0x358/0x348) for the "
			+ "remainder, then blits the 35px-wide x 9-row bar (hires-doubled). Called per slider item by "
			+ "render_menu_entry_list (item flag bit0x10). VISUAL (author-confirmed): the gauge is an ASCENDING "
			+ "WEDGE / stepped bars — small on the left, growing to the right — that shape lives in the ICONS.ALL "
			+ "DAS sprites (g_reloc_base 0x7f56c, dir offsets 0x340/0x350 lit + 0x348/0x358 unlit), NOT the code; the "
			+ "fill just slides the lit->unlit cut rightward, progressively lighting the bigger right-hand segments. "
			+ "CORRECTED 2026-06-19 (was mislabeled scrollbar thumb)."),
		new NamedFunction(0x24b1eL, "hit_test_ui_element",
			"[menu/UI] Hit-tests a point (EBX,param_2) against a grid of UI cells (pitch DAT_83e88), returning the "
			+ "1-based cell index whose box (param_6+4..+0x20, param_7+4..+0x20) contains the point, else 0. The "
			+ "mouse-pick for menu/list rows."),
		new NamedFunction(0x24fb1L, "draw_menu_box_zoom_anim",
			"[menu] Draws one frame of the message-box open/close ZOOM animation: 4 progressively-scaled copies of "
			+ "the box sprite (scale local_10/32 about the box center) via blit_clipped_sprite_smc. Called from "
			+ "show_message_box (0x25493) as the box expands/contracts."),
		new NamedFunction(0x243beL, "refresh_hud_layout",
			"[HUD] Per-frame HUD setup/refresh (called from the game loop 0x17350): runs FUN_2268e then computes the "
			+ "resolution-dependent panel layout offsets (branches on g_screen_height==0x85cdc / g_screen_pitch==0x280 "
			+ "= 320 vs 640). [name hedged — confirm it positions vs draws.]"),
		// --- Sprite/object render-queue clip+projection pipeline (0x3c region) ---
		new NamedFunction(0x3c4a1L, "build_sprite_render_queue",
			"[renderer/sprites] Per-frame build of the visible sprite/object render queue: walks the candidate "
			+ "object list (DAT_8b2fc, linked via [+8]), clip/culls + bounds each via clip_cull_object_to_view "
			+ "(0x3c511), and for the survivors computes the vertical center (compute_object_y_center 0x3c843) and "
			+ "links them into the queue (g_sprite_render_queue_head, count DAT_8b328). Feeds depth_sort_sprite_queue."),
		new NamedFunction(0x3c511L, "clip_cull_object_to_view",
			"[renderer/sprites] Projects + view-clips + back-face-culls one object/sprite quad (ESI = object record). "
			+ "Computes its screen bounding box into ESI+0x28(minX)/+0x2a(minY)/+0x2c(maxX)/+0x2e(maxY) tested vs the "
			+ "view bounds g_view_bound_right/left/bottom/top; rejects via vertex sign-mask + edge cross-product "
			+ "winding tests (back-face/degenerate); sets the +0x14 ready flag (clears bit0x100). On partial overlap "
			+ "calls FUN_0003c892 to clip. The visibility gate for the sprite queue."),
		new NamedFunction(0x3c843L, "compute_object_y_center",
			"[renderer/sprites] Computes an object's vertical center: min/max of its vertices' Y (record+0x36 list, "
			+ "count +0x34, via the transformed coords at +0x30+10) and writes the midpoint to ESI+0x10/+0x12 (the "
			+ "sprite anchor Y)."),
		new NamedFunction(0x3c7e7L, "depth_sort_sprite_queue",
			"[renderer/sprites] Bubble-sorts the sprite render queue (g_sprite_render_queue_head, count DAT_8b328) "
			+ "back-to-front by depth (node+0x12), swapping adjacent out-of-order nodes until a clean pass "
			+ "(DAT_8b358). Run after build_sprite_render_queue so sprites draw in the right order."),
		new NamedFunction(0x3cad6L, "interpolate_object_clip_vertex",
			"[renderer/sprites] Crossing-vertex interpolator for object/sprite clipping (sibling of the floor/ceil "
			+ "interpolate_clip_crossing_vertex): lerps the screen X/Y (EDI+6/+8) between two verts (ESI/EBX) by the "
			+ "parameter (param_2), copies the depth/flags, then perspective-projects to screen (DAT_9099c/90998 + "
			+ "view center 0x909a0/0x909a4) with the +/-8 near-clamp."),
		new NamedFunction(0x3c598L, "compute_object_screen_bbox",
			"[renderer/sprites] Computes an object's screen bounding box from its transformed vertices (ESI+0x36 "
			+ "index list, count +0x34, coords at +0x30): min/max X into local + min/max Y into DAT_8b354/DAT_8b356. "
			+ "Used by the object clip/cull path."),
		new NamedFunction(0x3c892L, "clip_object_to_frustum",
			"[renderer/sprites] Sutherland-Hodgman clips an object/sprite polygon against the view frustum (the "
			+ "sprite analog of the floor/ceil clip_one_boundary family): sets up the in/out vertex buffers "
			+ "(DAT_8b2e0/DAT_8b308), walks the (count+0xd) vertices (stride 0x14) and emits the clipped polygon. "
			+ "Called by clip_cull_object_to_view (0x3c511) when the object straddles a view boundary."),
		new NamedFunction(0x3c0beL, "compute_surface_normal_shade",
			"[renderer/lighting] Computes a face's flat-shading term from its geometry: takes two edge vectors of "
			+ "the quad (EBP vertex coords), forms their CROSS PRODUCT (the surface normal iVar5/6/7), and normalizes "
			+ "via isqrt_fixed(normal^2) / isqrt_fixed(edge^2) to derive the shade/light level. The per-surface light "
			+ "calc feeding the floor/ceil + wall shading (e.g. from draw_floorceil_surface 0x3a84e)."),
		new NamedFunction(0x3cc02L, "save_snapshot_file",
			"[debug/snapshot] Writes a screen snapshot to disk (param_1 = snapshot digit): DOS-deletes any existing "
			+ "g_snapshot_filename_buf (INT 21h AH=0x41), then writes g_snapshot_work_buf out. The 'B'-key debug "
			+ "screenshot path (see ROTH_snapshot_notes.md). Clears g_flush_predraw_flag."),
		new NamedFunction(0x3cf98L, "record_portal_clip_entry",
			"[renderer/sectors] During the sector render-tree build (build_sector_render_tree_recursive 0x29830), "
			+ "records a (parent, sector) pair into the 6-slot portal-clip list (DAT_8b3dc/DAT_8b3e8, count "
			+ "DAT_8b3d8 reset by begin_sector_render_tree) when the wall's neighbor is a real portal (<0xfffe). "
			+ "Marks sectors needing recursive cross-portal clipping."),
		new NamedFunction(0x1e2bdL, "build_entity_def_by_id",
			"[dbase100/entity] Resolves a dbase100 template by 1-based index (param_2, bounds-checked vs the count "
			+ "at g_dbase100_base+0x10) from g_dbase100_inventory_table and builds its entity definition via "
			+ "build_entity_def_record (0x1e128). The by-id wrapper used to instantiate monster/object defs."),
		new NamedFunction(0x1e774L, "close_voice_file",
			"[audio/dialogue] Closes the speech/voice resource file (g_voice_file_handle) via dos_close_handle and "
			+ "clears the handle."),
		new NamedFunction(0x1e7c3L, "lookup_cached_timed_message",
			"[UI/text cache] Retrieves a cached timed-message text by key (param_2) from the 32-node message cache "
			+ "(g_message_cache_head 0x820c1; nodes 0x20B: +0 next, +4 key, +8 len, +0xa color, +0xc text). On a hit "
			+ "it moves the node to the front (MRU), sets g_timed_message_color from +0xa, copies the +0xc text (len "
			+ "words[+8]) into param_1, and returns the length; 0 if absent (lazy-inits the freelist). Put side = "
			+ "store_cached_timed_message (0x1e827)."),
		new NamedFunction(0x1e827L, "store_cached_timed_message",
			"[UI/text cache] Inserts a timed message into the 32-node cache (g_message_cache_head 0x820c1): reuses "
			+ "the oldest (tail) node, moves it to the front, and stores key=param_2, color=param_3, length=EBX, and "
			+ "the EBX text bytes from param_1 at node+0xc. Read side = lookup_cached_timed_message (0x1e7c3)."),
		new NamedFunction(0x19ca7L, "free_cursor_entry_icons",
			"[inventory] Frees the loaded item-icon DAS handles for the inventory display list: walks "
			+ "g_cursor_entry_table (stride 3 dwords, count 0x80af8), pool_free_handle's each entry's handle and "
			+ "nulls every other entry sharing the same handle (dedup), and resets the display state "
			+ "(g_displayed_item_left/right, 0x81048/0x81030/0x8103c). Run when the inventory list is rebuilt/closed."),
		new NamedFunction(0x1a2d2L, "draw_inventory_tabs",
			"[inventory UI] Draws the 5 category TAB buttons of the inventory panel: for each tab, picks its "
			+ "active vs inactive icon (g_inventory_tab_context_map[i] == g_cursor_active_list ? active : inactive) "
			+ "from the icon table 0x712da, positions it at g_ui_panel_anchor_x + offset / anchor_y+0x38, blits via "
			+ "blit_reloc_das_image, and records its click hotspot (w=0x13,h=0x12, action = tab+0x17). Marks the tab "
			+ "strip dirty (register_dirty_rect)."),
		new NamedFunction(0x1bfaaL, "draw_equipped_item_right",
			"[inventory UI] Draws the right-hand displayed/equipped item icon: if g_displayed_item_right is set, "
			+ "blits its icon (blit_item_icon) centered in the 0x1c x 0x38 box at g_ui_panel_anchor_x+0x59 / "
			+ "anchor_y+0xf. Right-side counterpart of draw_equipped_item_left (0x1a2ef)."),
		new NamedFunction(0x142b7L, "capture_screen_thumbnail",
			"[savegame/UI] Downscales the current 3D view into a small 78x56 (0x4e x 0x38) thumbnail record at "
			+ "param_1 (+0 type=2, +2 w=0x4e, +3 h=0x38, +4 pixels): reads g_framebuffer_ptr at the view origin "
			+ "(0x85ce0/0x85cdc/0x85ce4, x2 if g_hires_line_doubling_flag) and box-samples by a fixed X/Y step "
			+ "(0x10000-scaled). Produces the save-slot preview written as .SAV chunk 0x0b (fits the 0x1130 scratch); "
			+ "also used for the inventory preview (0x1a451)."),
		new NamedFunction(0x12d27L, "blit_slide_transition",
			"[UI/transition] Renders one frame of a screen slide/wipe: builds a per-row displacement ramp in a 512B "
			+ "scratch (step 0x800000/width, position from param_2 = slide progress) and blits the descriptor's source "
			+ "(param_1[0]) over the destination (param_1[1], width param_1[3]) sheared by that ramp. The per-frame "
			+ "worker behind play_screen_slide_in/out (0x1ffb7/0x20134)."),
		new NamedFunction(0x1729cL, "update_player_tick",
			"[player] Per-frame player update (from game_play_loop 0x17344/0x17984). Runs update_player_movement, "
			+ "decays the per-frame action timer (DAT_853f6) by g_frame_time_scale, and drives the player "
			+ "weapon/action state machine (DAT_7fddc states 1/2/3 with the animation value DAT_7fde0 stepped by "
			+ "g_frame_time_scale; gated on g_player_health > 0): fires queued shots (fire_pending_weapon_shot), "
			+ "activates/uses weapons + held items (activate_weapon_item / consume_held_item), and updates the "
			+ "first-person weapon sprite (load_dbase200_sprite_cached). The player-side counterpart to the entity tick."),
		new NamedFunction(0x2198eL, "bundle_level_states",
			"[savegame] Writes .SAV chunk 0x0c = the bundled per-level raw-state. Lists every per-level state file "
			+ "(enumerate_files_by_pattern 0x217bc) and, for each, emits a sub-record into the save: dos_write_u16(8) "
			+ "+ the file's 0xe-byte directory entry (level descriptor) + dos_write_u16(9) + the whole file copied "
			+ "through a 65000-byte buffer (dos_read_items level file -> dos_write_items save). So one save captures "
			+ "the state of ALL visited levels (each = the .RAW-state stream from write_raw_state_stream), framed by "
			+ "the 8/9 sub-markers. Counterpart on load extracts each back out (copy_save_chunk_to_file -> .TMP -> "
			+ "read_raw_state_stream)."),
		new NamedFunction(0x217bcL, "enumerate_files_by_pattern",
			"[OS/files] DOS directory scan: dos_find_first/dos_find_next over a wildcard path (param_1), copying each "
			+ "match's 0xe-byte name entry into the caller's list (param_2, stride 0xe) and returning the count. Used "
			+ "by bundle_level_states to list the per-level state files."),
		new NamedFunction(0x21b9fL, "read_savegame_thumbnail",
			"[savegame] Extracts the screen thumbnail (TLV chunk 0x0b) from SAVE<param+1>.SAV for the load-menu "
			+ "preview. Confirms the .SAV TLV framing: reads a 4-byte chunk header dos_read_items(&hdr,4) = {u16 id, "
			+ "u16 size}, skipping each chunk by dos_lseek(size) until it hits id 0x0b (then reads the thumbnail into "
			+ "a g_das_cache_heap scratch block and returns it) or passes id 10. Returns the buffer, or NULL if the "
			+ "slot is empty/has no thumbnail."),
		new NamedFunction(0x21afdL, "copy_save_chunk_to_file",
			"[savegame] File-copy helper used in the save bundling/extraction path: opens a game-path file for write "
			+ "and streams EBX bytes from the source handle (ECX) into it via dos_read_items -> dos_write_items "
			+ "(e.g. extracting the bundled raw-state TLV chunk 0x0c out to a .TMP, or folding a .TMP in). Returns "
			+ "0 on success."),
		new NamedFunction(0x240d7L, "draw_active_ui_panels",
			"[UI] Per-frame composite of the two active UI panels: refreshes (FUN_2250e) then, for each present "
			+ "panel handle (DAT_83d78 with dirty flag DAT_83e80 -> render_ui_texture_panel; DAT_83d6c with DAT_83e7c "
			+ "-> FUN_235fe), draws its background + content (FUN_23897 / FUN_23cff). The HUD/overlay panel renderer."),
		new NamedFunction(0x1c0b1L, "format_inventory_item_label",
			"[UI/inventory] Builds the inventory item label string (DAT_8105e) as \"<name> (<count>)\" (format "
			+ "\"%s (%D)\" @0x75e2c): resolves the item's name text from g_dbase100_inventory_table[param_1] (or "
			+ "FUN_1a028 override) via read_next_dialogue_line, and appends param_2 = the stack count. Caches the last "
			+ "(item,count) in DAT_811a4/811a8 and returns 0 (unchanged) / 1 (rebuilt). Drives the item tooltip/label."),
		new NamedFunction(0x1dc02L, "execute_dialogue_branch",
			"[dialogue] Executes the param_1-th branch of the active dbase100 dialogue record (DAT_81ea2, opcode "
			+ "count DAT_81ea6). Walks the record tracking block nesting via the per-op high byte (op>>0x18): 8 = "
			+ "open block (depth++), 9 = close block (depth--); when the target branch's block closes at depth 0 it "
			+ "runs that branch via execute_dbase100_chain + finish_dialogue_record_eval. The choice/branch selector "
			+ "behind a picked dialogue option."),
		new NamedFunction(0x21879L, "write_raw_state_temp",
			"[savegame] Pre-save step run by write_savegame_file: builds the path for the current level's raw-state "
			+ "file, sets its extension to \"TMP\" (0x504d54) and writes the live raw world-state out via "
			+ "write_raw_state_stream — a temp snapshot of the persistent state folded into the save."),
		new NamedFunction(0x26349L, "prompt_save_overwrite",
			"[savegame UI] Shows the 'overwrite existing save?' confirmation message box (show_message_box on string "
			+ "0x71cad, flags 0x200) and returns the user's choice; write_savegame_file proceeds only if it returns 1."),
		new NamedFunction(0x1ffb7L, "play_screen_slide_in",
			"[UI/transition] Animated screen SLIDE-IN transition: snapshots the current framebuffer geometry "
			+ "(g_framebuffer_ptr/g_screen_pitch/g_screen_height/0x90bcc), clears via mem_fill, then time-steps "
			+ "(g_frame_time_scale=2) a slide of the new screen image (param_2) into view, driving the music "
			+ "(emit_music_sequence_event) and presenting each frame (add_dirty_rect/flush_dirty_rects/flip_video_page). "
			+ "Direction state DAT_83c4c. Paired with play_screen_slide_out (0x20134). [in/out hedged.]"),
		new NamedFunction(0x20134L, "play_screen_slide_out",
			"[UI/transition] Animated screen SLIDE-OUT transition: the partner of play_screen_slide_in (0x1ffb7) — "
			+ "same framebuffer-snapshot + timed-slide + music-step + dirty-rect-present machinery, but finalizes the "
			+ "audio sequence (finalize_audio_sequence_ref) and advances the DAT_83c4c state toward done. Uses the "
			+ "0x83c64/0x83c68 transition param block. [in/out hedged — confirm via caller.]"),
		new NamedFunction(0x2c5c5L, "decode_das_anim_frame",
			"[DAS/animation] Decodes a specific frame of an animated DAS sprite/texture and caches it. EAX=frame "
			+ "index, EDX=DAS record. If the record's cached frame (u16[+0x18]) already == index, returns the cached "
			+ "decoded buffer (*[+0x10]); else seeks to frame `index` in the frame table (stride [+6]), zero-fills the "
			+ "output (*[+0x10]+0x10) and ByteRun1-RLE-decodes the frame pixels (byte<0xf1 literal, >=0xf1 repeats the "
			+ "next byte (b+0x10) times) honoring per-row width/offset clipping. Stores the frame in "
			+ "g_current_decoded_frame (0x84944). The resolver behind select_surface_anim_frame (0x2b5ea)."),
		new NamedFunction(0x2fd6bL, "close_das_file_handle",
			"[DAS/OS] Atomically clears g_das_file_handle (LOCK xchg to 0) and, if it was open, closes it via DOS "
			+ "INT 21h (AH=3Eh). Releases the DAS resource file."),
		new NamedFunction(0x2f6e6L, "init_loaded_map_state",
			"[map load] Post-map-load runtime init: once both raw-state buffers are present "
			+ "(g_raw_state_primary_buffer / g_raw_state_secondary_buffer), runs the raw-state init (0x4f1a0) then "
			+ "setup_sfx_nodes. Called at startup + level transitions (0x101d5/0x110ff/0x21960)."),
		new NamedFunction(0x4366dL, "crt_int21_dispatch",
			"[Watcom CRT / OS — host-mapped] Thin INT 21h call gate that picks the real-mode vs DPMI calling path by "
			+ "g_crt_memory_mode (1..8 = protected: passes 4; else real). Watcom runtime DOS-call plumbing — recomp "
			+ "maps to the host, does not lift. (Resolves a previously-deferred frontier item.)"),
		new NamedFunction(0x4369aL, "crt_dos_vector_op",
			"[Watcom CRT / OS — host-mapped] DOS interrupt-vector get/set via INT 21h, mode-gated by g_crt_memory_mode: "
			+ "protected (2..8) issues AX=2502h (set-vector), else AH=35h (get-vector) with AL=param vector number. "
			+ "Watcom signal/exception vector hook plumbing — host-mapped, not lifted."),
		new NamedFunction(0x2b298L, "build_secondary_surface_list",
			"[renderer scene] Collects the deferred/secondary surfaces (doors/portals/translucent — the parked "
			+ "mirror/reflection candidates) for a second render pass: walks the per-sector worklist (ESI-relative "
			+ "into g_door_worklist), copying each entry into g_secondary_surface_list (stride 0x10) up to "
			+ "g_secondary_surface_count max 0x40, and sets g_has_secondary_surfaces=0xff (+ snapshots g_view_bound_right "
			+ "into 0x85314/0x85316) if any were found. Called from render_world_scene (0x290f5/0x2b0a8)."),
		new NamedFunction(0x2b5eaL, "select_surface_anim_frame",
			"[renderer/animation] Picks the current animation frame for an animated surface (param=surface record). "
			+ "By the surface flag byte[+9] (bit1/bit2) it reads a frame index from byte[+0xc] into the primary/"
			+ "secondary state tables (0x91e08 / 0x90fe8), divides by the surface's frame period (u16[+0x14]); the "
			+ "fallback path derives the frame from the global anim timer (DAT_8532a & 0x7fff) / period / frame count "
			+ "(u16[+0x22]). Resolves the frame via FUN_0002c5c5 and, on a frame change (vs DAT_84944), invalidates "
			+ "the cached entry (0xffff) + refresh_moved_das_cache_block. Drives scrolling/animated wall textures."),
		new NamedFunction(0x2a446L, "insert_depth_sorted_surface",
			"[renderer scene] Inserts a render surface node (EDI) into the per-sector depth-sorted worklist "
			+ "(g_door_worklist-relative, head in FS:[sector+...]): keeps the list ordered by depth (node[1]+4), "
			+ "walking until the insertion point, then splices. Sets node[2]=g_view_bound_right. Bounds-checked vs "
			+ "0x84990. Builds the back-to-front draw order for a sector's surfaces."),
		new NamedFunction(0x29dcfL, "transform_sector_objects_to_view",
			"[renderer scene] Walks a sector's object/sprite linked list (param), and for each visible node "
			+ "(sub-object [+1] with [+4]!=0, flag byte[+0xf] bit0 clear) transforms its world position "
			+ "([+2]+g_view_offset_x, [+0xa]+g_view_offset_y) through rotate_point_2d; if the resulting depth>0xfff it "
			+ "fills a render record (view X/depth, g_view_clip_plane, +0x12=1) and enqueues it via FUN_0002a4d0. The "
			+ "per-sector sprite/object projection + visibility cull."),
		new NamedFunction(0x2a7afL, "traverse_sectors_recursive",
			"[renderer scene] Depth-limited recursive portal flood that builds the sector visit order: from a sector "
			+ "(FS:EBX) walks its edges/portals (FS:[EBX+6] chain), and for each neighbor (FS:[edge+8]) not already "
			+ "visited (flag u16[+0x12] bit 0x10) recurses while the depth counter DAT_85300 < 0x32; then marks this "
			+ "sector visited (u16[+0x1a] |= 0x10) and appends it (FS:[EDI]=EBX). Companion to walk_visible_sectors."),
		new NamedFunction(0x2fb49L, "build_scanline_dest_offset_table",
			"[renderer/video] Builds g_scanline_dest_offset_table (0x854a8): dword[y] = y * g_screen_pitch (0x85498) "
			+ "for y in 0..g_screen_height(0x8549c), giving each scanline's framebuffer byte offset. Then seeds the "
			+ "wall span driver (patch_span_mapper_pitch 0x36464) and floor/ceil driver (call 0x3a848) with the pitch. "
			+ "Re-run on resolution change; read by all three span drivers. See lift_handoffs/3b1c1_floorceil_edge_walker.md."),
		new NamedFunction(0x36464L, "patch_span_mapper_pitch",
			"[renderer SMC — disasm-verified; called by build_scanline_dest_offset_table 0x2fb49] Self-modifying-code "
			+ "patcher: writes the framebuffer ROW PITCH (param_1) into the ~70 `add edi,<pitch>` scanline-advance "
			+ "immediates spread across EVERY wall span mapper (code region 0x37c60-0x39588), and 2x pitch into the ~24 "
			+ "line-doubled (hires) sites. Re-run whenever the pitch/resolution changes. RECOMP: model as the span "
			+ "drivers reading a g_screen_pitch register, NOT code-poking; complements lift_handoffs/"
			+ "wall_mappers_SMC_and_classification.md (this is the dest-stride layer those mappers were missing)."),
		new NamedFunction(0x39fc0L, "fill_span_solid",
			"[renderer span — disasm-verified; called by draw_scaled_sprite_spans + render_world_span_39e52] Fills a run "
			+ "of the destination scanline with the constant g_das_palette_remap_prefix (word, odd-start/odd-end handled "
			+ "as bytes), then tail-calls render_world_span_39e52 to continue. The solid-colour span fill (e.g. a fully "
			+ "remapped/flat sprite span). Register-context (EDI=dest, ECX=count)."),
		new NamedFunction(0x39093L, "invoke_span_callback",
			"[renderer span — disasm-verified; called by emit_world_face_span / rasterize_world_span] If the optional "
			+ "span hook g_span_callback (0x90a34) is set, calls it with the column/span index (BX); else no-op. A "
			+ "per-span post-process/debug hook seam."),
		new NamedFunction(0x3f0e0L, "collide_point_walls_recursive",
			"[collision] Point-test variant of wall collision (sibling of the swept collide_ray_walls_recursive "
			+ "0x3fae0; selected by prepare_sector_wall_collision 0x3ef6x when NOT in swept-step mode). Flood-walks "
			+ "the sector portal graph from the current sector (unaff_SI) using the visited-sector stack "
			+ "(g_collision_sector_stack 0x8c194, count 0x8c192, max depth 30, with dedup), testing the point against "
			+ "each sector's walls (count byte[sector+0xd], wall-array u16[sector+0xe]; neighbor u16[wall+4]==0xffff = "
			+ "solid) and writing results back through the caller's EBP state array."),

		// --- Dirty-rectangle screen-update subsystem (2026-06-17, COVERAGE Queue A 0x15dd9/0x15b69) ---
		// How ROTH presents frames: instead of blitting the whole screen, every draw marks its region
		// dirty (add_dirty_rect), then once per frame flush_dirty_rects blits only the changed rects.
		new NamedFunction(0x15b69L, "add_dirty_rect",
			"[SCREEN] Adds a rectangle to the dirty-region list (g_dirty_rects 0x7f580, stride 0x10 = "
			+ "left@+0/top@+4/right@+8/bottom@+0xc; count g_dirty_rect_count 0x7f57c, MAX 0x40). ABI: EAX=left, "
			+ "EDX=top, EBX=right, ECX=bottom. 8-pixel-aligns the x edges and clamps to screen (g_screen_pitch "
			+ "0x85498 x g_screen_height 0x854a0). RECURSIVE split/merge: when the new rect overlaps an existing "
			+ "one it splits itself into disjoint strips (recursing on the top/bottom remainders) so the list "
			+ "stays non-overlapping. Called by every draw path (17 callers) — the universal 'mark this region "
			+ "changed' primitive."),
		new NamedFunction(0x15dd9L, "flush_dirty_rects",
			"[SCREEN] Per-frame screen present (stdcall, no args; COVERAGE Queue A top, 13 callers). Runs the "
			+ "pre-flush hook flush_predraw_hook (0x3cf19) if g_flush_predraw_flag (0x90c04); snapshots the "
			+ "current dirty list; in buffered mode also re-adds LAST frame's rects (g_prev_dirty_rects 0x7f984 / "
			+ "g_prev_dirty_rect_count 0x7f980) so the double buffer also repaints what changed last frame; "
			+ "blits all rects via blit_dirty_rect_list (0x2dd85); resets g_dirty_rect_count=0; then rotates this "
			+ "frame's list into g_prev_dirty_rects for next frame. Raw-screen mode just blits + resets."),
		new NamedFunction(0x2dd85L, "blit_dirty_rect_list",
			"[SCREEN] Blits a list of dirty rects to the visible screen. EAX = rect array (stride 0x10), EDX = "
			+ "count; per rect reads left/top/right/bottom (+0/+4/+8/+0xc) and calls blit_screen_rect (0x2dddd) "
			+ "to copy that region (back buffer -> VGA). Brackets g_screen_busy_depth (0x7e8c8, inc on entry / "
			+ "dec on exit); clears the blit guard 0x85434."),
		new NamedFunction(0x2ddddL, "blit_screen_rect",
			"[SCREEN] Copies one screen rectangle (EAX=left, EDX=top, EBX=right, ECX=bottom) from the back "
			+ "buffer to the visible framebuffer. Re-entrancy-guarded by 0x85434. The per-rect leaf of "
			+ "blit_dirty_rect_list."),
		new NamedFunction(0x3cf19L, "flush_predraw_hook",
			"[SCREEN] Deferred-screenshot hook called at the top of flush_dirty_rects when g_flush_predraw_flag "
			+ "(0x90c04) is set: runs 0x3cc01 (a no-op ret stub) then save_snapshot_file (0x3cc02), which writes "
			+ "the queued 'B'-key screenshot as an IFF/ILBM-PBM file (FORM/PBM/BMHD/CMAP/BODY, inline INT 21h "
			+ "AH=0x41 delete + AH=0x40 write) so it captures the composited frame, then clears the flag. (The "
			+ "add_dirty_rect inside 0x3cc02 is post-save repaint cleanup, NOT the function's purpose.)"),

		// --- Queue A batch: cursor / entity-sound / door-gather (2026-06-17) ---
		new NamedFunction(0x12a08L, "set_cursor_shape",
			"[CURSOR] Selects + loads the mouse pointer graphic by resource id (EAX = one of 0x248/0x258/"
			+ "0x250/0x260 = slot offsets into the resource directory g_reloc_base 0x7f56c). If the UI/context "
			+ "flag byte[0x90bcc] & 0x10 is set, remaps the id to its alternate (0x3a8/0x3b8/0x3b0/0x3c0) and "
			+ "sets g_cursor_changed (0x7f250) when the shape actually changes (skips reload if unchanged via "
			+ "g_current_cursor_id 0x708e4). Decodes the sprite (w=rec[4], h=rec[6], pixels follow; RLE if "
			+ "rec[0]&1) into g_cursor_sprite (0x7e950: w@+0,h@+1,pixels@+2) + render state 0x7e93c..0x7e94c "
			+ "(aux/hotspot rec[2]/rec[3], color key 0x708e6). Returns the resolved id. Callers: game_play_loop, "
			+ "show_message_box (set the pointer per context)."),
		new NamedFunction(0x271c4L, "play_entity_sound",
			"[SFX] Gated thin wrapper for entity/attack/projectile sounds: if g_sound_enabled (0x7f550), sets "
			+ "g_pending_sound_param (0x84906)=0x20 and plays a positional sound via play_object_sound (0x270ca) "
			+ "bound to the shared entity emitter g_entity_sound_emitter (0x83eb0). P3 (short) = sound id. Called "
			+ "by tick_dynamic_entities, init_projectile_from_item, begin_enemy_attack (the monster-attack SFX)."),
		new NamedFunction(0x3f93bL, "gather_nearby_doors",
			"[COLLISION] Collects the doors in the player's sector + its portal-adjacent sectors into the work "
			+ "list g_door_worklist (0x8498c) as {tag=1, door} pairs. From g_player_sector: if the sector flag "
			+ "byte (g_raw_state_primary_buffer +0x16+sector) & 1, enumerate its doors via find_door_by_sector "
			+ "(0x3cfcc) + find_next_door (0x3cff6); &2 -> collect_doors_near_query (0x3fa62); then walks the sector's walls (count @+0xe), "
			+ "crosses each portal (wall+8 = neighbour sector) and repeats for neighbours. Called by the "
			+ "collision pass (resolve_collisions_in_sector, collide_ray_*) so dynamic door geometry is gathered "
			+ "for collision/proximity each step."),
		new NamedFunction(0x3fa62L, "collect_doors_near_query",
			"[collision spatial query — disasm-verified; called by gather_nearby_doors 0x3f93b for sector-flag bit2] "
			+ "Scans the secondary-buffer door-record list for the sector (g_raw_state_secondary_buffer, record found "
			+ "via (EBX - word[ESI+4])/0xd + 2; entries stride 8) and appends each ENABLED door (flag bytes +7 & +9 "
			+ "both clear of 0x82) whose Chebyshev distance (max|dx|,|dy|) from g_locate_query_x/y is < 0x121 to the "
			+ "output list (EDI, as {0, record} pairs). The secondary-door counterpart of the find_door_by_sector path. "
			+ "Register-context (ESI/EDI/EBX)."),
		new NamedFunction(0x3cff6L, "find_next_door",
			"[GEOM] Iterator continuation of find_door_by_sector (0x3cfcc): returns the next door record in the "
			+ "current sector's door chain (0 when exhausted). Used by gather_nearby_doors."),
		new NamedFunction(0x11ca9L, "begin_screen_draw",
			"[SCREEN] Enters a screen draw/update section: bumps g_screen_busy_depth (0x7e8c8) and preps the two "
			+ "screen-save buffers (0x76898, 0x7a8a4) via 0x11cd2. Pairs with end_screen_draw (0x11cc6). Callers "
			+ "include roth_main_sequence, show_message_box."),
		new NamedFunction(0x11cc6L, "end_screen_draw",
			"[SCREEN] Exits a screen draw/update section: decrements g_screen_busy_depth (0x7e8c8) and runs the "
			+ "matching teardown 0x116aa. Pair of begin_screen_draw (0x11ca9)."),
		new NamedFunction(0x11faeL, "poll_mouse_input",
			"[INPUT] Per-frame mouse poll via INT 33h function 3 (get button state + position). Applies the "
			+ "button-swap (g_mouse_button_swap): accumulates pressed buttons into g_mouse_buttons_held "
			+ "(0x7e928), and on a button PRESS edge (vs g_mouse_buttons_prev 0x7e929) sets the action flags "
			+ "g_cursor_primary_action_flag (0x7e938, left) / g_cursor_secondary_action_flag (0x7e939, right) = "
			+ "0xff and records the edge in g_mouse_click_edges (0x7e93a). Cursor position lands in g_mouse_x/y. "
			+ "Called from player_movement_tick + the menu loops."),
		new NamedFunction(0x115eaL, "blit_scaled_sprite_at_mouse",
			"[CURSOR] Composites a scaled sprite anchored to the mouse position (the cursor draw + similar UI "
			+ "overlays). EAX = descriptor {src ptr@0, @1, w@2, h@3, scale@4}; stages src/size (w*scale, h*scale) "
			+ "+ a clip sentinel (0x76890), computes the mouse-relative dest (g_mouse_x*scale - extent), brackets "
			+ "g_screen_busy_depth, then blits via 0x117db. Called by set_cursor_shape (draw the loaded pointer) "
			+ "+ other UI."),
		new NamedFunction(0x1bf7bL, "refresh_inventory_panel",
			"[INVENTORY] Redraws the inventory panel after a state change: marks it dirty (0x7f571|=2), rebuilds "
			+ "the entry list (build_inventory_entry_list) + grid (refresh_inventory_grid), draws the panel chrome "
			+ "tiles (draw_panel_slot_tile 10/0xb), draws the LEFT equipped-item icon via draw_equipped_item_left "
			+ "(0x1a2ef), and draws the RIGHT equipped item (g_displayed_item_right 0x81040) via blit_item_icon "
			+ "(0x13544) at panel-anchor +0x59. Callers: update_inventory_screen, use_item_on_self, "
			+ "combine_held_item_with_target."),
		new NamedFunction(0x1a2efL, "draw_equipped_item_left",
			"[INVENTORY] Draws the LEFT equipped/hand item icon on the inventory panel: if g_displayed_item_left "
			+ "(0x81034) is set, centers + blits its DAS icon (blit_item_icon 0x13544) at panel-anchor +0x3a, "
			+ "shaded with g_default_message_color. Called by refresh_inventory_panel + others."),
		new NamedFunction(0x13544L, "blit_item_icon",
			"[UI] Blits a DAS item/UI icon sprite (record: width@+4, height@+6) to a framebuffer destination ptr. "
			+ "EAX=record, EDX=dest (from screen_xy_to_framebuffer_ptr, which also carries the hi-res scale + a "
			+ "shade-row in the high byte). The shared icon renderer for inventory slots + equipped-item draws "
			+ "(draw_item_icon_in_slot, draw_equipped_item_left, refresh_inventory_panel)."),
		new NamedFunction(0x12ddeL, "blit_clipped_sprite_smc",
			"[RENDER — SELF-MODIFYING] Clipped sprite/region blit: patches g_screen_pitch into its own inner-loop "
			+ "immediates (the iRam 0x12fxx code-scratch writes; hi-res doubles the stride) then copies the source "
			+ "with top/bottom clipping vs g_screen_height (0x8549c). Used by render_inspect_popup_window, "
			+ "render_inventory_panel, draw_item_icon_in_slot. (One of the texture-mapper-style SMC sites — see "
			+ "recomp RENDERER_SMC_TRIAGE: the patched immediates are ephemeral, observable output is faithful.)"),
		new NamedFunction(0x1f71dL, "update_dialogue_choice_highlight",
			"[DIALOGUE] Syncs the highlighted dialogue choice / subtitle line to the input/playback position "
			+ "(param_1+param_2). Only while a dialogue line is active (g_dialogue_busy_flag) and the move "
			+ "freeze gate is engaged (g_move_freeze_gate==0x6ffff). Walks the g_dialogue_segments list (stride 5, "
			+ "count g_active_dialogue_context), writing the highlight char (0x83139) into the active segment; "
			+ "resets g_choice_selected_index when the position changes (0x83b16 = last pos). Called by "
			+ "run_gameplay_frame + dialogue_voice_force_end."),
		new NamedFunction(0x27207L, "play_world_sound_at_pos",
			"[SFX] Plays a positional world sound (e.g. doors) at a map position. EAX = ptr to {x,y}; gated on "
			+ "g_sound_enabled; sets g_pending_sound_param=0x20, computes the squared distance from the player "
			+ "origin (0x90a8c/0x90a94 >> 16), and plays via play_sound_unique (0x273f0, dedup so a looping "
			+ "emitter doesn't restart). Callers: alloc_door_record + door triggers."),
		new NamedFunction(0x2e0cbL, "set_vesa_bank",
			"[VIDEO/OS] Sets the VESA display window/bank via INT 10h AX=4F05h (Display Window Control) when "
			+ "g_vesa_available (0x71dcc); param_2 = bank number, cached in g_current_vesa_bank (0x71dc6, only "
			+ "re-banks on change). Falls back to a plain INT 10h otherwise. Used for banked hi-res framebuffer "
			+ "access. (OS-surface; host replaces with a flat framebuffer.)"),
		new NamedFunction(0x114d4L, "dos_print_char",
			"[OS] Prints a single character (low byte of EAX) to stdout via INT 21h AH=09h, building a 2-byte "
			+ "{char,'$'} DOS string on the stack. Used by the menu/save text paths."),
		new NamedFunction(0x1555fL, "emit_music_sequence_event",
			"[AUDIO] Thin wrapper: forwards to emit_audio_sequence_event (0x4627d) on the music sequence ctx "
			+ "g_audio_sequence_ctx (0x7f444). (decomp C shows the stale name 'g_information_chunk_ctx' for "
			+ "0x7f444 — the script renames it.) Called from cutscene/menu code (0x20xxx)."),
		new NamedFunction(0x26b4cL, "free_resource_chunk",
			"[POOL] Frees a chunk from the resource Pool g_resource_pool (0x85c40) via pool_free_chunk. Called "
			+ "by load_sound_sample, flush_object_das_handles, 0x279e4 (DAS/resource teardown). Alloc sibling at "
			+ "0x26b38."),
		new NamedFunction(0x117dbL, "poll_mouse_motion",
			"[INPUT] Reads relative mouse motion via INT 33h function 0xB. If g_mouse_relative_mode (0x7e8d0) "
			+ "(mouselook) is set, accumulates the deltas into g_mouse_dx/g_mouse_dy (camera look) and returns; "
			+ "otherwise advances the software-cursor position (motion*0x20 + offsets, clamped to screen extents "
			+ "0x7e8b0). The motion half of the mouse (poll_mouse_input 0x11fae is the button half)."),
		new NamedFunction(0x116b6L, "update_software_cursor",
			"[CURSOR] Per-frame software-cursor maintenance (guarded by g_screen_busy_depth==0): polls motion "
			+ "(poll_mouse_motion), and if the cursor moved (vs g_cursor_prev_x/y 0x76890/0x76894) erases the old "
			+ "cursor + redraws it at the new spot (raw vs buffered path). Keeps the OS-less software pointer in "
			+ "sync with the mouse."),
		new NamedFunction(0x116aaL, "force_cursor_redraw",
			"[CURSOR] Forces a software-cursor redraw: writes the move-sentinel (g_cursor_prev_x=0xffffff81) so "
			+ "update_software_cursor (0x116b6) always treats the cursor as moved. Called by end_screen_draw + "
			+ "play_record_gdv_cutscene (repaint the pointer after the screen changed)."),
		new NamedFunction(0x11ce1L, "blit_software_cursor",
			"[CURSOR] Composites (or restores) the software mouse-cursor sprite onto the screen, handling VESA "
			+ "bank switching (g_current_vesa_bank) and the raw vs buffered screen modes. The actual cursor "
			+ "pixel blit, invoked via restore_cursor_region_if_set (0x11cd2)."),
		new NamedFunction(0x11cd2L, "restore_cursor_region_if_set",
			"[CURSOR] If the saved cursor-background buffer (*EAX) is allocated, calls blit_software_cursor "
			+ "(0x11ce1) to restore/erase it. Called by begin_screen_draw on the two cursor-save buffers "
			+ "(0x76898, 0x7a8a4) to hide the pointer before drawing."),
		new NamedFunction(0x1a7a1L, "close_inventory_panel",
			"[INVENTORY] Tears down the inventory overlay (unless an inspect popup is active): clears the held "
			+ "cursor item, and on the dirty bits g_inventory_dirty_flags (0x7f571) frees the panel's cached DAS "
			+ "handles (g_ui_panel_scratch_handle, 0x811b0) + marks their region dirty; UNFREEZES the player "
			+ "(g_player_movement_enabled=1); refreshes the selected-item icon; clears the weapon-HUD cache via "
			+ "render_weapon_hud (0x24165, &g_active_weapon_attrs); and clears the cursor action flags. Callers: "
			+ "update_inventory_screen, update_ui_overlay."),
		new NamedFunction(0x1d0fdL, "consume_held_item",
			"[INVENTORY] Removes a specific item (EAX = item-id ptr) from the inventory: resolves its DBASE100 "
			+ "record (g_dbase100_inventory_table[id] + g_dbase100_base), calls remove_inventory_item, then "
			+ "rebuild_weapon_inventory_list; returns 1 if removed, 0 if absent/empty. The use/combine consume "
			+ "path (callers: use_item_on_self, combine_held_item_with_target). Record-resolving sibling of "
			+ "remove_item (0x1d077)."),
		new NamedFunction(0x4c334L, "write_vga_palette",
			"[VIDEO/OS] Writes param_3 palette entries (RGB byte triples from EDX) to the VGA DAC starting at "
			+ "index 0 via out 0x3c8 (write index) + out 0x3c9 x3 (R,G,B). Gated on g_palette_dirty (0x91de6) and "
			+ "an optional retrace-wait callback (0x91d00). (OS-surface; host maps to an SDL palette update.)"),
		new NamedFunction(0x24165L, "render_weapon_hud",
			"[HUD — name inferred from callers] Renders the on-screen weapon HUD element from an attrs struct "
			+ "(param_2 = &g_active_weapon_attrs); manages a DAS-cache-backed region (free/realloc 0x83d74) with a "
			+ "16-frame animation counter (attrs+0x48) and registers its dirty rect (add_dirty_rect / "
			+ "register_dirty_rect, hi-res aware via g_screen_pitch==0x280). Called per-frame by game_play_loop "
			+ "and on inventory close (close_inventory_panel passes the weapon attrs to clear it). 601B; the "
			+ "frame-stepping detail (0x22633, region globals 0x83e1c/0x83e20/0x83e28) is not fully traced."),
		new NamedFunction(0x1f8cbL, "show_no_ammo_message",
			"[UI] Flashes the \"No ammo\" on-screen message (text id 0x1f8 -> DBASE400.DAT, author+file "
			+ "confirmed): resolve_dbase100_text -> layout_timed_message_text (into g_timed_message_lines/"
			+ "g_timed_message_text_buffer, width g_screen_pitch) -> g_timed_message_line_count, and arms "
			+ "g_timed_message_timer = 0x46 frames. Primary caller: trigger_weapon_fire (firing with empty ammo). "
			+ "(0x1f8 is fixed, so this always shows \"No ammo\".)"),
		new NamedFunction(0x156bdL, "service_audio_sequence",
			"[AUDIO] Per-frame service of the music sequence: when g_audio_sequence_progress (0x7f468) & 7 == 7 "
			+ "and the sequence is ready (0x476fd on g_audio_sequence_ctx 0x7f444 returns 0/nonzero gate), runs "
			+ "0x46da7 + 0x46eb3 + step_audio_sequence (0x46d18) to advance it. Callers: game_play_loop, "
			+ "show_message_box."),
		new NamedFunction(0x15689L, "finalize_audio_sequence_ref",
			"[AUDIO] Thin wrapper (from finalize_dbase100_chain / execute_dbase100_chain): loads the music "
			+ "sequence ctx (g_audio_sequence_ctx 0x7f444), decrements g_audio_sequence_pending (0x7f474), and "
			+ "tail-calls the sequence op 0x45f1d — releases/finalizes a pending audio sequence started by a "
			+ "command chain."),
		new NamedFunction(0x20c16L, "play_record_gdv_cutscene",
			"[CUTSCENE] CORRECTED (was mislabeled prepare_message_box): plays the FMV cutscene named by a story/dialogue "
			+ "record (EAX=record; non-empty name). Registers the record in the PLAYBACK GALLERY (if rec[0x13]==0, stamps "
			+ "the next playback index into rec+0x10 high byte + bumps g_cutscenes_seen_count) so it appears in "
			+ "show_cutscene_playback_menu; saves the framebuffer into g_screen_backup_handle for restore; loads the "
			+ "record's caption/voice resource (24-bit offset @rec+0x10, size @rec+0xa) into g_message_resource_handle; "
			+ "freezes the player + wait cursor; then builds '<g_dir_gdv><name>.GDV' (set_filename_extension 'GDV' 0x564447) "
			+ "and calls play_gdv_cutscene (0x2059d). Callers: execute_dbase100_chain (a play-cutscene command), "
			+ "show_message_box (a selected playback entry)."),
		new NamedFunction(0x42400L, "spawn_projectile_from_aim",
			"[trace-confirmed: fire-only] Converts the screen-space aim (pitch coord param_2 + yaw coord in EBX) into a fixed-point pitch angle (clamp/curve table 0x423c5, 0x3a entries) and vertical offset, scaled by the hi-res line-doubling flag; calls init_inventory_item_object(0x18598) to build the projectile template, then spawn_entity_at_position(0x4254e) at the muzzle origin (0x90a8c/0x90a94). Initialises the new projectile entity's fields (clears +8, sets active bit, stores pitch +0x1a, weapon-def ref +0x14, etc.) and returns it. Register-context (EBX yaw)."),
		new NamedFunction(0x17629L, "arm_weapon_fire",
			"[trace-confirmed: fire-only] Small weapon fire-state-machine transition called by trigger_weapon_fire (and 0x17668) once a shot is committed: clears 0x7fdf0; if the fire state 0x7fddc==0 resets the fire timer/ammo 0x7fde0=100, advances state {0,1}->2 (firing). Register-context (params dropped in decomp)."),
		new NamedFunction(0x22760L, "clear_buffer_rows",
			"[trace-confirmed: fire-only] Zeros a vertical strip of the render buffer: starting at base+row*stride+col, mem_fill(row,0) for param_5 rows advancing by the stride param_3. Used by render_weapon_view to clear the weapon viewport before compositing. Register-context (start row in EBX)."),
		new NamedFunction(0x13be0L, "blit_transparent_sprite_clipped",
			"[trace-confirmed: fire-only] Column-table-driven TRANSPARENT (skip-zero) sprite blitter with horizontal+vertical clipping: walks a per-element run table (EBX = {u16 dest-offset, u16 advance}), copies non-zero source bytes (transparent pixels skipped) into dest with left/right clip vs the clip bounds (EBP[0]/EBP[4]), advancing dest by g_screen_pitch each of param_2 rows. Draws the muzzle-flash / projectile sprite. Register-context."),
		new NamedFunction(0x3e351L, "sweep_move_with_collision",
			"[trace-confirmed: fire-isolated (player stationary -> only the projectile moved)] Top-level SWEPT-MOVE collision query: moves an entity (EBX) by a velocity vector (param_1/param_2 + EBP), substepping the move (1/3/7 substeps chosen by distance thresholds 0xb/0x17/0x2f) and calling probe_collision_step(0x3eb90) per substep until a hit. Saves/restores g_player_sector, seeds the g_locate_query_x/y/z + radius/bound globals (0x8c130..0x8c144), then writes the resolved position/sector + hit-flag (g_collision_hit_flags) into the result struct param_3 and back into the entity. Used by both player movement and projectiles. Register-context."),
		new NamedFunction(0x3eb90L, "probe_collision_step",
			"[trace-confirmed: fire-isolated] One collision probe substep for sweep_move_with_collision: resets the probe state, runs the in-sector test 0x3ec5a, and if no hit and still in a sector crosses the portal via 0x3ec40 to the next sector; on failure sets g_collision_hit_flags bit0 and restores the saved query position/sector. Register-context (__stdcall stub)."),
		new NamedFunction(0x3fae0L, "collide_ray_walls_recursive",
			"[trace-confirmed: fire-isolated] Recursive sector-portal WALL collision for the swept ray: maintains a visited-sector stack (0x8c192 count / 0x8c194 list, max 0x1e) with dedup, walks the current sector's wall/portal records (stride 6 shorts), bounding-box rejects against the swept extents (0x8c130/0x8c134), does the line-segment crossing + perpendicular-distance-squared test, and on a solid wall hit clamps the position back (0x90ab4/0x90ab8) and sets g_collision_hit_flags bit0; recurses through portals into adjacent sectors. Register-context (EBP = ray state, SI = sector)."),
		new NamedFunction(0x4066fL, "collide_ray_entities",
			"[trace-confirmed: fire-isolated] ENTITY/object-list half of the swept collision: iterates the collision object list (g_door_worklist, count g_collision_entity_count), and for each tests the query position against the object's radius/height from g_das_collision_buffer (per-sprite collision dims, 4 bytes/entry) and z-range; on a blocking hit sets g_collision_hit_flags bit1 and records the hit entity in g_collision_hit_entity (0x8c0f4), distinguishing pass-through vs blocking flags. Register-context (EBP = ray state)."),
		new NamedFunction(0x405f6L, "test_ray_reached_target",
			"[trace-confirmed: fire-isolated] Destination/target hit-test along the swept ray (called from the in-sector dispatcher 0x3eeb0 alongside collide_ray_entities): if a target is active (0x8c0f0), tests whether the query position is within radius 0x8c0ec (max|dx|,|dy|) and the z-band [target_z, target_z+g_player_height+10] of the target point (0x90a8c/0x90a90/0x90a94); on match sets g_collision_hit_flags bit1 and clears the hit entity."),
		new NamedFunction(0x22e7bL, "render_weapon_view",
			"Renders the first-person weapon-view sprite: reads the active-weapon display state (g_active_weapon_attrs-derived 0x83e70/0x83e74/0x83d78/0x83d7c set by activate_weapon_item) and resolves+blits the weapon's DAS frames via resolve_reloc_ptr / blit_das_image_to_buffer / draw_ui_panel_image_block (two 1000B sprite-composite scratch buffers). On the HUD render chain 0x1691c -> 0x1768a; animates during firing."),
		new NamedFunction(0x4222bL, "relocate_sector_object_offsets",
			"[trace-confirmed weapon-fire/spawn path] On inserting a new object record into the GS-segment per-sector object lists: walks all sectors and adds the size delta (param_3) to every sector's object-list offset that is >= the insertion point (param_2); marks the object table dirty (DAT_000911c5=0xff, DAT_000911c7++). Register-context (GS-relative)."),
		new NamedFunction(0x42cf9L, "rebuild_pool_a_object_pointers",
			"[trace-confirmed weapon-fire/spawn path] Rebuilds the g_state_pool_a_records back-pointers by walking every sector's object list in the GS-segment state buffer and writing each live object's address into its pool-A slot (field +0xc index). Run after the object list is mutated by a spawn. Register-context."),
		new NamedFunction(0x3b4a2L, "build_floorceil_clip_edges",
			"[renderer floor/ceil; was render_floorceil_3b4a2] The Sutherland-Hodgman polygon-clip DRIVER: when the "
			+ "polygon bbox crosses the view window (g_floorceil_clip_flags 0x8a434: low byte = horizontal, high "
			+ "byte = vertical), calls clip_one_boundary (0x3b506) once per crossed side (view bounds "
			+ "g_view_bound_right/left 0x90968/0x9096a, bottom/top 0x9096c/0x9096e), ping-ponging the vertex list "
			+ "through clip_one_boundary's twin buffers. See lift_handoffs/3b1c1_floorceil_edge_walker.md."),
		new NamedFunction(0x3b506L, "clip_one_boundary",
			"[renderer floor/ceil clip; CORRECTED 2026-06-19 per recomp — was mislabeled "
			+ "'build_floorceil_boundary_gradient'] One **Sutherland-Hodgman** clip pass: clips the input vertex list "
			+ "against a single boundary line (value g_clip_boundary 0x8a436; the polygon vertex records are the "
			+ "0x8c946-format X/Y/depth/texcoord tuples). Walks input verts (in buffer 0x8c944/0x8cb28, swapped by "
			+ "sign of BH), keeping inside verts and, on a sign change across the boundary, emitting the crossing "
			+ "vertex via emit_clip_enter_crossing (0x3b5a8) / emit_clip_leave_crossing (0x3b5c2) into the output "
			+ "list (count g_clip_output_vertex_count 0x8a3cc). NOT a gradient builder."),
		new NamedFunction(0x3b5d2L, "interpolate_clip_crossing_vertex",
			"[renderer floor/ceil clip] The crossing-vertex INTERPOLATOR for clip_one_boundary: given the edge "
			+ "(ESI=current vert, EBX=previous vert) and a parametric numerator/denominator (ECX/EBP), lerps the full "
			+ "vertex record into the output vert (EDI): screen X[0]/Y[1], depth[2] (with the 0x10 near clamp + "
			+ "perspective term in 0x8a428/0x8a42c/0x8a430/0x8a432), and the texcoords [3] (g_render_textured_flag) / "
			+ "[4][5] (g_floorceil_tex submode 0x90a23). Increments g_clip_output_vertex_count (0x8a3cc)."),
		new NamedFunction(0x3b5a8L, "emit_clip_enter_crossing",
			"[renderer floor/ceil clip] Enter-crossing emitter for clip_one_boundary: emits the vertex where an edge "
			+ "crosses INTO the clip region, computing the crossing parameter as (BP - g_clip_boundary 0x8a436) then "
			+ "delegating to interpolate_clip_crossing_vertex (0x3b5d2)."),
		new NamedFunction(0x3b5c2L, "emit_clip_leave_crossing",
			"[renderer floor/ceil clip] Leave-crossing emitter for clip_one_boundary: emits the vertex where an edge "
			+ "crosses OUT of the clip region. Computes the crossing distance (vert - g_clip_boundary 0x8a436) and "
			+ "denominator inline and interpolates the full vertex record (same field set as "
			+ "interpolate_clip_crossing_vertex 0x3b5d2)."),
		new NamedFunction(0x3b724L, "project_floorceil_edge_texcoord",
			"[renderer floor/ceil; was render_floorceil_3b724] Maps one span-edge coordinate to texture space "
			+ "(perspective): reads the vertex record (esi+0/+4), applies the projection flags g_world_surface_draw_flags "
			+ "0x9093c / 0x909ae bit 0x8000 and view origin 0x90990, near-plane-clips via g_floorceil_depth_clip_bias "
			+ "(0x90a1e), and returns the texture coord (sets g_sprite_render_mode clip bits). Called by "
			+ "interp_floorceil_edge_texcoords / store_floorceil_flat_edge_texcoords."),
		new NamedFunction(0x3b8b7L, "interp_floorceil_edge_texcoords",
			"[renderer floor/ceil; was render_floorceil_3b8b7] Per-edge texture-coordinate INTERPOLATION (textured "
			+ "path, gated on g_render_textured_flag 0x90a22). Maps both edge endpoints to texture space via "
			+ "project_floorceil_edge_texcoord, computes per-scanline steps for the tc(+2)/U(+4)/V(+6)/W(+8) span-record "
			+ "fields (half-step bias signed by g_floorceil_edge_orientation 0x8a43a), and runs the column steppers "
			+ "write_ror_ramp_3bb1e + write_floorceil_span_texcoords (0x3badf). See the handoff doc."),
		new NamedFunction(0x3badfL, "write_floorceil_span_texcoords",
			"[renderer floor/ceil] Inner stepper for interp_floorceil_edge_texcoords: walks a span-record column "
			+ "(EDI, stride EBP) writing the interpolated U(+4)=hi16(accum_a), V(+6)=hi16(param), W(+8, dword)=accum, "
			+ "each stepped by g_floorceil_step_a / 0x8a3f0 per scanline. Counterpart to write_ror_ramp_3bb1e (which "
			+ "does the +2 tc ramp)."),
		new NamedFunction(0x3b84aL, "store_floorceil_flat_edge_texcoords",
			"[renderer floor/ceil] Degenerate/vertical-edge fast path (textured): when the edge collapses to one "
			+ "scanline, copies the endpoint texcoords straight into the span-record half (+2/+4/+6/+8 left, "
			+ "+0xe/+0x10/+0x12/+0x14 right) with no per-scanline interpolation; maps +6/+0x12 via "
			+ "project_floorceil_edge_texcoord when g_render_textured_flag (0x90a22) set. Sibling of "
			+ "interp_floorceil_edge_texcoords (0x3b8b7)."),
		new NamedFunction(0x3bbb0L, "build_floorceil_vertex_records",
			"[renderer floor/ceil; was render_floorceil_3bbb0] Produces the projected-vertex record array "
			+ "g_floorceil_vertex_records (0x8c946, stride 0xc; count 0x8c944) consumed by the edge-walk: for each "
			+ "vertex copies screen XY (dword[srcvtx+0xc]) + depth (word[srcvtx+0xa]) and, in the textured path, the "
			+ "shade index (+6) and texture coords (+8/+0xa from the texture-wrap extents 0x8a410/0x8a414/0x8a418/"
			+ "0x8a41c). Keyed on g_render_textured_flag 0x90a22 / 0x90a23 and g_world_surface_draw_flags bit 0x1000. "
			+ "Record format in lift_handoffs/3b1c1_floorceil_edge_walker.md."),
		new NamedFunction(0x3bdf3L, "floorceil_rotation_sincos",
			"[floor/ceiling texmap] Computes sin and cos of the floor/ceiling texture rotation angle ([ebp+8], masked 0x1ff) from g_sincos_table (0x72080), using the +0x80-entry quarter-phase for cosine (inc bh; and bh,3). Builds the rotation for perspective floor texture mapping."),
		new NamedFunction(0x42b8cL, "init_projectile_from_item",
			"Initializes a freshly-spawned projectile/effect entity from its inventory-item template: init_inventory_item_object(item id ESI[5]) fills the sprite/flags, plays the fire SFX via play_entity_sound, sets the object's sprite id (+4), flag +7 bit0x40, state byte +2=2. On the weapon-fire path (update_dynamic_entities)."),
		new NamedFunction(0x4b1b7L, "blit_backdrop_rows",
			"load_backdrop_image inner loop: iterates output rows, calling backdrop_ensure_source_bytes 0x4b269 to decode source + blit_backdrop_row 0x4b1ee, advancing the vertical 16.16 scale accumulator. (BACKDROP.RAW decoder; see ROTH_file_formats.md.)"),
		new NamedFunction(0x4b1eeL, "blit_backdrop_row",
			"Blits one scaled output row of a BACKDROP.RAW image: straight rep-movsd copy, or per-column sample through the h-scale table (0x4b230 path) when width is scaled; steps the vertical accumulator (0x10000 per src row)."),
		new NamedFunction(0x4b269L, "backdrop_ensure_source_bytes",
			"Ensures >= the requested count of decompressed source bytes are buffered for the backdrop blit; calls backdrop_decode_rle 0x4b27d to produce more when short."),
		new NamedFunction(0x4b27dL, "backdrop_decode_rle",
			"RLE-decodes the next chunk of a BACKDROP.RAW image into the work buffer (literal if byte<0xf1, else run of (byte-0xf0) of the following byte), pulling raw bytes via backdrop_refill_buffer 0x4b30b across 4KB block boundaries."),
		new NamedFunction(0x4b30bL, "backdrop_refill_buffer",
			"Refills the BACKDROP.RAW raw-read buffer from the open file via INT 21h AH=3Fh (size [ebp+0x30] into [ebp+0x2c]); returns bytes read."),
		new NamedFunction(0x4b322L, "build_backdrop_hscale_table",
			"Builds the per-column horizontal source-x sampling table for scaling a BACKDROP.RAW image to the destination width (16.16 step = (srcW<<16 - 0x7fff)/destW)."),
		new NamedFunction(0x38697L, "render_span_fill_38697",
			"[trace-confirmed renderer hot loop, indirect-dispatched] 8-way span-fill: jmp [ebx*4 + 0x386c0] dispatches on (pixel_count & 7) into an unrolled pixel-write loop (Doom-style remainder handling). Fires for floor/ceiling AND sprite columns."),
		new NamedFunction(0x3a368L, "render_span_texmap_3a368",
			"[trace-confirmed; SELF-MODIFYING] Texture-mapped span/column inner loop that patches its texture-step/base immediates directly into its own code (writes to 0x3a409/0x3a40f/0x3a418/0x3a42c/0x3a432/0x3a43b) from the step globals 0x8a38c/0x8a390/0x8a394/0x8a360. SMC -> recomp's oracle-verified lift is authority. Indirect-dispatched; fires for floor + sprite."),
		new NamedFunction(0x39e52L, "render_world_span_39e52",
			"[trace-confirmed renderer span handler, indirect-dispatched] Actually the per-span LOOP TAIL of draw_scaled_sprite_spans (0x39610): pops the saved regs, applies the SMC guard (g_sprite_column_loop_guard 0x8a370 -= patched imm), dec cx; jg 0x39bd2 (next span) else ret at 0x39e68. Carved standalone because the inner-loop variants reach it by direct jmp. The alt branch at 0x39e69 does the swap of g_current_span_record (0x8a36c) +2<->+0xe and the 0x909a0 screen-relative span. Fires for floor + sprite."),
		new NamedFunction(0x39610L, "draw_scaled_sprite_spans",
			"[SMC affine/scaled DAS-sprite span rasterizer; entry of the 0x39603-0x39e52 region recomp asked carved] Loads gs=g_active_world_remap_selector (colormap), reads scale/sign from 0x909fe, then a render-mode ladder (g_sprite_render_mode 0x90a30 = 1/2/default x g_column_clip_mode 0x90970 x g_world_surface_draw_flags 0x9093c bit3 / 0x8a352 / 0x8a354) selects a span inner-loop and stores its code addr into g_sprite_column_fn (0x8a368). Computes the log2 texture-width shift via 'bsr bx,ax' and SMC-patches it into the inner-loop family (writes to 0x3a23b/0x3a26b/0x3a383/... = the power-of-2 src-addr mask/shift). Per-SPAN loop: setup 0x39bd2 walks a per-scanline run list (esi=dest-offset table descending, ebx=0x18-byte span records: +0/+2/+3/+0xc count/+0xe), perspective-divides (g_sprite_perspective_step = 0x12345678/g_sprite_span_remaining) to build the U/V steppers, then dispatch 'jmp [g_sprite_column_fn]' (0x39e4c); inner loops jmp back to the loop tail render_world_span_39e52 (dec cx; jg 0x39bd2). Inner-loop family writes ES:[EDI] with edi+=1/pixel (HORIZONTAL spans, unlike the vertical wall mapper 0x390ac). Variants: render_sprite_span_fill_39fcd / render_sprite_span_solid_3a000 / render_sprite_span_gradient_3a0b1 / render_sprite_span_tex_3a100 / render_sprite_span_tex_3a220 / render_span_texmap_3a368 / render_sprite_span_tex_shaded_3a4f8 / render_sprite_span_tex_blend_3a700. Multiple rets (0x39e68, 0x39f86); sibling driver at 0x3a84e. See ROTH_renderer_notes.md 'Scaled-sprite span family'."),
		new NamedFunction(0x39fcdL, "render_sprite_span_fill_39fcd",
			"[sprite-span inner loop, g_sprite_column_fn variant] Solid UNSHADED fill: ax = g_sprite_fill_index duplicated, rep stosw across the span (edi+=1/px). The full-bright (shade 0x1f) / flat shortcut. jmp back to render_world_span_39e52."),
		new NamedFunction(0x3a000L, "render_sprite_span_solid_3a000",
			"[sprite-span inner loop] Solid SINGLE-SHADE fill: color = gs:[(g_sprite_span_shade<<8)|g_sprite_fill_index] looked up once, then alignment-aware rep stosd/stosb across the span (edi+=1/px). No texture, no transparency."),
		new NamedFunction(0x3a0b1L, "render_sprite_span_gradient_3a0b1",
			"[sprite-span inner loop] Gradient-shaded SOLID run: bl=g_sprite_fill_index (constant), bh=shade ramped per pixel via the EBP/EDX fixed-point (g_sprite_src_coord/_step + 0x8a376/0x8a37a), al=gs:[ebx] each pixel. Opaque, no transparency. edi+=1/px."),
		new NamedFunction(0x3a100L, "render_sprite_span_tex_3a100",
			"[sprite-span inner loop, SMC] Textured with TRANSPARENCY + translucency, constant shade. SMC-patches the width mask + steppers (0x3a191 'and ebx,mask', g_sprite_tex_step_u/_v) into itself. src=[g_render_source_base_ptr+ebx]; texel 0=skip, texel&0x80=blend via es:[(dest<<8)|color]; else color = [g_active_world_remap_base + (shade<<8) + texel] (FLAT remap table, not gs). 2px-unrolled, edi+=2."),
		new NamedFunction(0x3a220L, "render_sprite_span_tex_3a220",
			"[sprite-span inner loop, SMC] Textured variant with a forward/reverse split on g_sprite_span_flip ('cmp [0x8a3ac],0; jl 0x3a2e0'). SMC-patches steppers (g_sprite_tex_step_u/_v) into both sub-loops. Companion to render_span_texmap_3a368."),
		new NamedFunction(0x3a4f8L, "render_sprite_span_tex_shaded_3a4f8",
			"[sprite-span inner loop, SMC] Textured + per-pixel GRADIENT shade (ah ramps via 'adc ah,imm'), gs colormap gs:[(shade<<8)|texel]. Forward/reverse split on g_sprite_span_flip: 0x3a4f8 forward, 0x3a604 reversed (rotated-dword packed steppers + fs:[ebx] addressing). src=[g_render_source_base_ptr+ebx]. edi+=2 (2px unroll)."),
		new NamedFunction(0x3a700L, "render_sprite_span_tex_blend_3a700",
			"[sprite-span inner loop, SMC] Textured + per-pixel gradient shade + TRANSPARENCY + translucency, gs colormap. Per pixel: texel 0=skip, texel&0x80=blend via es:[(dest<<8)|gs-color], else gs:[(shade<<8)|texel]; shade ah ramps via 'adc ah,0x12'. Forward-only, 2px unroll, edi+=2. The richest sprite-span variant. Family ends at ret 0x3a84d; 0x3a84e = sibling driver."),
		new NamedFunction(0x390acL, "render_world_span_390ac",
			"[SMC vertical-column texture mapper; fn-ptr target installed into g_world_span_fn from pair table 0x71f80, jmp'd by dispatch_world_span_column] Linear (carry-stepped) depth-shaded column mapper. ABI (reached by jmp, registers flow through): ESI=src texel offset(+g_render_source_base_ptr 0x84980), EDI=dest offset(+g_render_target_buffer 0x85414, stride 0x140=vertical), ECX=row count(unrolled x2), EDX=integer src step(adc esi,edx), EAX/AX=hi16 of EAX-step, EBX/BH=shade seed; ES=g_transparency_blend_selector(blend table), GS=depth colormap. Per pixel: texel 0=transparent, texel&0x80=blend via es:[(dest<<8)|color], else gs:[(shade<<8)|texel]. Patches its own add ebp/adc eax step immediates from g_span_pixel_step/g_span_eax_step_lo etc. Clobbers ebp (no frame). See ROTH_renderer_notes.md 'Span/Column texture-mapper ABI'. recomp's oracle is semantic authority."),
		new NamedFunction(0x391d0L, "render_world_span_wrapped_391d0",
			"[SMC vertical-column texture mapper, tiled variant; sibling of render_world_span_390ac] Same entry ABI but indexes the source as [esi+ebx] with an SMC-patched 'and ebx,MASK' (power-of-two texture wrap) and carries the shade in DL/AH instead of AL/BH. The wrapped/tiled column mapper; 0x390ac is the linear one."),
		new NamedFunction(0x3778bL, "dispatch_world_span_column",
			"[per-column advance + fn-ptr dispatch for the world-column rasterizer; called from 0x375a4/0x3771e] Advances the interpolated texture endpoints (g_span_endpoint_a/_b += their colsteps), recomputes the per-pixel step g_span_pixel_step=(B-A)/count (idiv ecx) and the frac/shade seed g_span_accum_init/g_span_shade_seed, then tail-jmps the active mapper: jmp [g_world_span_fn] (or [g_world_span_fn2] no-clip path, [g_world_span_fn_alt] short-column path). NOT a call -> registers (ESI/EDI/ECX/EDX/EAX/EBX) flow straight into the mapper."),
		new NamedFunction(0x38c46L, "project_wall_edge_y",
			"[wall-column helper, called 4x by draw_world_surface_spans] Projects a wall-edge world Y to a screen row: clamps AX to the view frustum top/bottom (0x9096c/0x9096e), scales by the projection factor 0x90996, offsets by the horizon 0x90a1e. Results -> g_wall_proj_y0..3 (0x90948/4a/4c/4e), which feed the vertical span endpoint steppers g_span_endpoint_a/_b."),
		new NamedFunction(0x378dcL, "compute_wall_column_source_offset",
			"[wall-column helper, called from draw_world_surface_spans 0x37560] Computes the source-texel base for one wall column: depth-divides (0x8a308 / 0x8a300 = 1/Z), adds g_span_shade-ish bias 0x8a2f4, optional horizontal flip (g_world_surface_draw_flags bit1), masks by 0x90974, multiplies by the texture row width g_span_src_row_width (0x90978), adds into ESI -> g_span_src_wrap_base. Returns via carry (skip column on miss)."),
		new NamedFunction(0x38d6cL, "render_parallax_sky_columns",
			"[parallax-sky column renderer — renamed 2026-06-21, recomp-confirmed (RENDER_CAMPAIGN_findings_for_decomp.md §1); was the misnomer resolve_world_texture_source] Per-pixel vertical column FILL for the BUILD-style parallax sky. Called per column from the wall driver draw_world_surface_spans (0x36b39) when the per-face flag g_parallax_sky_active (0x90a2a, set when g_current_surface_render_flags bit 0x40) is set AND the wall top is above the horizon g_view_bound_top (0x9096e = open space). Pixel source = get_loaded_das_block_for_index(g_das_special_fat_index) (the per-map sky texture, map-header +0x18) and the source column is OFFSET by g_sprite_view_angle (the parallax drift). Does the classic double-scanline +0x140/+0x280 unrolled fill over g_render_column_source_table + an FS source; honors g_render_double_scanline_flag / g_render_x_flip_flag. It does NOT write g_active_das_frame_ptr/0x84980 (the original puzzle) because the caller saves/restores it around the call. NOTE: this is NOT the per-wall texture resolver — that resolution is inlined in three twin blocks (rasterize_world_spans_scanline 0x366cb / emit_world_face_spans 0x2c720 / render_world_secondary_surface 0x2bc3c), see ROTH_renderer_notes.md."),
		// Migrated 2026-06-30 from ROTHApplyDasTypes (DAS delta-stream codecs) so this script is the
		// single authoritative source of function names — see [[cross-script-name-conflicts]].
		new NamedFunction(0x4eda1L, "apply_das_sprite_frame_delta_stream",
			"Applies a byte-coded copy/fill/skip/end stream to the current DAS sprite frame buffer."),
		new NamedFunction(0x4ee1fL, "encode_literal_skip_delta_stream",
			"Compares two buffers and emits literal-copy or destination-skip delta commands."),
		new NamedFunction(0x4eeaeL, "apply_literal_skip_delta_stream",
			"Applies a simple literal-copy/destination-skip stream to a destination buffer."),
		// Interrupt-vector-target ISR bodies carved 2026-06-30 (ROTHDefineCommandHandlers ISR_BODIES) —
		// reached only via the runtime-installed int vector, so auto-analysis missed them. ENGINE (tick/
		// decode/input). See lift_handoffs/RESPONSE_carve_uncarved_timer_isr_bodies.md + [[interactive-lift-mode]].
		new NamedFunction(0x4e60bL, "gdv_decode_timer_isr",
			"GDV cutscene int-8/IRQ0 timer ISR (audio path), installed by gdv_install_timer_sync: saves regs + far-ptr DS (cs:[0x4e609]), calls the decode pump gdv_advance_decode_pump 0x4e310, advances frame counter [0x91884]; iretd."),
		new NamedFunction(0x4e310L, "gdv_advance_decode_pump",
			"Per-tick GDV decode pump (near-ret subroutine called by the timer ISRs): paces on the sample budget [0x91db0]/[0x91dbe], on underflow decodes the next chunk via gdv_decode_video_chunk 0x4d384 + emit/advance, advancing the decoder head [0x91d68]. The host_timer_driver calls this as the native-timer pump."),
		new NamedFunction(0x4e24bL, "gdv_decode_timer_isr_noaudio",
			"GDV int-8 timer ISR, no-audio variant (+0xbaa frame-time accumulate into [0x91dbc]): inline decode pacing on [0x91db0], advances frame counter; retf. [HYP exact variant-selection role]"),
		new NamedFunction(0x4e2edL, "gdv_tick_timer_isr",
			"GDV int-8 timer ISR, timing-only variant (+0x1400 into [0x91dbc]) — no decode, just advances the frame counter [0x91884]; retf. Installed via the site at 0x555a7. [HYP exact variant-selection role]"),
		new NamedFunction(0x12336L, "game_heartbeat_timer_isr",
			"Main-engine int-8/IRQ0 heartbeat ISR installed by install_timer_int8 0x12437 (the game's per-tick timing driver, twin of the GDV one); iretd."),
		new NamedFunction(0x12393L, "keyboard_int9_isr",
			"Keyboard IRQ1/int-9 ISR: PIC end-of-interrupt (out 0x20,0x20), reads scancode (in al,0x60 / in al,0x61), updates the input ring [ebx+0x90c1c] + last-scancode [0x7e91c]; iretd. (The int-9 handler referenced in [[interactive-lift-mode]].)"),
		new NamedFunction(0x436ccL, "chain_original_timer_vector",
			"Tail-chain trampoline for the int-8 timer ISRs (game_heartbeat_timer_isr / gdv_decode_timer_isr): loads the saved original int-8 vector (off [0x91d1c]/seg [0x91d20]), overwrites the saved CS:EIP on the interrupt frame ([ebp+0x28]/[ebp+0x2c]), pops the pushed regs, retf into the original DOS handler (~18.2 Hz chain). Pure interrupt-frame mechanics, no game state -> host_timer_driver (the native host owns timer delivery; nothing to chain)."),
		new NamedFunction(0x38b54L, "classify_surface_floorceil",
			"[surface-dispatch helper, called by rasterize_world_spans_scanline at 0x36a1e] Projects the surface's quad vertices (geometry ptr surf+0x30, vertex indices surf+0x36/+0x38/+0x3a/+0x3c) into the renderer working set (0x90958..) and returns AL != 0 when the surface is a FLOOR/CEILING (horizontal) span set rather than a vertical wall. The dispatcher routes a nonzero result to draw_floorceil_surface."),
		new NamedFunction(0x2c720L, "emit_world_face_spans",
			"[trace-confirmed, floor/ceiling + sprite world render] Walks the DAS entry-status table g_das_entry_status_table (0x86d30), indexed by the surface/DAS-id cursor g_current_das_entry_id (0x90a78); for each entry resolves the DAS cache slot in g_das_cache_slots (0x89930, block-ptr + tick) to source the surface texture. Part of the world surface-span build pipeline."),
		new NamedFunction(0x1f818L, "resolve_dbase100_text",
			"Resolves a UI/menu/dialogue text id (EBX) to its string from dbase100's text-string table: bounds-checks the id vs [g_dbase100_base+0x28] (count) and indexes [g_dbase100_base + [g_dbase100_base+0x2c] + id*4]; if present, reads the line via read_next_dialogue_line, else writes 'Missing Text'. This is the source of all menu labels (show_message_box descriptor text ids) - dbase100 is the master text/dialogue DB, always loaded, hence menus work on any map."),
		new NamedFunction(0x2c250L, "compute_face_span_extents",
			"Computes a world-face surface's vertical span extents into g_face_span_top (0x852ba) / g_face_span_bottom (0x852b8) (and the -origin-relative deltas at 0x852c0) from its two edge endpoints (ES-relative vertex reads). Applies the split/overlap adjustment from the surface's +0xc field when g_current_surface_render_flags & 8. Shared by draw_world_face_clipped_spans / draw_world_face_projected_spans (renderer notes: the 'bit 0x08 overlap/split setup'). Register-convention (ES/FS-relative)."),
		new NamedFunction(0x3efb0L, "scan_sector_edges_at_y",
			"Scanline edge-intersection for point-in-sector: walks the sector's edge list and, for the horizontal line at g_locate_query_y, linearly interpolates each crossing X, tracking the min (EBP+6) and max (EBP+4) bound (seeded 0x7fff/0x8000). Used by search_sector_from_hint / search_sector_global. Register-convention (EBP/ESI/GS-relative)."),
		new NamedFunction(0x21cc5L, "read_savegame_slot_names",
			"Enumerates all 9 save slots SAVE1..9.SAV (sprintf 'SAVE%D.SAV' + build_game_path) and reads each slot's display name from the .SAV (size word == 10 -> read name) into the caller's name-list buffer (param_1, 0xc-byte stride entries). The save/load menu descriptors (0x71c5d/0x71c0d) show a 5-item WINDOW over these 9 with up/down scroll arrows on the frame."),
		new NamedFunction(0x26501L, "run_options_menu",
			"The in-game OPTIONS/pause menu (descriptor &DAT_00071b6d = 'Options menu': New game / Load a game / Save a game / Settings / Quit to DOS). On Load it shows the load slot-list (&DAT_00071c5d), on Save the save slot-list (&DAT_00071c0d), filling slot names via read_savegame_slot_names. Returns a packed slot+action code. (Menu text = dbase100/dbase400; see resolve_dbase100_text.)"),
		new NamedFunction(0x26aefL, "show_cutscene_error_box",
			"Shows a GDV/cutscene load-error message box: picks one of 4 messages from g_gdv_error_strings 0x71d46 ('No errors.'/'Alloc_Mem_DISPLAY'/'Load_SPR'/'Load_RAW') by error index (FUN_00026a20). Called from play_gdv_cutscene."),
		new NamedFunction(0x24c72L, "run_settings_menu",
			"Settings-menu action handler (called from within show_message_box, hence the menu recursion). switch(param_1) on the chosen item: case 0 = the Quit-to-DOS confirm (&DAT_00071a00); case 1 = the Settings submenu (&DAT_00071a58 full incl. Screen [in-game] / &DAT_00071a9c reduced-no-Screen [front-end] per g_menu_frontend_flag) -> Volume settings (&0x71b18) / Subtitle settings (&0x71ad4) / Screen settings (&0x718f4 -> VESA-mode list) / Input Settings."),
		new NamedFunction(0x24f5eL, "update_frame_time_scale",
			"Per-frame timing: spins until g_frame_time_scale = g_frame_tick_counter(0x90bcc) - g_last_frame_tick(0x85320) is nonzero, stamps g_last_frame_tick, and decays g_damage_flash_level by 4*elapsed (clamped >=0), refreshing the palette via refresh_palette_dac."),
		new NamedFunction(0x4f6c0L, "crt_getenv",
			"getenv: searches the environ array for the variable named param_1 (strlen + FUN_00055816 compare, checks the '=' after the name) and returns a pointer to its value, or 0. Used by spawn_search_path / spawn_exec_path."),
		new NamedFunction(0x2626fL, "apply_audio_volume_settings",
			"Pushes the configured 12-bit volumes to the sound system: scales g_vol_soundfx/g_vol_speech/g_vol_movie (x0x80, clamp 0x7fff) and g_vol_music via set_71d84 / set_voice_sample_rate / set_71388, plus a 0..0x7f value to FUN_0001556f. From the settings/menu path."),
		new NamedFunction(0x3ac96L, "setup_floorceil_span",
			"Prepares a floor/ceiling render span descriptor (param_5): computes the row span from fields +0x18/+0x24 (count in_stack[0]<1 -> skip) and, when g_render_x_flip_flag is set, swaps the texture-coordinate field pairs (+0x1a<->+0x26, +0x1e<->+0x2a, ...) for horizontal flip. Called by the render_floorceil_* span drawers (11 callers). ALSO the per-row LOOP TAIL of draw_floorceil_surface: the fill family jmp here to pop the row regs and advance edi by 0x140 (next scanline)."),
		new NamedFunction(0x3a84eL, "draw_floorceil_surface",
			"[top-level floor/ceiling textured-surface span driver; sibling of draw_scaled_sprite_spans] gs=g_active_world_remap_selector colormap; computes the surface shade via a light calc at 0x3c0be ('neg al; add al,0x1f' clamp into [esi+0x18] with 0xe0e0e0e0 mask); calls rasterize_floorceil_polygon (0x3b1c1) to edge-walk the surface into the per-Y span tables (left/right X at 0x8cd0c, min/max Y 0x90a1a/0x90a1c); then a render-mode x texture matrix (g_render_textured? 0x90a23, g_world_surface_draw_flags 0x9093c bit0, g_floor_tex_caps 0x909b2 bit10, degenerate 0x90978|0x90988==0) selects a FILL inner-loop into g_floorceil_span_fn (0x8a3c0) + _alt (0x8a3c4), bsr-shifting the texture width 0x90978. Row loop: for each scanline span record (ebx, +6/+0x12 + +4/+0x10 + +2/+0xe perspective-divided by the span pixel count into the steppers g_floorceil_du/_dv/_dw 0x8a3f4/0x8a3f7/0x8a3fa) it dispatches 'jmp [g_floorceil_span_fn]' (0x3ac16) / '[_alt]' (0x3abd8); the fill loop returns via setup_floorceil_span (0x3ac96) which advances edi by 0x140. Multiple exits (ret 0x3ac95, 0x3aca9). See ROTH_renderer_notes.md 'Floor/ceiling fill family'."),
		new NamedFunction(0x3acecL, "render_floorceil_solid_3acec",
			"[floorceil fill, g_floorceil_span_fn variant] Untextured solid UNSHADED fill: al=g_sprite_fill_index, rep stosb/stosw across the scanline span (edi+=1/px). jmp setup_floorceil_span. Selected when g_render_textured?(0x90a23)==0."),
		new NamedFunction(0x3ad04L, "render_floorceil_solid_shaded_3ad04",
			"[floorceil fill _alt] Untextured solid SINGLE-SHADE fill: color = gs:[(ah<<8)|g_sprite_fill_index]. Untextured shaded companion of render_floorceil_solid_3acec."),
		new NamedFunction(0x3ad28L, "render_floorceil_solid_blend_3ad28",
			"[floorceil fill, g_render_textured_flag(0x90a22) variant] Untextured solid fill, translucent-blend variant of the render_floorceil_solid_* pair (selected when 0x90a22 set)."),
		new NamedFunction(0x3ad80L, "render_floorceil_tex_3ad80",
			"[floorceil fill, SMC] Textured OPAQUE perspective span: src bl=fs:[ebx] where ebx=(ebp ror 0xb)&mask | (dh shade), steppers ebp/edx += g_floorceil_du/_dv (0x8a3f4/0x8a3f8). No transparency test. edi+=1/px. Base variant for the 0x9093c bit0-clear path."),
		new NamedFunction(0x3af38L, "render_floorceil_tex_shaded_3af38",
			"[floorceil fill _alt, SMC] Textured + shade: 'or ah,ah; je render_floorceil_tex_3ad80' (ah==0 -> simple); else uses fs:[ebx] then the FLAT remap [g_active_world_remap_base 0x8a2ac + (shade<<8)+texel]. Shaded companion of render_floorceil_tex_3ad80."),
		new NamedFunction(0x3af94L, "render_floorceil_tex_blend_3af94",
			"[floorceil fill, 0x90a22 variant, SMC] Textured translucent-blend companion of the render_floorceil_tex_3ad80 group (selected when g_render_textured_flag 0x90a22 set)."),
		new NamedFunction(0x3adc0L, "render_floorceil_tex_masked_3adc0",
			"[floorceil fill, SMC] Textured MASKED perspective span: like render_floorceil_tex_3ad80 but with a transparency test ('or bl,bl; je skip') so texel 0 = transparent. Base for the 0x909b2 bit10-clear textured path."),
		new NamedFunction(0x3aed8L, "render_floorceil_tex_masked_shaded_3aed8",
			"[floorceil fill _alt, SMC] Textured masked + shade gradient: 'or ah,ah; je render_floorceil_tex_masked_3adc0'; else fs:[ebx] -> gs:[(shade<<8)|texel] with ah ramping. Shaded companion of render_floorceil_tex_masked_3adc0."),
		new NamedFunction(0x3b070L, "render_floorceil_tex_masked_blend_3b070",
			"[floorceil fill, 0x90a22 variant, SMC] Textured masked translucent-blend companion of the render_floorceil_tex_masked_3adc0 group."),
		new NamedFunction(0x3ae04L, "render_floorceil_tex_blend_3ae04",
			"[floorceil fill, SMC] Textured + TRANSPARENCY + translucency: pushes es=g_transparency_blend_selector; per pixel fs:[ebx], texel 0=skip, texel&0x80=blend via es:[(dest<<8)|color]. Base for the 0x909b2 bit10-set textured path (blend-capable floors)."),
		new NamedFunction(0x3ae68L, "render_floorceil_tex_blend_shaded_3ae68",
			"[floorceil fill _alt, SMC] Textured blend + shade-gradient companion of render_floorceil_tex_blend_3ae04 (the 'or ah,ah' shade entry)."),
		new NamedFunction(0x3aff4L, "render_floorceil_tex_blend_alt_3aff4",
			"[floorceil fill, 0x90a22 variant, SMC] Textured blend companion of the render_floorceil_tex_blend_3ae04 group (selected when g_render_textured_flag 0x90a22 set)."),
		new NamedFunction(0x3b0d8L, "render_floorceil_tex_small_3b0d8",
			"[floorceil fill, SMC] DEGENERATE small-texture span: 16-bit source addressing (ebx=(ebp ror 8); bl=dh; fs:[bx]) with no width mask. Base for the 0x90978|0x90988==0 path."),
		new NamedFunction(0x3b110L, "render_floorceil_tex_small_shaded_3b110",
			"[floorceil fill _alt, SMC] Small-texture shaded companion of render_floorceil_tex_small_3b0d8."),
		new NamedFunction(0x3b15cL, "render_floorceil_tex_small_blend_3b15c",
			"[floorceil fill, 0x90a22 variant, SMC] Small-texture blend companion of the render_floorceil_tex_small_3b0d8 group."),
		new NamedFunction(0x13136L, "free_das_cache_handle",
			"Frees a DAS-cache pool handle (param_1) from g_das_cache_heap_handle (via blit_descriptor_rows + pool_free_handle) and returns 0 - so callers do `handle = free_das_cache_handle(handle)` to null it. Releases overlay save-under buffers."),
		new NamedFunction(0x1dc73L, "eval_dialogue_record_by_id",
			"Looks up dbase100 dialogue record param_1 (bounds: <= [g_dbase100_base+0x18]) in the table g_dbase100_dialogue_table (0x81e24) and runs its commands via eval_or_queue_dialogue_record_commands(rec+g_dbase100_base,...). Returns 0 if out of range/empty."),
		new NamedFunction(0x21806L, "delete_temp_files",
			"Enumerates files in the data dir (build_game_path with DAT_00076540) via FUN_000217bc and dos_delete_file's each match in a loop - temp/cache cleanup. (This is the function whose Ghidra no-return mis-flag once truncated roth_main_sequence; see reachability-chokepoint-mainseq.)"),
		new NamedFunction(0x18a2aL, "try_interrupt_dialogue_voice",
			"If a dialogue action queue is pending (or an active choice with g_move_freeze_gate!=0x7ffff), force-ends the current voice line via dialogue_voice_force_end(g_mouse_x,g_mouse_y,...) and returns 1; else returns 0. The click-to-skip-voice check."),
		new NamedFunction(0x26cd4L, "flush_object_das_handles",
			"Walks the render-object table DAT_000848f4 (DAT_000848fc entries, 0xc-byte stride) and releases each object's cached DAS image handle: field +0xb indexes the handle table &DAT_00084874, freed via FUN_00026b4c (and FUN_00026eaf if live), then reset to 0xff. Cache flush on map reload / render-mode toggle."),
		new NamedFunction(0x550a3L, "crt_read",
			"Watcom C read(): reads from a file via INT 21h AH=3Fh into param_2, looping until the request is satisfied, with text-mode buffer processing (CR/LF). Mode/flags from FUN_000561a4. Returns bytes read."),
		new NamedFunction(0x1bb4bL, "update_selected_item_icon",
			"When the primary selected inventory item (g_selected_item_primary) changes, loads its DAS icon: looks up g_dbase100_inventory_table[id], gets the DAS resource index (rec[+0xc]), opens g_dbase200_filename, FAT-seeks index<<3, reads + blit_das_image_to_buffer into a work buffer (FUN_00013e35). 11 callers."),
		new NamedFunction(0x1a8e5L, "update_inventory_screen",
			"[the inventory / item-bar UI handler; called every frame from game_play_loop 0x179ee] Polls "
			+ "the input ring (input_ring_dequeue 0x1299a, returns a keyboard SCANCODE byte) and dispatches "
			+ "the FULL keyboard navigation. KEYMAP (scancode -> action): 0x48/0x50 up/down arrow = move "
			+ "cursor one ROW (+/-5) + scroll; 0x4b/0x4d left/right arrow = move cursor +/-1 + scroll; "
			+ "0x02-0x06 (number 1-5) = jump to tab 0-4 (via select_inventory_tab 0x1a2b5); 0x0f (Tab) = "
			+ "cycle to next tab (wrap at 5); 0x1c (Enter) = select/equip the cursor item (weapons list -> "
			+ "activate_weapon_item 0x184ab; items list -> g_selected_item_primary 0x81044 + "
			+ "update_selected_item_icon); 0x1f ('S') = g_inventory_ui_action=1 (synthetic SELECT/pickup of "
			+ "the current cell); 0x16 ('U') = g_inventory_ui_action=2 (synthetic USE: sets "
			+ "g_inventory_synthetic_primary 0x812fc so the cell acts as a primary click -> "
			+ "use_item_on_self / combine_held_item_with_target); 0x20 ('D') = g_inventory_options_request "
			+ "0x7febc=1 -> tail opens run_options_menu 0x26501; 0x39 (Space) = open the item INSPECT "
			+ "close-up window for the highlighted entry (sets g_inventory_inspect_request 0x80b3c; the "
			+ "tail loads the item's close-up image template[+8] via load_dbase300_resource_at_offset 0x196b9 -> "
			+ "render_inspect_popup_window 0x18e9e); 0x30 ('B') = debug screenshot (check_snapshot_key "
			+ "0x11124); 0x01 (Esc)/0x17 ('I') "
			+ "= leave/commit (try_interrupt_dialogue_voice 0x18a2a + commit_held_cursor_item 0x1a88b). The "
			+ "synthetic g_inventory_ui_action codes are consumed next frame by hit_test_dialogue_ui_action "
			+ "(0x1ad2f) -> dispatch_dialogue_ui_action (the SAME path as a mouse cell click). The "
			+ "options-menu RETURN value drives a jump table (0x1a8cd) into the new-game/load/save/quit "
			+ "request flags (0x7fea8 bits, 0x7feac/0x7feb0). State globals: g_cursor_active_list 0x80b38, "
			+ "g_cursor_list_positions 0x80afc, g_cursor_scroll_offsets 0x80b10, g_cursor_entry_count "
			+ "0x80af4. So inventory is FULLY keyboard-navigable; mouse and keyboard converge on the same "
			+ "select/use/combine/scroll handlers."),
		new NamedFunction(0x1a132L, "update_ui_overlay",
			"[per-frame UI overlay gate, from run_gameplay_frame] Decides whether to (re)draw the "
			+ "INVENTORY bag panel this frame. If a dialogue/monologue is active (g_active_dialogue_context "
			+ "0x83115 != 0) AND the move-freeze gate (0x83125) == 0x6ffff, the screen is owned by the "
			+ "monologue/choice UI (render_text_ui 0x1f0e8) -> return (don't draw the inventory). "
			+ "Otherwise, when 0x8a0f0 == 0 it runs the pre-pass 0x1a7a1 and resets the render latch "
			+ "(0x7fec4=0); then, gated by that latch, calls render_inventory_panel (0x1a399) once and "
			+ "sets the latch to 2. Companion of handle_cursor_click (input side)."),
		new NamedFunction(0x1a399L, "render_inventory_panel",
			"The INVENTORY bag panel renderer (called by update_ui_overlay 0x1a132). Sets the panel "
			+ "anchor (compute_viewport_half_extents), allocates a ~0x1130-byte DAS-cache scratch buffer "
			+ "(g_ui_panel_scratch_handle 0x811ac), fills the 0x128x0x58 (296x88) panel background and "
			+ "saves the framebuffer behind it (save_framebuffer_region 0x13062), then draws the item "
			+ "grid (render_inventory_grid 0x1c163 directly) and the selected item's "
			+ "name/description text (read_next_dialogue_line 0x1e8cc + draw_text_at_screen_xy 0x1a079), "
			+ "and builds the cell/arrow/tab hotspot list. Clears the cursor click flags at the end. "
			+ "NOTE (corrected 2026-06-17 per game-author feedback): this is the INVENTORY panel, NOT an "
			+ "NPC dialogue/conversation panel, and 0x811ac is a render scratch buffer, NOT a portrait — "
			+ "ROTH has no NPC dialogue portraits. The actual monologue/choice UI is render_text_ui "
			+ "(0x1f0e8); update_ui_overlay defers to it when a dialogue is active."),
		new NamedFunction(0x1a88bL, "commit_held_cursor_item",
			"Commits the currently held cursor item (g_current_cursor_entry 0x7fef0) when leaving the "
			+ "inventory screen (the Esc/'I' path in update_inventory_screen). If something is held and the "
			+ "active list is the weapons list (g_cursor_active_list==1), equips it via activate_weapon_item "
			+ "(0x184ab) with the entry's id (+4) / aux (+8). On the ITEMS list (==0) it instead commits the held "
			+ "item as g_selected_item_primary (+ update_selected_item_icon). No-op only if nothing held or on list 2."),
		new NamedFunction(0x1b141L, "use_item_on_self",
			"[inventory: USE/CONSUME the held item on itself = drink a potion etc.] Click the cursor-held item (g_current_cursor_entry 0x7fef0) on its OWN slot. Gets the template (get_dbase100_inventory_entry 0x18147), calls resolve_item_use_action with TARGET=0 (the use-on-self recipe in the OnUse 0x0B block). If a recipe matched: CONSUMES the original (0x1d0fd = decrement/remove), give_item(s) the RESULT item(s) (0x34 sub-op, e.g. empty bottle), shows the 'you use X' message (resolve_dbase100_text id 0x2d + sprintf 0x27c53 + display 0x1f859), and RUNS THE EFFECT command-record (the 0x35 sub-op id) via eval_dialogue_record_by_id (0x1dc73) -> e.g. the heal/buff chain. If not usable: shows the 'nothing happens' message (text 0x2a)."),
		new NamedFunction(0x1b26dL, "combine_held_item_with_target",
			"[inventory: USE the held item ON ANOTHER item = combine, BIDIRECTIONAL] Click the cursor-held item on a DIFFERENT slot. Resolves both templates (get_dbase100_inventory_entry x2). Tries resolve_item_use_action(heldTemplate, targetId); if no recipe, tries (targetTemplate, heldId) — so a recipe on EITHER item works. On a match: consume/give_item-result/run-effect like use_item_on_self, with the combine-success message (text 0x28). No recipe -> 'these don't combine' message (text 0x29). Recipes live in each item's OnUse 0x0B block keyed by the partner's item id."),
		new NamedFunction(0x18060L, "resolve_item_use_action",
			"[inventory: the OnUse RECIPE matcher] EAX=item template, EDX=target item id (0 = use-on-self), EBX=out ptr. Bails (0) unless template[+5] & 0x40 (USABLE/combinable). Walks the template's trigger-block list at +0x14 for the TRIGGER 0x0B (OnUse) block, then scans its dword sub-records for the RECIPE whose target matches EDX; sub-op 0x34 = RESULT item id (primary, 0xb4 = secondary), sub-op 0x35 = an EFFECT command-record id (-> [EBX]). Returns the packed result item id(s) ((secondary<<16)|primary), or -1 if matched with no result, 0 if no recipe. So 0x0B is a recipe table: target 0 = use-on-self, target=other-id = combine-with-that-item. (0x04 = OnInspect is a different block; see scan_tag4_chunk.)"),
		new NamedFunction(0x1b007L, "swap_inventory_entries",
			"[inventory: MOVE / rearrange] Exchanges two g_cursor_entry_table entries (EAX, EDX) and fixes up any selection pointers that referenced them (g_left_hand_item 0x81030/0x81038, g_right_hand_item 0x8103c/0x81044, 0x81048). Reached from dispatch_dialogue_ui_action when the held cursor item is dropped onto an occupied slot -> the two items swap places (rearranging the inventory page). PURE DATA (recomp oracle-verified byte-identical 2026-07-01): the trailing `jmp 0x18747` borrows load_das_cache_resource's register-restore epilogue (shared_epilogue_5reg) - a Watcom shared-code multi-entry tail, NOT a call into the DAS loader. That is why functions.json shows flow_succ->0x1869b; the raw edge is correct, but it does not mean swap touches DAS."),
		new NamedFunction(0x1cb35L, "test_dbase100_record_flag",
			"Tests record param_1's bit in the dbase100 active-record bitmap g_dbase100_record_bitmap (0x81e28) using the bit-mask LUT g_bit_mask_lut. Returns 0 only if the bitmap exists AND the bit is CLEAR; else -1 (bit set or no bitmap). Used by filter_dbase100_active_records / execute_dbase100_chain."),
		new NamedFunction(0x1d2aaL, "run_dialogue_action_queue",
			"Drains the dialogue action queue (g_dialogue_action_queue_count entries at DAT_00081e42, 0xc-byte stride), executing each via execute_dbase100_chain and shifting the queue down; interrupts/finalizes any active voice (dialogue_voice_force_end, g_voice_stream_state). Re-entrancy guard DAT_00081ef6."),
		new NamedFunction(0x15492L, "load_dbase300_chunk",
			"Loads dbase300 chunk param_1 into g_dbase300_chunk_buf (0x7f450): if it differs from the current chunk g_current_dbase300_chunk_id (0x7f46c), opens g_dbase300_filename, FAT-seeks param_1<<3, reads the u32 size then that many bytes (cap 0x11801), retrying via format_to_static_buf. Then FUN_0001548c."),
		new NamedFunction(0x1558dL, "process_audio_sequence_chunk",
			"[AUDIO — MIDI music; was mislabeled 'process_audio_sequence_chunk'/document-image] Per-frame manager for the "
			+ "loaded MIDI music SEQUENCE chunk (a song). Lifecycle on the chunk buffer (0x7f450): init "
			+ "init_audio_sequence (0x464f9 -> ctx g_audio_sequence_ctx 0x7f444); then step_audio_sequence "
			+ "(0x46d18) ARMS the SOS timer-driven playback (the tick ISR sos_sequence_timer_tick 0x51ad5 fires "
			+ "due MIDI events via sos_dispatch_midi_event 0x44e0d -> the SOS music-driver vtable 0x92f9c); on "
			+ "completion emit_audio_sequence_event (0x4627d, full vol 0x7f) + finalize_audio_sequence (0x471da). "
			+ "Progress bits g_audio_sequence_progress (0x7f468): 1=active,2=inited,4=done. Chunk loaded by "
			+ "load_dbase300_chunk (0x15492), id-tracked by 0x7f46c, (re)started by the dbase100 chain (commit op "
			+ "0x1b = per-area music change). NOTE: the inspect-modal document image is a SEPARATE visual path."),
		new NamedFunction(0x44e0dL, "sos_dispatch_midi_event",
			"[AUDIO — MIDI event router; was 'dispatch_audio_sequence_event'/'document-image']. Routes ONE MIDI "
			+ "channel event to the HMI SOS music driver. The event is read from a packed MIDI byte stream via a "
			+ "far (GS) pointer (EBX:=ptr, EAX/[ebp-8]=track/song index, EDX/[ebp-4]=driver slot, [ebp+0x10]=SOS "
			+ "message class). Byte0 = MIDI status: high nibble = command (0x8n noteoff / 0x9n noteon / 0xAn poly "
			+ "aftertouch / 0xBn control-change / 0xCn program / 0xDn chan-pressure / 0xEn pitch-bend), low nibble "
			+ "= MIDI channel. The assembled message (status,d1,d2,d3) is staged at g_sos_midi_message "
			+ "(0x951b4..0x951b7) and emitted via `call far [slot*0x48 + 0x92f9c]` = driver method 0 (event-out). "
			+ "0xBn special case: controller 7 (channel volume) is scaled by g_sound_channel_volume (0x7370c, "
			+ "init 0x7f; v*vol>>7) and master 0x73708, and muted if 0x93124[track]. Mode g_sos_voice_alloc_mode "
			+ "(0x951cc): 0 = direct passthrough; !=0 = DYNAMIC VIRTUAL-CHANNEL ALLOCATION (AIL/SOS-style) — the "
			+ "logical channel is mapped to a physical voice via g_midi_logical_to_physical_chan (0x729d8); on a "
			+ "new allocation it scans the busy table g_midi_physical_chan_busy (0x736b8), records reverse maps "
			+ "(0x72ca8/0x72cf8) and REPLAYS the saved per-channel controller state (program/volume/pan/... in "
			+ "0x72d48..0x72d4c) to the fresh voice before sending the event. 2880-byte function."),
		new NamedFunction(0x464f9L, "init_audio_sequence",
			"[AUDIO] Inits a sound/music sequence chunk: sets up the sequencer context (g_audio_sequence_ctx "
			+ "0x7f444) from the chunk buffer (0x7f450) + a GS selector, resets state (0x7f3b4/0x7f3c0). Called by "
			+ "process_audio_sequence_chunk before stepping. Returns nonzero on error."),
		new NamedFunction(0x46d18L, "step_audio_sequence",
			"[AUDIO] Starts timer-driven playback of the MIDI sequence: ARMS an SOS timer event via "
			+ "sos_timer_register_event (0x49923) with the tick ISR sos_sequence_timer_tick (0x51ad5) at the "
			+ "music driver's tick rate (driver descriptor gs:[0x93164]+0x38) and per-track context "
			+ "g_sos_sequence_ctx_table (0x72908[track]); marks the track active (0x93144[track]=1). The timer "
			+ "ISR thereafter advances the sequence and fires due events. Returns nonzero on error."),
		new NamedFunction(0x4627dL, "emit_audio_sequence_event",
			"[AUDIO] Emits MIDI events at a given per-channel volume (EDX; 0x7f = full). Wrapper that calls "
			+ "sos_dispatch_midi_event (0x44e0d). Used for volume changes and the final all-notes-off at finalize."),
		new NamedFunction(0x471daL, "finalize_audio_sequence",
			"[AUDIO] Finalizes the sound/music sequence (calls emit_audio_sequence_event 0x4627d with the snapshot "
			+ "byte 0x71124). Last step in process_audio_sequence_chunk before the done bit is set."),
		new NamedFunction(0x1fb1eL, "choice_select_prev",
			"Moves the dialogue/menu choice selection UP one (g_choice_selected_index--, wraps to last), and repaints the highlight over the active choice-line records (g_choice_line_records / DAT_000827fd). Paired with choice_select_next."),
		new NamedFunction(0x1fc16L, "choice_select_next",
			"Moves the dialogue/menu choice selection DOWN one (g_choice_selected_index++, wraps to 0), and repaints the highlight marker (g_map_menu_marker_selected) over the active choice lines. Paired with choice_select_prev."),
		new NamedFunction(0x1fbbaL, "choice_accept_selected",
			"Confirms the highlighted dialogue/menu choice (Enter): sets g_pending_choice_accept_index = sel+1, clears the choice state (DAT_00083115/g_move_freeze_gate/g_dialogue_busy_flag, sel=-1) and runs FUN_0001dc02(DAT_0008313d). From use_enter_key_handler."),
		new NamedFunction(0x3e03fL, "point_to_wall_distance_sq",
			"[collision/distance — disasm-verified; CORRECTED from 'draw_edge_between_verts' — this DOES NOT draw a line] "
			+ "Returns the squared distance from the query point (EBX) to a wall: looks up the wall's two vertices "
			+ "(wall record param_1 -> vtxA@+0, vtxB@+2 via g_geometry_selector; coords via DAT_90bec) and calls "
			+ "point_segment_distance_sq (0x40805) with radius param_2. Result (dist^2, or a far sentinel) is in EAX "
			+ "(the decomp shows void — the EAX return is dropped). All callers use it as a distance: blast/face damage "
			+ "falloff (cmd_apply_damage, cmd_face_emits_damage, damage_player_from_emitter), the portal proximity scan, "
			+ "and the dev door-spawn tool."),
		new NamedFunction(0x40805L, "point_segment_distance_sq",
			"[geometry primitive — disasm-verified; the leaf behind point_to_wall_distance_sq 0x3e03f] Returns the "
			+ "squared perpendicular distance from a point (EBX) to the 2D line segment (param_2 = endpoint A packed XY, "
			+ "param_3 = endpoint B): AABB-rejects against the radius param_1, computes dist^2 = cross(point,seg)^2 / "
			+ "|seg|^2, and returns dist^2 + 1 if dist^2 <= param_1^2, else the sentinel 0x7ffff (out of range). Pure "
			+ "math, no side effects."),
		new NamedFunction(0x2e1e8L, "flip_video_page",
			"Page-flip / set display start: swaps the front/back page offsets DAT_00071f06<->0x71f0a and writes the new display start via CRTC regs 0xC/0xD (out 0x3d4/0x3d5) or VBE 0x4F07 (int 10h) in VESA mode. Per-frame double-buffer swap (14 callers)."),
		new NamedFunction(0x2245cL, "rebuild_weapon_inventory_list",
			"Scans g_inventory_slots (g_inventory_count entries) and collects items whose weapon attributes (apply_weapon_action_attributes) have bit 0x8000 into the usable-weapon list DAT_00083d84 (max 16), count -> DAT_00083e04. Rebuilt on give_item / menu changes."),
		new NamedFunction(0x3001bL, "reset_das_entry_status_table",
			"Resets the DAS entry-status table g_das_entry_status_table (0x1600 u16 slots): frees each in-use entry via free_das_cache_entry (0x41413) and marks every slot free (0xff,0). Called by roth_main_sequence and the render-mode toggle."),
		new NamedFunction(0x41413L, "free_das_cache_entry",
			"[DAS cache — disasm-verified; called per-slot by reset_das_entry_status_table 0x3001b] Evicts one DAS cache "
			+ "entry: marks the status byte free (0xff), clears the slot, and releases the DAS record's storage from the "
			+ "g_das_cache_heap_handle pool (pool_free_handle). For a MULTI-FRAME DAS (record+0xa bit0x40) it also frees "
			+ "each animation frame's own DPMI selector (INT31h fn1) before freeing the record; for a record with a "
			+ "linked sub-buffer (record+0xa bit0x100 && record+0x16==-2) it frees that selector+chunk too. "
			+ "Register-context (ESI=slot ptr, EDI=status byte)."),
		new NamedFunction(0x40b5cL, "alloc_image_view_descriptor",
			"[image/surface — disasm-verified] Builds a 0x18-byte image/surface descriptor from a source image header "
			+ "(param_1: width@+0, height@+2, +6, data ptr@+8) via game_heap_alloc_round4(0x18): copies the data ptr, "
			+ "width and height, and precomputes clip bounds max-x = width-1, max-y = height-1; zeroes the cursor/scroll "
			+ "fields. Returns the descriptor (or 0 on alloc fail). A blit-surface/clip-rect view over a DAS image."),
		new NamedFunction(0x2fd21L, "init_backdrop_image_surface",
			"[image/surface — disasm-verified] Builds the global image surface g_image_surface (0x90a9c) from the static "
			+ "image header at 0x71ef8 via alloc_image_view_descriptor; sets g_roth_error_code=7 first. [hedged: 0x71ef8 "
			+ "looks like the backdrop/fullscreen surface header.] Called from roth_main_sequence."),
		new NamedFunction(0x2f9b0L, "free_render_color_selectors",
			"[renderer teardown — disasm-verified] Releases the render colour-table DPMI selectors + buffers allocated "
			+ "by allocate_das_worker_buffers (0x2fa29): the DOS transfer block (0x89f0e), the master table buffer "
			+ "(0x85c54), and the descriptors g_transparency_blend_selector (the 256x256 blend table), 0x85d0c, 0x89f14, "
			+ "and g_text_color_ramp_selector — zeroing each handle. Run on shutdown / before re-init."),
		new NamedFunction(0x40a61L, "map_buffer_to_dpmi_selector",
			"[DPMI/DAS — disasm-verified; called by allocate_das_worker_buffers 0x2fa29] Allocates/configures a DPMI LDT "
			+ "selector to wrap a buffer: sets its base address (INT31h fn7, from param_1) and limit (fn8, param_2-1); on "
			+ "any INT31h error frees the descriptor (fn1) and the heap block (game_heap_free). Returns the selector. "
			+ "Used to give a DAS worker buffer a flat selector."),
		new NamedFunction(0x18a23L, "shared_epilogue_6reg",
			"Shared function EPILOGUE (leave; pop edi/esi/edx/ecx/ebx; ret) reached by ~14 jumps - a register-restore-and-return tail, NOT a standalone function. (Watcom shared-code; see flow_succ.)"),
		new NamedFunction(0x3c7e2L, "shared_error_return",
			"Shared FAILURE-return tail (add esp,4; stc; ret) reached by ~15 jumps - pops one stack arg, sets carry=error, returns. NOT a standalone function. (Watcom shared-code.)"),
		new NamedFunction(0x1f330L, "mark_overlay_dirty_rects",
			"Per-frame: registers dirty rects (register_dirty_rect) for up to 3 active timed overlay regions (guards DAT_000827e9/0x83141/0x83145), decrementing each timer via FUN_00013136. From gameplay_frame_step / game_play_loop."),
		new NamedFunction(0x4b360L, "mem_fill",
			"memset primitive: EAX=dst, DL=fill byte, EBX=count; returns dst. 18 callers (DL=0 to zero-fill buffers)."),
		new NamedFunction(0x2508fL, "show_message_box",
			"Modal message/dialog box AND the engine's menu frame (run_main_menu/run_options_menu/"
			+ "run_settings_menu + error boxes all call it): param_1(ESI)=box descriptor struct "
			+ "(+0/+4=title/body text ids, +8=icon-tile id, +0x10=line count, flag bytes at desc+? "
			+ "drive the style). Lays out the wrapped text (resolve_dbase100_text 0x1f818 per line into "
			+ "a stack buffer, 0xb=11px row height), sizes the window to content, then COMPOSITES the "
			+ "chrome from ICONS.ALL DAS tiles: solid interior via clear_framebuffer_rect (0x12cea), "
			+ "horizontal frame rules via 0x12dde / centered 0x24fb1, ornate corner/edge tiles via "
			+ "screen_xy_to_framebuffer_ptr (0x18040) -> blit_reloc_das_image (0x18e68) with directory "
			+ "byte-offsets 0x2a0(51x15)/0x2b8(29x15)/0x318(7x15)/0x2a8(7x12) edges, 0x328(288x80) "
			+ "ornate panel bg, 0x360(73x58)/0x20(29x24) accents; an optional pre-composited box image via "
			+ "0x18e48 from g_ui_panel_scratch_handle 0x811ac (a DAS-cache scratch buffer, NOT a portrait "
			+ "- ROTH has no dialogue portraits); for scroll-list (save/load 9-slot) boxes a 0xd0(35x157) "
			+ "scrollbar + up/down "
			+ "arrows via draw_scroll_indicators (0x24ebe). Then runs its OWN blocking input loop "
			+ "(input_ring_dequeue + FUN_00015dd9 + flip_video_page) until dismissed. String formatting "
			+ "delegated to the printf core 0x27c53. See ROTH_file_formats.md 'Window/menu frame "
			+ "rendering'. (NOTE: earlier mislabeled vsnprintf.)"),
		new NamedFunction(0x24ebeL, "draw_scroll_indicators",
			"Draws the up/down scroll-arrow tiles for a scroll-list message box (the save/load 9-slot "
			+ "list). EAX=box state (reads scroll offset [eax+0xc] vs range [eax+0xe]), EDX=box top Y, "
			+ "EBX=box left X. Picks tile 0xa8(up-active)/0xb0(up-inactive) by whether offset>0, and "
			+ "0xb8(down-active)/0xc0(down-inactive) by whether offset<range, blits each via "
			+ "screen_xy_to_framebuffer_ptr + blit_reloc_das_image, then register_dirty_rect + 0x15b5b "
			+ "for the list body. Called by show_message_box. (Scroll mechanic: window 5 + range 4 = 9.)"),
		new NamedFunction(0x19ee6L, "draw_panel_slot_tile",
			"Non-modal UI panel slot draw. EAX = logical slot index into g_ui_slot_layout_table "
			+ "(0x71208): X = table[i].x + g_ui_panel_anchor_x (0x80b24), Y = table[i].y + "
			+ "g_ui_panel_anchor_y (0x80b28). register_dirty_rect for the 0x1b-sized cell, then "
			+ "screen_xy_to_framebuffer_ptr -> blit_reloc_das_image of the 28x28 slot-background tile "
			+ "(ICONS.ALL dir offset 0x110). This is how inventory/dialogue panels lay out their cells "
			+ "(data-driven slots vs show_message_box's content-sized composition). See "
			+ "ROTH_file_formats.md 'Non-modal panels'."),
		new NamedFunction(0x1c020L, "draw_inventory_entry_label",
			"Draws one inventory entry's name+count LABEL (NOT an icon — renamed from draw_inventory_slot_icon, "
			+ "consistency audit 2026-06-21). EAX = entry index into the cursor-entry array (0x7fef4 family, "
			+ "stride 0xc). Reads the entry (apply_weapon_action_attributes), derives the count (item record +2, "
			+ ">>8 when the record flag byte & 0x80), formats the 'name (count)' string via "
			+ "format_inventory_item_label (0x1c0b1), and draws the label/count badge via "
			+ "draw_ui_panel_count_element (0x1a0ab). Called on the inventory render path (0x1a399 / 0x1bf7b)."),
		new NamedFunction(0x19d30L, "build_inventory_entry_list",
			"Builds the on-screen inventory entry list for one TAB. EAX = item-type category (= "
			+ "g_cursor_active_list). Walks g_inventory_slots (0x80c30, g_inventory_count 0x80c2c), "
			+ "resolves each item's template (offset table 0x81e20 + base 0x81e1c), and KEEPS only items "
			+ "whose type nibble template[+5]&0xf matches the category (category 2 = the KNOWLEDGE/KEY group: "
			+ "people/concepts topics + key items + key documents — in-game verified, NOT 'stackable'; these are "
			+ "additionally gated by node_has_available_choice 0x1fa91 = an availability/condition test, so only "
			+ "'known/encountered' topics show). Each kept item is appended to g_cursor_entry_table (0x7fef4, stride 0xc: "
			+ "+0 inventory-slot ptr, +4 item id), and the running total is stored in g_cursor_entry_count "
			+ "(0x80af4) -> this is the count the scroll logic compares against 10. Also re-points the "
			+ "selected/held-entry markers (0x81030/0x8103c/0x81048). So tabs = item-type filters over "
			+ "one shared inventory."),
		new NamedFunction(0x1c163L, "render_inventory_grid",
			"Draws the inventory page: the visible 10 cells of the 5x2 grid AND the scroll arrows. "
			+ "Reads g_cursor_scroll_offsets[ctx] (0x80b10) = first visible entry; loops slots 0..9 "
			+ "(draw_panel_slot_tile 0x19ee6 for the empty cell, draw_item_icon_in_slot 0x19f34 for an "
			+ "occupied one, highlight colour if the entry is the selected/held marker), mapping "
			+ "g_cursor_entry_table[offset+slot]; a slot past g_cursor_entry_count stays empty. Then the "
			+ "ARROWS: UP (tile 0xa8) iff offset>0 else erase (0xb0); DOWN (tile 0xb8) iff offset < "
			+ "roundup5(count)-10 else erase (0xc0); tracks which are shown in g_inventory_arrow_state "
			+ "(0x811a0) and records cell/arrow click regions into g_inventory_hotspot_list (0x80bc4). "
			+ "This is the answer to 'how the scroll arrows appear with >10 items'."),
		new NamedFunction(0x1c469L, "refresh_inventory_grid",
			"Dirty-gated wrapper for render_inventory_grid: only redraws when g_inventory_dirty_flags "
			+ "(0x7f571 bit 2) is set; clears it, registers the panel dirty rect, calls "
			+ "render_inventory_grid (0x1c163), then redraws the currently-selected item's name+count label "
			+ "(draw_inventory_entry_label 0x1c020) if its index is within the visible window "
			+ "(cursor - scroll_offset < count). Called from the inventory render path."),
		new NamedFunction(0x1a2b5L, "select_inventory_tab",
			"Switches the inventory TAB: g_cursor_active_list = g_inventory_tab_context_map[ "
			+ "g_inventory_active_tab (0x80b70) ] (0x7123c = {0,1,3,4,2}), rebuilds the entry list (build_inventory_entry_list 0x19d30 "
			+ "directly), re-blits the 5 tab tiles + hotspots, and flags a grid redraw (g_inventory_dirty_flags += 2). Invoked when the player cycles "
			+ "inventory tabs."),
		new NamedFunction(0x1661fL, "handle_cursor_click",
			"Per-frame cursor/mouse interaction handler (from run_gameplay_frame). Builds a click code "
			+ "from the edge flags g_cursor_primary_action_flag (0x7e938) / g_cursor_secondary_action_flag "
			+ "(0x7e939) (+ a pending bit from g_inventory_ui_action 0x80b30), then calls "
			+ "hit_test_dialogue_ui_action (0x1ad2f) with the cursor pos (g_mouse_x 0x707b3 / g_mouse_y "
			+ "0x707b7) to get the widget action code under the cursor. On a non-zero action it calls "
			+ "dispatch_dialogue_ui_action (0x1b4e5, EAX=action, EDX=click) — which is how an arrow/cell/tab "
			+ "CLICK takes effect (e.g. clicking the inventory scroll arrows). Special-cases action 0x27 "
			+ "(dialogue end) and 4 inline. Sets the hardware cursor shape (0x12a08) and clears the click "
			+ "flags. (World right-click inspect goes via examine_object_under_cursor, the sibling path.)"),
		new NamedFunction(0x1b0e3L, "scroll_entry_into_view",
			"Selects a clicked cursor-entry by POINTER and scrolls the grid so it stays visible. EAX = "
			+ "pointer to a g_cursor_entry_table entry; finds its index (linear scan, bounded by "
			+ "g_cursor_entry_count), stores it as the cursor g_cursor_list_positions[ctx] (0x80afc), then "
			+ "clamps g_cursor_scroll_offsets[ctx] (0x80b10): while index < offset, offset -= 5; while "
			+ "index-9 > offset, offset += 5. So clicking an item that's partly off-page scrolls it into "
			+ "the 10-cell window. Called by dispatch_dialogue_ui_action for grid-cell clicks."),
		new NamedFunction(0x19f34L, "draw_item_icon_in_slot",
			"[provisional] Draws a DAS image centred in a grid cell. EAX = DAS image record (item icon), "
			+ "EDX = slot index into g_ui_slot_layout_table (0x71208). Centres by the DAS width/height "
			+ "(reads +4/+6) within the 0x1c (28px) cell, adds g_ui_panel_anchor_x/y, registers the dirty "
			+ "rect, and blits. The item-icon counterpart of draw_panel_slot_tile (which draws the empty "
			+ "cell). Used by render_inventory_grid per occupied cell."),
		new NamedFunction(0x2632aL, "show_resource_error_box",
			"Shows a resource-failure message box: fills the box descriptor g_message_box_state 0x71d05 and calls show_message_box 0x2508f. Used by the DAS/voice loaders on load failure (cf. 'Cannot init .DAS file')."),
		new NamedFunction(0x2febeL, "upload_palette_dac",
			"Uploads 256 RGB palette entries to the VGA DAC (out 0x3c8/0x3c9) from the palette block (DAT_00090bca<<4). If g_damage_flash_level!=0, scales toward the red damage overlay into a scratch buffer, then FUN_0002fefb uploads it."),
		new NamedFunction(0x2ff38L, "refresh_palette_dac",
			"Thin wrapper: re-uploads the palette via upload_palette_dac 0x2febe and returns its arg. Per-frame palette commit (gameplay_frame_step, play_gdv_cutscene)."),
		new NamedFunction(0x18e68L, "blit_reloc_das_image",
			"Core UI/icon sprite draw (39 xrefs): resolves a reloc-table offset (param_2) into the ICONS.ALL blob (g_reloc_base 0x7f56c) and blits that DAS image to buffer param_1 via blit_das_image_to_buffer (honoring hires line-doubling)."),
		new NamedFunction(0x5519eL, "crt_lseek",
			"Watcom C lseek: INT 21h AH=42h, BL=whence, param_2=offset (DX:AX); returns new file position. High-word special-cased via FUN_00056133 when offset bit15 set."),
		new NamedFunction(0x414b6L, "das_cache_make_room",
			"Ensures the DAS cache heap has >= ECX free bytes: loops evict_one_das_cache_slot until block_payload_size(g_das_cache_heap_handle) >= ECX (or eviction fails)."),
		new NamedFunction(0x41bc1L, "dos_get_file_size",
			"Returns a file's size: dos_lseek(handle,0,END) then lseek back to start. (Decomp drops the register-returned size.) Used by init_game_databases, load_disk_path_config."),
		new NamedFunction(0x40a17L, "game_heap_alloc_round4",
			"game_heap_alloc with size rounded up to a 4-byte multiple; returns the pointer (dropped by decomp). Used by load_file_blob, write_snapshot_lbm."),
		new NamedFunction(0x2196aL, "dos_write_u16",
			"Writes one 16-bit value (param_2) to file handle param_1 via dos_write_items(buf,1,handle). Savegame/stream-writer helper (14 xrefs)."),
		new NamedFunction(0x35c03L, "pool_alloc_checked",
			"Validated front-door to pool_carve_chunk: EAX=pool, EDX=size; checks pool!=0, size!=0, hdr[+0xc]==0x18, then falls into the carve body (rounds size+0x10, splits a free chunk). Called by game_heap_alloc, sos_load_driver."),
		new NamedFunction(0x184abL, "activate_weapon_item",
			"Selects/activates an inventory weapon (param_1=id; 0 -> default DAT_00081054): loads its attributes into the active-weapon block g_active_weapon_attrs 0x811b4 via apply_weapon_action_attributes, sets g_selected_item_secondary, and resolves ammo from player inventory. From the use/dialogue UI."),
		new NamedFunction(0x1e2f6L, "entity_def_cache_lookup",
			"Entity-definition attribute cache lookup (LRU, 10 entries). EAX=def-id key. Walks list at g_entity_def_cache_head 0x819d8 comparing word[node+4]; HIT -> move-to-front; MISS -> build via entity_def_cache_build_entry into 108B scratch, append (g_entity_def_cache_count 0x81e14 < 10, array g_entity_def_cache_nodes 0x819dc x0x6c) or evict tail. Node 0x6c: +0 next, +4 key, +6.. attrs. Used by revalidate_entity_def 0x426fc -> compute_projectile_hit_damage."),
		new NamedFunction(0x1e2a4L, "entity_def_cache_build_entry",
			"Builds a cache record: EAX=dst(108B), EDX=def-id. lookup_dbase100_record_by_id 0x1dcac resolves id->DBASE100 record; if found, build_entity_def_record 0x1e128 parses it into dst. Returns 0 on miss."),
		new NamedFunction(0x1e128L, "build_entity_def_record",
			"Fills a 108B entity-definition cache node (ECX=dst, ESI=DBASE100 record). Zero-fills, sets word[dst+4]=word[src+2] (key), then parses the record's +0x14 command section ([size:24|code:8] trigger blocks) extracting attribute fields (combat: +0x2c/+0x2e/+0x46) into the node."),
		new NamedFunction(0x1dcacL, "lookup_dbase100_record_by_id",
			"Resolve a definition id -> its DBASE100 record. EAX=id, EDX=ctx. Searches g_dbase100_base (0x81e1c)/g_dbase100_inventory_table (0x81e20) for word[rec+2]==id, ONLY for ids >= 0x200 (returns 0 below). The id resolver behind the entity-definition attribute cache."),
		new NamedFunction(0x244c8L, "string_length_244c8",
			"[recomp-lift] EAX=str. strlen — returns byte length (excl. NUL). A 3rd strlen-class compiler copy (cf. string_length 0x55bd0)."),
		new NamedFunction(0x57da2L, "string_find_char",
			"[recomp-lift] EAX=str, DL=char. strchr — returns ptr to first occurrence (matches the terminating NUL when DL==0), or 0 if not found."),
		new NamedFunction(0x150faL, "path_basename",
			"[recomp-lift] EAX=path. Returns ptr to the component after the last '\\' (0x5c) — i.e. the filename. (No '\\' -> returns the whole string.)"),
		new NamedFunction(0x1089cL, "cmd_set_hires",
			"[recomp-lift] HIRES / '/H' switch & ROTH.RES @-block flag handler. word[0x90be6] |= 4; if (byte[0x90c08] != 0) word[0x90be6] &= 3. No args. Sets a bit then conditionally masks the flag word."),
		new NamedFunction(0x12504L, "reset_input_ring",
			"[recomp-lift] word[0x7e91c]=0 (head), word[0x7e91e]=0 (tail), word[0x7e91a]=3 (mask). Resets the input ring buffer consumed by input_ring_dequeue (0x1299a). No args."),
		new NamedFunction(0x289bfL, "init_84964_block",
			"[recomp-lift] dword[0x84964]=0xffffffff, dword[0x84970]=0x800000, dword[0x84974]=0. No args (initializes a 3-field block; 0x800000 looks like an 8.0 fixed-point value)."),
		new NamedFunction(0x320a7L, "advance_clamp_8a0f0",
			"[recomp-lift] EAX=increment, EDX=max. dword[0x83e7c]=1; dword[0x8a0f0]+=EAX; if ((u32)[0x8a0f0] >= EDX) [0x8a0f0]=EDX. Advances a counter and clamps it to a max."),
		new NamedFunction(0x11057L, "copy_path_ensure_trailing_slash",
			"[recomp-lift] ESI=src, EDI=dst. Copies the string (incl NUL); if the last real char wasn't '\\' (0x5c), replaces the NUL with '\\' and re-terminates. ESI==0 => no-op. Ensures a path ends with a backslash."),
		new NamedFunction(0x1428aL, "copy_nonzero_bytes_2x",
			"[recomp-lift] EAX=dst, EBX=count, EDX=src. Like copy_nonzero_bytes (0x1426f) but writes each non-zero source byte to TWO adjacent dst bytes (horizontal 2x doubling). No-op if count<=1."),
		new NamedFunction(0x1622dL, "begin_item_pickup_lock",
			"[PICKUP; <- give_item] Arms the 'pickup in progress' lock: sets g_item_pickup_flags (0x7fd84) |= 5 and stashes "
			+ "the just-added item's fields ([0x7fd88]=item id, [0x7fd8c]=qty, [0x7fd90]=EBX, word[0x71150]=CX). The flag "
			+ "blocks re-grabbing in activate_targeted_object until tick_item_pickup_lock clears it (~0x1b frames = the fly "
			+ "duration). The stashed fields feed an eased 0x7114c position that is VESTIGIAL (unused by any renderer); the "
			+ "actual fly is a separate traveling world object."),
		new NamedFunction(0x115b5L, "compute_screen_extents_7e8b0",
			"[recomp-lift] ecx=word[0x707bb]; [0x7e8b0]=[0x85498]*ecx-1; [0x7e8b4]=[0x8549c]*ecx-1. (0x85498=g_screen_pitch.) Computes max pixel extents. No args."),
		new NamedFunction(0x12179L, "compute_view_offsets_90a74",
			"[recomp-lift] eax = -((int32)[0x76874] >> 1); [0x90a74]=eax; [0x8c108]=eax (g_view_pitch_applied); word[0x90a8a] = (word[0x7e8f4] - [0x76870]) low16. Recomputes view/pitch offsets. No args."),
		new NamedFunction(0x1c630L, "approach_value",
			"[recomp-lift] EAX=current, EDX=target, EBX=step (all signed). Moves EAX toward EDX by EBX, clamping at EDX (overshoot snaps to EDX). Returns the new value. A move-toward-target helper."),
		new NamedFunction(0x26f2dL, "clamp_symmetric_26f2d",
			"[recomp-lift] EAX=value, EDX=center, EBX=halfrange (signed). Clamps EAX to [EDX-EBX, EDX+EBX]; returns EAX unchanged if within range."),
		new NamedFunction(0x43dd8L, "interpolate_words_43dd8",
			"[recomp-lift] EAX=dst s16*, EDX=src s16*, EBX=count. Per input word w (sign-extended): writes the pair [ (prev_sum + w) >> 1 (UNSIGNED shr — faithful to the asm, can misbehave on negatives), w ]; prev_sum carries w forward. 2x upsample/interpolate."),
		new NamedFunction(0x3bb1eL, "write_ror_ramp_3bb1e",
			"[recomp-lift] EDI=dst, CX=count, EBP=stride. Writes word[dst+2 + k*stride] = low16(ror(edx,8)) for k=0..CX (CX+1 words), edx starting at [0x8a3d4], stepping by [0x8a3d0] each write. A stepped/gradient word writer."),
		new NamedFunction(0x35d52L, "pool_recompute_max_free",
			"[recomp-lift] ESI=pool. Walks all used-count(+0x14) chunks from pool+hdrsize(+0xc), records the max free-chunk size(+4 of each, skipping allocated bit0) into pool largest-free(+4), and (re-)marks the last chunk's last-flag(bit1). Shared helper of pool_carve_chunk + pool_find_free_chunk."),
		new NamedFunction(0x143b0L, "load_file_blob",
			"[MED] Generic load-entire-file: INT 21h open, LSEEK-end for size, LSEEK-start, "
			+ "malloc(size), read full file, return buffer ptr. Used by load_icons_all to slurp "
			+ "ICONS.ALL into g_reloc_base (the self-relative pointer-table blob)."),
		new NamedFunction(0x4b08cL, "load_backdrop_image",
			"[MED] BACKDROP.RAW decoder (only caller load_backdrop_raw 0x16164). 8-byte header "
			+ "{u16 width@+4, u16 height@+6}; body is RLE (byte<0xf1=literal pixel, byte>=0xf1=run of "
			+ "(byte-0xf0) copies of next byte), streamed in 4KB blocks (0x4b30b). Blits to the "
			+ "framebuffer with horizontal+vertical scaling to fit the current video mode."),
		new NamedFunction(0x10f6cL, "parse_config_ini_paths",
			"[MED] Parses CONFIG.INI install paths (template 0x10f21 SOURCEPATH/DESTINATIONPATH/"
			+ "INSTALLATION) via parse_config_keywords, then fans the roots out into the asset-dir "
			+ "prefixes: g_dir_data 0x763b0, dbase dirs, g_dir_gdv 0x764f0 (SOURCE+GDV\\), g_dir_midi "
			+ "0x76400 (DEST+MIDI\\), g_dir_digi 0x76450 (DEST+DIGI\\). INSTALLATION='MI' keeps movies on CD."),
		new NamedFunction(0x10584L, "set_cfg_asset_name",
			"[MED] Copies an 80-byte config asset-name buffer (src->dest), then if a default extension "
			+ "is given applies it via set_filename_extension 0x2fbbc. load_roth_res @-block uses it: "
			+ "SND-> g_cfg_snd_arg 0x7028c (+.SFX), DAS2-> g_cfg_das2_arg 0x702dc (+.DAS), GDVS-> g_dir_gdv."),
		new NamedFunction(0x2059dL, "play_gdv_cutscene",
			"[MED] GDV cutscene player entry. Allocs a ~1.2MB (0x12c000) streaming decode buffer from the "
			+ "DAS cache (g_das_cache_heap_handle) and runs the frame decode/blit loop. Path is built as "
			+ "<g_dir_gdv><name>.GDV (extension 'GDV' 0x564447 applied via set_filename_extension)."),
		new NamedFunction(0x2f4b4L, "load_raw_map_file",
			"[HIGH] Loads a .RAW map. Validates signature 'WR' (0x5257) at header+0x0e and "
			+ "version 0x70 at header+0x02, then reads the geometry/commands/SFX/objects/footer "
			+ "sections into heap buffers. Section bases land in g_map_geometry_buffer etc."),
		new NamedFunction(0x2f782L, "fixup_raw_sectors_after_load",
			"[MED] Walks the 0x1a-byte sector records through the geometry selector and patches "
			+ "sectors whose field +0x14 (FLOOR_TRIGGER_ID) equals -3 (0xfffd)."),
		new NamedFunction(0x303ffL, "run_leftclick_object_trigger",
			"[MED-HIGH] Entry-command CATEGORY-1 trigger handler for a left-clicked object. param_1 = the "
			+ "clicked object (param+0xe = its ID). Reads the command table header g_object_table_header: "
			+ "+8 = category-1 entry-ref offset, +0xa = count; walks the entry-command-references, and for "
			+ "the command whose +8 (Object ID arg) matches the object, dispatches on `cmp byte[rec+3]` "
			+ "(COMMAND_BASE): 0x02 Light Switch (-> FUN_00033b94 predicate, then play_sound_effect 0x27270 "
			+ "= the switch click SFX, toggles "
			+ "obj+4 bit0) / 0x08 On-Left-Click-Object (-> walk_command_chain_flow 0x353c4 with rec+4 = "
			+ "NEXT_COMMAND). Confirms .RAW command struct: +2 modifier(bit3=skip), +3 base, +4 next."),
		new NamedFunction(0x353c4L, "walk_command_chain_flow",
			"[HIGH] Command-chain FLOW/CONDITION walker (NOT the opcode switch). Takes a NEXT_COMMAND "
			+ "index; loop: cmd = resolve_command_by_index (0x315a7); stop if index==0 or cmd==0; acts ONLY "
			+ "on flow-control opcodes - COMMAND_BASE 0x12 Delay-Timer ((mod&4)==0 && (mod&0x21)!=0 -> stop) "
			+ "and 0x1e Modify-Count (if cmd+8 sub-index != 0, recurse on it; stop if that returns nonzero "
			+ "- conditional branch); all other bases are skipped, follow NEXT = cmd+4. Returns a gate value "
			+ "(0 = chain clear) that the trigger uses to decide whether to run the chain. The per-opcode "
			+ "EXECUTION (give-item/warp/spawn/...) is downstream: run_leftclick_object_trigger calls "
			+ "FUN_0003065a + FUN_0003484b when this returns 0 - those (esp. 0x3065a) hold the real switch."),
		new NamedFunction(0x3065aL, "execute_command_chain",
			"[HIGH] THE command executor. Walks a command chain (NEXT = cmd+4, resolved via "
			+ "resolve_command_by_index) and for each command (unless modifier bit3 set) DISPATCHES via "
			+ "`g_command_dispatch_table[byte[cmd+3] & 0x7f]()` (table at 0x30780). Accumulates handler "
			+ "results into 0x8a138, stops the chain on COMMAND_BASE 0x12 (Delay Timer), and on completion "
			+ "applies post-effects (play_sound_effect 0x27270 + 0x2730b SFX, left-click toggle) and flushes the deferred "
			+ "queue. 64/128 opcodes implemented; see ROTH_command_system_notes.md for the full table."),
		new NamedFunction(0x3065eL, "finalize_command_chain",
			"[command executor] The COMPLETION/post-effects entry of the executor — shared code with "
			+ "execute_command_chain (0x3065a), entered 4 bytes in (Watcom multi-entry). On chain end (handling the "
			+ "g_command_chain_interrupt state): plays the chain's queued sound (DAT_8a264-1 via play_sound_effect or "
			+ "play_command_sound), applies the left-click STATE TOGGLE when the source command is type 8 with the "
			+ "right flags (XORs bit0 of DAT_8a134+4 = the door/switch toggle), then finish_dialogue_record_eval and "
			+ "resets the chain state (DAT_8a26c/89f60). Also called directly by reset_command_chain_state (0x305b6)."),
		new NamedFunction(0x3484bL, "process_deferred_command_queue",
			"[MED] Double-buffered deferred-command flush. Swaps the two queue pointers "
			+ "PTR_DAT_00071f40 / PTR_DAT_00071f44, then for each queued entry resolves its command "
			+ "(FUN_00034d14 / g_raw_state_primary_buffer-relative) and runs it via FUN_000305b6. Called "
			+ "by execute_command_chain to run commands deferred during the current chain."),
		// --- World-state: object-table init + effect-record builders (0x31/0x33 region) ---
		new NamedFunction(0x33f0eL, "init_loaded_object_table",
			"[map/save load; verified — caller set_state_record_count 0x33c3e] Post-load object-table init: resets "
			+ "the chunk-4 save-link context globals (g_state_link_word_a/b, g_state_link_obj_ptr, g_state_link_buf_ptr, "
			+ "0x8a140/0x8a144), installs the link callbacks (0x90a34=0x33cf3, 0x8a2a0=0x33dde), then if "
			+ "g_object_table_header has the 0x7533 magic: flag_referenced_object_textures + rebuild_object_pointer_array "
			+ "+ walks the live objects. Rebuilds the runtime object table after a map/save load."),
		new NamedFunction(0x33c49L, "flag_referenced_object_textures",
			"[map load; verified — caller init_loaded_object_table] Walks the object table (g_object_table_header "
			+ "0x85c30, two lists at +0x28/+0x2a and +0x3c/+0x3e) and marks each object's texture id as referenced by "
			+ "OR-ing bit0 into the DAS entry-status table g_das_entry_status_table (0x86d30+id*2); for animated entries (flag+6 bit0) "
			+ "resolves base+0x1000. Pre-flags which textures the placed objects need so they get loaded."),
		new NamedFunction(0x329d5L, "build_effect_record_from_matches",
			"[world/effects; verified — caller cmd_scroll_face_texture 0x324a7] Collects the raw-state records "
			+ "matching a key (collect_raw_state_matches), allocates an effect record sized to hold them "
			+ "(alloc_effect_record) and copies the match list in (at +param_2). The generic 'register an effect over "
			+ "a matched geometry set' helper (used by the animated/scroll texture commands)."),
		new NamedFunction(0x310bcL, "build_damage_emitter_from_matches",
			"[world/effects] Damage-emitter variant of build_effect_record_from_matches: collect_raw_state_matches "
			+ "then register_damage_emitter (instead of alloc_effect_record) and copies the matched faces in. Builds "
			+ "a damage-over-time emitter (lava/spikes face) from a matched geometry set."),
		new NamedFunction(0x31176L, "register_object_state_effect",
			"[world/effects] Registers a per-object state effect if the object is idle (obj+2 & 0x21 == 0): "
			+ "snapshot_keyed_secondary_records(obj+8) -> effect record, links source (effect+8=obj), the object-table GENERATION stamp "
			+ "(g_object_table_generation 0x911c7 -> effect+0xc; the tick re-resolves when it differs = table relocated, NOT a countdown), COMMAND_BASE (obj+3 -> effect+4), marks obj+2 bit0x20. Returns -1. The "
			+ "effect-registration helper shared by the per-object timed commands."),
		// --- World-state: object-trigger execution + save-state object links (0x35 region) ---
		new NamedFunction(0x35735L, "write_state_object_links",
			"[savegame chunk-4 WRITE; verified — caller write_state_record_list 0x35648, exact mirror of "
			+ "load_state_object_links 0x35839] Per-object writer for the relocatable link/reference fields: "
			+ "find_object_index_by_ptr -> 1-based index into EDI[0], then by object type (CL = obj+3) writes "
			+ "obj+5/+6/+0xc, RELOCATING the pointer fields to buffer-relative (obj+0xc - g_sfx_nodes for "
			+ "types 3/7; - g_raw_state_primary_buffer | 0xffff0000 for type 0x12). The save-side inverse of the "
			+ "load relocation (load ADDs the base, this SUBTRACTS it)."),
		new NamedFunction(0x3534bL, "fire_wall_object_trigger",
			"[world/triggers; verified — caller collide_ray_walls_recursive 0x3fae0] Fires a wall-mounted object's "
			+ "trigger when a movement/use ray hits the wall: computes the wall midpoint (from the two edge vertices "
			+ "via g_sector_geom_base+8/+10) into the trigger source position DAT_8a260/8a262, sets g_active_object, "
			+ "looks up the object (find_object_list20 by obj+0xc) and runs its trigger via exec_object_contact_trigger."),
		new NamedFunction(0x351cdL, "exec_object_contact_trigger",
			"[world/triggers] Runs an object's contact/use trigger if it's idle (obj+2 flags & 0x29 == 0): clears the "
			+ "pending-record state (DAT_8a0dc/DAT_8a134) and calls fire_trigger_on_contact at the position. The "
			+ "trigger-execution wrapper used by the wall/contact path."),
		new NamedFunction(0x3520bL, "exec_object_trigger",
			"[world/triggers] Runs an object's trigger if idle (obj+2 & 0x29 == 0) via fire_trigger_on_contact; "
			+ "the variant used by begin_object_command_chain (0x35303). Clears DAT_8a0dc."),
		new NamedFunction(0x345e2L, "tick_command_timer_queue",
			"[world/effects; verified — caller tick_world_effects 0x3464c] Per-frame tick of the delayed-command "
			+ "timer queue (DAT_89fc0, stride 2 dwords = {timer, command ptr}, param_1 entries): decrements each "
			+ "timer by g_frame_time_scale and, when one expires (<0) and its command isn't disabled (cmd+2 bit3), "
			+ "clears the chain source state and fire_queued_command. The runtime side of cmd_delay_timer (0x12)."),
		new NamedFunction(0x30549L, "run_object_commands_by_id",
			"[world/commands; verified — caller execute_dbase100_chain 0x1d430] Finds the world object whose id "
			+ "(obj+8) == param_1 and flag obj+2 bit3 clear in g_object_table_header, then runs its command chain "
			+ "(reset_command_chain_no_source on obj+4 with DAT_8a26c=1). The dbase100 -> RAW bridge for 'activate "
			+ "object N'."),
		new NamedFunction(0x305a1L, "reset_command_chain_no_source",
			"[command executor] reset_command_chain_state wrapper that also clears the positional source "
			+ "(DAT_8a260 = 0x80008000 'no position' sentinel) and the queued sound (DAT_8a264). Used to prime a "
			+ "fresh command chain run."),
		new NamedFunction(0x31f3cL, "register_command_save_link",
			"[world/savegame; verified — callers fire_trigger_on_contact/interact 0x31fb0/0x31ffe] After a trigger "
			+ "fires, finalizes the chain (reset_command_chain_state + process_deferred_command_queue) and records "
			+ "the chunk-4 SAVE-LINK context for the touched object: by obj+6 flags (0x40/0x20) stores the object ptr "
			+ "(g_state_link_obj_ptr) and current g_player_sector into g_state_link_word_a/word_b/buf_ptr, so the "
			+ "object's references can be relocated on reload. Returns -1."),
		new NamedFunction(0x35201L, "exec_object_trigger_no_source",
			"[world/triggers] Trigger-fire wrapper (sibling of exec_object_contact_trigger): clears the source "
			+ "position (DAT_8a260=0x80008000) + pending state, and if the object is idle (obj+2 & 0x29 == 0) calls "
			+ "fire_trigger_on_contact. Used by the tracked/wall trigger paths (0x35260/0x3534b)."),
		new NamedFunction(0x35260L, "fire_tracked_object_trigger",
			"[world/triggers] Fires an object's trigger while tracking the (possibly spawned) secondary-buffer record: "
			+ "find_object_list40 by obj+0xe; if the object isn't a registered effect (obj+6 bit1 clear) runs FUN_35201, "
			+ "else temporarily renames the object to id 0xc200, runs the trigger, then collect_secondary_state_records_"
			+ "by_key(0xc200) to recover the spawned record and restore its id (+marks it via DAT_8a138). [name hedged.]"),
		new NamedFunction(0x30ab0L, "cmd_default_nop",
			"[LOW] Default/no-op handler that fills the unused slots of g_command_dispatch_table "
			+ "(0x30780). A dispatch-table entry pointing here means that COMMAND_BASE is unimplemented."),
		// --- High EXECUTE bases 0x40-0x42 (disasm-verified 2026-06-19; uncarved targets of g_command_dispatch_table,
		//     naming DEFINES them). These complete the EXECUTE table beyond the BTI-documented 0x00-0x3f range. ---
		new NamedFunction(0x304b8L, "cmd_run_indexed_object_command",
			"[.RAW EXECUTE base 0x40 — disasm-verified] Indirect/call command: takes object index = word[cmd+6] (0 = "
			+ "no-op), resolves the (index-1)th object via g_object_ptr_array (0x8a0d8), and — unless it is disabled "
			+ "(obj+2 bit0x8) — dispatches THAT object's command (base = obj+3 & 0x7f) recursively through the EXECUTE "
			+ "table 0x30780. Lets one command fire another object's command chain."),
		new NamedFunction(0x30ab3L, "cmd_set_player_speed_reduction",
			"[.RAW EXECUTE base 0x41 = BTI 'Slow Player Speed' — disasm+effect-verified] Stores cmd+7 (byte) into "
			+ "g_player_speed_reduction_request (0x89f54), honors the sticky-flag (record+6 bit0x10 -> record+2 |= 8), "
			+ "returns -1. EFFECT: tick_world_effects (0x3464c) latches 0x89f54 -> g_player_speed_reduction_shift "
			+ "(0x89f58) each frame (then clears 0x89f54, so it must re-fire per frame = continuous while in the sector); "
			+ "player_movement_tick (0x12520) then does player_vel_x/y >>= (shift & 0x1f) when the shift != 0. So cmd+7 is "
			+ "a velocity RIGHT-SHIFT count (1=half speed, 2=quarter, ...), NOT a linear value. (Was the generic "
			+ "cmd_store_param_byte; renamed 2026-06-24 to the BTI-confirmed effect.)"),
		new NamedFunction(0x30f63L, "cmd_set_inventory_filter",
			"[.RAW EXECUTE base 0x42 = BTI 'Take Inventory' — disasm+playtest-verified] Calls set_inventory_list_filter "
			+ "(0x1ca2e) with cmd+6 bit0: bit0=0 marks every slot whose DBASE100 ITEM_TYPE low nibble (entry+0x05 & 0x0f) "
			+ "!= 2 with the HIDDEN bit (0x80) -> the inventory LOOKS emptied. The kept category 2 = BTI 'characters and "
			+ "important info' (ITEM_TYPE 0x02) + 'Adam Randall' (0x12) = the people/concepts topics + key info; "
			+ "weapons/ammo/coins/readables/consumables (other nibbles) all hidden — in-game verified, NOT 'stackable' "
			+ "(stackable is the SEPARATE 0x20 flag bit). Also clears the selection "
			+ "+ resets the weapon HUD; bit0=1 clears the hidden bit on ALL slots -> everything visible again ('given "
			+ "back'). Honors the sticky-flag (cmd+6 bit0x10 -> cmd+2 |= 8), returns -1. It is a DISPLAY FILTER — items "
			+ "are NEVER removed from g_inventory_slots, just hidden/shown (this is the puzzle area that 'takes' then "
			+ "'returns' your inventory). (Was cmd_refresh_inventory_list; renamed 2026-06-24.)"),
		// --- Remaining RAW command-table handlers (BTI cross-walk + disasm-verified 2026-06-19). ---
		// These are dispatch-table-only targets Ghidra never carved as functions; names from the BTI
		// RAW.md/DBASE100 cross-walk (ROTH_command_system_notes.md "BTI command-list cross-walk"),
		// with 6/13 bodies disasm-confirmed (rotation/id/height/sfx/jump/timer all matched).
		new NamedFunction(0x30acbL, "cmd_player_rotation",
			"[.RAW cmd 0x3f 'Player Rotation', decompile-verified] Rotates the player facing g_player_angle "
			+ "(0x90a8a): delta = -(cmd+7)*2. cmd+6 flags: bit 0x2 = randomize delta via the AI LCG "
			+ "(g_command_rng 0x71f48, *0x5e5+0x29) and set cmd+2 bit3; bit 0x1 = frame-rate-independent accumulate "
			+ "(g_player_angle += delta * g_frame_time_scale (0x85324)) else g_player_angle = delta. Returns -1."),
		new NamedFunction(0x30b23L, "cmd_empty_allow_sfx",
			"[.RAW cmd 0x3e 'Empty (Allow SFX)', disasm-verified] No-op body (`or eax,-1; ret`) — like cmd_default_nop "
			+ "but at its own slot so the chain's post-effect SFX still fires (vs the silent default)."),
		new NamedFunction(0x30b45L, "init_command_timer_countdown",
			"[command-timer helper, disasm-verified — called by fire_queued_command 0x30b7c] Initialises a newly-queued "
			+ "command-timer node (EBX): countdown = cmdrec+6 (word), optionally randomized (* g_command_rng>>16) when "
			+ "cmdrec+2 bit0x2 is set; stores node+0 = countdown+1 and node+4 = the source command record (ESI). The "
			+ "Delay-Timer/repeat-count seed; the node is ticked down by tick_command_timer_queue (0x345e2). "
			+ "Register-context (node in EBX, command record in ESI)."),
		new NamedFunction(0x30bb7L, "mark_object_trigger_links",
			"[object wiring, disasm-verified — called by cmd_change_object_id 0x31000 & cmd_spawn_object_adv 0x30d10] "
			+ "Scans the world object/trigger table (g_object_table_header, records from header+4, count header+6, "
			+ "stride = record[+0]) for records that reference object id param_2 (record word[+4]==id), and sets the "
			+ "matching link bit in the target object's flag byte (param_1+9): record type 0x1b -> bit0x20, '0'(0x30) -> "
			+ "bit0x8, '9'(0x39) -> bit0x4. Run after a spawn / id change so the object knows which trigger types wire to it."),
		new NamedFunction(0x30c1aL, "object_has_active_trigger_link",
			"[predicate, disasm-verified — called by 0x1624d under run_gameplay_frame] Returns -1 if an enabled "
			+ "(record+2 bit0x8 clear) record in the object/trigger table references the object/cell param_1, else 0. "
			+ "param_1+1 selects the class: ==4 scans the header+0x24 list for a type-0x1b record matching the object id "
			+ "(word at *(param_1+0xe)+0xe); ==3 scans the header+0x20 list for a type-0x1a record matching the raw-state "
			+ "cell id (g_raw_state_primary_buffer). Used to decide whether the object/cell is currently wired to fire."),
		new NamedFunction(0x30d10L, "cmd_spawn_object_adv",
			"[.RAW cmd 0x3c 'Spawn Object (Adv)', BTI cross-walk] Advanced object-spawn variant of cmd_spawn_object "
			+ "(0x16); registers/instantiates an object from the command record. Helper spawn_object_from_das_resource "
			+ "(0x302e0) does the resource-driven instantiation."),
		new NamedFunction(0x302e0L, "spawn_object_from_das_resource",
			"[.RAW spawn helper, disasm-verified — called by cmd_spawn_object_adv 0x30d10] Instantiates an object whose "
			+ "appearance is a DAS resource id (param_2&0xffff >= 0x200): indexes the DAS FAT g_ademo_das_fat_buffer at "
			+ "(id-0x200)*8, requires the entry type tag byte[+6]=='$', then spawns the runtime entity via "
			+ "spawn_entity_into_state_pool_a (0x4f00d, passing the resource file id byte[+7]). On a successful slot it "
			+ "drops the object (g_state_pool_a-adjacent per-slot arrays 0x91e0e/0x91e1d), nudges Y (cmdrec+0xa -= 0x50, "
			+ "sets cmdrec+7 bit0x40), plays the def's spawn sound (play_entity_sound), and orients it toward the player "
			+ "via compute_player_object_bearing (0x30389 -> cmdrec+6). Returns -1 on spawn, 0 if the resource id is "
			+ "invalid/below 0x200."),
		new NamedFunction(0x30389L, "compute_player_object_bearing",
			"[disasm-verified — shared by spawn_object_from_das_resource 0x302e0, cmd_rotate_object 0x3146d, "
			+ "cmd_spawn_object_adv 0x30d10] Returns the bearing between the player and an object as an 8-bit facing: "
			+ "atan2_bearing(g_player_x int@0x90a8e, ESI[1]=objY, ESI[0]=objX) (delta vs player position; player Y in BX), "
			+ "result >> 1 to fold the 9-bit (0x1ff) bearing into the 0-255 object-facing range. Used to make a spawned/"
			+ "rotated object face the player. Register-context (object position in ESI)."),
		new NamedFunction(0x4f00dL, "spawn_entity_into_state_pool_a",
			"[entity spawn — disasm-verified; GAME logic despite the high VA] Registers a new runtime entity into the "
			+ "16-slot save/load pool A (g_state_pool_a_records, stride 0x22): finds the first free slot (slot[+4]==0, "
			+ "capacity g_state_pool_a_count<0x10), resolves the entity def via entity_def_cache_lookup(obj word@ESI+4), "
			+ "allocates the 0x68-byte runtime record from base 0x85cf4 (index in ECX), links slot<->record, copies the "
			+ "def's flags (rec+0x69 -> slot+9) and base offset (rec+8 -> slot+0xc), stamps the def id, back-links the "
			+ "object (ESI+0xc = slot index, ESI+9 |= 1), and bumps g_state_pool_a_count. Called by 0x2c720 (map load) "
			+ "and spawn_object_from_das_resource. Register-context (object record in ESI)."),
		new NamedFunction(0x301ebL, "remap_rgb_to_palette_indices",
			"[palette quantizer — disasm-verified] Maps param_1 source RGB triples (param_2, 3 bytes/pixel) to the "
			+ "nearest palette index, output to the EDI/EBX dest buffer. Builds a luminance-weighted scaled copy of the "
			+ "live 256-entry palette (0x90bca<<4 palette block; weights R*0x28/G*0x40/B*0x18 ~= 0.31/0.5/0.19 perceptual) "
			+ "in a 768-short stack table, then for each source pixel picks the index minimizing the summed weighted "
			+ "abs-difference (early-out on an exact match). Register-context (dest in EBX)."),
		new NamedFunction(0x10d67L, "remap_builtin_palette_image",
			"[startup, hedged] Remaps a built-in RGB block (count DAT_7041a, data &DAT_7041c) to the current palette via "
			+ "remap_rgb_to_palette_indices (0x301eb), then runs 0x10d90 + noop_stub_10d87. Called from roth_main_sequence "
			+ "and 0x1107e — likely re-quantizes an embedded image/gradient to the loaded palette at init (purpose of the "
			+ "block not yet pinned)."),
		new NamedFunction(0x31000L, "cmd_change_object_id",
			"[.RAW cmd 0x3a 'Change Object ID', disasm-verified] Sets the target object's id word (obj+0xe) from "
			+ "cmd+6; if cmd+6 == -1 mints a fresh id (0x8a0c0 counter, high byte 0xc1). Clears obj+9 low bits and, "
			+ "if non-zero, calls 0x30bb7. Target object = 0x8a100."),
		new NamedFunction(0x31107L, "cmd_change_object_height",
			"[.RAW cmd 0x23 'Change Object Height', disasm-verified] Registers a height-change EFFECT for the object: "
			+ "alloc_effect_record (via 0x32a20), links the source command (effect+8=cmd), stamps the object-table GENERATION "
			+ "(g_object_table_generation 0x911c7 -> effect+0xc; the tick re-resolves the object when it differs, NOT a countdown), the direction (cmd+2 bit1 -> effect+5 bit0x80) and COMMAND_BASE (cmd+3 -> "
			+ "effect+4); marks cmd+2 bit0x20 registered. tick'd each frame like the moving-sector effects."),
		new NamedFunction(0x31326L, "cmd_dbase100_if_next_fails",
			"[.RAW cmd 0x36 'DBASE100 if next fails', BTI cross-walk] Flow-control: STAGES this command as the "
			+ "pending DBASE100 record (0x8a0dc; also clears g_item_autoselected_flag, returns 0) — it does NOT run "
			+ "a dbase100 action here. The staged record is run later by run_command_dbase100_record (0x3540b -> "
			+ "eval_dialogue_record_by_id) if a following conditional command (cmd_if_not_item / cmd_if_not_flag / "
			+ "cmd_count) reaches its fail path."),
		new NamedFunction(0x31339L, "cmd_activate_sfx_node",
			"[.RAW cmd 0x10 'Activate SFX Node', disasm-verified] Toggles/sets the active flag (bit0x80 of node+8) "
			+ "of the SFX node(s) (g_sfx_nodes 0x85c44, 0x12-byte) resolved from cmd+8 via 0x43ab4; cmd+6 bits "
			+ "select toggle(default)/set(bit1or2)/clear(bit2)."),
		new NamedFunction(0x31563L, "cmd_toggle_command",
			"[.RAW cmd 0x17 'Toggle Command', BTI cross-walk] Toggles a command/state (the flip-flop variant in the "
			+ "RAW command set)."),
		new NamedFunction(0x318fdL, "cmd_count",
			"[.RAW cmd 0x15 'Count', BTI cross-walk] Counter command — drives an animated texture/state counter "
			+ "(cf. cmd_texture_change_count 0x1f, cmd_count_addl_arg 0x22; see the counter step table 0x71f30). "
			+ "Per-frame tick = step_count_command (0x3192d)."),
		new NamedFunction(0x3192dL, "step_count_command",
			"[counter tick — disasm-verified; the per-frame worker of cmd_count 0x318fd] Advances the command's counter "
			+ "via the step fn g_anim_step_fn_table[g_anim_step_mode] -> cmdrec+0xa (current). When it reaches the target "
			+ "cmdrec+0xc: clears g_command_chain_interrupt/g_anim_step_mode/0x8a0dc and returns -1 (done). Otherwise, if "
			+ "a pending record is flagged (0x8a0dc) and 0x89f60==0, fires it via run_command_dbase100_record. The plain "
			+ "counter (no state write). Register-context (command record in ESI)."),
		new NamedFunction(0x319c0L, "step_count_apply_to_primary_cells",
			"[counter tick — disasm-verified; worker of cmd_texture_change_count 0x3198e] Steps the counter (as "
			+ "step_count_command) then writes the value (cmdrec+0xa-1 + base cmdrec+0x10) into every matching primary "
			+ "raw-state cell: collect_raw_state_matches(cmdrec+0xe) -> for each, g_raw_state_primary_buffer[off + field], "
			+ "field = 6/4/2 chosen by cmdrec+6 bits 1/2 (which surface tex/state). Done at target; else "
			+ "flush_pending_command_record. Register-context (ESI)."),
		new NamedFunction(0x31a94L, "step_count_apply_to_secondary_records",
			"[counter tick — disasm-verified; worker of cmd_count_addl_arg 0x31a62] Steps the counter then writes the "
			+ "value into every matching secondary state record (collect_secondary_state_records_by_key(cmdrec+0xe) -> "
			+ "g_raw_state_secondary_buffer[off+4]). Done at target cmdrec+0xc; else flush_pending_command_record. "
			+ "Register-context (ESI)."),
		new NamedFunction(0x31b4fL, "step_count_apply_to_geometry_faces",
			"[counter tick — disasm-verified; worker of cmd_animate_facegroup_texture 0x31b1a] Steps the counter then "
			+ "writes the value (cmdrec+0xa-1 + cmdrec+0x10) into matching geometry faces: matches via geom_find_matches "
			+ "(or 0x4f3d0 when cmdrec+2 bit4 set); field offset 6/8 by cmdrec+6 bit1, with a bit2 variant that follows "
			+ "the cell's +0x18 indirection to write field+6. Done at target; else flush_pending_command_record. "
			+ "Register-context (ESI)."),
		new NamedFunction(0x31a62L, "cmd_count_addl_arg",
			"[.RAW cmd 0x22 'Count (AddlArg)', BTI cross-walk] Counter command variant taking an additional argument; "
			+ "sibling of cmd_count (0x15)."),
		new NamedFunction(0x31c31L, "cmd_modify_count",
			"[.RAW cmd 0x1e 'Modify Count', cross-walk + flow-confirmed] Modifies a counter; flagged by "
			+ "walk_command_chain_flow as a flow-affecting opcode (acts when cmd+8 sub-index != 0)."),
		new NamedFunction(0x30f55L, "cmd_jump_if_next_fails",
			"[.RAW cmd 0x38 'Jump if Next Fails', disasm-verified] Stores a jump target/count (cmd+8) into the "
			+ "chain skip register 0x8a0cc so the executor skips ahead if the next command fails. Flow-control."),
		new NamedFunction(0x32195L, "cmd_delay_timer",
			"[.RAW cmd 0x12 'Delay Timer', disasm-verified] Registers a delay-timer effect: alloc_effect_record "
			+ "(0x34464), links the command (effect+8), stores the delay (0x8a0fc/0x8a0c4 -> effect+0xc); the chain "
			+ "stops/defers here and re-runs after the timer. The mechanism behind the executor's 0x12 stop."),
		new NamedFunction(0x315a7L, "resolve_command_by_index",
			"[HIGH] Resolves a 1-based command index to a command-record pointer: returns "
			+ "(*g_object_ptr_array)[index-1] (4-byte ptr entries), or 0 for index 0. NOT a dispatcher - "
			+ "just the NEXT_COMMAND/index resolver used throughout the command system."),
		new NamedFunction(0x33b94L, "cmd_light_switch",
			"[MED-HIGH] COMMAND_BASE 0x02 (Light Switch) handler. esi = the command record. Toggles a "
			+ "light/animated value: cVar2 = esi[7] (delta), negated unless esi[6]&8 (direction); "
			+ "esi[0xc] += cVar2; flips direction bit esi[6]^=8 and state bit esi[2]^=2. Registers an "
			+ "ACTIVE-EFFECT record via find_active_effect (0x32606, type 2) / alloc_active_effect "
			+ "(0x32910, key esi[10], size 0xc), storing the command base (esi[3]) at rec+4 and a "
			+ "back-pointer at rec+8. Returns -1 (done)."),
		new NamedFunction(0x30f51L, "cmd_06_empty_noop",
			"[MED] COMMAND_BASE 0x06 handler: `or eax,-1; ret`. Empty/reserved no-op (returns -1), "
			+ "same shape as the documented Empty commands 0x01/0x3e. Undocumented in BTI RAW.md but inert."),
		new NamedFunction(0x315c4L, "cmd_sync_facegroup_texture",
			"[MED-HIGH, CONFIRMED] COMMAND_BASE 0x14 (UNDOCUMENTED in RAW.md, functional/map-authorable). "
			+ "Sync/advance face-group texture: gather_faces_by_id (0x34c38) collects all faces with Face "
			+ "ID = cmd+8; sets their slot texture to (reference.slot + 1) where reference = cmd+0xa (or "
			+ "first matched face if 0). Slot via cmd+6: bit0->LOWER(+6), bit1->UPPER(+4), else MID(+2); "
			+ "bit4 sets cmd+2 bit3 (dirty). Returns -1 if any changed. SIZE 0x0c. One-shot lockstep "
			+ "texture bump. See ROTH_command_system_notes.md."),
		new NamedFunction(0x31b1aL, "cmd_animate_facegroup_texture",
			"[MED-HIGH, CONFIRMED] COMMAND_BASE 0x21 (UNDOCUMENTED in RAW.md, functional/map-authorable). "
			+ "MULTI-FRAME texture animation over a face group. Sets chain-interrupt g_command_chain_interrupt "
			+ "(0x8a268)=1 so it advances one step per tick. Counter cmd+0xa (RUNTIME STATE) stepped via "
			+ "g_anim_step_fn_table[g_anim_step_mode] (0x71f30[0x8a104]); paints all faces with Face ID = "
			+ "cmd+0xe to texture (cmd+0x10 base + counter - 1); bounds cmd+8 (max/wrap, cmd+6 bit5) and "
			+ "cmd+0xc (end -> finish, clear flags). SIZE 0x12. See ROTH_command_system_notes.md."),
		new NamedFunction(0x34c38L, "gather_faces_by_id",
			"[MED] Collects geometry records (faces) matching a given ID into a caller stack buffer; "
			+ "returns the count. Used by the texture-animation commands (0x14, 0x21) to paint a whole "
			+ "group of faces at once. Variants 0x4f313 / 0x4f3d0 (selected by command modifier bit2)."),
		new NamedFunction(0x32606L, "find_active_effect",
			"[MED, provisional] Active-effect pool lookup by type (arg = type id, e.g. 2 for light "
			+ "switch). Part of the runtime pool of timed/animated command effects (lights, moving "
			+ "sectors, texture cycles) that the per-frame tick advances. Returns the record or 0."),
		new NamedFunction(0x32910L, "alloc_active_effect",
			"[MED, provisional] Allocates/finds an active-effect record (args: target key, record "
			+ "size e.g. 0xc) in the runtime active-effect pool. Used by command handlers (e.g. "
			+ "cmd_light_switch 0x33b94) to register an ongoing effect keyed to a target id."),
		new NamedFunction(0x43c46L, "setup_sfx_nodes",
			"[MED] Post-load SFX setup (called from FUN_0002f6e6). Walks the SFX section at "
			+ "g_sfx_nodes (0x85c44): count = word[+2], 0x12-byte nodes from +4 (BTI RAW.md SFX "
			+ "node). For continuous nodes (byte[+8] & 0x80, low3 > 1) computes word[+0xe] = word[+0xc]*7/2."),
		new NamedFunction(0x3bfe5L, "isqrt_fixed",
			"[HIGH] Fixed-point integer square root. Uses BSR to normalise the input and a "
			+ "lookup table at 0x8a446. Input in EAX, result returned in EAX/EDX. Called after "
			+ "dx*dx + dy*dy to produce a planar distance."),
		new NamedFunction(0x3c201L, "atan2_bearing",
			"[HIGH] Fixed-point atan2. Decomposes into octants (sign/swap flags in EBP) and uses "
			+ "an arctangent table at 0x8aa46. Used to compute the bearing from one point to "
			+ "another (e.g. player->object aiming)."),
		new NamedFunction(0x43187L, "entity_apply_vertical_movement",
			"[HIGH, decompiler-verified] Per-entity vertical (height) GRAVITY/fall integrator. The 16.16 "
			+ "height is at struct +0xc (integer part in the high word). A vertical-velocity accumulator "
			+ "lives at ESI+6 (word) and ACCELERATES by +2 each tick (gravity); height moves by "
			+ "height - vel*0x10000, i.e. the velocity is integrated into position - this is the jump/"
			+ "fall arc. Two regimes: (1) constrained branch (flag bit 4 at ESI+10 clear and [ESI]+4 !=0) "
			+ "tracks toward a target relative to the player Z (DAT_00090a90) in smaller +/-0x20000 steps; "
			+ "(2) free branch steps toward the target height at +8, falling at the accelerating velocity "
			+ "or rising in +0x80000 (8.0) steps. ALL paths CLAMP to the sector floor/ceiling limits "
			+ "(+0x10 / +0x12, with a 0x20 margin) so motion is incremental and never tunnels through a "
			+ "floor. Ends with a LOCKed sector-change callback (add_secondary_state_record) when the entity's sector "
			+ "field (+0x16) changes. Landing = velocity reset, flags cleared (& 0xf9)."),
		new NamedFunction(0x42300L, "spawn_object_projectile_at_player",
			"[RENAMED 2026-06-16, was the mislabel 'check_object_player_proximity' — it does NOT just "
			+ "test proximity, it SPAWNS.] Object/enemy projectile emitter: builds a projectile template "
			+ "from the object's def (init_inventory_item_object param_1), measures planar distance to the "
			+ "player (isqrt_fixed, gated by a +/-0x10 Z window around player eye height + g_spawn_projectile_is_player "
			+ "0x911cb) to derive an aim/lead factor, then unconditionally spawn_entity_at_position(0x4254e) "
			+ "at the object position (param_2) and inits the new projectile entity's fields (+8=0, +9 flags, "
			+ "velocity +0x16, +0x1a, source +5). Returns the spawned entity. Called ONE-SHOT from the pool-A "
			+ "proximity-trigger branch (tick_dynamic_entities, +8&0x08) when the actor's age counter +0x1a "
			+ "reaches its delay threshold +0x1e and its projectile-def field +7 is set. This is the NPC/object "
			+ "analogue of the player's spawn_projectile_from_aim (0x42400) and is the strongest candidate for "
			+ "the ENEMY RANGED ATTACK / projectile-trap emitter (Alex: some enemies have ranged attacks) "
			+ "[HYP on the exact 'ranged enemy attack' role vs generic player-triggered projectile]."),
		new NamedFunction(0x43413L, "check_entity_player_contact",
			"[MED] Entity-vs-player contact test. Chebyshev max(|dx|,|dy|) minus a radius "
			+ "(0x30 or 0x60 by entity flag bit 0x80 at +9) minus a per-type radius read via "
			+ "g_das_collision_buffer, then requires |dz| < 0xaa. Returns -1 on contact."),
		new NamedFunction(0x4254eL, "spawn_entity_at_position",
			"[HIGH] Spawns a dynamic entity, weaving it into THREE structures (cap g_dynamic_entity_count "
			+ "< 0x10). (1) An OBJECT record - the same 0x10-byte structure as the RAW Objects-section "
			+ "object (beyond-the-ire RAW.md) - is allocated in g_raw_state_secondary_buffer via "
			+ "alloc_object_record_slot (0x42199) and filled: +0 POS_X, +2 POS_Y, +4/+5 texture index/"
			+ "source (word arg), +6 ROTATION byte (from the angle arg, negated & >>1), +7 = 2 (the RAW "
			+ "UNK_0x07 flags byte), +8 = 0x80 (LIGHTING), +9 = 2 (RENDER_TYPE), +0xa POS_Z, +0xc = "
			+ "back-reference to this entity's dynamic-table slot (= slot_ptr - 0xfe3; this is the RAW "
			+ "UNK_0x0C at runtime), +0xe = 0 (RAW UNK_0x0E command id; none for spawned). (2) It finds the "
			+ "CONTAINING sector for the spawn position via locate_sector_at_position (0x3ee4b) and sets that "
			+ "sector record's +0x16 bit1 (a 'sector has (dynamic) objects' / dirty flag) in "
			+ "g_raw_state_primary_buffer. (3) It claims a dynamic-entity TABLE slot: "
			+ "find_free_entity_slot (0x42626) returns the first free index, and the slot at "
			+ "g_dynamic_entity_table + index*0x1c is filled (+0 -> the object record ptr, +0x10 self-ptr, "
			+ "+0x18 speed = 8, +6 sector, +4 heading, +0xa/+0xc = 0). Position/texture/angle arrive in "
			+ "registers (Watcom convention; exact reg mapping unreliable in the decompiler). "
			+ "reserve_object_buffer_space (0x420e1) is called first if g_object_buffer_free (0x85c28) < "
			+ "0x12. Returns the table slot, or 0 if full."),
		new NamedFunction(0x42d74L, "tick_dynamic_entities",
			"[HIGH] Per-frame entity update dispatcher (called once from the frame sequence at 0x1795b). "
			+ "Reads g_frame_time_scale (0x85324); if 0 (paused) skips. (1) Moves projectiles/dynamic objects "
			+ "via update_dynamic_entities (0x42872). (2) Runs THE ENEMY/NPC ACTOR THINK LOOP over pool A "
			+ "(g_state_pool_a_count 0x91e00 / g_state_pool_a_records 0x91e04 base, ACTOR STRIDE 0x22): per active actor (skip if dead "
			+ "+9 bit1) it dispatches on the STATE byte actor+8 — bit0x40=emerging (rise from ground, +0x1a ramp), "
			+ "bit0x20=vertical/height adjust to sector, bit0x08=ATTACKING (run the attack anim; at the strike "
			+ "frame +0x1e spawn the attack payload +0x1c), value 5=dying/despawn (+0x1a timeout), +0x21!=0="
			+ "scripted-action countdown; ELSE the normal NPC behaviour: roll g_ai_anim_rng for the next "
			+ "behaviour/anim (schedules g_actor_anim_scheduler 0x7273c), then update_actor_movement_ai (0x43326, "
			+ "locomotion) + aim_enemy_at_player (0x4355a, face+attack the player, unless +9 bit8 'no-aim'). "
			+ "g_actor_move_rate (0x72740)/g_actor_tick_rate (0x72744) come from the actor def. Motion is "
			+ "frame-time scaled. See docs/reference/ROTH_enemy_ai_notes.md."),
		new NamedFunction(0x42872L, "update_dynamic_entities",
			"[HIGH] The dynamic-entity THINK/MOVE loop. Iterates g_dynamic_entity_count slots of "
			+ "g_dynamic_entity_table (0x1c-byte stride). Per active slot: if +8 bit0(0x01) set -> the PROJECTILE "
			+ "sweep-move + hit/damage path (sweep_move_with_collision, compute_projectile_hit_damage, destroy on "
			+ "impact); else if +8 bit1(0x02) set -> timed/dying (bumps the +0x1a age counter, destroy_dynamic_entity "
			+ "at cap 0x100); else the normal heading move: "
			+ "takes heading from slot+4, computes sin/cos via sincos_lookup (0x3c1f3), scales by speed "
			+ "(slot+0x18, <<2) * frame time, integrates motion into the object record X/Y (obj+0/+2) using "
			+ "slot+0xa/+0xc as fractional accumulators, re-resolves the sector via locate_sector_at_position "
			+ "(0x3ee4b, passing slot+6 as the hint) and a floor/ceiling clearance test "
			+ "(check_entity_sector_clearance 0x42c04). On a "
			+ "blocked move it adjusts heading (slot+4 hi byte) and writes obj+6 rotation; on a sector change "
			+ "it updates slot+6. This is what flies a spawned projectile each frame - the subject of the "
			+ "fire-then-load persistence glitch."),
		new NamedFunction(0x41f24L, "destroy_dynamic_entity",
			"[MED-HIGH] Frees a dynamic entity: clears its g_dynamic_entity_table slot (0x41f6d) and "
			+ "decrements g_dynamic_entity_count (0x41f77), and releases its object record. Called by "
			+ "update_dynamic_entities when an entity's lifetime (slot+0x1a) reaches 0x100. Takes the object "
			+ "record pointer in EDX + a 0x20-byte stack scratch."),
		new NamedFunction(0x42c04L, "check_entity_sector_clearance",
			"[MED, provisional] Validity check used mid-move by update_dynamic_entities: indexes a sector "
			+ "record in g_map_geometry_buffer (0x90aa8) and compares its floor/ceiling height words against "
			+ "the object Z (obj+0xa). Returns blocked (carry) when the entity would not fit - the entity's "
			+ "vertical clearance / collision gate."),
		new NamedFunction(0x42c3cL, "check_projectile_sector_clearance",
			"[entity collision — disasm-verified; the PROJECTILE twin of check_entity_sector_clearance, called by "
			+ "update_dynamic_entities for bit1 (projectile/timed) entities] Tests whether the moving entity's Y "
			+ "(EDI+0xa) fits within the sector's floor/ceiling Y-band [g_raw_state_primary_buffer[sector+2] + hw, "
			+ "g_raw_state_primary_buffer[sector] - hw], where hw = g_projectile_collision_width>>1. Returns the sector / "
			+ "blocked status (in a register; the decomp drops it, both paths return param_1). Register-context (EDI=entity)."),
		new NamedFunction(0x42793L, "fire_entity_pending_trigger",
			"[entity tick — disasm-verified; called by tick_dynamic_entities 0x42d74] Per-entity step: clears the "
			+ "object's +7 bit0x40, and if its touch-trigger-pending bit is set (obj+9 bit0x20, the bit raised by "
			+ "collide_ray_entities on contact) clears it and fires the object's .RAW command chain via "
			+ "begin_object_command_chain (the 'something touched me' reaction). Syncs obj+10 from the raw-state record "
			+ "when flagged (EDI+8 bit0x40), then calls reset_entity_state_with_sound (0x4273e). EDI = entity slot "
			+ "(object ptr at +4)."),
		new NamedFunction(0x4273eL, "reset_entity_state_with_sound",
			"[entity tick — disasm-verified; called by fire_entity_pending_trigger 0x42793] Resets the entity to a "
			+ "settled state: sets state byte EDI+2 = 0x20 and EDI+0xb = 1, revalidate_entity_def, then plays the def's "
			+ "sound (def+0x60, or def+0x62 + sets EDI+2 bit1 when def+8 <= the passed value), and clears EDI+0x1a. "
			+ "[exact state semantics hedged — looks like the land/settle/emerge transition.] Register-context (EDI=entity)."),
		new NamedFunction(0x42199L, "alloc_object_record_slot",
			"[MED, provisional] Allocates a 0x10-byte object record in g_raw_state_secondary_buffer and "
			+ "returns its buffer-relative offset (0 if none free). Used by spawn_entity_at_position."),
		new NamedFunction(0x3ee4bL, "locate_sector_at_position",
			"[HIGH] Point-in-sector location: stores the query position X/Y/Z (args, each <<0x10 to 16.16) "
			+ "into g_locate_query_x/y/z (0x8c120/0x8c128/0x8c124), then finds the sector CONTAINING that "
			+ "point and returns its reference (g_raw_state_primary_buffer-relative offset; 0 if none). "
			+ "param_3 is a starting-sector HINT: nonzero -> localized search from the hint "
			+ "(search_sector_from_hint 0x3eceb, with a wider fallback 0x3f090); zero -> hintless search "
			+ "(search_sector_global 0x3edf0). A core engine primitive: spawn_entity_at_position uses it to "
			+ "find a new object's home sector, and update_dynamic_entities calls it each frame (passing the "
			+ "entity's current sector as the hint) to track sector transitions."),
		new NamedFunction(0x3ecebL, "search_sector_from_hint",
			"[MED, provisional] Localized point-in-sector search starting from a hint sector "
			+ "(walks neighbours/portals from the caller-supplied sector). Used by locate_sector_at_position "
			+ "when a hint is given; reads the query position globals g_locate_query_x/y/z."),
		new NamedFunction(0x3edf0L, "search_sector_global",
			"[MED, provisional] Hintless point-in-sector search (scans for the sector containing the query "
			+ "position g_locate_query_x/y/z). Fallback used by locate_sector_at_position when no hint."),
		new NamedFunction(0x42626L, "find_free_entity_slot",
			"[HIGH] Scans g_dynamic_entity_table (0x10 slots, 0x1c-byte stride) for the first slot whose "
			+ "object-pointer field (+0) is 0 and returns its INDEX (0..0xf), or 0 if the table is full. "
			+ "spawn_entity_at_position uses the returned index to address the new entity's slot. (Earlier "
			+ "guessed to be a sector-container linker - that was wrong; it only finds a free slot.)"),
		new NamedFunction(0x420e1L, "reserve_object_buffer_space",
			"[MED, provisional] Called by spawn_entity_at_position when g_object_buffer_free (0x85c28) < "
			+ "0x12 to make room for a new object record (compaction/grow). Also called by "
			+ "write_raw_state_stream during save."),
		new NamedFunction(0x426fcL, "revalidate_entity_def",
			"[AI — CORRECTED 2026-06-17; was mislabeled 'resolve_entity_sector', but 0x1e2f6 is the "
			+ "entity-DEF cache, not a sector lookup] Revalidates an actor's cached entity-def pointer. ESI = "
			+ "the actor's def-handle (handle+0x60 = expected def id), EBX = the current def record (+4 = its id); "
			+ "if they differ it re-resolves via entity_def_cache_lookup (0x1e2f6) and updates handle[0]. Returns "
			+ "CARRY set if the def is gone (the actor is then skipped). Called at the top of every actor "
			+ "tick + attack (tick_dynamic_entities, begin_enemy_attack)."),
		new NamedFunction(0x2f7bbL, "init_movement_tuning_from_first_map",
			"[HIGH] New-game / load init (called from 0x101df and 0x11109, NOT from per-map "
			+ "transitions). Reads the first map's metadata via the geometry selector and sets the "
			+ "whole-game movement tuning: MOVE_SPEED (meta+0x08) is SELF-PATCHED into the immediate "
			+ "at 0x12570 (instr 0x12569); PLAYER_HEIGHT (+0x0a)*2 -> g_player_height (0x8c110); "
			+ "MAX_CLIMB (+0x0c)*2+1 -> g_max_climb (0x8c148); MIN_FIT (+0x0e)*2 -> g_min_fit "
			+ "(0x90be0). Also seeds player pos/angle and lighting. This is why the FIRST map's "
			+ "speed applies for the entire game."),
		new NamedFunction(0x2f8a2L, "init_player_position_from_metadata",
			"[HIGH] Per-map-transition reset: copies only metadata INIT_X/Z/Y/ROTATION into the "
			+ "player position globals. Called from the map orchestrator at 0x10bca, gated by the "
			+ "first-load flag g_map_first_load_flag (0x85484)==-1. Does NOT touch movement tuning, "
			+ "so transitions never change MOVE_SPEED/height/climb/fit."),
		new NamedFunction(0x2f8faL, "init_map_lighting_from_metadata",
			"[MED-HIGH] Per-map lighting/sky setup from metadata (+0x10/+0x12/+0x14/+0x16/+0x18). "
			+ "Called every map load from 0x10bcf."),
		new NamedFunction(0x32c05L, "tick_moving_sector",
			"[HIGH, decompiler-verified] Per-frame updater for ONE moving sector/platform (param_1 = "
			+ "mover record; param_1+8 -> the runtime sector record; geometry base g_sector_geom_base "
			+ "0x90aac). UPSTREAM end of the platform-carry clip - the sole writer of g_player_move_delta_x/y "
			+ "(0x32cf0 etc.). Flow: (1) if sector flag (+2 bit3) is set, the move is done -> bail. (2) If "
			+ "mover+5 bit0x40 (dwell) is set, count down the dwell timer (+6) by g_frame_time_scale "
			+ "(0x85324) and return. (3) Else compute the step magnitude = g_frame_time_scale * speed_byte "
			+ "(sector+7), 16.16 fixed; direction sign from mover+5 bit0x80; clamp so it does not overshoot "
			+ "the endpoint (sector+0xa fwd / +0xc back, each *-2). On arrival jump to the endpoint handler "
			+ "(reverse via ^0xe0 + reload dwell, or stop by setting sector+2 bit3, or toggle - per sector+0xe "
			+ "mode and +6 bit0x20). (4) Translate the sector's four geometry slots (mover+0xe/0x10/0x12/0x14 "
			+ "indices into g_sector_geom_base) by the step. (5) CARRY: build a bitmask from sector+6 (bit0 -> "
			+ "carry player, bit2 -> carry objects); if nonzero, set g_player_move_delta = step on ONE axis "
			+ "(sector+6 bit0x40 set -> X, clear -> Y; Z always 0) and call apply_moving_sector_carry. NO "
			+ "wall/collision test gates the delta - this is the clip's source. (6) Also slides linked/attached "
			+ "object coords (sector+6 bits1/2/4/8) by the step's low byte. So a flagged horizontally-moving "
			+ "sector you stand in drags you by speed_byte*frame_time each frame, walls or not."),
		// ---- Per-frame effect TICK handlers (g_command_tick_dispatch_table 0x3088c, indexed by the effect record's
		//      COMMAND_BASE rec+4). Cross-verified against the EXECUTE table 0x30780 (same base -> command), confirmed
		//      by the existing pair tick[0x09]=tick_moving_sector / EXECUTE[0x09]=cmd_move_sector. These were dispatch-
		//      only targets Ghidra never carved, so naming them DEFINES the functions. ----
		new NamedFunction(0x33be2L, "tick_light_switch",
			"[effect tick — table 0x3088c[0x02]; runtime of cmd_light_switch 0x33b94] Per-frame advance of a light-"
			+ "switch effect from the active-effect pool; returns nonzero when finished (then unlinked)."),
		new NamedFunction(0x335ecL, "tick_modify_sector",
			"[effect tick — table 0x3088c[0x03]; runtime of cmd_modify_sector 0x312a1] Per-frame advance of a sector-"
			+ "modify effect; returns done-flag."),
		// --- effect-tick handlers defined 2026-06-25 (ROTHDefineCommandHandlers); were undefined gap code
		//     dispatched only via the tick table 0x3088c. Named from disasm/decompile. ---
		new NamedFunction(0x3107dL, "tick_spawn_damage_emitter",
			"[effect tick — table 0x3088c (type 0x78)] Builds a damage emitter from the effect's face matches "
			+ "(build_damage_emitter_from_matches), back-links the effect record, and resolves each face id via "
			+ "find_face_record. [MED-HIGH]"),
		new NamedFunction(0x3405eL, "tick_register_object_state",
			"[effect tick — table 0x3088c (type 0x67)] One-shot: clears the pending bit and calls "
			+ "register_object_state_effect, then marks the effect applied (flag bit0). [MED-HIGH]"),
		new NamedFunction(0x30b27L, "tick_register_timed_effect",
			"[effect tick — table 0x3088c (type 0x80)] Appends {effect record, value+1} to the 32-slot table at "
			+ "0x89fc0/0x89fc4 (the value from effect+6, optionally RNG-scaled when flag bit1 set). Looks like a "
			+ "scheduled/timed-value registration. [MED]"),
		new NamedFunction(0x34322L, "tick_apply_geometry_effect",
			"[effect tick — table 0x3088c (type 0x4a)] Resolves a geometry match set (geom_find_matches or "
			+ "collect_connected_geometry_group), dispatches via the 2-entry sub-table 0x343ac (0x343b4/0x343e1), "
			+ "then chains tick_rerun_command_execute. [MED-HIGH]"),
		new NamedFunction(0x31ccdL, "tick_cache_effect_base",
			"[effect tick — table 0x3088c (type 0x58)] On first tick caches the effect's base value (effect+8 -> "
			+ "effect+0xc) so later ticks have the original. [MED-HIGH]"),
		new NamedFunction(0x34086L, "tick_rerun_command_execute",
			"[effect tick — table 0x3088c (types 0x4c/0x50/0x51/0x52/0x54/0x66)] Re-runs the command's EXECUTE "
			+ "handler via g_command_dispatch_table[cmd+3 & 0x7f], guarded by the effect flag bits. Shared by "
			+ "several effect types; also chained from tick_apply_geometry_effect. [MED-HIGH]"),
		new NamedFunction(0x15ee2L, "relocate_moving_objects_if_dirty",
			"[<- post free_sfx_scratch_buffer gap] When g_item_pickup_flags bit0 is set, calls "
			+ "relocate_moving_objects_to_sectors(0x71144) and returns the table ptr; else 0. [MED-HIGH]"),
		// --- command 'mark records by key' effect handlers + their mov-cl multi-entry stubs
		//     (defined 2026-06-25; each ORs a flag bit into records matching the effect's key @effect+8) ---
		new NamedFunction(0x31d31L, "mark_geometry_faces_by_key",
			"[command effect body] geom_find_matches(key=effect+8) then ORs the stub-supplied CL bitmask into "
			+ "each matched geometry face's flag byte (g_map_geometry_buffer[match]+0x16). Shared body of the "
			+ "0x31d2b/0x31d2f stubs. [MED-HIGH]"),
		new NamedFunction(0x31d84L, "mark_raw_state_records_by_key",
			"[command effect body] collect_raw_state_matches(key=effect+8) then ORs CL into each match's flag "
			+ "byte (g_map_geometry_buffer[match]+9). Shared body of 0x31d7a/0x31d7e/0x31d82. [MED-HIGH]"),
		new NamedFunction(0x31dd5L, "mark_object_records_by_key",
			"[command effect body] collect_secondary_state_records_by_key(effect+8) then ORs CL into each "
			+ "match's flag byte (g_map_objects_buffer[match]+9). Shared body of 0x31dcb/0x31dcf/0x31dd3. [MED-HIGH]"),
		new NamedFunction(0x31d2bL, "mark_geom_faces_b20",
			"[command handler; mov cl,0x20 -> mark_geometry_faces_by_key] sets geometry-face flag 0x20. [MED]"),
		new NamedFunction(0x31d2fL, "mark_geom_faces_b10",
			"[command handler; mov cl,0x10 -> mark_geometry_faces_by_key] sets geometry-face flag 0x10. [MED]"),
		new NamedFunction(0x31d7aL, "mark_raw_state_b04",
			"[command handler; mov cl,0x04 -> mark_raw_state_records_by_key] sets state flag 0x04. [MED]"),
		new NamedFunction(0x31d7eL, "mark_raw_state_b02",
			"[command handler; mov cl,0x02 -> mark_raw_state_records_by_key] sets state flag 0x02. [MED]"),
		new NamedFunction(0x31d82L, "mark_raw_state_b01",
			"[command handler; mov cl,0x01 -> mark_raw_state_records_by_key] sets state flag 0x01. [MED]"),
		new NamedFunction(0x31dcbL, "mark_objects_b08",
			"[command handler; mov cl,0x08 -> mark_object_records_by_key] sets object flag 0x08. [MED]"),
		new NamedFunction(0x31dcfL, "mark_objects_b04",
			"[command handler; mov cl,0x04 -> mark_object_records_by_key] sets object flag 0x04. [MED]"),
		new NamedFunction(0x31dd3L, "mark_objects_b20",
			"[command handler; mov cl,0x20 -> mark_object_records_by_key] sets object flag 0x20. [MED]"),
		new NamedFunction(0x31cddL, "mark_geometry_records_by_id",
			"[command effect] walks the geometry record array (stride 0x1a); for each record whose id (+0x14) "
			+ "== effect+8, ORs a flag (0x40, or 0xc0/0x80 per effect+7 bits) into +0x17. [MED]"),
		new NamedFunction(0x340bcL, "tick_resolve_state_and_rerun",
			"[effect tick] resolves effect+8 (find_raw_state_record -> find_face_record), stores it back, then "
			+ "either swap_cell_state_linked_pair + tick_rerun_command_execute, or re-dispatches the EXECUTE "
			+ "handler (g_command_dispatch_table[cmd+3]). [MED]"),
		new NamedFunction(0x343b4L, "apply_geometry_move_with_player",
			"[geometry-effect sub-handler — table 0x343ac[0]] For each face in the list, sets geometry+2 (height) "
			+ "and moves the player with it via apply_cell_move_to_player / g_player_move_delta_z. [MED]"),
		new NamedFunction(0x343e1L, "apply_geometry_face_write",
			"[geometry-effect sub-handler — table 0x343ac[1]] For each face in the list, writes the BX value into "
			+ "the geometry record (no player move). [MED]"),
		new NamedFunction(0x1fce2L, "run_timed_message_sequence",
			"[cutscene subtitle / timed-text player; sibling of clear_cutscene_region 0x1fc5c] Modal state machine "
			+ "on param_1: mode 0 = render the next timed text entry from the sequence buffer (g@0x83b30; entry "
			+ "[0]=size,[2]=color idx,+5=text) gated by the frame timer (0x91d54/0x89d), via layout_timed_message_text "
			+ "+ draw_text_to_buffer + add_dirty_rect, then flush_dirty_rects to the VESA framebuffer (bank switch "
			+ "0x71f04/g_current_vesa_bank); modes 1-2 = input_ring_dequeue to skip; mode 3 = reset/rewind. Color "
			+ "resolved via find_nearest_palette_index (cache 0x83b4c). Drives the DBASE100 cutscene SUBTITLE_SEQ. [MED-HIGH]"),
		new NamedFunction(0x32d7dL, "tick_change_height",
			"[effect tick — table 0x3088c[0x07]; runtime of cmd_change_height 0x3121c] Per-frame advance of a sector "
			+ "floor/ceiling height-change effect; returns done-flag."),
		new NamedFunction(0x33229L, "tick_change_floor_texture",
			"[effect tick — table 0x3088c[0x0a]; runtime of cmd_change_floor_texture 0x32626] Per-frame floor-texture "
			+ "change effect; returns done-flag."),
		new NamedFunction(0x333c0L, "tick_change_floor_texture_b",
			"[effect tick — table 0x3088c[0x0b]; cmd 0x0b shares EXECUTE with cmd_change_floor_texture but has this "
			+ "distinct tick] Applies its step via swap_cell_state_group_v2 (0x333ec, call @0x333db). Returns done-flag."),
		new NamedFunction(0x3354aL, "tick_change_face_texture_adv",
			"[effect tick — table 0x3088c[0x0c]; runtime of cmd_change_face_texture_adv 0x32645] Applies its step via "
			+ "swap_cell_state_linked_pair (0x33571, call @0x33561). Returns done-flag."),
		new NamedFunction(0x3286bL, "tick_change_object_texture",
			"[effect tick — table 0x3088c[0x0d]; runtime of cmd_change_object_texture 0x327f8] Collects targets then "
			+ "applies via apply_object_state_to_group (0x328aa, call @0x3289a). Returns done-flag."),
		new NamedFunction(0x324d2L, "tick_scroll_sector_texture",
			"[effect tick — table 0x3088c[0x0e]; runtime of cmd_scroll_sector_texture 0x32473] Per-frame texture-scroll "
			+ "on a sector surface; returns done-flag."),
		new NamedFunction(0x32592L, "tick_scroll_face_texture",
			"[effect tick — table 0x3088c[0x0f]; runtime of cmd_scroll_face_texture 0x324a7] Per-frame texture-scroll on "
			+ "a face; returns done-flag."),
		new NamedFunction(0x32324L, "tick_flash_lights",
			"[effect tick — table 0x3088c[0x11]; runtime of cmd_flash_lights 0x32269] Per-frame light-flash animation; "
			+ "returns done-flag."),
		new NamedFunction(0x32221L, "tick_delay_timer",
			"[effect tick — table 0x3088c[0x12]; runtime of cmd_delay_timer 0x32195] Counts down a delay then fires the "
			+ "deferred command chain; returns done-flag when elapsed."),
		new NamedFunction(0x33b3bL, "tick_change_lighting",
			"[effect tick — table 0x3088c[0x1d]; runtime of cmd_change_lighting 0x33ac4] Per-frame lighting-level ramp; "
			+ "returns done-flag."),
		new NamedFunction(0x33091L, "tick_change_object_height",
			"[effect tick — table 0x3088c[0x23]; runtime of cmd_change_object_height 0x31107] Per-frame object/cell "
			+ "height-change effect (calls collect_secondary_matches_into_struct @0x330ac); returns done-flag."),
		new NamedFunction(0x33188L, "tick_rotate_object",
			"[effect tick — table 0x3088c[0x24]; runtime of cmd_rotate_object 0x3146d] Per-frame object-rotation effect; "
			+ "applies its step via swap_cell_state_group_v1 (0x33255, call @0x33244). Returns done-flag."),
		new NamedFunction(0x339ffL, "tick_cmd_45",
			"[effect tick — table 0x3088c[0x45]; command 0x45 (high/rare, reuses 0x33be2 as its EXECUTE). Per-frame "
			+ "advance; returns done-flag. Exact command semantics not yet pinned (hedged).]"),
		new NamedFunction(0x340f3L, "tick_move_floorceil",
			"[effect tick — table 0x3088c[0x46]; disasm-verified] Per-frame floor/ceiling MOVE effect: collects the "
			+ "target cell group and applies the height step via apply_floor_move_to_group (0x3423e @0x341a1) and "
			+ "apply_floorceil_move_to_group (0x3427b @0x34234), riding the player on the moving surface. Returns "
			+ "done-flag. (Command 0x46 reuses 0x335ec as its EXECUTE.)"),
		// ---- Moving floor/ceiling apply-cores (called by the height ticks above) ----
		new NamedFunction(0x3423eL, "apply_floor_move_to_group",
			"[moving-floor apply — disasm-verified; called by tick_move_floorceil @0x341a1] Lowers the floor height "
			+ "(cell+2) of each matched cell (EDI query {count@+0, offsets@+2}) toward the target EBX when EBX < current, "
			+ "writing g_player_move_delta_z and calling apply_cell_move_to_player(1) so the player rides the surface. "
			+ "Register-context (EDI=query, EBX=target height)."),
		new NamedFunction(0x3427bL, "apply_floorceil_move_to_group",
			"[moving floor+ceiling apply — disasm-verified; called by tick_move_floorceil @0x34234] Like "
			+ "apply_floor_move_to_group but moves both floor (cell+2) and the linked ceiling (cell+8 via cell+0x18) of "
			+ "the matched group toward target = word[ESI+10]*2; ESI+6 bit1 = also move ceiling, bit2 = clamp cell+0xc. "
			+ "Calls apply_cell_move_to_player(1/2). Register-context (ESI=effect, EBP=query)."),
		new NamedFunction(0x348edL, "apply_cell_move_to_player",
			"[moving-cell side-effect — disasm-verified; called by apply_floor/floorceil_move_to_group] When a moving "
			+ "cell IS the player's sector (g_player_sector), shifts the player's view Z (g_player_z hi @0x90a92) by "
			+ "g_player_move_delta_z so the player rides the floor (bit1) / ceiling (bit2, via cell+0x18); then "
			+ "propagates the move to linked secondary records via adjust_records_z_carry. param_1 = floor/ceil mask. "
			+ "Returns 0x8a130. (DAT_8a114=0 variant; see apply_cell_move_to_player_portalcheck.)"),
		new NamedFunction(0x348f9L, "apply_cell_move_to_player_portalcheck",
			"[moving-cell side-effect — disasm-verified; called from 5 sites (0x32ea5/0x32f28/0x3383b/0x338c5/0x33959)] "
			+ "Twin of apply_cell_move_to_player (sets DAT_8a114=1) that ALSO runs the portal-proximity scan "
			+ "scan_portal_walls_near_query (0x3db20) when the floor/ceiling gap shrinks below 0x61 — i.e. checks whether "
			+ "the closing geometry is near a portal (NOT a redraw; corrected). Same player-ride + linked-record "
			+ "propagation. The widely-used moving-cell variant."),
		new NamedFunction(0x1c648L, "update_player_vertical_physics",
			"[player physics — disasm-verified; called by update_player_view_bob 0x3ecfe with param_1=floor, param_2="
			+ "ceiling, EBX=current Z, returns new Z] Resolves the player's vertical position against the sector "
			+ "floor/ceiling each frame: FALLING/airborne arc via g_player_airborne stepping a gravity/launch velocity "
			+ "table (0x71304), LANDING when the feet reach the floor (param_2 - eye 0x1c), step-down, head-clearance "
			+ "(forces crouch flags if floor-to-ceiling < 0x70), CROUCH when dead (key_z_crouch on g_player_health<1), "
			+ "and smooth eye-height via approach_value. Drives g_player_locomotion_flags and the jump/fall state vars "
			+ "0x819c5/0x819c9/0x819cd/0x819d1. Also (via apply_direct_damage_to_player 0x32058) the hazard-floor damage "
			+ "path. The player's gravity/floor-contact resolver."),
		new NamedFunction(0x34531L, "find_object_record_by_id",
			"[object lookup — disasm-verified; called by tick_world_effects 0x3464c] Scans the object-table index list "
			+ "at g_object_table_header+0x14 (count +0x16) for the first ENABLED record (byte+2 bit0x8 clear) whose id "
			+ "word+8 == param_1, and RETURNS its address (g_object_table_header+offset), else 0. Distinct from "
			+ "find_unflagged_object_by_key (0x303ab), which is a membership BOOLEAN over the +8 list."),
		new NamedFunction(0x351c3L, "fire_command_contact_trigger",
			"[trigger — disasm-verified; called by 0x10d1e after dispatch_entry_command_trigger fires] Resets command "
			+ "scratch (0x8a260 = 0x80008000 bounds, g_command_chain_interrupt-adjacent 0x8a0dc/0x8a134 = 0) and, if the "
			+ "command record (param_1+2) has none of bits 0x29 set, fires fire_trigger_on_contact(0, x, y, x, y). The "
			+ "follow-up contact trigger after a use/interaction."),
		new NamedFunction(0x35580L, "resolve_conditional_command",
			"[command flow — disasm-verified; called by cmd_if_not_item 0x35544] Given a predicate result (param_1), "
			+ "drives the .RAW chain: sets g_command_chain_interrupt (1=interrupt while 0x89f60 busy, 2=continue) and the "
			+ "pending-record flag 0x8a0dc, honoring the record's invert/sticky flags (ESI+6 bit0x1, bit0x10 -> ESI+2 "
			+ "|=8). Returns -1 (take branch), 0 (skip), or the pending state. The shared if/if-not branch resolver. "
			+ "Register-context (command record in ESI)."),
		new NamedFunction(0x35b53L, "init_resource_chunk_pool",
			"[pool init — disasm-verified] Thin guard around pool_init: if the block is non-null, inits a Pool over it "
			+ "with 0x18-byte chunks (pool_init(block, 0x18, ...)). Used for g_resource_pool (alloc_audio_stream_buffers "
			+ "0x30051) and by alloc_largest_heap_block (0x35ff9)."),
		new NamedFunction(0x34bb2L, "commit_player_position_delta",
			"[HIGH, decompiler-verified] Adds the precomputed move delta (g_player_move_delta_x/y/z = "
			+ "0x8a124/0x8a128/0x8a12c) to the player position globals (g_player_x/y/z high words). PURE "
			+ "add of three shorts, NO collision check here - confirms the platform-carry clip premise: "
			+ "when apply_moving_sector_carry calls this, a horizontal sector delta moves the player with "
			+ "no wall test."),
		new NamedFunction(0x34a8eL, "apply_moving_sector_carry",
			"[HIGH, decompiler-verified] Dispatcher that carries the player and objects when a sector "
			+ "(platform/lift/door floor) moves. param_1 = selector bitmask (bit1 = primary/floor half, "
			+ "bit2 = linked sector at +0x18); param_2 = count-prefixed list of moving-sector indices. "
			+ "PLAYER CARRY: only when a moving sector index == g_player_sector (0x90c12) AND the player Z "
			+ "(0x90a92) lies within the sector's [height-delta_z, height] vertical span - then it calls "
			+ "commit_player_position_delta, a PURE position add with NO horizontal wall/collision test. "
			+ "This is the mechanism behind the platform-carry clip: a horizontally moving sector can push "
			+ "the player through a wall. OBJECT CARRY: for sectors flagged (+0x16 bit2) it walks the "
			+ "secondary state buffer and calls carry_objects_by_player_delta for contained objects."),
		new NamedFunction(0x34bd7L, "carry_objects_by_player_delta",
			"[MED] Applies the same move delta to objects whose coordinate lies within a range "
			+ "(esi walks 0x10-byte object records). The 'ride a moving platform/sector' carry "
			+ "mechanic: objects and the player are translated together."),
		// --- Save / load state stream (see ROTH_speedrun_leads.md) ---
		new NamedFunction(0x33ea1L, "rebuild_object_pointer_array",
			"[HIGH, decompiler-verified] Lazily (re)builds g_object_ptr_array, the index into the live "
			+ "object table. No-op unless g_object_ptr_array is NULL and g_object_table_header is set. "
			+ "Validates the table header magic word (*header == 0x7533); if wrong, nulls the header. "
			+ "Object records are VARIABLE-LENGTH, laid out contiguously starting at header+header[+4], "
			+ "each prefixed by its own size word at record+0; this walks header[+6] (= object count) "
			+ "records, storing a pointer to each into a freshly allocated count*4 array and advancing by "
			+ "each record's size. Called by read_raw_state_stream right after the secondary buffer load - "
			+ "so the object index is rebuilt before the per-object state patch runs."),
		new NamedFunction(0x214b9L, "read_raw_state_stream",
			"[HIGH, decompiler-verified] Save-LOAD: restores runtime state from a save stream (param_1 = "
			+ "file handle), terminated by an 'EXIT' (0x45584954) marker (returns true on missing marker = "
			+ "error). Chunk order: (1) primary RAW state -> g_raw_state_primary_buffer (0xffff header => "
			+ "literal/skip-delta compressed, decoded by apply_literal_skip_delta_stream; else raw); (2) "
			+ "secondary buffer -> g_raw_state_secondary_buffer + FUN_00033ea1 rebuild; (3) OBJECT TABLE "
			+ "patch; (4-6) three subsystem chunks FUN_0003580c / FUN_0004ef61 / FUN_00043d98. "
			+ "OBJECT PATCH (the save/load-glitch site): loops g_object_table_header(+6) live objects via "
			+ "the pointer array *g_object_ptr_array, dispatching on each object's TYPE byte (obj+3). It "
			+ "patches IN PLACE - it never clears or rebuilds the object table and never destroys live "
			+ "objects absent from the save. Restore is SELECTIVE BY TYPE: types 2/0xa-0xb/0xd/0x15/0x1f/"
			+ "0x22/0x34 get specific position/state bytes (obj+6,+7,+0xa..+0xd) restored; EVERY object gets "
			+ "only obj+2 (a state/flags byte) restored; all OTHER types restore obj+2 alone. So an object "
			+ "whose type is not in the switch (e.g. a live projectile) keeps its pre-load position AND "
			+ "velocity -> it survives the load still in flight. This is the 'fire-then-load' projectile-"
			+ "persistence glitch, and the substrate for savewarp/state-desync."),
		new NamedFunction(0x2114eL, "write_raw_state_stream",
			"[HIGH, decompiler-verified] Save-WRITE: mirror of read_raw_state_stream. Builds the same "
			+ "chunk layout to a file: primary RAW state (optionally literal/skip-delta compressed via "
			+ "encode_literal_skip_delta_stream), secondary buffer, the per-type OBJECT field dump (same "
			+ "type switch on obj+3, same fields), then the three subsystem chunks (FUN_00035648 / "
			+ "FUN_0004eee0 / FUN_00043d53) and the 'EXIT' marker (writes 0x4954,0x4558 = 'TIXE' in memory, "
			+ "read back as the 0x45584954 terminator). The save records exactly the fields the loader "
			+ "restores - so the read/write asymmetry that enables the glitch is the IN-PLACE, "
			+ "non-clearing, type-selective restore on the LOAD side, not the data written here."),
		new NamedFunction(0x31e14L, "strip_transient_flags_for_save",
			"[save helper — disasm-verified; called by write_raw_state_stream 0x2114e] Walks the three record arrays of "
			+ "a raw-state buffer (param_1) — list at +[4] stride 0x1a (objects: clears +0x16 &=0xc9, +0x17 &=0x3f, "
			+ "+4 word=0), list at +[8] stride 0xa/0xe (walls: if +1 bit0x80, +9 &=0xf8), list at +[6] stride 0xc "
			+ "(+0xa &=0x9f) — clearing runtime/transient flag bits so the serialized state is clean. Each list length "
			+ "is the word at (list-2)."),
		// Save/load subsystem chunks 4-6 (what else survives a load), reader/writer pairs:
		new NamedFunction(0x3580cL, "load_state_record_list",
			"[MED] Save/load chunk 4 (load side). Resets g_state_record_list_count (0x89f5c) and walks a "
			+ "variable-length record stream, processing each via load_state_object_links (0x35839, which "
			+ "returns the record size to advance by) until a -1 sentinel word or a zero-size record. "
			+ "Writer: write_state_record_list (0x35648)."),
		new NamedFunction(0x35839L, "load_state_object_links",
			"[MED-HIGH] Chunk-4 per-record handler: restores an object's POINTER/REFERENCE fields (the "
			+ "ones that need relocating against freshly-loaded buffers, which the raw chunk-3 object patch "
			+ "can't store literally). Each record starts with a short: a 1-based object index, or -2 for a "
			+ "header record. HEADER (-2): restores link-context globals from the record - g_state_link_word_a "
			+ "(0x8a0e8), g_state_link_word_b (0x8a0ec), g_state_link_obj_ptr (0x8a0e4, relocated += "
			+ "g_object_table_header), g_state_link_buf_ptr (0x8a13c, relocated += g_raw_state_primary_buffer); "
			+ "size 10. OBJECT: looks up object (index-1) via g_object_ptr_array, reads its type (obj+3 & "
			+ "0x7f), resolves the live record via resolve_state_link_target (0x359ad), then writes obj+5 "
			+ "(byte) / obj+6 (word) / obj+0xc (pointer) per type: types 3,7 -> obj+0xc relocated into "
			+ "g_sfx_nodes (switch/door linked to a toggle flag), 0x12 -> obj+0xc relocated into "
			+ "g_raw_state_primary_buffer (sector/geometry ref), 0x11 -> three words, 9-0xd -> obj+5 only, "
			+ "2/0xe/0xf/0x1d/0x23 -> obj+5/+6. Return = record size (4/6/8/10); 0 on an unknown type ends "
			+ "the stream. So obj+0xc is a relocatable link field, varying target by object type."),
		new NamedFunction(0x359adL, "resolve_state_link_target",
			"[MED, provisional] Helper called per chunk-4 record by load_state_object_links; returns (in "
			+ "EDX) the live object record pointer to write the restored link fields into, or 0 to skip. "
			+ "Exact resolve/validate logic not yet decompiled - name is provisional."),
		new NamedFunction(0x35648L, "write_state_record_list",
			"[MED] Save/load chunk 4 (save side); mirror of load_state_record_list (0x3580c). Returns the "
			+ "byte size of the emitted record stream."),
		new NamedFunction(0x4ef61L, "load_state_dynamic_entities",
			"[MED-HIGH] Save/load chunk 5 (load side). Restores TWO dynamic pools, each count-prefixed, "
			+ "relocating saved offsets back to live pointers. Pool A: g_state_pool_a_count (0x91e00) "
			+ "records of 0x22 bytes at g_state_pool_a_records (0x91e04); fields +0/+4 are pointer offsets "
			+ "fixed up into base 0x85cf4 / g_raw_state_secondary_buffer, then re-linked (reads a word at "
			+ "ptr+4 and re-resolves via FUN_0001e2f6, the sector lookup). Pool B: the DYNAMIC ENTITY "
			+ "table - g_dynamic_entity_count (0x90fe0) records of 0x1c bytes at g_dynamic_entity_table "
			+ "(0x90fe4), the slots spawn_entity_at_position (0x4254e) allocates; field +0 fixed up into "
			+ "g_raw_state_secondary_buffer. So dynamic entities (and pool A) persist across a load. Writer: "
			+ "write_state_dynamic_entities (0x4eee0)."),
		new NamedFunction(0x4eee0L, "write_state_dynamic_entities",
			"[MED] Save/load chunk 5 (save side); mirror of load_state_dynamic_entities (0x4ef61). Dumps "
			+ "both dynamic pools, converting live pointers back to buffer-relative offsets."),
		new NamedFunction(0x43d98L, "load_sfx_node_active_state",
			"[MED] Save/load chunk 6 (load side). Unpacks a packed bitstream (32 bits/dword from the saved "
			+ "buffer) into a 1-bit-per-record flag (bit 0x80) across the fixed-stride (0x12) record array "
			+ "at g_sfx_nodes (0x85c44); record count = high word of *0x85c44. A compact per-"
			+ "element boolean state (switches/secrets/toggled elements) that survives a load. Writer: "
			+ "save_sfx_node_active_state (0x43d53)."),
		new NamedFunction(0x43d53L, "save_sfx_node_active_state",
			"[MED] Save/load chunk 6 (save side); mirror of load_sfx_node_active_state (0x43d98). "
			+ "MSB-first packs each record's bit-0x80 flag (stride 0x12) into the bitstream and returns "
			+ "the byte count. recomp-VERIFIED: the outer loop is a do/while (post-tested), so count==0 "
			+ "still emits one zero dword and returns 4 (not 0)."),
		// --- Hidden developer mode (see ROTH_devmode_notes.md) ---
		new NamedFunction(0x14464L, "enable_dev_mode",
			"[HIGH] Dormant enable for the hidden dev mode: mov byte [g_dev_mode_flag],1 ; "
			+ "not byte [0x7f36f] ; ret. HAS ZERO CROSS-REFERENCES - never called by the shipped "
			+ "game, which is why dev mode is off. Same address as the GOG build."),
		new NamedFunction(0x17fa4L, "dev_toggle_map_menu",
			"[HIGH] The 'W' action: if g_dev_mode_flag is set, toggles g_map_menu_active "
			+ "(xor byte [0x7fe28],1); otherwise forces the menu off."),
		new NamedFunction(0x17453L, "build_map_selector_menu",
			"[HIGH] Formats the on-screen map-selector list from the string at 0x711cc "
			+ "('--Press + - to choose map, press RETURN to go there') and g_map_list_ptr."),
		new NamedFunction(0x173f4L, "use_enter_key_handler",
			"[HIGH, lift-confirmed 2026-06-14] The Enter/Use action (scancode 0x1c). Real function "
			+ "entry is 0x173f4 (prologue push edx; shared pop edx/ret exits). Gated by "
			+ "g_dialogue_busy_flag (0x83aea) / g_move_freeze_gate (0x83125); calls 0x1fbba or "
			+ "0x1f671 then falls into the map-selector RETURN action: if g_map_menu_active (0x7fe28) "
			+ "is set, clears it, sets g_map_first_load_flag (0x85484) = -1, and copies "
			+ "g_map_menu_selected_entry (0x7fe34) to the pending-map global 0x76630 to warp. "
			+ "NOTE: the former 'warp_to_selected_map' label at 0x17420 was a MID-INSTRUCTION address "
			+ "(inside the call at 0x1741e) - do NOT create a function there; this is the correct entry. "
			+ "(2 internal calls -> Tier 3, not a leaf.)"),
		new NamedFunction(0x3df96L, "dev_open_nearest_door",
			"[dev tool — disasm-verified; CORRECTED from 'render_dev_maphack' (renders nothing) and refined from the "
			+ "earlier 'spawn_door_at_near_portal' over-read after empirical test] Bound to SPACE (scancode 0x39, keymap "
			+ "entry [34] of g_keymap_table 0x7093d; dispatched every frame by keymap_dispatch 0x14525 <- game_play_loop) "
			+ "and gated on g_dev_mode_flag bit0. Walks g_player_sector's walls and force-opens the FIRST portal wall "
			+ "that is (a) a portal (wall+8 != 0xffff), (b) door-capable (neighbor door-config field >= 0xfffd), (c) in "
			+ "the rendered view + in front of the camera (per-frame transformed vertex depth in GS), and (d) within "
			+ "~60 units (point_to_wall_distance_sq < 0xe11) — by calling spawn_door_instance (the SAME routine the normal "
			+ "door-open trigger uses). It does NOT conjure a door on a blank wall: spawn_door_instance/"
			+ "setup_door_swing_geometry require an actual DOOR-SECTOR quad (face-type 4) to swing, and bail if that "
			+ "doorway already has an active door. PLAYTEST-CONFIRMED (2026-06-19): standing point-blank in front of ANY "
			+ "door and pressing SPACE opens it, BYPASSING its normal key/item/trigger requirement — a dev 'skeleton "
			+ "key'. This works because the lock/permission logic lives in the .RAW trigger chain that normally DECIDES "
			+ "whether to call spawn_door_instance; this tool calls spawn_door_instance directly, skipping the checks. "
			+ "No-op on ordinary hallway portals (no door-sector). (The 'L' key 0x26 -> 0x1444c wireframe toggle is the "
			+ "actual dev maphack; the in-game map is draw_map_overlay 0x10dce.)"),
		new NamedFunction(0x14ca7L, "key_t_handler_vestigial",
			"[HIGH] The 'T' key (scancode 0x14). Toggles 0x7f370 - which NOTHING else in the binary "
			+ "reads, so the feature was cut - and sets the shared redraw flag 0x7f570=1. Net effect: "
			+ "a one-frame icon flicker and nothing functional. See ROTH_keymap.md."),
		new NamedFunction(0x144daL, "key_m_toggle_render_mode",
			"[HIGH] The 'M' key (scancode 0x32). CORRECTION (lift-confirmed 2026-06-14): cycles "
			+ "g_render_mode (0x7f36a) 0<->1 ONLY, not 0->1->2->0 - it does `inc; cmp 2; jb keep; "
			+ "else =0`, so it resets to 0 the moment it would reach 2. Mode 2 (the unfinished "
			+ "'stays flat' state) is NOT reachable via M (would need an external writer). Then calls "
			+ "apply_render_mode (0x14506), and 0x3001b + 0x26cd4 to refresh/re-render. Flat-shading "
			+ "debug toggle."),
		new NamedFunction(0x14506L, "apply_render_mode",
			"[HIGH] Reads g_render_mode (0x7f36a): mode 0 clears g_flat_shading_flag (textured), "
			+ "mode 1 sets it to 0xff (flat color). Mode 2 is a no-op (leaves flat on) - an "
			+ "apparently unfinished third state."),
		new NamedFunction(0x14525L, "keymap_dispatch",
			"[HIGH] Reads a keypress (0x1299a) and walks g_keymap_table (0x7093d) - {u8 scancode, "
			+ "u32 handler} records, stride 5 - calling the matching handler via `call [ebx+1]`. The 37-entry table "
			+ "is the full in-game key bindings; see docs/reference/ROTH_keymap.md. Most handlers are dispatch-only "
			+ "(naming DEFINES them). Many PLAYTEST-CONFIRMED 2026-06-19."),
		// --- g_keymap_table (0x7093d) handlers — the in-game key bindings. PLAYTEST-CONFIRMED where noted.
		//     Most were uncarved dispatch-only targets; naming defines them. Full table: docs/reference/ROTH_keymap.md ---
		new NamedFunction(0x1444cL, "key_toggle_wireframe_map",
			"[DEV] 'L' key — gated on g_dev_mode_flag; toggles the wireframe map overlay g_debug_map_enabled (0x7f36e). "
			+ "PLAYTEST-CONFIRMED."),
		new NamedFunction(0x17fedL, "key_toggle_sprint",
			"[input] CapsLock — toggles g_run_toggle (0x7e8dc). PLAYTEST-CONFIRMED: sprint toggle."),
		new NamedFunction(0x17fc0L, "key_toggle_help_overlay",
			"['H' — toggles g_help_overlay_enabled (0x7fe38). PLAYTEST-CONFIRMED: shows the help/keybind overlay.]"),
		new NamedFunction(0x175d8L, "key_toggle_weapon_overlay",
			"['F1' — sets the player action/anim state (0x7fddc=2, 0x7fde0=0x64) to show the first-person hands/weapon. "
			+ "PLAYTEST-CONFIRMED: displays the hands/weapon overlay.]"),
		new NamedFunction(0x1f89bL, "key_toggle_subtitles",
			"['F2' — toggles subtitles and shows an on/off message via resolve_dbase100_text + layout_timed_message_text. "
			+ "PLAYTEST-CONFIRMED: subtitle toggle.]"),
		new NamedFunction(0x14c9cL, "key_show_version",
			"['F8' — displays g_version_string (0x767c0) via the message overlay (0x1f88c). PLAYTEST-CONFIRMED: shows the "
			+ "ROTH version.]"),
		new NamedFunction(0x14ce5L, "key_quicksave",
			"['F9' — requests a quick game action: 0x7feac=2, 0x7feb0=0, g_menu_action_flags(0x7fea8)|=2. "
			+ "PLAYTEST-CONFIRMED: F9/F10 are quick save/load (F9 = action 2).]"),
		new NamedFunction(0x14cc9L, "key_quickload",
			"['F10' — sibling of key_quicksave with action code 0x7feac=1 (the other of quick save/load). "
			+ "PLAYTEST-CONFIRMED.]"),
		new NamedFunction(0x14794L, "key_cycle_display_type",
			"['F6' — re-applies the video/display mode (0x2e609) per g_display_type (0x7f372) with a full screen "
			+ "redraw. PLAYTEST-CONFIRMED: F4/F6 toggle between display types. (F4 = key_cycle_display_type_alt 0x147a8.)]"),
		new NamedFunction(0x147a8L, "key_cycle_display_type_alt",
			"['F4' — the other display-type toggle (pairs with F6 key_cycle_display_type 0x14794). PLAYTEST-CONFIRMED.]"),
		new NamedFunction(0x1801cL, "key_toggle_easy_select",
			"['F3' — toggles g_object_select_easy_flag (0x81e34) and shows 'Manual'/'Automatic object select' "
			+ "(strings 0x75ded/0x75e0b). The auto-target interaction-select option read by query_player_inventory.]"),
		new NamedFunction(0x17fd2L, "key_toggle_mouse_swap",
			"['F5' — toggles g_mouse_button_swap (0x7feb8), then shows a 'mouse buttons normal/swapped' message "
			+ "(jmp 0x1f8cb, al=7/8). Mouse-button swap.]"),
		new NamedFunction(0x17fd1L, "key_f7_noop",
			"['F7' — a bare `ret`: BOUND but does NOTHING (verified; corrects an earlier mislabel where a disasm window "
			+ "overran this 1-byte handler into F5's code). Likely a removed/placeholder binding.]"),
		new NamedFunction(0x14601L, "key_gamma_increase",
			"['C' — raises g_gamma_level (0x89f12) then reloads/uploads the palette (read_das_palette + "
			+ "upload_palette_dac). PLAYTEST-CONFIRMED: gamma up.]"),
		new NamedFunction(0x145ecL, "key_gamma_decrease",
			"['V' — lowers g_gamma_level (0x89f12) then refreshes the palette. PLAYTEST-CONFIRMED: gamma down.]"),
		new NamedFunction(0x14678L, "key_view_size_decrease",
			"['-' — shrinks the 3D viewport: bumps the view-size level (0x7049a) and reconfigures via "
			+ "configure_render_viewport. The saved 'ViewSize' setting.]"),
		new NamedFunction(0x14613L, "key_view_size_increase",
			"['=' — grows the 3D viewport (pair of key_view_size_decrease 0x14678).]"),
		new NamedFunction(0x144fbL, "key_flush_texture_cache",
			"['F' — reset_das_entry_status_table + flush_object_das_handles = reloads the DAS texture cache. A debug "
			+ "reload (no obvious visible effect, hence uncertain in testing).]"),
		new NamedFunction(0x14cb6L, "key_fire_weapon",
			"['LeftCtrl' — clears 0x7f568 and tail-calls trigger_weapon_fire (0x1768a). The keyboard fire binding.]"),
		new NamedFunction(0x145a4L, "key_n_vestigial",
			"['N' — sets word 0x90c14 (adjacent to g_player_sector) to 0xffff and returns. NOTHING in the binary reads "
			+ "0x90c14, so this key has NO effect — dead/vestigial code (like key_t_handler_vestigial). Resolves the "
			+ "'what does N do?' question: nothing.]"),
		new NamedFunction(0x14573L, "key_set_view_scale",
			"['0' — sets g_view_scale_flags (0x90bd4) + the viewport-dirty flag (0x8c1d2): a view detail/scale toggle.]"),
		// --- Video resolution/mode setup (the screen-resolution cycler + VESA) ---
		new NamedFunction(0x1480cL, "cycle_screen_resolution",
			"[VIDEO] Advances g_screen_resolution_index (0x7f358) to the next entry of the mode table at 0x1470c "
			+ "(stride 10B: u16 width, u16 height, u16 ?, u16 ?, u8 mode-tag@+8) — skipping any mode whose framebuffer "
			+ "(width*height) exceeds g_framebuffer_bytes — then APPLIES it: tag 0xd -> plain VGA mode 13h (320x200, INT10h "
			+ "AX=0x13); tag 0 with 320x200 -> Mode X 320x200; tag 0 with 320x400 -> Mode X 320x400 (g_video_mode_flags=4, "
			+ "line-doubled); else -> VESA via set_vesa_video_mode (0x14b24, LinBase or banked). Sets g_screen_pitch/height, "
			+ "shows the mode name via show_timed_message ('Mode X 320x200'/'VGA 320x200'/'Mode X 320x400'/'Vesa dx d'/"
			+ "'LinBase dx d'), then build_scanline_dest_offset_table + recompute_hires_line_doubling + configure_render_viewport "
			+ "+ upload_palette_dac + compute_screen_extents. One-shot-inits the mode table via 0x14772 the first time.]"),
		new NamedFunction(0x14b24L, "set_vesa_video_mode",
			"[VIDEO] Sets a VESA SuperVGA mode: INT 10h AX=0x4F02 (set mode, param_1 = VESA mode | flags), checks AL==0x4F, "
			+ "queries the mode-info block via vesa_get_mode_info_block (0x27f6f) and reads BytesPerScanline(+0x12 -> "
			+ "g_screen_pitch), YResolution(+0x14 -> height), XResolution(+0x10 -> g_video_mode_width 0x146dc). Bit 0x4000 "
			+ "selects a LINEAR-framebuffer map (PhysBasePtr +0x28 via dpmi_map_physical_memory 0x28350 -> g_linear_framebuffer_ptr "
			+ "0x146d8); else BANKED windowing (WinGranularity +4 -> g_vesa_page_bank_offset, set_vesa_bank). Halves the "
			+ "displayed height + sets line-doubling when pitch<=height (interlaced layout). Register/INT-context."),
		new NamedFunction(0x14772L, "init_video_mode_table_once",
			"[VIDEO] Lazy one-shot init (guard byte 0x14770) of the 8-entry VESA mode-descriptor table at 0x14716, via "
			+ "the structured-fill helper 0x27fbf. Called by cycle_screen_resolution before first use."),
		new NamedFunction(0x27f6fL, "vesa_get_mode_info_block",
			"[VIDEO] DPMI real-mode bridge that fetches a VESA mode-info block: stages a DOS transfer buffer "
			+ "(ensure_dos_transfer_buffer), fills the real-mode register frame with AX=0x4F01 / mode (EDX), invokes "
			+ "INT 31h AX=0x300 (simulate real-mode INT 10h), and on AL==0x4F returns the buffer (caller reads "
			+ "BytesPerScanline/X/Y res + PhysBasePtr). Returns 0 on failure. Used by set_vesa_video_mode."),
		new NamedFunction(0x10e4eL, "recompute_view_region_offsets",
			"[VIDEO] Recomputes the centered 3D-viewport rectangle (g_view_w 0x85cd8 / g_view_x 0x85ce0 / g_view_h 0x85cdc "
			+ "/ g_view_y 0x85ce4) from the current view-size level (0x7049a -> a {width,height} pair at 0x703d0/0x703d2) — "
			+ "scaling width by g_screen_pitch/320 and height by g_screen_height/200 when in a non-320x200 mode "
			+ "(g_video_linear_flag 0x76634), centering horizontally/vertically. Called after every mode/view-size change."),
		// --- First-person viewmodel (weapon/hands) sprite animation + the clipped-blit family ---
		new NamedFunction(0x139a0L, "draw_player_viewmodel_sprite",
			"[VIDEO/HUD; <- update_player_tick] Selects the current animation frame of a first-person overlay sprite "
			+ "descriptor (param_1: +8 width, +0xa height, +4 = frame-record list, stride record+6; flag bit 0x10=animated "
			+ "[advance param_2 frames], 0x8=drawable, 0x4=per-frame x/w/h offset, 0x2=shade-table present), computes the "
			+ "vertical screen position from a bob/offset (param_3) projected by g_das_render_scale-relative factor 0x85408/0x9b "
			+ "+ view-height/2, clips to the view, and dispatches to the clipped-sprite blit family: scale>0x9b -> the x2 "
			+ "(pixel-doubled) variants, else 1x; g_viewmodel_shade_level (0x8c1de) selects shaded vs plain. The hands/weapon "
			+ "overlay (F1) draw path."),
		new NamedFunction(0x13cf0L, "blit_transparent_sprite_clipped_shaded",
			"[VIDEO] 1x SHADED sibling of blit_transparent_sprite_clipped (0x13be0): same column-run-table + top/bottom "
			+ "clip, but each non-zero source byte is remapped through the FS-relative colormap row at shade level param_1 "
			+ "(clamped 0..0x1f) before writing one dest pixel. Used for faded/darkened viewmodel sprites. Register-context."),
		new NamedFunction(0x13c60L, "blit_transparent_sprite_clipped_x2",
			"[VIDEO] 2x (horizontally pixel-DOUBLED) sibling of blit_transparent_sprite_clipped: writes each non-zero "
			+ "source byte to two adjacent dest pixels (for 320x400/hires layouts). Plain (no shade). Register-context."),
		new NamedFunction(0x13d90L, "blit_transparent_sprite_clipped_x2_shaded",
			"[VIDEO] 2x pixel-DOUBLED + SHADED sibling: combines the x2 doubling of 0x13c60 with the colormap shade "
			+ "(param_1, clamped 0..0x1f) of 0x13cf0. The fully-attenuated hires viewmodel blit. Register-context."),
		new NamedFunction(0x13f2eL, "draw_text_glyph_with_shadow",
			"[VIDEO/UI; <- render_ui_panel_text] Renders a UI text glyph block to the active display with TRANSPARENCY + "
			+ "drop-SHADOW: walks rows of a glyph cell (descriptor param_1: +0=src, +4=dest, +8=behind/bg, +0xc=width, "
			+ "+0x10=row count, +0x14=src stride, +0x18=dest stride, +0x1c=bg stride, +0x20=mode). Opaque (non-zero) texels "
			+ "are drawn; texel 0 shows the background, and a 0-texel adjacent to a glyph edge is filled with a shadow color "
			+ "from the world shading table (g_world_shading_table_ptr+0xa00). Three layout paths (mode 1 = Mode X two-page, "
			+ "3 = word-doubled hires, else = plain) write the matching framebuffer offsets (+0x1e242 / +0x12d687 page-2). "
			+ "Self-modifies inner-loop stride immediates."),
		// --- Map warp / level transition (the .RAW loader entry + in-map relocation) ---
		new NamedFunction(0x1096fL, "process_map_warp_or_load",
			"[MAP; <- game_play_loop] Resolves a pending warp destination (g_warp_dest_a). Compares the requested map name "
			+ "against the currently-loaded one: if DIFFERENT, builds '<name>.RAW', unloads the current map "
			+ "(unload_map_geometry + reset_entity_pools), loads the new .RAW (load_raw_file_wrapper) and re-inits player "
			+ "position/lighting/geometry; if SAME map (or first load), relocates the player to the warp-tagged sector via the "
			+ "sector search (same logic as relocate_player_to_warp_sector 0x10a4d) — finds the sector whose tag word (+0x14) "
			+ "matches g_map_first_load_flag, computes its bbox center, and sets g_player_sector + camera position. Returns 0 "
			+ "ok / -1 on load failure."),
		new NamedFunction(0x10a4dL, "relocate_player_to_warp_sector",
			"[MAP; <- process_map_warp_or_load] Post-load player placement: scans all sectors for the one whose warp-tag "
			+ "word (+0x14) equals g_map_first_load_flag, walks its wall ring (count@+0xd, walls@+0xe) to compute the "
			+ "vertex bounding-box center, and writes g_player_sector / g_player_sector_cache / the camera X/Y center "
			+ "(0x90a8c/0x90a94) / g_state_link_buf_ptr. Clears the warp flags. Register/GS-context."),
		new NamedFunction(0x15efeL, "tick_item_pickup_lock",
			"[PICKUP; <- gameplay_frame_step] Counts down the 'pickup in progress' lock armed by begin_item_pickup_lock on "
			+ "item pickup: while g_item_pickup_flags (0x7fd84) bit0 is set, advances the step counter 0x7fda0 += "
			+ "g_frame_time_scale and clears the flag after 0x1b steps (~the pickup-fly duration). The FLAG IS LIVE — "
			+ "activate_targeted_object gates new pickups on (0x7fd84 & 1)==0, so this blocks re-grabbing while the item "
			+ "flies. It ALSO eases a position 0x7114c/4e/56 toward a point in front of the player (from 'source' 0x7fd88, "
			+ "curve 0x7115c) but THAT OUTPUT IS UNUSED — no renderer reads 0x7114c (corpus + trace verified); the visible "
			+ "fly is a separate traveling WORLD OBJECT (TRACE-CONFIRMED 2026-06-20: mid-fly trace shows the item projected "
			+ "by transform_sector_objects_to_view + relocated through sectors by 0x283ad). So: lock/timer = live, eased "
			+ "position = vestigial. (Earlier mislabel 'scripted camera' fully retracted.)"),
		new NamedFunction(0x11945L, "blit_sprite_save_under",
			"[VIDEO] Display-layout-polymorphic sprite blit that draws an opaque-keyed sprite (source stride 0x12) to the "
			+ "active display AND records, into the result descriptor (EDI: +0=dest ptr, +4=width, +8=src ptr, +7=LAYOUT "
			+ "TAG, +0xc.. = save-under table of (orig<<8|drawn) shorts), enough to later erase/restore it. Six layout paths "
			+ "tagged at +7: 0x11/0x12 = VESA linear (normal/hires-doubled, g_linear_framebuffer_ptr); 1/0x80 = Mode X planar "
			+ "(normal/hires, plane writes via out 0x3c5/0x3cf); 0 = VGA 13h linear; 2 = VESA BANKED (set_vesa_bank on 64KB "
			+ "page crossings). Register-context."),
		new NamedFunction(0x12ec2L, "blit_translucent_overlay_block",
			"[VIDEO; <- blit_clipped_sprite_smc] Stamps a small (4-column-stepped) TRANSLUCENT overlay onto the framebuffer: "
			+ "each screen pixel is replaced by colormap/translucency-table[(overlay<<8)|screen] (FS-relative table), so the "
			+ "overlay blends with what is behind it. Right/bottom clipped (vs g_screen_pitch / g_screen_height 0x8549c); in "
			+ "hires line-doubling mode also writes the second framebuffer page (+0x1e1b8, double row stride). Register-context."),
		new NamedFunction(0x1107eL, "reset_and_start_new_game",
			"[GAME; <- game_play_loop] Full teardown + reload to the initial game state (new game): copies the DEFAULT map/das "
			+ "argument strings (0x7037c -> raw-name buffer, 0x7032c -> g_cfg_das_arg), tears everything down (delete_temp_files, "
			+ "free_dbase100_data, reset_das_entry_status_table, reset_entity_pools, close_das_file_handle, unload_map_geometry, "
			+ "reset_renderer_tables, frees g_map_das_dir_table_buffer), then reinitializes (init_game_databases, "
			+ "load_das_file_wrapper, load_raw_file_wrapper, set_state_record_count, init_loaded_map_state, "
			+ "mark_geom_sentinel_entries, init_movement_tuning_from_first_map, remap_builtin_palette_image, "
			+ "init_render_struct_89ed0). Returns 0 ok / -1 on a load failure."),
		new NamedFunction(0x12f6dL, "blit_translucent_overlay_rows",
			"[VIDEO] Row-oriented sibling of blit_translucent_overlay_block: stamps up to 4 framebuffer rows (each "
			+ "unaff_EBX pixels wide) where every screen pixel is replaced by colormap/translucency-table[(overlay<<8)|"
			+ "screen] (FS-relative). Two-page in hires line-doubling (writes +0x1e240). The other shadow edge of the "
			+ "menu/cursor box. Register-context."),
		new NamedFunction(0x13183L, "blit_opaque_rect",
			"[VIDEO] Plain rectangular byte-copy into the framebuffer: copies an unaff_EBX-wide x param_3-high block from "
			+ "source param_1 to dest param_2, advancing the dest by g_screen_pitch per row (rep-movsd + tail bytes). In "
			+ "hires line-doubling mode each scanline is written to both framebuffer pages (dest and dest+pitch). Used to "
			+ "blit solid panel/backdrop image blocks. Register-context (width in EBX)."),
		new NamedFunction(0x10686L, "lookup_map_raw_filename",
			"[MAP] Looks a map name (param_1) up in the loaded map-list text (g_map_list_ptr; entries are whitespace-"
			+ "delimited, '\\' path-separated), matching case-insensitively (uppercase mask 0xdfdf). On a match, copies the "
			+ "entry and applies the '.RAW' extension via set_filename_extension (ext 0x574152='RAW'), returning the "
			+ "post-match cursor; returns 0 if not found. Resolves a level name to its .RAW geometry file."),
		new NamedFunction(0x1374fL, "rle_decode_scroll_segment",
			"[VIDEO/UI] Decodes one segment of an RLE-compressed wide (800px) image into a scrolling buffer: first shifts "
			+ "the existing window (memmove src[1]->dest[0], length [2]), then RLE-expands from the source cursor ([5]) up to "
			+ "an 800-(offset) row budget — control byte >0xf0 => a run of (b+0x10) copies of the next byte, else a literal — "
			+ "advancing the offset/remaining counters ([2]/[9]) and saving the source cursor. Drives a scroll-unroll "
			+ "animation. Register-context (EBP = decode-context struct)."),
		new NamedFunction(0x12b45L, "grayscale_background_view",
			"[VIDEO] PLAYTEST-CONFIRMED: the fullscreen GRAYSCALE effect applied to the background 3D view while the "
			+ "INVENTORY overlay is open. Remaps the whole 3D-viewport rectangle (centered region 0x85ce0/0x85ce4/0x85cdc/"
			+ "0x85cd8) through a 256-entry luminance LUT (g_view_grayscale_lut 0x7f254). Rebuilds the LUT via "
			+ "build_view_grayscale_lut (0x12be2) when g_view_grayscale_lut_valid (0x7f354)==0; marks the region dirty "
			+ "(add_dirty_rect, with the remap chunk selected by param_1>>8 into g_das_remap_chunk_10000_ptr); two-page-"
			+ "aware in hires. Returns the (possibly recomputed) param_1."),
		new NamedFunction(0x11c3cL, "clip_sprite_extents_to_screen",
			"[VIDEO] Clamps a sprite's draw extents to the screen: given top-left (param_1=x, param_2=y) and packed "
			+ "dimensions in param_3 (high byte = height, low byte = width), clips height against the display height "
			+ "(0x8549c) and width against g_screen_pitch, returning early/0 when the sprite is fully off-screen. NOTE: "
			+ "the clipped dimensions are returned in a second register the decompiler drops (multi-reg return)."),
		new NamedFunction(0x114e2L, "build_screenshot_filename",
			"[FILE] Composes the screenshot output path into g_snapshot_filename_buf: copies the configured directory "
			+ "(string 0x70666+0x7d), ensures a trailing '\\', appends the base name (0x70738), then the decimal snapshot "
			+ "sequence number (g_snapshot_name_seq 0x70744 via num_to_decimal_digits) and the extension. Feeds the "
			+ "'B'-key debug screenshot writer."),
		new NamedFunction(0x13e35L, "encode_item_icon_to_spans",
			"[HUD] Compresses the held-item icon bitmap (param_2, stride EBX, param_3 rows) into the per-row span format "
			+ "consumed by draw_translucent_icon_spans: for each row writes {leading-zero count, trimmed run length, "
			+ "pixel bytes} (trailing zeros dropped), advancing the output by 2+length. The encode half of the held-item "
			+ "HUD-icon pipeline (sole caller: update_selected_item_icon)."),
		new NamedFunction(0x13e81L, "draw_translucent_icon_spans",
			"[HUD] Draws the {x-offset, run-length, pixels} per-row span format produced by encode_item_icon_to_spans with "
			+ "PARTIAL-TRANSPARENCY blending + a 0-byte edge: per row, seeks to the x-offset, writes a leading 0 (edge), "
			+ "then run-length pixels each blended through the FS translucency colormap[(icon_pixel<<8)|screen_pixel] (the "
			+ "same see-through blend as wall transparency), then a trailing 0. The decode/draw half of the held-item "
			+ "HUD-icon pipeline (sole caller: draw_held_item_icon). Register-context (dest stride in EBX)."),
		new NamedFunction(0x13010L, "blit_translucent_overlay_column",
			"[VIDEO] Column-major translucent-overlay stamp (sibling of blit_translucent_overlay_block/_rows): for up to 4 "
			+ "source columns, walks param_3 framebuffer rows replacing each screen pixel with colormap[(overlay<<8)|screen] "
			+ "(FS-relative). The vertical edge of the menu/cursor-box drop shadow. Two-page-aware in hires. Register-context."),
		new NamedFunction(0x12be2L, "build_view_grayscale_lut",
			"[VIDEO] Builds g_view_grayscale_lut (0x7f254): for each of the 256 palette entries (g_palette_rgb_ptr "
			+ "0x85488, 6-bit R/G/B) computes a green-weighted luminance ((R*4 + G*8 + B)*0x500>>16) and maps it to a "
			+ "grayscale-ramp index (-(lum-0x4f)); sets g_view_grayscale_lut_valid=1. The LUT that "
			+ "grayscale_background_view uses to desaturate the 3D view behind the inventory overlay."),
		new NamedFunction(0x118a9L, "draw_software_cursor_sprite",
			"[CURSOR] Draws the software mouse-cursor sprite (called by restore_and_redraw_cursor 0x11f49) in its current "
			+ "COLOR: bumps g_screen_busy_depth, patches the cursor color (*g_saveunder_sprite_color_ptr 0x76878) into the "
			+ "SIX layout-specific SMC immediate sites inside blit_sprite_save_under (0x119e1/0x11a7b/0x11aed/0x11b58/"
			+ "0x11ba2/0x11c22), clips the draw rect via clip_sprite_extents_to_screen, and if non-empty blits the cursor "
			+ "(save-under) via blit_sprite_save_under. Resolves the long-deferred 0x118a9 = the SMC cursor color-patch."),
		new NamedFunction(0x12cd4L, "fill_rect_solid",
			"[VIDEO] Fills a framebuffer rectangle (x=param_1, y=param_2, width=EBX, height=param_3) with the solid byte "
			+ "g_rect_fill_color (0x7f355), hires-line-doubling-aware. Register-context (width in EBX)."),
		new NamedFunction(0x1073aL, "select_map_entry_by_index",
			"[MAP] Picks the param_1-th space-delimited entry from the map list (g_map_list_ptr), copies its name into the "
			+ "'.RAW' filename buffer (extension via set_filename_extension 'RAW'), and if the entry carries a DAS argument "
			+ "(after a space) parses it into g_cfg_das_arg (0x1078a). Backs the '+/-' map-chooser / warp-by-index."),
		new NamedFunction(0x1063dL, "compare_name_token_ci",
			"[STR] Case-insensitive compare (uppercase mask 0xdfdf) of a filename's last path component (param_1, after the "
			+ "final '\\') against a token (param_2), treating space and '.' as terminators. Returns 0 on match / -1 on "
			+ "mismatch. Used by the map-list name lookups."),
		new NamedFunction(0x113b9L, "console_edit_text_field",
			"[BOOT/CONSOLE] DOS text-mode input-line editor: prints the current buffer (0x114a3), reads keys "
			+ "(0x11548), echoes printable chars into g_console_input_buffer (0x7684c) up to g_console_input_maxlen "
			+ "(0x76844) at cursor g_console_input_pos (0x76848) — restricted to digits when g_console_input_numeric_only "
			+ "(0x76854) is set — handles backspace (BS/space/BS) and returns on Enter. The startup config prompt "
			+ "(Name/Path entry)."),
		new NamedFunction(0x11f49L, "restore_and_redraw_cursor",
			"[CURSOR] Restores the framebuffer under the previous cursor position and redraws the cursor at the current "
			+ "mouse spot: guarded by g_screen_busy_depth<2; handles each display layout (VESA-linear, Mode X plane setup "
			+ "via out 0x3c4/0x3ce, VGA13h), calls restore_cursor_region_if_set for the saved region (two save buffers "
			+ "0x7a8a4 / 0x76898 chosen by page), polls mouse motion (poll_mouse_motion), then redraws via "
			+ "draw_software_cursor_sprite."),
		new NamedFunction(0x114a3L, "dos_print_concat",
			"[BOOT/CONSOLE] Concatenates param_2 then param_1 into a stack buffer, '$'-terminates it, and prints via "
			+ "INT 21h AH=0x09. Used by the console line editor to repaint the prompt + current input."),
		new NamedFunction(0x11548L, "console_read_key",
			"[BOOT/CONSOLE] Reads one key (0x129ca), returns 0 for '$' (0x24), and upper-cases a-z; the input source for "
			+ "console_edit_text_field."),
		new NamedFunction(0x113c0L, "console_edit_field",
			"[BOOT/CONSOLE] Core of the DOS line editor (shared-code sibling that console_edit_text_field 0x113b9 falls into "
			+ "after forcing text mode): same edit loop but PRESERVES the caller-set g_console_input_numeric_only flag "
			+ "(use this entry for a digits-only field)."),
		new NamedFunction(0x1078aL, "parse_map_das_filename",
			"[MAP] Copies a space/null-terminated token (param_1) into param_2 and applies the '.DAS' extension "
			+ "(set_filename_extension 'DAS'=0x534144). Extracts the DAS-resource name from a map-list entry for "
			+ "select_map_entry_by_index."),
		new NamedFunction(0x10920L, "copy_switch_token_upper",
			"[BOOT/STR] Copies a command-line token (ESI) into the length-prefixed buffer at 0x76718 (byte 0 = count, "
			+ "text from +1), upper-casing letters and preserving '-'/'/'(switch prefixes), stopping at space/null/non-"
			+ "printable. Startup argument tokenizer."),
		new NamedFunction(0x129caL, "dequeue_translated_key",
			"[INPUT] Pops a raw scancode (input_ring_dequeue) and translates it via the scancode table "
			+ "g_scancode_translate_table (0x7082e, stride 3: {scancode u8, value u16}, 0xff-terminated), applying the "
			+ "shifted form when g_key_modifier_flags (0x90c42) bit 0x40 is set. The translated-key source for the console "
			+ "editor (console_read_key)."),
		new NamedFunction(0x107b3L, "dispatch_arg_command",
			"[BOOT] Matches the parsed startup token in g_arg_token_buf (0x76718) against the command table at "
			+ "g_arg_command_table (0x704a5, variable-stride records {u16 size, code* handler, keyword...}) and calls the "
			+ "matching handler. The command-line/console verb dispatcher."),
		new NamedFunction(0x105c0L, "switch_map_das_resources",
			"[MAP] On a map change, reloads the DAS resource set if the new map names a different DAS: strips both "
			+ "filenames to basenames (basename_strip_ext), looks the map up (lookup_map_raw_filename), and on a name "
			+ "mismatch (compare_name_token_ci) parses the new DAS name (parse_map_das_filename), tears down the old DAS "
			+ "(reset_das_entry_status_table / close_das_file_handle / reset_renderer_tables / frees "
			+ "g_map_das_dir_table_buffer) and reloads via load_das_file_wrapper with g_das_skip_palette_load_flag set "
			+ "(keeps the current palette). Called from process_map_warp_or_load."),
		new NamedFunction(0x1059bL, "load_map_list",
			"[MAP] Heap-allocates g_map_list_ptr and copies the master map-list text into it, then selects the first entry "
			+ "(select_map_entry_by_index 0). Installs the level list parsed at startup."),
		new NamedFunction(0x103eaL, "detect_vga_display_subtype",
			"[VIDEO/BOOT] Queries the display combination (INT 10h AX=0x1A00); when supported (AL==0x1A) and the active "
			+ "display code (BL) is 7 or 8, records the VGA color/mono submode mask at 0x7674c (0x3f3f vs 0xffff) and prints "
			+ "the matching banner (dos_print_dollar_string). Sets g_roth_error_code=8 as the in-video-init stage marker."),
		new NamedFunction(0x11382L, "dispatch_config_field_key",
			"[BOOT/CONSOLE] Boot-config menu key handler: reads a menu key (0x11337) and edits the matching field — 'N' "
			+ "-> Name (console_edit_text_field, max 4), 'P' -> Path (max 0x3c), 'F'/'C' -> 0x11462. Backs the 'Use / Name "
			+ "/ Path / ...' startup prompt."),
		// --- Cursor interaction + HUD panel/icon drawing ---
		new NamedFunction(0x1624dL, "classify_cursor_target_object",
			"[INTERACT; <- run_gameplay_frame] Evaluates the world object/entity under the cursor (param_1 record: type "
			+ "byte +1 = 3/4, trigger block at +0xe, distance^2 at +0x20) to decide what interaction is offered: probes "
			+ "pickable/inspectable/usable via dispatch_entry_command_trigger[_b], find_oninspect_block_by_id, "
			+ "find_unflagged_object_by_key, is_item_id_pickable, and the trigger-flag bits (+9 & 1/0x20/0x13). Sets the "
			+ "interaction cursor shape g_interaction_cursor_type (0x7e932 = 1/3/5) and the interaction flag bits "
			+ "g_cursor_interaction_flags (0x7fdac: bit2=has command trigger, bit4=blocked/out-of-range); returns the "
			+ "CURSOR-SHAPE id to display (passed to set_cursor_shape; e.g. 0x240/0x248/0x250/0x398/0x3a0), banded by the "
			+ "interaction-range distance thresholds 600/2000/5000."),
		new NamedFunction(0x187d1L, "draw_das_panel_slide_reveal",
			"[UI; <- load_dbase300_resource_at_offset] Blits a DAS image sub-rect into the framebuffer with a SLIDE/REVEAL "
			+ "animation: param_1 is a panel descriptor (+1 dest x, +2 dest y, +3 src width, +5/+6 full w/h, +7 dest pitch, "
			+ "+8 src offset, +9 src y, +10 reveal progress). Advances the reveal by g_frame_time_scale*4 (sentinel 0x4d2 "
			+ "= settle/clear pass), registers the dirty rect, copies the revealed rows (two-page in hires), then shades "
			+ "the edges via shade_remap_blit. The inspect/close-up popup opening animation."),
		new NamedFunction(0x16831L, "draw_character_portrait_corner",
			"[HUD; <- gameplay_frame_step] PLAYTEST-CONFIRMED: the top-left CHARACTER-PORTRAIT widget (clicking it opens the "
			+ "inventory). When the cursor enters the top-left 0x24x0x24 corner it animates in (param_1 0..9 = approach "
			+ "offset 0x12-(p+4), >=10 = settled): save/restore the under-region via g_corner_icon_saveunder (0x7fdbc, "
			+ "save_framebuffer_region/blit_save_region), blits the portrait sprite (blit_clipped_sprite_smc) + clears, and "
			+ "when settled overlays the active-item sub-icon (blit_item_icon via 0x19fcf) from g_active_item_hud_icon "
			+ "(0x7fed0). Register dirty rect 0..0x24."),
		// --- Inventory / weapon selection + HUD ---
		new NamedFunction(0x1bd8cL, "equip_first_usable_weapon",
			"[WEAPON; <- trigger_weapon_fire] Scans g_inventory_slots for the first item that is a WEAPON (dbase100 type "
			+ "nibble ((def+4>>8)&0xf)==1) and has available ammo (query_player_inventory of its ammo id from "
			+ "apply_weapon_action_attributes); on a match deselects any current primary/secondary item, then equips it "
			+ "(activate_weapon_item) and refreshes the weapon HUD (render_weapon_hud). The auto-equip used when firing "
			+ "with no weapon active."),
		new NamedFunction(0x1cb6cL, "find_or_autoselect_inventory_item",
			"[INVENTORY; <- cmd_if_not_item] Queries the inventory for items whose id appears in the caller's id list "
			+ "(param_1[0..EBX]); param_2 bits select the mode: bit0 clear = COUNT matches (return count, record "
			+ "g_last_item_record); bit0 set = test whether the SELECTED item (primary/secondary) matches and, when "
			+ "easy-select is off, gather all matches and RANDOMLY pick one as g_selected_item_primary "
			+ "(rng_next_index_for_count). bit1 forces easy-select. Drives item-conditional commands + auto-targeting."),
		new NamedFunction(0x1ca2eL, "set_inventory_list_filter",
			"[INVENTORY; <- cmd_refresh_inventory_list] Filters the displayed inventory list: param_1 bit0 clear marks "
			+ "every slot whose dbase100 type nibble != 2 with the hidden bit (slot flags |= 0x80), clears the selection "
			+ "and refreshes (0x1be8e); bit0 set clears the hidden bit on all slots (show all). Then "
			+ "rebuild_weapon_inventory_list."),
		new NamedFunction(0x1bcc4L, "draw_held_item_icon",
			"[HUD; <- gameplay_frame_step] PLAYTEST-CONFIRMED: the bottom-right HELD-ITEM icon (the item in the player's "
			+ "right hand). Drawn with PARTIAL-TRANSPARENCY (see-through) via draw_translucent_icon_spans from the encoded "
			+ "icon data g_held_item_icon_spans (0x81310). Normally sits with its bottom cropped off the screen edge; when "
			+ "the player interacts with something (or opens inventory) the slide timer g_held_item_slide_timer (0x819bc, "
			+ "vs 0x8c) advances and the icon slides UP fully into view (width g_held_item_icon_width 0x819b4, x 0x819b0). "
			+ "Anchored at the view's bottom-right (_DAT_00085cd8/0x85ce0 minus x, 0x85cdc/0x85ce4 minus height); only when "
			+ "the view is tall enough (0x85cdc>0x45). Two-page-aware in hires."),
		new NamedFunction(0x1951dL, "load_inspect_document_page",
			"[UI; <- load_dbase300_resource_at_offset] Loads one page of a multi-page inspect/close-up document and draws the "
			+ "pagination arrows: when g_inspect_page_count (0x810fc) > 1, blits the up-arrow (sprite 0x128 active / 0x118 "
			+ "at-top) and down-arrow (0x140 active / 0x130 at-end) per g_inspect_current_page (0x81184); frees the prior "
			+ "DAS handle (pool_free_handle), loads the current page's resource (table 0x81100[page]) via "
			+ "load_das_cache_resource, parses it into the panel descriptor (0x1874d, EBX) and clamps the scroll offsets."),
		new NamedFunction(0x1818dL, "restore_active_held_item",
			"[INVENTORY; <- game_play_loop] Finds the inventory slot flagged active (dbase100 def+5 bit 0x10), loads its "
			+ "close-up image icon (def+0xc) into g_active_item_hud_icon (0x7fed0), records the active item "
			+ "(0x81054/0x8104c/0x81050), and — if no secondary item is selected — re-equips it via activate_weapon_item. "
			+ "Restores the player's active/held item (e.g. after a load or inventory change)."),
		new NamedFunction(0x16585L, "update_dialogue_cursor_and_click",
			"[DIALOGUE; <- game_play_loop] Manages the cursor + click during a dialogue/choice modal: with no button held, "
			+ "if a choice is hovered (update_dialogue_choice_highlight) shows the hover cursor 0x248 else the default "
			+ "0x240; on a click while dialogue is busy, requests a skip (0x7f564=1), force-ends the current voice line "
			+ "(dialogue_voice_force_end), shows the click cursor 0x268, and clears the action flags. Cursor shape via "
			+ "set_cursor_shape."),
		new NamedFunction(0x1be8eL, "reset_weapon_hud",
			"[WEAPON] Clears the active weapon (activate_weapon_item(0,0)) and refreshes the weapon HUD "
			+ "(render_weapon_hud). Called after inventory edits that may invalidate the equipped weapon."),
		new NamedFunction(0x1a178L, "redraw_inventory_cursor_cell",
			"[INVENTORY; <- game_play_loop] Redraws the icon of the currently-highlighted inventory grid cell: when not "
			+ "suppressed (0x80b2c==0), refreshes the grid and, if the highlighted entry (g_cursor_list_positions"
			+ "[g_cursor_active_list]) is within the visible 10-cell window and non-empty, draws it via "
			+ "draw_item_icon_in_slot."),
		new NamedFunction(0x17317L, "repaint_hud_and_present",
			"[HUD; <- game_play_loop] Full gameplay-HUD repaint + present, used when returning to gameplay (e.g. closing "
			+ "the inventory): closes the inventory panel if g_inventory_panel_open (0x7fec4), reloads the HUD backdrop, "
			+ "ticks the player, rebuilds the HUD (refresh_hud_layout / render_weapon_hud / draw_active_ui_panels / "
			+ "render_text_ui), then presents (flush_dirty_rects + flip_video_page, or the 0x20b91 path), and stamps "
			+ "g_last_frame_tick."),
		// --- Inventory/inspect helpers + dbase100 record accessors ---
		new NamedFunction(0x1874dL, "decode_das_to_padded_buffer",
			"[UI; <- load_inspect_document_page] Decodes a DAS image (*param_1: +4 width, +6 height) into a freshly "
			+ "pool-allocated buffer padded by 0x10 in each dimension (8px border): sizes (w+0x10)*(h+0x10), zero-fills, "
			+ "blits the image in at the 8px inset (blit_das_image_to_buffer), frees the source DAS handle, and returns the "
			+ "buffer (writing the padded width/height back through param_2/EBX). Preps the inspect close-up image."),
		new NamedFunction(0x19fcfL, "draw_item_icon_centered",
			"[HUD/UI] Draws an item icon (param_1 = icon record, +4 width, +6 height) centered within a 0x1c x 0x38 cell at "
			+ "(param_2,EBX) via blit_item_icon; no-op for a null icon. Generic centered-icon blit; the caller determines usage."),
		new NamedFunction(0x1823aL, "free_active_item_hud_icon",
			"[HUD; <- restore_active_held_item] Releases the active-item HUD icon DAS handle (g_active_item_hud_icon "
			+ "0x7fed0) back to the DAS cache pool and clears it, before a fresh one is loaded."),
		new NamedFunction(0x1854bL, "copy_record_block_op7",
			"[DBASE100] Walks a dbase100 record's trigger-block list (param_1+0x14, each {opcode<<24 | size}; gated by "
			+ "param_1+4 bit 2), finds the first opcode-7 block and copies its payload bytes into param_2 (capped at EBX "
			+ "entries x4). Returns the count copied, 0 if absent."),
		new NamedFunction(0x1a028L, "resolve_record_conditional_op2",
			"[DBASE100] Walks a dbase100 record's trigger-block list (param_1+0x14; gated by param_1+4 bit 4) for opcode-2 "
			+ "blocks, evaluates each one's condition (eval_dialogue_record_condition_with_cleanup), and returns the value "
			+ "(block[1]&0xffffff) of the first whose condition passes; 0 if none. A data-driven conditional attribute lookup."),
		new NamedFunction(0x1c512L, "draw_reloc_ui_row",
			"[UI] Draws one relocatable UI image row: resolves the reloc record fields (resolve_reloc_record_fields), "
			+ "computes the x from a base (0x810e4)+0x11+offset, blits via 0x1a10a, and registers the dirty rect spanning "
			+ "the row height (record+6) at y=param_1. Part of the inspect/choice popup layout."),
		new NamedFunction(0x18a64L, "blit_saved_ui_block",
			"[UI] Restores a saved UI image block back to the screen when flagged dirty: if the saved-region globals "
			+ "(0x810f4/0x810f8/0x810d0) are set and g_choice_interaction_mode != 1, copies the block (blit_opaque_rect) "
			+ "and registers its dirty rect (geometry 0x810dc/0x810de/0x810e2). Clears the dirty flag (0x810f8)."),
		new NamedFunction(0x10d1eL, "fire_object_use_trigger",
			"[INTERACT; <- activate_targeted_object] Runs the clicked object's entry/contact command trigger: clears "
			+ "g_mouse_buttons_held, calls dispatch_entry_command_trigger and, if it matched, fire_command_contact_trigger. "
			+ "The path taken when run_leftclick_object_trigger reports the object had an On-Left-Click .RAW command. Returns "
			+ "-1 if a trigger fired, else 0."),
		new NamedFunction(0x1a10aL, "blit_das_image_at_xy",
			"[UI] Thin helper: blits a DAS image (param_1) to the framebuffer at screen (param_2 = packed x/y) via "
			+ "screen_xy_to_framebuffer_ptr + blit_das_image_to_buffer."),
		new NamedFunction(0x1b0b2L, "get_item_tab_index",
			"[INVENTORY] Maps an item id (param_1) to its inventory TAB (0..4): looks up the item's dbase100 entry and "
			+ "matches its type nibble ((entry+4>>8)&0xf) against g_inventory_tab_context_map. Returns the tab index (0 if "
			+ "not found)."),
		new NamedFunction(0x1a0abL, "draw_ui_panel_count_element",
			"[UI/HUD] Draws a fixed panel sub-element: blits reloc DAS tile 200 at (0x81058 + g_ui_panel_anchor_x - 2, "
			+ "g_ui_panel_anchor_y + 2), and when enabled (0x8105e) draws a one-character count/value (0x8105d from "
			+ "0x76768) via draw_text_at_screen_xy. A quantity/badge indicator on the panel."),
		new NamedFunction(0x1bc91L, "reset_hud_icon_state",
			"[HUD] Invalidates both HUD item-icon widgets: frees the portrait-corner save-under region "
			+ "(g_corner_icon_saveunder 0x7fdbc) and forces the held-item icon to rebuild (sets the dedup id 0x8130c=-1 + "
			+ "update_selected_item_icon). Used on state changes that require re-drawing the HUD icons."),
		new NamedFunction(0x19678L, "free_inspect_popup_and_redraw",
			"[UI] Frees the current inspect close-up image image (free_das_cache_handle) and registers the dirty rect over "
			+ "its screen footprint (geometry 0x810e4/0x810e6/0x810ea) so the area behind it repaints. Closes the inspect popup."),
		new NamedFunction(0x18003L, "reset_item_pickup_lock",
			"[PICKUP; <- load_raw_map_file 0x2f4b4] Clears the item-pickup lock state on MAP LOAD: clears g_item_pickup_flags "
			+ "(0x7fd84) and the eased-position output (0x71148), and resets the list field (clear_list_field30). Counterpart "
			+ "to tick_item_pickup_lock (this is NOT a camera)."),
		new NamedFunction(0x1816aL, "load_item_icon_resource",
			"[INVENTORY] Loads an item's icon/close-up image by item id: looks up the dbase100 entry "
			+ "(g_dbase100_inventory_table[id]) and loads its DAS resource (entry+0xc) via load_das_cache_resource. "
			+ "Returns the handle, 0 if the item has no entry. param_2 (EDX = the open DAS file handle) sets no "
			+ "EDX of its own and passes straight through as load_das_cache_resource's 2nd arg (recomp 2026-07-01)."),
		new NamedFunction(0x18cb9L, "free_inspect_overlay_image",
			"[UI] Releases the inspect/close-up overlay DAS handle (0x7fed4) back to the DAS cache and registers its "
			+ "screen region (0x7fed8/0x7fee0/0x7fee4) dirty so the area repaints."),
		new NamedFunction(0x18e48L, "blit_das_image_auto_scale",
			"[UI] Thin wrapper: blits DAS image param_2 to dest param_1, passing the scale flag (1 in 320-wide modes, 0 "
			+ "when hires line-doubling) to blit_das_image_to_buffer."),
		// --- Mirror / reflection rendering (complements the subpass texture-flip; see RESPONSE_28dbe_*) ---
		new NamedFunction(0x284dfL, "render_reflection_subviews",
			"[RENDER/mirror] Renders each mirror/reflection sub-view: saves the camera (g_sprite_view_angle, "
			+ "g_view_offset_x/y), walks the reflection-view list (0x85344, count 0x85340), and per entry reflects the view "
			+ "across the mirror plane (reflect_view_across_mirror_plane) + re-transforms the vertices "
			+ "(transform_world_vertices), projects the mirror's screen bounds, clips, and re-renders the scene "
			+ "(render_clipped_sector_subscene; render_secondary_viewport_pass when the viewport height differs). Toggles "
			+ "g_render_x_flip_flag per view; restores the camera at the end."),
		new NamedFunction(0x28456L, "reflect_view_across_mirror_plane",
			"[RENDER/mirror] Reflects the camera across a mirror edge (two vertices at fs:[EBX]/[EBX+2]). Toggles "
			+ "g_render_x_flip_flag; picks the mirror axis by the larger of |dx|/|dy|, then mirrors the view: vertical "
			+ "mirror -> negate g_sprite_view_angle + reflect g_view_offset_x about the edge; horizontal mirror -> "
			+ "g_sprite_view_angle = 0x100 - angle + reflect g_view_offset_y. The geometric heart of the reflection "
			+ "(the texture x-flip half is in the subpass mapper)."),
		new NamedFunction(0x29305L, "render_clipped_sector_subscene",
			"[RENDER] Renders the scene tree restricted to the current clip regions (0x85224 stride 3, count 0x85220): per "
			+ "region begin_sector_render_tree, then build_sector_draw_order + build_scene_draw_list + render_world_face_list. "
			+ "Sets 0x852e8 = found/empty. Used for the mirror/reflection clipped re-render."),
		new NamedFunction(0x286dfL, "render_secondary_viewport_pass",
			"[RENDER] Re-renders the face list into the SECONDARY render target (g_render_target_buffer += 0x89f2c, selector "
			+ "g_render_target_selector = 0x89f28), shifting the view origin down by g_render_viewport_height "
			+ "(shift_wall_nodes_vertical), then restores the primary target. The split/secondary viewport (reflection or "
			+ "lower-region) render."),
		new NamedFunction(0x2c400L, "project_wall_face_span_extents",
			"[RENDER; <- draw_world_face_clipped_spans] Projects a wall face's screen-Y extents: from the surface record "
			+ "(es:[SI+8]->+6->+0x18 height sub-record, es:[SI+6] edge) computes g_face_span_top/bottom, then the 4 corner "
			+ "Y coords (near/far x top/bottom -> 0x852b0/0x852ac) = worldY*g_perspective_scale/depth + view-center, with the "
			+ "edge depths from fs:[BX+0xc]/[BX+0x20] (or 0x1000 when the flags &4/&8 bit is set). Clamped to +-0x3ffe."),
		new NamedFunction(0x2a952L, "apply_view_camera_params",
			"[RENDER] Loads the camera/projection from a view-params block (g_view_params_block 0x85270) + view-bounds rect "
			+ "(g_view_bounds_rect 0x8526c): sets g_sprite_view_angle (=[7]+[10]), g_view_offset_x/y (=[0]/[2]), the view "
			+ "bounds (0x85308/0x8530c top/bottom), g_world_alt_render_flags, and 0x852fa = -view_z. Lazily allocs a DPMI "
			+ "selector (0x29e64). The per-view camera setup (used for main + reflection views)."),
		new NamedFunction(0x2aa3eL, "setup_frame_render_context",
			"[RENDER] Per-frame render preamble from a render context (param_1: +0=bounds, +1=view params, +2=target, "
			+ "+4/+5/+3=selectors/flags): loads them, computes g_frame_time_scale = g_frame_tick_counter - g_last_frame_tick "
			+ "**CLAMPED to 0x2d** (the delta-time cap), stamps g_anim_clock (0x8532a) + g_last_frame_tick, then sub-setup "
			+ "(0x2ab30), bumps g_das_cache_tick, 0x3d959, update_active_sounds, setup_surface_render_constants."),
		new NamedFunction(0x29403L, "compute_floor_clearance_for_render",
			"[RENDER] Walks down from g_player_sector through floor portals (wall stride 6, neighbor at +8; descends via "
			+ "+0x18 sub-sector) to the sector under the player, then sets g_view_floor_clearance (0x8497c) = player Z "
			+ "(0x90a92) minus that sector's floor height (clamped, -0x2f floor). Feeds the floor/height render setup."),
		new NamedFunction(0x287b6L, "render_world_view_pass",
			"[RENDER] One full world-view render: sets the render-active flag (g_render_active 0x89f38=0xff), runs "
			+ "setup_frame_render_context, an optional render hook (0x8495c), then render_scene_body (0x2885d); when the "
			+ "viewport height differs (g_render_height 0x90bf6 != g_render_viewport_height) also renders the second "
			+ "viewport region (0x288fb, into the shifted target). Restores the viewport state."),
		new NamedFunction(0x2885dL, "render_scene_body",
			"[RENDER] Main scene render body: apply_view_camera_params, compute the view-center half-extents "
			+ "(0x84962 half-height, 0x84960 half-width from the view bounds), set the vertical origin (0x909f6), render the "
			+ "mirror/reflection sub-views (render_reflection_subviews 0x284df), then — if surface records exist "
			+ "(g_surface_record_selector 0x852c8) — transform_world_vertices + the main face render (0x292be)."),
		new NamedFunction(0x2ab30L, "tick_ambient_render_animation",
			"[RENDER] Per-frame ambient render animation: every >6 ticks runs an LCG (0x85328*0x5e5+0x29) to jitter the "
			+ "view sway offsets 0x71ef4/0x71ef6 (scaled by 0x71ee8/0x71eea about g_view center) = subtle camera sway; and "
			+ "advances 4 scroll/cycle offsets at 0x909b8 by g_frame_time_scale at staggered rates (modular, stride 4..0x3a) "
			+ "= animated texture scroll (water/lava/sky). Called from setup_frame_render_context."),
		new NamedFunction(0x292beL, "render_primary_scene_view",
			"[RENDER] The PRIMARY (main-camera) scene render: sets the view bounds (0x85308/0x8530c), walk_visible_sectors, "
			+ "then per clip region (0x85224 stride 3, count 0x85220) begin_sector_render_tree + build_sector_draw_order + "
			+ "build_scene_draw_list + render_world_face_list; sets 0x852e8 = nonempty. Non-reflection twin of "
			+ "render_clipped_sector_subscene; called by render_scene_body."),
		new NamedFunction(0x293caL, "compute_sector_wall_depth_range",
			"[RENDER] Walks a sector's walls (param_1+0xe list, +0xd count) and returns the MIN/MAX wall depth "
			+ "(gs:[wall+4]) in registers (multi-reg return the decompiler drops). Used by compute_floor_clearance_for_render "
			+ "to cull by the sector's nearest depth (< 0x4001)."),
		new NamedFunction(0x289deL, "store_secondary_surface_record",
			"[RENDER; <- render_world_secondary_surface] Builds a secondary-surface clip/render record at 0x84964 when the "
			+ "surface's screen bounds (0x90958/0x85314..) overlap the view: stores width/height (0x8496c/0x8496e), the "
			+ "center offsets relative to the view half-extents (0x84968/0x8496a), the clip plane (g_view_clip_plane), "
			+ "0x90a44, and param_1. Feeds render_reflection_subviews."),
		new NamedFunction(0x288fbL, "render_split_viewport_lower",
			"[RENDER] Renders the face list into the SECONDARY/lower viewport target (g_render_target_buffer += 0x89f2c, "
			+ "selector 0x89f28), shifting the vertical origin down by g_view_bound_bottom (shift_wall_nodes_vertical), then "
			+ "restores. The minimal split-viewport second pass (cf. render_secondary_viewport_pass)."),
		new NamedFunction(0x283adL, "relocate_moving_objects_to_sectors",
			"[RENDER/WORLD] Walks a linked list of moving objects (param_1 = head, next at *param_1) and re-resolves each "
			+ "node's sector via locate_sector_at_position(x,y,z) -> node[1]. The per-frame 're-sector the things that "
			+ "moved' pass (fires in the trace when a picked-up item is flying); reached via a Watcom shared-code fall-through "
			+ "tail (no direct caller in the corpus)."),
		new NamedFunction(0x283d9L, "add_reflection_view_entry",
			"[RENDER/mirror] Appends a reflection/mirror view to the list render_reflection_subviews walks "
			+ "(g_reflection_view_list 0x85344, stride 8, count g_reflection_view_count 0x85340, max 0x10), deduped by "
			+ "(0x84950, 0x853cc); only when 0x90a26==0 and 0x84950==0. Records the portal/edge ref (fs:[..+6])."),
		new NamedFunction(0x28350L, "dpmi_map_physical_memory",
			"[DPMI/VIDEO] Maps a physical memory region to a linear address via INT 31h AX=0x800 (size param_1 must be "
			+ ">0x10000; physical addr param_2). Returns the linear address, or 0 on carry/failure. Used by set_vesa_video_mode "
			+ "for the linear framebuffer (sibling of dpmi_map_physical_address 0x28387)."),
		new NamedFunction(0x2a909L, "alloc_scene_render_arena",
			"[RENDER] Allocates the 0x18000-byte scene render arena (g_door_worklist via game_heap_alloc_round4), sets the "
			+ "arena mid-pointer 0x84990 (= base + 0x7fda), and allocates its DPMI selector (g_map_geometry_selector). The "
			+ "sector-render-tree / draw-list working buffer."),
		new NamedFunction(0x2b25bL, "rotate_point_2d_shifted",
			"[RENDER/math] Thin wrapper: rotate_point_2d() >> 8 (the rotated coordinate scaled down by 256)."),
		new NamedFunction(0x2250eL, "tick_weapon_hud_ammo_anim",
			"[HUD; <- draw_active_ui_panels] Per-frame animator for the weapon-HUD ammo/value counters. "
			+ "If DAT_83e04 entries exist, advances a 0x10-step accumulator (DAT_83e08) by g_frame_time_scale "
			+ "and lerps each animated value (table DAT_83d84, stride 8) toward its target by 0x1000/(rate*0x46); "
			+ "when the animated entry is the selected weapon, writes g_active_weapon_item_id and refreshes via "
			+ "render_weapon_view(1)."),
		new NamedFunction(0x22633L, "free_hud_panel_das_handles",
			"[HUD] Frees the two HUD-panel DAS cache handles DAT_83d74/DAT_83d78 via pool_free_handle on "
			+ "g_das_cache_heap_handle and zeroes them. Releases cached weapon/panel imagery."),
		new NamedFunction(0x2268eL, "free_hud_weapon_das_handle",
			"[HUD] Frees the cached weapon-view DAS handle DAT_83d6c via pool_free_handle on "
			+ "g_das_cache_heap_handle and zeroes it."),
		new NamedFunction(0x22c84L, "render_health_status_panel",
			"[HUD; <- refresh_hud_layout] Renders a HUD status panel (param_2 = layout descriptor): draws the "
			+ "background panel image, resolves the normal/low-health bar reloc images (record[7]/[8]), computes a "
			+ "fill width from g_player_health/DAT_7fe44, swaps to the low-health image (reloc 0x298) below half, "
			+ "blits the clipped bar into the framebuffer row-by-row, and records the dirty rect (DAT_83e3c..)."),
		new NamedFunction(0x26266L, "free_das_cache_handle_if",
			"[RESOURCE] Thin guard: if param_1 != 0 calls free_das_cache_handle(). Conditional resource release."),
		new NamedFunction(0x2633cL, "show_simple_message_box",
			"[MENU] Wrapper that opens a message box with title string 0x71cd9 and flags 0x1200 "
			+ "(forwards param_2/param_3 to show_message_box)."),
		new NamedFunction(0x26356L, "show_cutscene_playback_menu",
			"[MENU/CUTSCENE; <- run_options_menu, options action 2000] PLAYTEST-CONFIRMED: the 'Playback menu' — the FMV "
			+ "cutscene gallery, opened by clicking the LEFT MARGIN of the options menu (the action-2000 hotspot, not a "
			+ "listed item). Lists every cutscene/story record SEEN so far (1..g_cutscenes_seen_count 0x82006): finds the "
			+ "first record tagged with each playback index (high byte of record+0x10), reads its title/line "
			+ "(read_next_dialogue_line), and builds a scrollable list (anchor g_playback_menu_scroll_anchor 0x83ea4); "
			+ "selecting an entry re-evaluates that record (action bit 0x800000 -> finish_dialogue_record_eval) to RE-WATCH "
			+ "the cutscene. Entries are registered by play_record_gdv_cutscene (assigns the next playback index, guarded by "
			+ "record[0x13])."),
		new NamedFunction(0x26a20L, "find_gdv_error_index",
			"[CUTSCENE; <- show_cutscene_error_box] Scans the 4-entry GDV/cutscene error-flag table (*DAT_83ea8, "
			+ "starting at DAT_83eac) calling FUN_000150b8(param_1) on each set flag; returns the matching error "
			+ "index 0..3, or 0x32 if none. Selects which g_gdv_error_strings message to display."),
		new NamedFunction(0x26b38L, "alloc_resource_pool_block",
			"[RESOURCE] Thin wrapper: pool_alloc_checked(g_resource_pool, param_1, param_3, param_2)."),
		new NamedFunction(0x26b66L, "load_sound_effect_bank",
			"[SOUND; <- via 0x15805] If sound enabled, (re)opens the digital sound bank file param_1: frees any "
			+ "prior buffers, allocates audio stream buffers, opens the file, verifies the 'SFX0' magic (0x53465830), "
			+ "allocates g_sound_sample_table (g_sound_sample_count = size/0xc), reads the sample directory and marks "
			+ "every entry's +0xb byte 0xff (unloaded). Returns the table ptr, or 0 (and disables sound) on failure."),
		new NamedFunction(0x26d3eL, "stop_sound_handle_voice",
			"[SOUND; <- cmd_activate_sfx_node/tick_change_height/tick_modify_sector] Finds the active sound handle "
			+ "(g_active_sound_handles, stride 0x9a) matching param_1, stops its SOS voice (sos_stop_voice), "
			+ "decrements the voice descriptor refcount and zeroes the handle slot. Returns 1 if stopped, else 0."),
		new NamedFunction(0x27080L, "play_sound_sequence_group",
			"[SOUND; <- 0x151c9] Plays a group of unique sounds: for a record (param_1) with count at +6, calls "
			+ "play_sound_unique on each 8-byte sub-entry, advancing g_pending_sound_param per sound. No-op if the "
			+ "sound bank file (DAT_848f8) is not open."),
		new NamedFunction(0x271e2L, "play_object_sound_thunk",
			"[SOUND] Thin thunk forwarding to play_object_sound()."),
		new NamedFunction(0x271fbL, "start_persistent_looping_sound",
			"[SOUND] Allocates a sound handle (find_free_slot_83ed4) and starts a persistent/looping voice: stores "
			+ "name ptr 0x84907, id (ECX&0x7fff), param_2 at +0x1a, volume 0x20, resolves the sample slot via "
			+ "resolve_sound_sample and calls start_sound_voice. Returns the handle ptr, or 0 if unavailable."),
		new NamedFunction(0x2721cL, "play_world_sound_squared_dist",
			"[SOUND] Plays a positional world sound: computes the squared distance from the point at param_1 "
			+ "(x@+0, y@+2) to the player position (DAT_90a8c/DAT_90a94 >> 16), then calls play_sound_unique. "
			+ "No-op when sound is disabled."),
		new NamedFunction(0x2799cL, "find_free_voice_descriptor",
			"[SOUND] Scans g_sound_voice_descriptors (32 slots) for the first empty (==0) entry; returns its index "
			+ "in DL, or 0xff if all 32 voice slots are in use."),
		new NamedFunction(0x279e4L, "release_voice_descriptor",
			"[SOUND] Releases voice descriptor slot param_1: if not busy (+8==0), marks its sample (g_sound_sample_table "
			+ "entry +0xb = 0xff = unloaded), frees its resource chunk and zeroes the descriptor. Returns 1 freed, "
			+ "2 if still busy, 0 if already empty."),
		new NamedFunction(0x27a3eL, "evict_oldest_voice_descriptor",
			"[SOUND] Voice-slot reclaimer: scans g_sound_voice_descriptors for the least-recently-used non-busy voice "
			+ "(by g_das_cache_tick - desc+0xc), or failing that the oldest voice including its +9 bias; stops its "
			+ "sample group and releases it (release_voice_descriptor). Returns the freed slot index, or 0xff."),
		new NamedFunction(0x27e46L, "format_decimal_grouped",
			"[CRT/FORMAT; <- vsprintf_core] Emits a decimal integer into the output buffer (EDI) digit by digit from "
			+ "1e9 down, honoring sign, width/precision state packed in the working flags, and the thousands-grouping "
			+ "comma when g_format_flags bit0 is set. printf %d core."),
		new NamedFunction(0x27f9bL, "copy_vesa_mode_list_block",
			"[VIDEO; <- match_vesa_video_modes 0x27fbf] Copies 0x40 dwords of the VESA mode-list (real-mode far ptr built "
			+ "from param+0xe/+0x10 segment:offset) into the caller's buffer and terminates it with 0xffff."),
		new NamedFunction(0x27fbfL, "match_vesa_video_modes",
			"[VIDEO; <- init_video_mode_table_once] Enumerates VESA modes (via dpmi_simulate_real_int + "
			+ "vesa_get_mode_info_block): for each supported mode, derives the bit-depth, and for every requested mode "
			+ "descriptor (param_1, count param_2) matching width/height/bpp, fills in the VESA mode number and "
			+ "framebuffer info (+6/+8). Populates the video mode table."),
		new NamedFunction(0x2d70cL, "draw_world_sprite_billboard",
			"[RENDER; <- render_world_sprite / render_world_secondary_surface] Draws one billboard sprite for an entity/object: inits the sprite render queue (project record fields +2 size / +10 vertical bias minus 0x852fa view-z), projects the sprite into the queue by its frame index (record+6), then finalizes and draws the queue unless the frame index overflows."),
		new NamedFunction(0x2d757L, "clip_and_emit_floor_walls",
			"[RENDER; <- emit_world_surface] Seeds the floor/ceiling clip span bounds (g_view_bound_right halves from 0x90958/0x90960, mode flags 0x853d7=3/0x853d8=0, saved EBP into 0x853c4) and runs clip_sector_walls_to_view to walk and clip the current sector's walls into view-space spans."),
		new NamedFunction(0x2db40L, "blit_scaled_viewport_to_framebuffer",
			"[VIDEO; <- update_player_tick] Copies the rendered viewport into the visible framebuffer applying g_view_scale_flags (0x90bd4): 0=1:1 (with optional turn-blend via g_turn_view_scale_state lookup table), 2=2x, 3=double both axes; pixels are byte-replicated and rows doubled as needed, then add_dirty_rect marks the region. Flags==0 path only marks dirty."),
		new NamedFunction(0x2ddceL, "redraw_cursor_after_blit",
			"[VIDEO; <- blit_dirty_rect_list] If the blit re-entrancy guard 0x85434 is set, restores the saved background and redraws the software mouse cursor (restore_and_redraw_cursor) after a dirty-rect framebuffer blit."),
		new NamedFunction(0x2de3cL, "blit_image_to_video_target",
			"[VIDEO; <- blit_screen_rect] Low-level rectangle blitter that copies a source image (width param_1, rows param_3, at row param_2) to the active video target, branching on the surface type: linear framebuffer (g_linear_framebuffer_ptr), VESA banked LFB (set_vesa_bank/_page2 across 64KB bank boundaries), raw 320x200, or planar VGA (out 0x3c4/0x3c5 plane mask, byte-spread into 4 planes). Returns rows/bytes written."),
		new NamedFunction(0x2e18bL, "clear_planar_vga_page",
			"[VIDEO; <- blank_active_video_page] Selects all four VGA bit-planes (out 0x3c4,2 / 0x3c5,0xf) and zeroes the active unchained page at (0x71f04<<4): 4000 dwords normally, 8000 when g_hires_line_doubling_flag is set."),
		new NamedFunction(0x2ea9fL, "automap_draw_entity_markers",
			"[AUTOMAP; <- render_map_geometry] Iterates the state pool (g_state_pool_a_records, stride 0x22) and dynamic-entity table (g_dynamic_entity_table, stride 0x1c) and, for each live record, draws its position as a marker on the automap via map_draw_player_marker, offset by g_map_world_center_x/_y and colored from the record's type byte."),
		new NamedFunction(0x2eb3aL, "automap_draw_doors",
			"[AUTOMAP; <- render_map_geometry] Walks the door pool (g_door_pool, g_door_count) and for each door copies its 4 wall corner vertices (record +0x82) into scratch 0x85462 and draws the 4 edges on the automap via map_draw_world_edge."),
		new NamedFunction(0x2f708L, "release_raw_state_and_setup_sfx",
			"[INIT/AUDIO; <- 0x21934] If g_raw_state_primary_buffer is allocated, releases the secondary raw-state buffer (0x4f221) when present and (re)builds the SFX node list via setup_sfx_nodes."),
		new NamedFunction(0x2fbe8L, "alloc_framebuffer_surface",
			"[VIDEO; <- init_video_surface] Allocates the off-screen framebuffer: 0x4b000 bytes for hi-res video modes 7/8, else 0x20000, preferring a DOS conventional-memory block (alloc_dos_block, flag 0x89f3a=1) and falling back to the game heap (flag=0). Stores the pointer in g_framebuffer_ptr/0x71f00 and builds the DPMI selectors via 0x2fd7c (hi-res) or 0x2fdbc (320x200)."),
		new NamedFunction(0x2fc98L, "init_video_surface",
			"[VIDEO; <- roth_main_sequence] Initializes the render surface: in non-linear (planar) mode sets g_screen_pitch=0x140, height=200, and rebuilds the scanline offset table (build_scanline_dest_offset_table), then allocates the framebuffer surface (alloc_framebuffer_surface)."),
		new NamedFunction(0x2fcd4L, "shutdown_render_subsystem",
			"[VIDEO/TEARDOWN; <- roth_main_sequence] Tears down the render/resource subsystem: frees the render color selectors, releases the framebuffer surface (free_framebuffer_surface), frees resource buffers, and closes the voice file."),
		new NamedFunction(0x2fce9L, "free_framebuffer_surface",
			"[VIDEO; <- shutdown_render_subsystem] Frees the framebuffer DPMI selectors (free_framebuffer_selectors) then releases g_framebuffer_ptr via the matching allocator: free_os_block_guarded when it came from a DOS block (flag 0x89f3a) else the game heap."),
		new NamedFunction(0x2fd7cL, "alloc_framebuffer_selectors_hires",
			"[VIDEO/DPMI; <- alloc_framebuffer_surface] Allocates two DPMI descriptors (INT 31h fn 0) for the hi-res (0x4b000) framebuffer — the primary render-target selector and the secondary at 0x89f28 — clears the secondary size/height fields (0x89f2c/0x89f2a) and sets the selector base/limit over g_framebuffer_ptr (dpmi_set_segment_limit)."),
		new NamedFunction(0x2fdbcL, "alloc_framebuffer_selectors_lores",
			"[VIDEO/DPMI; <- alloc_framebuffer_surface] Allocates the two DPMI descriptors (INT 31h fn 0) for the 320x200 (0x20000) framebuffer — primary render-target selector and secondary 0x89f28 — sets the secondary page size 64000 / height 200 (0x89f2c/0x89f2a) and bases the selectors over g_framebuffer_ptr."),
		new NamedFunction(0x2fe77L, "free_framebuffer_selectors",
			"[VIDEO/DPMI; <- free_framebuffer_surface] Frees the framebuffer DPMI descriptors (INT 31h fn 1): the primary render-target selector and the secondary 0x89f28, each zeroed atomically before release."),
		new NamedFunction(0x2fea0L, "refresh_palette_dac_wrapper",
			"[PALETTE; <- 0x20905] Thin wrapper that re-uploads the active 256-color palette to the VGA DAC via upload_palette_dac."),
		new NamedFunction(0x2fefbL, "upload_dac_palette_6bit",
			"[PALETTE; <- upload_palette_dac] Writes a prepared 256-entry RGB palette (pointer in EDI, e.g. the damage-flash scratch buffer) to the VGA DAC as-is: out 0x3c8 index then three out 0x3c9 6-bit components per entry."),
		new NamedFunction(0x2feffL, "upload_dac_palette_8to6",
			"[PALETTE; <- 0x20e98] Writes a 256-entry 8-bit RGB palette to the VGA DAC, scaling each component down to 6 bits (>>2): out 0x3c8 index then three shifted out 0x3c9 per entry."),
		new NamedFunction(0x2ffaeL, "find_nearest_palette_index",
			"[PALETTE; standalone] Returns the palette index (0..255) in g_palette_rgb_ptr whose RGB is closest to the given color (param_2 = ptr to r,g,b), using a weighted distance |dG|*4 + 2*|dR| + |dB|. Returns 0 if param_2 is null."),
		new NamedFunction(0x1de59L, "resolve_object_template_record",
			"[dbase100/spawn; <- cmd_spawn_object_adv 0x30d10] Resolves a dbase100 template by TABLE INDEX "
			+ "(param_1; 0 => use g_selected_item_primary). Stores param_1 in g_last_item_record, looks up "
			+ "g_dbase100_inventory_table[param_1], copies the template flags (+4) into g_object_template_flags "
			+ "(0x81f02), validates the template id (+2) is a real object (>= 0x200), and returns that id (or 0). "
			+ "Caller gates the spawn on flags bit0x20 (renderable). The by-index counterpart to give_item_by_dbase_id."),
		new NamedFunction(0x1ef9eL, "dialogue_window_open_hook",
			"[dbase100/dialogue; <- dbase100_open_dialogue_window 0x1eabc] Empty stub in this build (no-op called "
			+ "with arg 1 at the tail of opening an inspect/dialogue window). Likely a stripped debug/notification hook. "
			+ "LOW confidence on the exact intent; mechanism = does nothing."),
		new NamedFunction(0x1fbe4L, "close_dialogue_and_run_branch",
			"[dbase100/dialogue; <- dialogue_voice_force_end 0x1f671] Closes the active dialogue/choice window and "
			+ "runs its pending branch: clears g_active_dialogue_context/g_move_freeze_gate/g_dialogue_busy_flag, "
			+ "resets g_choice_selected_index=-1, then execute_dialogue_branch(DAT_0008313d) (the selected/default "
			+ "choice record). Invoked when a choice is accepted at end of voice playback."),
		new NamedFunction(0x1fc5cL, "clear_cutscene_region",
			"[cutscene; <- play_gdv_cutscene 0x2059d] Black-fills the cutscene/letterbox screen region "
			+ "(rows DAT_83b40..DAT_83b48, x DAT_83b3c) row-by-row via mem_fill(0), then add_dirty_rect over it and "
			+ "clears the region-dirty flag DAT_83b44. Called when DAT_83b44 != 0 (region needs clearing)."),
		new NamedFunction(0x202d5L, "blit_image_scaled_to_framebuffer",
			"[cutscene/video; <- present_cutscene_frame 0x20a8a] Copies a source 8-bit bitmap (param_1) to the "
			+ "framebuffer at (param_2,EBX) with optional pixel doubling. param_5/param_6 select X/Y scale (4=1x, "
			+ "2/1=double): handles 2x-both (writes 2x2 blocks), 2x-X-only, 2x-Y-only and 1:1 copy paths. Width "
			+ "param_3, height param_4, src stride param_3 (or 2x via local_1c). The cutscene/splash frame blitter."),
		new NamedFunction(0x20437L, "find_nearest_palette_color",
			"[palette; <- remap_pixels_to_palette 0x204a3] Finds the palette entry (over param_4 entries of the "
			+ "expanded-RGB table param_1, stride 3 u16) nearest to target RGB (param_2,EBX,param_3) by minimal "
			+ "Manhattan distance (abs(dR)+abs(dG)+abs(dB)). Returns the best index (byte); short-circuits on an exact "
			+ "match (distance 0)."),
		new NamedFunction(0x204a3L, "remap_pixels_to_palette",
			"[palette; <- present_cutscene_frame 0x20a8a] Remaps an 8-bit image (param_3, length param_4) from a "
			+ "source palette (param_2) into a destination palette (param_1). expand_rgb's both palettes (dst doubled), "
			+ "then for each source pixel finds the nearest dest color via find_nearest_palette_color (0x20437), caching "
			+ "results in a 256-entry LUT. Writes remapped bytes to EBX. Used to fit a cutscene frame to the live palette."),
		new NamedFunction(0x2057aL, "drain_input_and_clear_clicks",
			"[input; <- play_gdv_cutscene 0x2059d, show_fullscreen_image 0x20f81] Empties the keyboard ring "
			+ "(input_ring_dequeue until 0), polls the mouse once, and clears both cursor click flags "
			+ "(g_cursor_primary/secondary_action_flag). Flushes stale input before/around a modal screen."),
		new NamedFunction(0x20905L, "exit_cutscene_overlay_mode",
			"[cutscene/transition; <- finish_dialogue_record_eval 0x1db5e] Tears down the fullscreen cutscene/overlay "
			+ "mode (gated on DAT_83c70 active flag): clears the framebuffer, presents, restores the saved screen "
			+ "(slide-out via play_screen_slide_out or restore from g_screen_backup_handle), resumes music "
			+ "(finalize_audio_sequence_ref + emit_music_sequence_event), restores g_player_movement_enabled, ends the "
			+ "draw batch, frees the cutscene image handle (DAT_83c74) and clears the click flags."),
		new NamedFunction(0x20a8aL, "present_cutscene_frame",
			"[cutscene/video; <- dbase100_open_dialogue_window 0x1eabc] Presents one decoded cutscene/splash frame: "
			+ "if an image handle (DAT_83c74) is set, remaps it to the live palette (remap_pixels_to_palette 0x204a3) "
			+ "and blits it scaled (blit_image_scaled_to_framebuffer 0x202d5), marks dirty, frees the handle; else just "
			+ "marks the full screen dirty. Then flush_dirty_rects + flip_video_page + refresh_palette_dac, clears click "
			+ "flags, ends the draw batch and sets g_player_movement_enabled=5."),
		new NamedFunction(0x20b91L, "snapshot_screen_and_slide_out",
			"[UI/transition; <- repaint_hud_and_present 0x17317] Snapshots the current framebuffer into a fresh "
			+ "g_das_cache_heap backup handle (frees any prior), then plays the slide-out transition "
			+ "(play_screen_slide_out) and frees the backup. One-shot capture-then-slide-out of the live screen."),
		new NamedFunction(0x20e98L, "load_and_center_fullscreen_image",
			"[UI/image; <- show_fullscreen_image 0x20f81] Loads a DAS resource (param_1) from the map DAS file "
			+ "(g_dbase300_filename) into the cache, centers it on screen (x=(pitch-w)/2, y=(height-h)/2, bounds-checked "
			+ "to 320x200), optionally line-doubles in hires, decodes if uncompressed (flag bit1 clear -> 0x2feff), and "
			+ "blits it to the framebuffer. Frees the handle and returns nonzero on success."),
		new NamedFunction(0x20f81L, "show_fullscreen_image",
			"[UI/modal; called indirectly] Shows a fullscreen still image (param_1 = DAS resource id) as a modal "
			+ "screen: sets the wait cursor, snapshots+slide-in's the prior screen into g_screen_backup_handle, begins a "
			+ "draw batch, loads/centers the image via load_and_center_fullscreen_image (0x20e98), presents, then "
			+ "spins polling input until Esc (scancode 1) or a mouse click dismisses it. Returns 1 if param_1 != 0."),
		new NamedFunction(0x218deL, "open_raw_state_temp",
			"[savegame/state; <- process_map_warp_or_load 0x1096f] Builds the per-level raw-state temp path (game "
			+ "dir + base name + extension \"TMP\" 0x504d54) and dos_open_file's it for read, returning the handle. The "
			+ "read counterpart of write_raw_state_temp (0x21879)."),
		new NamedFunction(0x21934L, "load_raw_state_from_temp",
			"[savegame/state; <- process_map_warp_or_load 0x1096f] Loads the raw world/map state from the .TMP handle "
			+ "(param_1, from open_raw_state_temp): if handle==0 freshly init_loaded_map_state(0,0,...); else "
			+ "read_raw_state_stream() then close. On read success returns 1; on failure runs the fallback init 0x2f708 "
			+ "and returns 0."),
		new NamedFunction(0x21cb1L, "free_das_image_handle",
			"[das-cache; <- show_message_box 0x2508f] Thin wrapper that pool_free_handle's a DAS-cache image handle "
			+ "(g_das_cache_heap_handle, param_1) after it has been blitted — frees the savegame-thumbnail DAS block. "
			+ "(Decompiler's extra args are spurious Watcom register noise.)"),
		new NamedFunction(0x3c28cL, "thunk_build_atan_table",
			"[MATH; <- roth_game_startup] Thin __stdcall thunk that just calls build_atan_table (the atan2 lookup-table builder)."),
		new NamedFunction(0x3cac5L, "thunk_compute_object_screen_bbox",
			"[SPRITE; <- clip_object_to_frustum] Thin __stdcall thunk that just calls compute_object_screen_bbox."),
		new NamedFunction(0x3d387L, "setup_door_corner_surface_a",
			"[DOOR; <- setup_door_swing_geometry] Populates one door-corner wall-surface descriptor from FS-segmented "
			+ "geometry: reads sector id (+0x26 = word&0xfff), tex word (+0xc) and the surface draw-flag byte, "
			+ "deriving the +0x16 draw flags (0x100/0x40/0x18/0x10 from flag bits 4/0x10/8/1) plus the flip byte +0xe. "
			+ "Paired with setup_door_corner_surface_b (0x3d3a8); both build the rotating door quad's per-edge surface records."),
		new NamedFunction(0x3d3a8L, "setup_door_corner_surface_b",
			"[DOOR; <- setup_door_swing_geometry] Sibling of setup_door_corner_surface_a (0x3d387): same surface-flag "
			+ "derivation but indexes the geometry through BX[8]->[+4] (a different door-corner edge). Fills the door "
			+ "quad surface record (+0x26 sector, +0xc tex, +0x16 draw flags, +0xe flip)."),
		new NamedFunction(0x3d8f2L, "restart_door_open_sound",
			"[DOOR; <- toggle_door_open_state] On a single door record: stops the previous looping sound (+0x1a) if "
			+ "playing, then if it has an open-sound id (+0x26) starts play_world_sound_at_pos at the door position "
			+ "(+0x14), sets the loop handle (+0x1e=1000), and updates the door state flags (+2: clear bit1, set bit2 = opening)."),
		new NamedFunction(0x3d93fL, "toggle_door_open_state",
			"[DOOR; <- activate_targeted_object (type6 door)] Toggles the door whose record sits at g_door_state_table "
			+ "(0x8b3fa)[id]: if already opening (flag bit2) decrements the bit and returns via restart_door_open_sound; "
			+ "otherwise stops/restarts the open sound and sets the opening flags. The left-click door-activation entry."),
		new NamedFunction(0x3d959L, "tick_doors_for_frame",
			"[DOOR; <- setup_frame_render_context] Per-frame door driver: if a map is loaded (g_surface_record_selector!=0) "
			+ "runs both door pools for this frame's time slice (g_frame_time_scale) via tick_secondary_doors(0x3d98f) "
			+ "and tick_swinging_doors(0x3db8d)."),
		new NamedFunction(0x3d98fL, "tick_secondary_doors",
			"[DOOR; <- tick_doors_for_frame] Advances every active record in g_secondary_door_pool (stride 0x16 words, "
			+ "count g_secondary_door_count): slides the door surface offset (+4) toward open/closed by the frame step, "
			+ "clamps at the open/closed limits, runs open-dwell timers, plays/stops the loop sound, fires the per-door "
			+ "completion callback (+5), and writes the resulting wall offset back into the geometry via g_geometry_selector. "
			+ "Handles the SLIDING (non-swinging) doors."),
		new NamedFunction(0x3dafbL, "test_door_query_near_player",
			"[DOOR; <- tick_secondary_doors] Guard that runs scan_portal_walls_near_query against the moving door wall "
			+ "(EDI[0]) and g_player_sector only when the door's travel is within ~0x40 of the camera bound (DAT_00090a90); "
			+ "limits the expensive portal-wall rescan to doors near the player."),
		new NamedFunction(0x3db8dL, "tick_swinging_doors",
			"[DOOR; <- tick_doors_for_frame] Advances every active record in g_door_pool (stride 0xfb words, count "
			+ "g_door_count): integrates the swing angle (+3) by the frame step toward the open/closed limit, calls "
			+ "update_door_swing/rotate_quad to recompute the rotated corner positions each step, manages the looping "
			+ "open/close sounds (stop_sound_by_id/play_world_sound_at_pos/play_entity_sound), runs the completion "
			+ "callback (+2), marks the affected sectors dirty (+0x16 bit0), and removes finished doors (decrements "
			+ "g_door_count). The SWINGING (hinged) door integrator."),
		new NamedFunction(0x3de36L, "compute_door_quad_bounds",
			"[DOOR; <- tick_swinging_doors] Scans the 4 rotated corners of the door quad (record+0x2e, stride 8) to find "
			+ "the min/max X and Y, then tests that bounding box (inflated by 0x1a) against the camera position "
			+ "(DAT_00090a8c/DAT_00090a94) — a coarse visibility/cull check used while integrating a door's swing."),
		new NamedFunction(0x40a2aL, "game_free_if_not_null",
			"[HEAP] Null-safe wrapper around game_heap_free: frees the block only when the pointer is non-zero."),
		new NamedFunction(0x41051L, "postprocess_loaded_das_block",
			"[DAS-CACHE; <- DAS loader] Post-processes a DAS block just read into cache: for RLE/atlas blocks "
			+ "(flags&0x100, marker -2) repairs the frame count and allocates a backing cache chunk via the DAS pool "
			+ "(pool_alloc_handle, eviction-protected), wiring the chunk header to the block; otherwise walks the "
			+ "sub-frame directory (+0x12) computing per-cell sizes and (re)allocating descriptors via setup_das_block_selector."),
		new NamedFunction(0x411e0L, "select_das_fat_entry",
			"[DAS-CACHE] Selects a DAS FAT entry from the map FAT buffer (or the ADEMO FAT past index 0x2400) at "
			+ "g_current_das_fat_index_x2 and copies its offset/size/flags into g_current_das_fat_entry, setting "
			+ "g_current_das_block_size_bytes; falls back to a 10-byte stub entry for empty slots."),
		new NamedFunction(0x41250L, "refresh_moved_das_cache_block",
			"[DAS-CACHE] Re-validates a DAS cache block whose backing chunk may have been relocated by the pool "
			+ "allocator: re-reads the handle back-reference and fixes up the block's data pointer before use."),
		new NamedFunction(0x41317L, "read_das_block_payload",
			"[DAS-CACHE] Reads a DAS block's raw payload bytes from the open data file into the cache buffer."),
		new NamedFunction(0x41331L, "read_das_block_with_size_prefix",
			"[DAS-CACHE] Reads a DAS block that carries a leading size prefix: reads the size word then that many "
			+ "payload bytes into the cache buffer."),
		new NamedFunction(0x4134aL, "reserve_das_cache_slot",
			"[DAS-CACHE] Reserves/initialises a DAS cache directory slot (selects the slot index, records the "
			+ "current allocation) prior to loading a block into it."),
		new NamedFunction(0x413eaL, "evict_one_das_cache_slot",
			"[DAS-CACHE] Evicts a single least-needed DAS cache slot to reclaim space (frees its chunk back to the "
			+ "DAS pool); driven by ensure_das_cache_heap_space."),
		new NamedFunction(0x414d2L, "ensure_das_cache_heap_space",
			"[DAS-CACHE] Frees DAS cache slots (looping evict_one_das_cache_slot) until the requested byte count "
			+ "can be allocated from the DAS pool heap; respects g_das_eviction_protected_allocation."),
		new NamedFunction(0x414f4L, "get_loaded_das_block_for_index",
			"[DAS-CACHE] Returns the in-cache DAS block for a FAT index, loading it on demand (FAT select -> read -> "
			+ "postprocess) if not already resident. The DAS cache lookup entry point."),
		new NamedFunction(0x41554L, "initialize_das_block_internal_pointers",
			"[DAS-CACHE] After a DAS block is resident, fixes up its internal pointers/offsets (frame directory, "
			+ "pixel base) to absolute addresses within the cache chunk."),
		new NamedFunction(0x41616L, "zero_memory",
			"[CRT/MEM] memset-to-zero helper: clears a byte range to 0."),
		new NamedFunction(0x41631L, "repair_das_rle_frame_count",
			"[DAS-CACHE; <- postprocess_loaded_das_block] Repairs/recomputes the frame count in an RLE DAS block "
			+ "header by walking the compressed payload to the declared byte length."),
		new NamedFunction(0x41b41L, "dos_close_handle",
			"[CRT/DOS — host-mapped] INT 21h 0x3E close of a DOS file handle."),
		new NamedFunction(0x41b53L, "dos_read_items",
			"[CRT/DOS — host-mapped] INT 21h 0x3F read of N items into a buffer from a DOS file handle."),
		new NamedFunction(0x41b7aL, "dos_write_items",
			"[CRT/DOS — host-mapped] INT 21h 0x40 write of N items from a buffer to a DOS file handle."),
		new NamedFunction(0x42014L, "release_object_secondary_state",
			"[OBJECT-POOL; <- add_secondary_state_record] Releases the per-object secondary-state record indexed by "
			+ "(id - _DAT_00091dfc)/0xd via remove_secondary_state_record, and if the object has no remaining state "
			+ "clears its active bit (+0x16 bit1) in g_raw_state_primary_buffer."),
		new NamedFunction(0x42189L, "alloc_object_record_ensuring_space",
			"[OBJECT-POOL; <- cmd_spawn_object_adv / add_secondary_state_record] Ensures at least 0x12 free object "
			+ "slots (reserve_object_buffer_space when low) then allocates an object record slot."),
		new NamedFunction(0x422ecL, "spawn_player_projectile_flagged",
			"[OBJECT-POOL; <- cmd_spawn_object_adv] Sets DAT_000911cb=1 around spawn_object_projectile_at_player so "
			+ "the spawned projectile is tagged as the player's, then clears the flag."),
		new NamedFunction(0x4347eL, "launch_enemy_attack_animation",
			"[ENEMY-AI; <- aim_enemy_at_player] Begins an enemy's attack action: re-validates the entity def, picks the "
			+ "primary or secondary attack from the def flags (entity+9 bits2/6, DAT_00072731 threshold), sets the attack "
			+ "animation frame (+0x1e = attack-frame+1), plays the attack sound (play_entity_sound), and raises the "
			+ "attacking flags (+2 bit3, resets +0x1a timer). The attack-windup launcher beside begin_enemy_attack."),
		new NamedFunction(0x43854L, "watcom_runtime_startup",
			"[CRT — host-mapped] Watcom C runtime startup / __CMain bootstrap (argv setup, init tables); maps to the "
			+ "host program entry."),
		new NamedFunction(0x43a6dL, "crt_log_and_exit",
			"[CRT/DOS — host-mapped] Opens/creates a log file (INT 21h 0x3D01), writes a NUL-terminated message "
			+ "(0x40), runs the fini table, and terminates the process (INT 21h 0x4C). Abort/exit path."),
		new NamedFunction(0x43ab4L, "collect_sfx_nodes_by_key",
			"[SFX/TRIGGER; <- cmd_activate_sfx_node] Scans g_sfx_nodes for records whose key (+6) matches "
			+ "param_1, writing each match's relative offset into the caller's list (param_2+2..), and returns the "
			+ "count (also stored at param_2[0]); bounded by the caller-supplied capacity (EBX)."),
		new NamedFunction(0x43b3bL, "query_sfx_emitters_in_range",
			"[SFX/TRIGGER; <- audio-sequence 0x151c9] Proximity query over g_sfx_nodes: collects active "
			+ "(+4 bit0x80) emitter records whose squared distance from the query point is within their radius (+5), "
			+ "advancing per-record retrigger timers for periodic types (+4 low bits 2/3), into the caller's "
			+ "{record,dist^2} list; stores the count, then sorts the list by distance via sort_sfx_query_by_distance."),
		new NamedFunction(0x43c89L, "sort_sfx_query_by_distance",
			"[SFX/TRIGGER; <- query_sfx_emitters_in_range] Bubble-sorts the {record-ptr, distance^2} result pairs "
			+ "ascending by distance so the nearest emitters come first."),
		new NamedFunction(0x43cceL, "compute_sound_pan_from_position",
			"[AUDIO; <- play_sound_unique] Rotates a 2D source position into view space (rotate_point_2d_shifted) and "
			+ "maps the lateral component to a 16-bit stereo pan value (scaled by 0x7400/(depth+1), biased 0x8000, "
			+ "clamped 0..0xffff)."),
		new NamedFunction(0x43dfcL, "crt_spawn_via_comspec",
			"[CRT — host-mapped] Looks up the COMSPEC environment variable and spawns the command processor "
			+ "(Watcom system()/spawn helper); returns 1 when COMSPEC is unset."),
		new NamedFunction(0x43e71L, "dpmi_lock_sos_driver_regions",
			"[SOS/DPMI — host-mapped; <- install_sos_driver_vtables] DPMI-locks the (up to 15) linear memory regions "
			+ "used by the HMI SOS sound driver so they stay resident for IRQ-time access; returns 0 on success, 5 on "
			+ "any lock failure."),
		new NamedFunction(0x37c60L, "render_world_col_unshaded_37c60",
			"[wall-column span mapper, SECONDARY/no-clip variant; fn-ptr in g_world_span_fn2 (col1, table 0x71f84), tail-jmp'd by dispatch_world_span_column 0x3778b] Vertical (dest stride 0x140, 2-row unrolled) UNSHADED OPAQUE column: direct texel copy *dst = src[esi]; carry-stepped src walk (esi += carry+step). No colormap/transparency. The minimal opaque mapper. See lift_handoffs/wall_mappers_SMC_and_classification.md."),
		new NamedFunction(0x37cecL, "render_world_col_shaded_masked_clipped_37cec",
			"[wall-column span mapper, PRIMARY/clipped variant; fn-ptr in g_world_span_fn (col0, table 0x71f80), tail-jmp'd by dispatch_world_span_column 0x3778b] The FULL primary wall mapper: vertical 2-row-unrolled SHADED + TRANSPARENT column. Texel 0 skipped; texel -> remap colormap (ebx + g_active_world_remap_base 0x8a2ac); g_span_accum_init bit15 (0x80) selects a depth-gradient path that decrements the colormap row by 0x100 per step. Reads steps live from the working-set (no self-patch). See wall_mappers_SMC_and_classification.md (\"shaded, transparent, CLIPPED\")."),
		new NamedFunction(0x37ec8L, "render_world_col_shaded_gs_37ec8",
			"[wall-column span mapper, PRIMARY; fn-ptr g_world_span_fn (col0, table 0x71f80), tail-jmp'd by dispatch_world_span_column] Vertical 2-row-unrolled SHADED OPAQUE column through the GS depth colormap (gs:[(shade<<8)|texel]). Dual interleaved fixed-point accumulators (SMC-patched add ebp / adc eax step immediates at 0x37f48/0x37f64). No transparency test. See wall_mappers_SMC_and_classification.md."),
		new NamedFunction(0x37facL, "render_world_col_unshaded_masked_2axis_37fac",
			"[wall-column span mapper, PRIMARY; fn-ptr g_world_span_fn (col0, table 0x71f80), tail-jmp'd by dispatch_world_span_column] Vertical 3-body-unrolled 2-AXIS (U+V) UNSHADED TRANSPARENT column: source addressed via a wrap-masked offset (src[(SI-wrap_base)&reoffset]); g_span_accum_init bit15 + the 0x8a34e/0x8a2b0 parity pick a -0x100 colormap-decrement gradient sub-loop. Self-patches its V add edx / adc ebx steps (writers 0x37fd4../0x37fbf..). See wall_mappers_SMC_and_classification.md."),
		new NamedFunction(0x38198L, "render_world_col_shaded_masked_gs_38198",
			"[wall-column span mapper, PRIMARY; fn-ptr g_world_span_fn (col0, table 0x71f80), tail-jmp'd by dispatch_world_span_column] Sibling of render_world_col_shaded_gs_37ec8 but TRANSPARENT: 'if (texel != 0)' before the gs:[(shade<<8)|texel] store. Vertical 2-row-unrolled, dual SMC-patched accumulators (add ebp 0x3823b / adc eax 0x38240). The masked GS-shaded primary column."),
		new NamedFunction(0x38288L, "render_world_col_unshaded_masked_2axis_38288",
			"[wall-column span mapper, PRIMARY; fn-ptr g_world_span_fn (col0, table 0x71f80), tail-jmp'd by dispatch_world_span_column] Vertical 2-row-unrolled 2-AXIS UNSHADED TRANSPARENT column: wrap-masked source (src[(SI-wrap_base)&reoffset]), texel 0 skipped, raw copy (no colormap). Self-patches V add edx 0x3830a / adc ebx 0x38313. Masked sibling of the 2-axis family (cf. 0x37fac without shade-gradient)."),
		new NamedFunction(0x3832cL, "render_world_col_unshaded_2axis_3832c",
			"[wall-column span mapper, SECONDARY/no-clip; fn-ptr g_world_span_fn2 (col1, table 0x71f84), tail-jmp'd by dispatch_world_span_column] Minimal vertical 2-row-unrolled 2-AXIS UNSHADED OPAQUE column: wrap-masked source ((SI-wrap_base)&reoffset), raw texel copy, no transparency. Self-patches adc ebx 0x3838b/0x383a4. The opaque secondary 2-axis mapper."),
		new NamedFunction(0x383acL, "render_world_col_unshaded_masked_2axis_383ac",
			"[wall-column span mapper, SECONDARY/no-clip; fn-ptr g_world_span_fn2 (col1, table 0x71f84), tail-jmp'd by dispatch_world_span_column] Transparent companion of render_world_col_unshaded_2axis_3832c: same wrap-masked 2-axis raw copy but with 'if (texel != 0)' skip. Self-patches adc ebx 0x3840f/0x3842c."),
		new NamedFunction(0x38434L, "render_world_col_shaded_gs_wrapped_38434",
			"[wall-column span mapper, PRIMARY, WRAPPED; fn-ptr g_world_span_fn (col0, table 0x71f80), tail-jmp'd by dispatch_world_span_column] Vertical 2-row-unrolled SHADED OPAQUE column with a power-of-two TEXTURE-WRAP mask ('and esi, MASK' driver-patched at 0x384b2/0x384d1 from g_span_src_wrap_reoffset); samples gs:[(shade<<8)|texel]. One of the three wrapped wall mappers. See wall_mappers_SMC_and_classification.md."),
		new NamedFunction(0x384fcL, "render_world_col_shaded_masked_gs_wrapped_384fc",
			"[wall-column span mapper, PRIMARY, WRAPPED; fn-ptr g_world_span_fn (col0, table 0x71f80), tail-jmp'd by dispatch_world_span_column] Transparent companion of render_world_col_shaded_gs_wrapped_38434: same wrap-masked source (driver patches 0x38582/0x385a5) and gs colormap, but 'if (texel != 0)' skip. The masked wrapped GS-shaded primary column."),
		new NamedFunction(0x385d4L, "render_world_col_tint_385d4",
			"[wall-column span mapper, SECONDARY/no-clip stub; fn-ptr g_world_span_fn2 (col1, table 0x71f84), tail-jmp'd by dispatch_world_span_column] Tiny untextured TRANSLUCENT-TINT column: reads each dest pixel and remaps it through the colormap row (g_sprite_fill_index<<8 | dst) = a constant-shade tint/fog over the existing framebuffer column (no source texture). 8-byte stub form of the 0x385dc/0x38631 tint family."),
		new NamedFunction(0x385dcL, "render_world_col_tint_gs_385dc",
			"[wall-column span mapper, PRIMARY; fn-ptr g_world_span_fn (col0, table 0x71f80), tail-jmp'd by dispatch_world_span_column] Untextured TRANSLUCENT-TINT column through the GS colormap: color = gs:[(dst<<8)|g_sprite_fill_index] written back over the dest. Constant-shade tint/fog over the framebuffer column (cf. 0x385d4 without the gs segment). 'blended' in the classification table."),
		new NamedFunction(0x38631L, "render_world_col_tint_gradient_38631",
			"[wall-column span mapper, PRIMARY; fn-ptr g_world_span_fn (col0, table 0x71f80), tail-jmp'd by dispatch_world_span_column] Untextured TRANSLUCENT-TINT column with a per-row GRADIENT: blends gs:[(fill_index<<8)|dst] over the dest while ramping the colormap row by g_span_pixel_step each step (single non-unrolled loop, stride 0x140). The gradient tint/fog column (sibling of render_world_col_tint_gs_385dc)."),
		new NamedFunction(0x38684L, "render_world_col_solid_fill_38684",
			"[wall-column span mapper, PRIMARY; fn-ptr g_world_span_fn (col0, table 0x71f80), tail-jmp'd by dispatch_world_span_column] Untextured SOLID-FILL column: loads gs:[g_sprite_fill_index] once and writes it down the column (8-way Duff-device unrolled, stride 0x140). g_span_accum_init bit15 selects a shade-gradient path (decrements the colormap row, parity-selected sub-table PTR_LAB_00038750). The flat-color wall/fill column."),
		new NamedFunction(0x387e0L, "render_world_col_fill_wrap_387e0",
			"[wall-column span mapper, SECONDARY/no-clip trampoline; fn-ptr g_world_span_fn2 (col1, table 0x71f84), tail-jmp'd by dispatch_world_span_column] 16-byte trampoline that tail-calls render_span_fill_38697(g_sprite_fill_index) = the generic solid-fill column helper. The secondary-bank solid-fill entry."),
		new NamedFunction(0x387f0L, "render_world_col_noop_387f0",
			"[wall-column span mapper, PRIMARY degenerate; fn-ptr g_world_span_fn (col0, table 0x71f80), tail-jmp'd by dispatch_world_span_column] Degenerate / zero-pixel column: writes nothing, just returns the EAX shade accumulator (g_span_accum_init<<0x10). The empty-span no-op handler installed for the no-draw mode."),
		new NamedFunction(0x388beL, "render_world_col_unshaded_masked_388be",
			"[wall-column span mapper, SECONDARY/no-clip; fn-ptr g_world_span_fn2 (col1, table 0x71f84), tail-jmp'd by dispatch_world_span_column] Transparent companion of render_world_col_unshaded_37c60: vertical 2-row-unrolled UNSHADED column, direct texel copy with 'if (texel != 0)' skip and the tail-pixel wrap reload. Reads steps live (no self-patch). The masked opaque-style secondary column."),
		new NamedFunction(0x38964L, "render_world_col_shaded_masked_mirror_38964",
			"[wall-column span mapper, PRIMARY, MIRROR/x-flip family; fn-ptr g_world_span_fn (col0, table 0x71f80), tail-jmp'd by dispatch_world_span_column] The big (~1864-byte) reversed-step mega-mapper covering the back-facing / MIRRORED-REFLECTION cases (its fs-addressed x-flip sub-loops, entered on g_span_mode flag 0x8a356, produce the reflected pixels for the deferred secondary/mirror surface pass — see lift_handoffs/RESPONSE_28dbe_subpass_consumer.md). Masked-transparent SHADED column: texel 0 skipped; texel -> remap colormap (g_active_world_remap_base); g_span_accum_init bit15 + 0x8a34e/0x8a2b0 parity pick a -0x100 depth-gradient sub-loop. The mirror/back-face wall column mapper."),
		new NamedFunction(0x392ccL, "render_world_col_shaded_blend_2axis_392cc",
			"[wall-column span mapper, PRIMARY; fn-ptr g_world_span_fn (col0, table 0x71f80), tail-jmp'd by dispatch_world_span_column] Vertical 2-row-unrolled 2-AXIS SHADED+BLEND TRANSPARENT column with wrap-masked source ((SI-wrap_base)&reoffset). Per texel: 0 skipped; texel&0x80 -> translucency blend (CONCAT11(dst, gs:[texel])) ; else opaque gs:[(shade<<8)|texel]. Self-patches V add edx 0x39337 / adc ebx 0x39356. The shaded+blended 2-axis primary column."),
		new NamedFunction(0x39398L, "render_world_col_blend_2axis_39398",
			"[wall-column span mapper, SECONDARY/no-clip; fn-ptr g_world_span_fn2 (col1, table 0x71f84), tail-jmp'd by dispatch_world_span_column] Vertical 2-row-unrolled 2-AXIS BLEND TRANSPARENT column with wrap-masked source. Per texel: 0 skipped; texel&0x80 -> es translucency blend (dst<<8|texel); else raw texel. Self-patches adc ebx 0x39411/0x39430. The blend/transparent secondary 2-axis column."),
		new NamedFunction(0x39453L, "render_world_col_blend_masked_39453",
			"[wall-column span mapper, SECONDARY/no-clip; fn-ptr g_world_span_fn2 (col1, table 0x71f84), tail-jmp'd by dispatch_world_span_column] Vertical 2-row-unrolled BLEND TRANSPARENT column, linear source (no wrap mask): texel 0 skipped, texel&0x80 -> es translucency blend (dst<<8|texel), else raw texel; tail-pixel wrap reload. Reads steps live (no self-patch). The linear blend/transparent secondary column."),
		new NamedFunction(0x39520L, "render_world_col_shaded_blend_masked_39520",
			"[wall-column span mapper, PRIMARY; fn-ptr g_world_span_fn (col0, table 0x71f80), tail-jmp'd by dispatch_world_span_column] Vertical 2-row-unrolled SHADED+BLEND TRANSPARENT column, linear source: texel 0 skipped; texel&0x80 -> translucency blend (dst<<8 | remap[texel]); else opaque remap[texel] (g_active_world_remap_base). Self-patches add ebp 0x39574/0x39588. The linear shaded+blended primary column."),
		new NamedFunction(0x38fecL, "advance_das_sprite_animation_frame",
			"[DAS sprite animator; <- DAS frame/draw setup, ESI=loaded DAS block] Advances an animated DAS sprite's frame state: -2 sentinel (+0x16) = static (return); steps the frame timer (+0x1a) by g_frame_time_scale gated on g_das_cache_tick (+0x10), wrapping the frame index (+0x18) against the frame count (+0x16) and re-applying the loop point (+0x1b). Sets g_render_source_base_ptr to the current frame's pixel base (ESI+0x10+[+0x14]) and, when the frame has a delta stream ([+0x1c+idx*4] != 0), calls apply_das_sprite_frame_delta_stream. NOT a span mapper despite the address range."),
		new NamedFunction(0x3bfd6L, "isqrt_fixed_wrapper_3bfd6",
			"[math; thin wrapper] Tail-wraps isqrt_fixed (0x3bfe5) and returns its 16-bit result. A trivial forwarding stub (register-passed args)."),
		new NamedFunction(0x10382L, "tick_ambient_render_and_map",
			"[RENDER/per-frame; <- update_player_movement 0x1035a] Advances the ambient render-animation phase counter 0x8a355 by (0x85328>>1), wrapping on overflow and forcing it to 1 while the high byte of 0x85328 is <3, then renders the main world view (render_world_view_pass &DAT_00089ed0) and, when g_debug_map_enabled is set, draws the debug map overlay."),
		new NamedFunction(0x103c8L, "begin_frame_then_init_mouse",
			"[BOOT/SCREEN; <- roth_game_startup] Starts a screen draw (begin_screen_draw), initializes the software mouse cursor via FUN_00011594 (INT 33h reset), sets DAT_0007674e=0xffff, and returns the mouse-init result."),
		new NamedFunction(0x10d90L, "blit_remapped_cursor_glyph",
			"[CURSOR; <- remap_builtin_palette_image 0x10d67] Copies a small remap-template string (0x70443) into a scratch buffer at 0x76769, substituting bytes 1/2 with the per-call palette indices at 0x7675c, then blits it as a scaled sprite at the mouse position (blit_scaled_sprite_at_mouse). Builds the recolored hardware-cursor glyph."),
		new NamedFunction(0x11337L, "console_read_key_crlf",
			"[BOOT/CONSOLE; <- dispatch_config_field_key 0x11382 / 0x1134d] Reads one console key (dos_print_char with no arg = input), echoes a CR+LF, and returns the key char. Used to drive the startup boot-config field menu."),
		new NamedFunction(0x1134dL, "dispatch_config_field_key_alt",
			"[BOOT/CONSOLE] Boot-config menu key handler (near-duplicate of dispatch_config_field_key 0x11382): reads a key (console_read_key_crlf), edits the matching startup field — 'N'->Name (console_edit_text_field max 4), 'P'->Path (max 0x3c), 'F'->console_edit_numeric_field (0x11462)."),
		new NamedFunction(0x11462L, "console_edit_numeric_field",
			"[BOOT/CONSOLE; <- dispatch_config_field_key] Edits a numeric startup-config field: formats the current value (*ESI) to decimal digits into 0x7073d, runs the line editor (console_edit_field) with numeric-only input, then re-parses the typed decimal digits back into the short at *ESI."),
		new NamedFunction(0x11594L, "init_software_mouse",
			"[CURSOR/INPUT; <- begin_frame_then_init_mouse 0x103c8] Resets the mouse via INT 33h (function 0); if a mouse is present it blits the cursor sprite (blit_scaled_sprite_at_mouse, PTR 0x7079f) and returns 0, otherwise bumps g_screen_busy_depth by 0x50 and returns -1 (no-mouse path)."),
		new NamedFunction(0x11eecL, "present_dirty_cursor_region",
			"[SCREEN/CURSOR; <- blit_screen_rect 0x2dddd] When g_screen_busy_depth<2, programs the VGA sequencer/GC for the back-to-front copy (planar path when not raw/linear), then restores the saved cursor region (restore_cursor_region_if_set) from whichever save buffer (0x7a8a4 or 0x76898) the dirty-rect index 0x71f04 selects. The cursor-aware tail of the per-rect screen blit."),
		new NamedFunction(0x122e3L, "vsync_timer_tick",
			"[INPUT/TIMER; INT-driven] Per-tick service: bumps the frame-tick counter 0x90bcc, and when g_player_movement_enabled bit0 is set updates the software cursor (update_software_cursor) and runs the player movement tick; then invokes the optional installed callback at 0x7e8d4 if present. The timer/vsync heartbeat."),
		new NamedFunction(0x12437L, "install_timer_int8",
			"[INPUT/TIMER; <- roth_main_sequence] Installs the game's INT 08h (PIT) handler: saves the prior vector (crt_dos_vector_op(8) -> off 0x7e8e4 / seg 0x7e914), hooks the new one (crt_int21_dispatch(8)), and reprograms PIT channel 0 to divisor 0x4242 for the faster game tick rate."),
		new NamedFunction(0x1246aL, "install_keyboard_int9",
			"[INPUT; <- roth_main_sequence] Installs the game's INT 09h keyboard handler: clears the input ring (reset_input_ring), saves the prior vector (crt_dos_vector_op(9) -> off 0x7e8e8 / seg 0x7e916), and hooks the new one (crt_int21_dispatch(9))."),
		new NamedFunction(0x12498L, "restore_keyboard_int9",
			"[INPUT; <- roth_main_sequence] Restores the original INT 09h keyboard vector if one was saved (0x7e916 != 0). Teardown counterpart to install_keyboard_int9."),
		new NamedFunction(0x124b5L, "restore_timer_int8",
			"[INPUT/TIMER; <- roth_main_sequence] Restores the original INT 08h vector and resets PIT channel 0 back to divisor 0xffff (default ~18.2Hz) if a vector was saved (0x7e914 != 0). Teardown counterpart to install_timer_int8."),
		new NamedFunction(0x128fbL, "dispatch_held_key_actions",
			"[INPUT; <- player_movement_tick 0x12520] Walks the held-key->action table g_held_key_move_table (5-byte entries: key byte + function pointer), clears the per-frame edge bits (clear_819c0_bits / 0x76858), and for each non-zero entry whose key bit is set invokes its bound action handler. Drives held-key (held-down) movement/action input."),
		new NamedFunction(0x12976L, "keybit_mask_for",
			"[INPUT; <- dispatch_held_key_actions] Returns the single-bit mask g_keybit_mask_table[index&7] used to test a key in the held-key bitset."),
		new NamedFunction(0x12b20L, "redraw_software_cursor_sprite",
			"[CURSOR; <- repaint_hud_and_present] Re-blits the software cursor sprite (blit_clipped_sprite_smc) from its saved bitmap and position (0x85ce0/0x85ce4/0x85cdc)."),
		new NamedFunction(0x147e6L, "set_resolution_index_and_cycle_display",
			"[SCREEN/INPUT; <- game_play_loop] Sets g_screen_resolution_index to param-1 and triggers a display-type cycle (key_cycle_display_type)."),
		new NamedFunction(0x147f4L, "set_resolution_index_and_cycle",
			"[SCREEN/INPUT; <- roth_main_sequence / key_cycle_display_type_alt] Sets g_screen_resolution_index to param-1 and applies a screen-resolution change (cycle_screen_resolution)."),
		new NamedFunction(0x150b8L, "match_word_in_list_ci",
			"[TEXT/PARSE; <- 0x26a20] Case-insensitive word match: scans the space-separated word list param_2 for a token equal (mod case, mask 0xdf) to the string param_1, returning the matched word's index or 0 if none. Used to look up a keyword against a list."),
		new NamedFunction(0x151a5L, "query_game_heap_free",
			"[MEM; <- init_das_cache_heap / alloc_audio_stream_buffers] Queries the free payload size of the game heap (block_payload_size on g_game_heap_handle)."),
		new NamedFunction(0x151c9L, "play_nearby_sfx_emitters",
			"[AUDIO/per-frame; <- update_player_movement 0x1035a] CORRECTED (was mislabeled log_player_position_record): "
			+ "each frame, queries the positional SFX emitters near the player (query_sfx_emitters_in_range 0x43b3b vs the "
			+ "player position 0x90a8c into a 256-byte {record,dist^2} list) and, if any are in range, plays their sounds "
			+ "(play_sound_sequence_group 0x27080). The proximity ambient-sound trigger (dripping/fire/etc. as you move)."),
		new NamedFunction(0x15210L, "alloc_block_or_heap",
			"[MEM; <- load_file_fully 0x1522d] Allocates a DOS memory block (alloc_dos_block); on failure falls back to a game-heap allocation (game_heap_alloc). Returns the block address."),
		new NamedFunction(0x1522dL, "load_file_fully",
			"[FILE; <- sos_load_driver / load_dbase300_chunk] Opens a file read-only, records its size in 0x7f464, allocates a buffer (alloc_block_or_heap), reads the whole file into it, closes the handle, and returns the buffer (0 on open/alloc failure)."),
		new NamedFunction(0x15280L, "free_block_or_pool",
			"[MEM; <- sos_unload_driver] Frees a previously-allocated region: low addresses (<0x100000) go through free_os_block_guarded, otherwise pool_free_chunk on g_game_heap_handle. Counterpart to alloc_block_or_heap."),
		new NamedFunction(0x1548cL, "noop_ret_stub_1548c",
			"[STUB] Empty function (returns immediately); error/return stub referenced by sos_load_driver."),
		new NamedFunction(0x1556fL, "set_music_master_volume",
			"[AUDIO/music; <- apply_audio_volume_settings 0x2626f] Stores the music master volume (0..0x7f) at 0x71124 and, when the information/music chunk is active (g_information_chunk_progress bit4), pushes it into the running sequence via emit_audio_sequence_event."),
		new NamedFunction(0x15630L, "stop_music_sequence",
			"[AUDIO/music] Stops the active information/music sequence chunk: when running (progress bit0), finalizes the sequence (finalize_audio_sequence + 0x46da7) and releases it (0x46cce), leaving progress=1 (loaded-but-stopped)."),
		new NamedFunction(0x15671L, "resume_music_sequence",
			"[AUDIO/music; <- play_screen_slide_in] Bumps the pending-sequence counter and (re)starts the information/music chunk via FUN_00045dc5(ctx,1)."),
		new NamedFunction(0x15699L, "is_music_sequence_finished",
			"[AUDIO/music; <- play_screen_slide_in / play_screen_slide_out] Returns 1 if the information/music chunk is fully active (progress&7==7) and its play position has reached the end (is_entry_93144_zero), else 0."),
		new NamedFunction(0x15805L, "reload_sfx_bank_if_pending",
			"[AUDIO/SFX; <- load_sfx_file_wrapper 0x10c51] If a SFX reload is flagged (0x7f548 != 0), reloads the sound-effects bank via FUN_00026b66."),
		new NamedFunction(0x159faL, "register_music_timer_event",
			"[AUDIO/music/timer; <- roth_main_sequence] When the music subsystem is enabled (0x7f554 bit3), registers a periodic SOS timer event (sos_timer_register_event rate 0x46, handler 0x7f4e0), bumps the install refcount 0x7f55d, and returns 1 on success."),
		new NamedFunction(0x15a30L, "remove_music_timer_event",
			"[AUDIO/music/timer; <- roth_main_sequence] Removes the SOS music timer event (sos_timer_remove_event 0x7f4e0) and decrements its refcount if one is installed (0x7f55d bit0). Teardown counterpart to register_music_timer_event."),
		new NamedFunction(0x15a92L, "sos_voice_set_callback",
			"[AUDIO/SOS; <- sos_user_callback_trampoline / voice_stream_sos_callback] Thin wrapper forwarding to FUN_0004ad03 (sets/installs a SOS voice end/continue callback). [SOS — host-mapped]"),
		new NamedFunction(0x15a9cL, "sos_voice_set_w32",
			"[AUDIO/SOS; <- update_active_sounds] Sets SOS voice field w32 on the active digital device (sos_voice_xchg_w32_if_active on g_sos_digital_device). [SOS — host-mapped]"),
		new NamedFunction(0x15ab2L, "sos_voice_set_w54",
			"[AUDIO/SOS; <- update_active_sounds] Sets SOS voice field w54 on the active digital device (sos_voice_xchg_w54_if_active on g_sos_digital_device). [SOS — host-mapped]"),
		new NamedFunction(0x15ec4L, "free_sfx_scratch_buffer",
			"[AUDIO/MEM; <- roth_main_sequence] Frees the SFX scratch/work buffer at 0x7f56c (game_heap_free) and clears the pointer."),
		new NamedFunction(0x167d7L, "clear_corner_peek_icon",
			"[CURSOR/HUD; <- run_gameplay_frame / render_inventory_panel] Discards the top-left corner peek-icon save-under: clears the active flag 0x7fdc0 and frees the saved-region handle g_corner_icon_saveunder (pool_free_handle on g_das_cache_heap_handle). Hides the corner icon when the cursor leaves the top-left."),
		new NamedFunction(0x16807L, "restore_corner_peek_icon",
			"[CURSOR/HUD; <- gameplay_frame_step] Re-blits the saved top-left corner peek-icon (blit_descriptor_rows from g_corner_icon_saveunder) and marks the (0,0) region dirty. Counterpart to clear_corner_peek_icon."),
		new NamedFunction(0x1765cL, "reset_weapon_fire_timing",
			"[WEAPON; <- equip_first_usable_weapon] Resets per-weapon fire state before equip: clears the fire timer 0x7fdf0, sets the reload/cooldown base 0x7fde0=100 and the fire-rate 0x7fddc=2."),
		new NamedFunction(0x17668L, "arm_weapon_and_cache_def",
			"[WEAPON; <- activate_weapon_item] Arms the weapon (arm_weapon_fire) and caches three fields from its definition record into the active-weapon HUD/fire globals: def[0]->0x7fdf8, def[8]->0x7fde8, def[7]->0x7fdec."),
		new NamedFunction(0x179d2L, "clear_damage_flash",
			"[VIDEO/HUD; <- game_play_loop] Clears the red damage-flash overlay: if g_damage_flash_level is nonzero, zeroes it and reloads the palette DAC (refresh_palette_dac)."),
		new NamedFunction(0x17fe5L, "show_status_message_wrap",
			"[HUD; <- key_toggle_sprint / key_toggle_mouse_swap] Thin wrapper that displays a HUD status message by id (show_no_ammo_message), passing a char message index (e.g. 2/3 for sprint on/off)."),
		new NamedFunction(0x10010L, "roth_game_startup",
			"[STARTUP] Top-level game startup (name from decomp export / recomp handoffs; reconciled into the script)."),
		new NamedFunction(0x100e4L, "dos_print_dollar_string",
			"[CRT] Prints a '$'-terminated string via INT 21h AH=0x09 (reconciled from decomp export)."),
		new NamedFunction(0x100f6L, "roth_main_sequence",
			"[STARTUP] The main game-sequence driver (the reachability-root boundary function — see memory note on the mainseq boundary). Reconciled from decomp export."),
		new NamedFunction(0x10c13L, "load_raw_file_wrapper",
			"[MAP] Wrapper that loads a .RAW map file (reconciled from decomp export / OS-bound handoff)."),
		new NamedFunction(0x10c32L, "load_das_file_wrapper",
			"[RESOURCE] Wrapper that loads a DAS resource file (reconciled from decomp export)."),
		new NamedFunction(0x10c70L, "load_ademo_das_wrapper",
			"[RESOURCE] Wrapper that loads the ADEMO DAS file (reconciled from decomp export)."),
		new NamedFunction(0x1517dL, "game_heap_alloc",
			"[MEM] Game heap allocator (reconciled from decomp export / handoff 1517d_game_heap_alloc)."),
		new NamedFunction(0x15191L, "game_heap_free",
			"[MEM] Game heap free (reconciled from decomp export / handoff 15191_game_heap_free)."),
		new NamedFunction(0x15a79L, "sos_voice_get_w34_wrapper",
			"[SOS/audio — host-mapped] Game-side wrapper to the SOS-library sos_voice_get_w34 (0x4a54a); reconciled from decomp export."),
		new NamedFunction(0x2effbL, "load_ademo_das_file",
			"[RESOURCE] Loads the ADEMO DAS file (reconciled from decomp export)."),
		new NamedFunction(0x2f163L, "close_das_handles_and_buffers",
			"[RESOURCE] Closes the DAS file handles and frees the worker buffers (reconciled from decomp export)."),
		new NamedFunction(0x2f1a1L, "dos_seek_file_start",
			"[OS] Seeks a DOS file handle to offset 0 (INT 21h AH=0x42). Reconciled from decomp export."),
		new NamedFunction(0x2f1b4L, "load_map_das_file",
			"[RESOURCE] Loads the per-map DAS resource file (reconciled from decomp export)."),
		new NamedFunction(0x2f379L, "read_das_palette",
			"[RESOURCE/VIDEO] Reads the DAS palette (reconciled from decomp export)."),
		new NamedFunction(0x2fa29L, "allocate_das_worker_buffers",
			"[RESOURCE] Allocates the DAS decode worker buffers (reconciled from decomp export)."),
		new NamedFunction(0x2fb7fL, "build_game_path",
			"[OS] Builds a game data-file path string (reconciled from decomp export)."),
		// --- In-game text rendering (see ROTH_text_rendering_notes.md) ---
		new NamedFunction(0x14d04L, "draw_text_to_buffer",
			"[HIGH, decompiler-verified] Low-level in-game font renderer. Args by register: EAX = control-coded string, "
			+ "EDX = destination framebuffer pointer, EBX = screen pitch/stride, ECX = flags. Uses "
			+ "g_font_descriptor (0x70f12). Control bytes: 0 terminates, 0x0d/0x0a newline, "
			+ "0x01 + color byte loads a 12-byte palette/ramp through g_text_color_ramp_selector "
			+ "(unless flag bit3 forces a flat color), and 0x02 + word advances the destination. "
			+ "Glyph records are reached by signed offsets from g_font_descriptor+6+char*2 and store "
			+ "a packed metrics word followed by bitmask rows. This routine gives menu/message text "
			+ "the game's own font and gradient."),
		new NamedFunction(0x14f61L, "draw_text_outline_prepass_helper",
			"[MED-HIGH] Helper called only by draw_text_to_buffer before glyph pixels are written "
			+ "(unless text flag bit2 is set). It marks neighbouring pixels around glyph bits, giving "
			+ "the shadow/outline mask. It relies on draw_text_to_buffer's EBP frame, so treat it as "
			+ "an internal helper rather than a normal standalone API."),
		new NamedFunction(0x1508aL, "measure_font_char_advance",
			"[HIGH] Returns the pixel advance for one font character through g_font_descriptor. "
			+ "Chars <= 0x0d return 0; missing glyphs use the descriptor default advance."),
		new NamedFunction(0x18040L, "screen_xy_to_framebuffer_ptr",
			"[HIGH] Converts x/y to a pointer in g_framebuffer_ptr using g_screen_pitch. If "
			+ "g_hires_line_doubling_flag is set, y is doubled first. This is the same destination "
			+ "math used by positioned text and several UI draw paths."),
		new NamedFunction(0x1a079L, "draw_text_at_screen_xy",
			"[HIGH, decompiler-verified] Convenience wrapper around draw_text_to_buffer. Register args: EAX = control-coded "
			+ "string, EBX = x pixel offset, ECX = y row, EDX = text flags. It computes "
			+ "g_framebuffer_ptr + x + y*g_screen_pitch (doubling y/flags in hi-res) and then calls "
			+ "draw_text_to_buffer. This is the best candidate API for a custom on-screen watermark."),
		new NamedFunction(0x1f91fL, "measure_control_text_width",
			"[HIGH] Measures a control-coded text string. It skips 0x01/color and 0x02/advance "
			+ "control payloads, calls measure_font_char_advance for printable bytes, and returns "
			+ "the total pixel width in EAX."),
		new NamedFunction(0x1f950L, "build_available_choice_menu",
			"[HIGH] Builds the visible choice/menu line records from a dialogue/menu node in EAX. "
			+ "Requires node flag +4 bit 0x08, scans variable-length records at node+0x14, filters "
			+ "type-1 records through 0x1db89(record,2), uses record +4 low 24 bits as a probable "
			+ "text id for 0x1e8cc, stores accepted source record pointers at 0x83149, and lays "
			+ "out final control-coded line records at 0x83189 / text buffer 0x832c9. Returns "
			+ "visible choice count."),
		new NamedFunction(0x1fa91L, "node_has_available_choice",
			"[MED-HIGH] Tests whether a dialogue/menu node has any immediately available choice/action "
			+ "record. Node flag +5 bit 0x10 is an immediate true case; otherwise scans variable "
			+ "records and calls 0x1db89(record,2) for candidate types."),
		new NamedFunction(0x1d430L, "execute_dbase100_chain",
			"[HIGH, dispatch-cracked 2026-06-14] The DBASE100 action-chain interpreter. Walks 4-byte "
			+ "records (opcode=(w>>24)&0x7f, operand=low24/bx, flag=bit31 = the '0x80|op' If-NOT "
			+ "variants), count in EDX, stream cursor at [ebp-0xc7c]. Dispatch at 0x1dac5 is a "
			+ "two-level Watcom switch: range-check opcodes 0x01..0x37, repne scasb over the 25-byte "
			+ "VALUE table @0x1d3b4, then jmp [ecx*4 + 0x1d3cc] (JUMP table; default/NOP=0x1d47b). "
			+ "Full opcode->handler enumeration in ROTH_command_system_notes.md. This is the "
			+ "ACTION-CHAIN context (flags/choices/audio/video/jumps/give-item/map-callbacks); "
			+ "weapon/monster attribute opcodes are handled by the separate inventory-init walk and "
			+ "NOP here. LATENT (implemented, undocumented) opcodes: 0x1b (0x1d711) + 0x37 (0x1d72d)."),
		new NamedFunction(0x1d146L, "filter_dbase100_active_records",
			"[HIGH, 2026-06-14] The DBASE100 flow/condition PRE-WALKER (entry 0x1d146, enter 0x14,0; "
			+ "args EAX=record stream, EDX=out list, EBX). Walks the same 4-byte records but uses a "
			+ "cmp-CHAIN (0x1d195), not a jump table: classifies each opcode as COPY-to-active-list "
			+ "(0x1d1bf, structural/displayable: choices, content) vs SKIP (0x1d1b7), and for the "
			+ "if-family calls the flag evaluator 0x1cb35 to include/exclude the conditional branch. "
			+ "Builds the flag-filtered active-record list the choice/dialogue UI consumes (the "
			+ "executor execute_dbase100_chain 0x1d430 is separate)."),
		new NamedFunction(0x18598L, "init_inventory_item_object",
			"[HIGH, 2026-06-14; trigger-0x06 decode VERIFIED 2026-06-17] Builds the 0xc-byte object "
			+ "RENDER/appearance record for a spawned item/projectile from its DBASE100 entry's trigger "
			+ "0x06 (render) block. ABI: EAX=item id (index into inventory offset table 0x81e20), "
			+ "EDX=dest 0xc-byte record (callers pass a stack scratch buf; e.g. spawn_projectile_from_aim "
			+ "0x42400 then hands it to spawn_entity_at_position 0x4254e). Resolves the entry via "
			+ "g_dbase100_base (0x81e1c) + offset table [0x81e20][id*4], memsets the dest to 0 (via "
			+ "0x4b360), sets default [dst+8]=0x10. GATE: entry+4 bit 0x20 (renderable flag) — if clear, "
			+ "returns 0 (item has no world representation; caller skips the spawn). Then walks the "
			+ "TRIGGER BLOCKS at entry+0x14 ([size:24][code:8] header), SKIPPING non-0x06 blocks "
			+ "(advance by block size), and applies the FIRST 0x06 block. Each sub-op dword = "
			+ "(opcode<<24)|value24; opcode &= 0x7f. Sub-op -> field: 0x15->[+6] word (rotation), "
			+ "0x16->[+4] byte (texture idx), 0x17->[+0] word, 0x19->[+2] word, 0x2e->[+5] byte (tex "
			+ "source), 0x2f->[+8] byte (lighting; overrides the 0x10 default), 0x30->[+9] byte (render "
			+ "type). Returns the item id (entry+2) when a 0x06 block was applied, else 0. This is the "
			+ "RENDER pass of the per-trigger MULTI-PASS model: weapon pass = trigger 0x05 = "
			+ "apply_weapon_action_attributes (0x18260); monster pass = trigger 0x0A, still TBD. "
			+ "NOTE: entry+4 = trigger-PRESENCE flags (0x40=has OnInspect/0x04, 0x20=renderable/0x06); "
			+ "entry+5 = type/usage flags (0x20=stackable, 0x40=usable/combinable) — distinct bytes."),
		new NamedFunction(0x18260L, "apply_weapon_action_attributes",
			"[HIGH, 2026-06-14 — VERIFIED vs DBASE100_inventory_examples.md Staff weapon] DBASE100 "
			+ "inventory trigger 0x05 (WeaponAction) pass. Resolves the item entry (g_dbase100_base + "
			+ "inventory table), walks its entry+0x14 command section, and for the trigger-0x05 block "
			+ "applies sub-opcodes to a WeaponAttributes struct (dword[0x14]): 0x12 anim->[0], 0x13 "
			+ "bullet->[2], 0x14 ammo-cap->[1] (signed if flag), 0x18 bullet-delay->[3], 0x19 fire-SFX"
			+ "->[4], 0x1f reload-anim->[0xb], 0x20 ammo-recharge->[0xc], 0x21 reload-SFX->[0xd], 0x30 "
			+ "flash->[0x11], 0x33 icon->[0x12]; 0x1e/0x22/0x2c are value accumulators consumed by the "
			+ "next anim/bullet op; 0x2d val5/6 sets flag bits in [0x13]. Sub-opcode namespace is "
			+ "PER-TRIGGER (same numbers mean other fields under trigger 0x06)."),
		new NamedFunction(0x1d25eL, "finalize_dbase100_chain",
			"[HIGH, 2026-06-14] Called at the end of execute_dbase100_chain (0x1d430). Reads the "
			+ "pending-topic value g_dbase100_pending_topic (0x81eb2) staged by action opcode 0x1b; if "
			+ "nonzero, validates via 0x15492 and (gated on [0x83c4c]==2) commits it (0x15689/0x1555f/"
			+ "0x1558d), then clears 0x81eb2."),
		new NamedFunction(0x1db89L, "eval_dialogue_record_condition_with_cleanup",
			"[MED-HIGH] Thin wrapper around eval_or_queue_dialogue_record_commands (0x1daea): "
			+ "calls it, preserves its EAX result in EDX, calls finish_dialogue_record_eval "
			+ "(0x1db5e), then returns the original result. Used by visible-choice filtering and "
			+ "choice/action activation."),
		new NamedFunction(0x1daeaL, "eval_or_queue_dialogue_record_commands",
			"[MED] Evaluates or queues a variable-length dialogue/action record. EAX = record ptr, "
			+ "EDX = mode. It converts the low-16 record length into a payload dword count and either "
			+ "calls the command interpreter at 0x1d430 directly or queues {payload,count,mode} in "
			+ "12-byte records at 0x81e42 when the deferred queue counter 0x81e3e is active."),
		new NamedFunction(0x1eabcL, "dbase100_open_dialogue_window",
			"[DBASE100 command handler, called from execute_dbase100_chain 0x1d430] Opens a dialogue / inspect / "
			+ "choice window: lays out the text via layout_timed_message_text (0x1f3d3, capacity 0xa = up to ~10 "
			+ "choice lines), stores the window handle in g_active_dialogue_context (0x83115), sets "
			+ "g_move_freeze_gate (0x83125) = 0x6ffff (mode 6 = object/inspect dialogue; freezes player movement) "
			+ "and anchors it at the player position (0x90a8c/0x90a94 -> 0x83b0e/0x83b12). This is the command an "
			+ "object/item's 0x04 OnInspect chain runs to show the inspect monologue + choice menu. Per-frame the "
			+ "window is rendered by 0x1a132 -> FUN_0001a399."),
		new NamedFunction(0x1ebb4L, "dbase100_open_dialogue_window_alt",
			"[DBASE100 command handler, sibling of dbase100_open_dialogue_window] Opens the mode-7 dialogue window "
			+ "(g_move_freeze_gate = 0x7ffff; capacity 3), gated on 0x8202c/0x83e90 (e.g. NPC conversation vs the "
			+ "object/inspect mode-6 variant)."),
		new NamedFunction(0x1db5eL, "finish_dialogue_record_eval",
			"[MED] Cleanup/finalisation after dialogue/action record evaluation. Clears 0x81e18 and, "
			+ "when no queued action work remains, may call 0x20905 if 0x83c70 is set."),
		new NamedFunction(0x1ad2fL, "hit_test_dialogue_ui_action",
			"[MED-HIGH] Maps the mouse cursor (EAX=g_mouse_x 0x707b3, EDX=g_mouse_y 0x707b7, EBX=click "
			+ "code) to a UI ACTION CODE by region-testing against the panel anchor (g_ui_panel_anchor_x/y "
			+ "0x80b24/0x80b28) and the choice/inventory widgets. Action codes returned: inventory GRID "
			+ "CELLS = 0x1c..0x25 (cell = code-0x1c, the 5x2=10 slots), scroll UP arrow = 0x28, scroll "
			+ "DOWN arrow = 0x29, tab widgets = 0x2a/0x2b, 0x26 = outside/background, 0x27 = busy/dialogue, "
			+ "choice lines = index+7. When choice mode is active (0x83acd==1) it walks g_choice_line_records "
			+ "and applies the hover colour. The caller handle_cursor_click (0x1661f) feeds the code to "
			+ "dispatch_dialogue_ui_action (0x1b4e5). (The arrow codes 0x28/0x29 are what turn an arrow "
			+ "CLICK into a scroll; see g_cursor_scroll_offsets.)"),
		new NamedFunction(0x1b4e5L, "dispatch_dialogue_ui_action",
			"[MED] Dispatches the action codes produced by hit_test_dialogue_ui_action (0x1ad2f) on a "
			+ "click (EAX=action, EDX=click code). INVENTORY SCROLL: action 0x28 (UP arrow) -> if "
			+ "g_cursor_scroll_offsets[ctx] (0x80b10) > 0, subtract 5 (one row) + flag redraw; action "
			+ "0x29 (DOWN arrow) -> if g_cursor_entry_count-9 > offset, add 5 + flag redraw (same +/-5 "
			+ "step and bounds as the keyboard arrows in update_inventory_screen). Grid CELLS (0x1c..0x25) "
			+ "-> select the item / scroll_entry_into_view (0x1b0e3). Tabs 0x2a/0x2b -> switch tab. Also "
			+ "handles choice/menu mode toggling and visible-choice activation: action 3 toggles choice "
			+ "mode only when g_choice_line_count != 0; actions 7..0x16 queue g_pending_choice_accept_index "
			+ "= action-6. Clears the click flags (g_cursor_primary/secondary_action_flag) on exit."),
		new NamedFunction(0x1baddL, "activate_selected_choice_record",
			"[MED-HIGH] Maps a 1-based visible choice index through g_choice_option_records, clears "
			+ "g_choice_line_count, evaluates the selected variable-length record via "
			+ "eval_dialogue_record_condition_with_cleanup(record,0), then sets choice mode to 2."),
		new NamedFunction(0x18bb2L, "draw_current_mouse_cursor_sprite",
			"[MED-HIGH] Draws the current cursor sprite from g_current_cursor_entry. Saves the "
			+ "under-cursor framebuffer rectangle, registers the dirty rect, computes the framebuffer "
			+ "destination from g_mouse_x/g_mouse_y, and calls the cursor blitter at 0x13544. Draw-only; "
			+ "cursor identity is selected upstream."),
		new NamedFunction(0x1325bL, "blit_das_image_to_buffer",
			"[MED-HIGH] Generic DAS/image block blitter. EAX = source image block, EDX = destination, "
			+ "EBX = destination stride/pitch or packed stride/fill parameter, ECX low byte = blit "
			+ "mode and high bytes = palette/remap selector. Supports direct rows, compressed row "
			+ "refill through 0x1374f, palette/remap tables at g_das_remap_chunk_10000_ptr/0x86d28, "
			+ "duplicate rows, and alternating-row modes. Note: 0x13322 is only this function's "
			+ "shared epilogue, not a separate function."),
		new NamedFunction(0x227e9L, "render_ui_texture_panel",
			"[MED-HIGH] Structured UI/menu panel renderer. Takes a heap-backed destination wrapper "
			+ "and a panel descriptor, resolves image blocks through 0x226c6, draws/tile-renders them "
			+ "with blit_das_image_to_buffer, and handles reveal/wipe modes by rendering into "
			+ "100-byte-wide stack buffers then copying strips with 0x4f2b7. Current evidence points "
			+ "to UI panel rendering, not the 3D wall/portal face renderer."),
		new NamedFunction(0x2271dL, "draw_ui_panel_image_at_xy",
			"[MED] Small wrapper around blit_das_image_to_buffer. Resolves an image id through "
			+ "0x226c6, computes destination + x + y*pitch, then calls the image blitter with ECX=1."),
		new NamedFunction(0x227b1L, "draw_ui_panel_image_block",
			"[MED] Similar wrapper around blit_das_image_to_buffer used by render_ui_texture_panel. "
			+ "Computes destination + x + y*pitch and draws a resolved image block with ECX=1."),
		new NamedFunction(0x1691cL, "run_gameplay_frame",
			"[per-frame gameplay tick + world render; called once per game_play_loop (0x179ee) iteration] Advances the animation/frame-timing accumulator 0x7fdc0 (by 0x85324, vs 0x19) gated on the motion counters 0x707b3/0x707b7, fires queued actions incl. trigger_weapon_fire (0x1768a), runs the world render via render_world_view (0x10c8f), and ticks assorted subsystems (0x164c9/0x1624d/0x167d7/0x12179/0x1a132/0x1f671/0x1f71d/0x12a08). The in-level frame step."),
		new NamedFunction(0x10c8fL, "render_world_view",
			"[world-view render entry; called from run_gameplay_frame] Computes the camera-relative position delta (cursor pos g_mouse_x/g_mouse_y (0x707b3/0x707b7) minus viewport origin g_view_x/g_view_y (0x85ce0/0x85ce4)) into EAX/EDX and calls render_world_scene (0x28a79). Returns &g_world_render_subpass_kind (0x90a48)."),
		new NamedFunction(0x28a79L, "render_world_scene",
			"[3D scene-render orchestrator; called by render_world_view] Sets up the view (0x2a6d0/0x293a3/0x294c0/0x2abfb/0x29812 frustum+sector prep) then walks the visible faces via render_world_face_list_subpass (0x28dbe). Top of the world face-render fan-out that ends in the three span drivers."),
		new NamedFunction(0x2a814L, "transform_world_vertices",
			"[render-geometry: the per-frame world->view VERTEX TRANSFORM; from the scene-walk setup 0x284df/0x2885d] Sets es=the vertex selector 0x852cc, computes the camera rotation sincos via rotate-prep (sincos_pair 0x3bdd2 -> g_camera_sin 0x85310/g_camera_cos 0x85312) from g_sprite_view_angle (0x909f8), then iterates the vertex table (stride 0xc): reads each vertex's world X/Y (vtx+8/+0xa), translates by g_view_offset_x/_y (0x90a04/0x90a06), rotates via rotate_point_2d (0x2a898), and writes the VIEW-space coords es:[vtx+0]=edx (view X) and es:[vtx+4]=eax (depth). These are exactly the gs:[vtx+0]/[vtx+4] dwords that walk_visible_sectors + clip_sector_walls_to_view then read. Confirms the 0xc-byte vertex record."),
		new NamedFunction(0x294c0L, "walk_visible_sectors",
			"[render-geometry: the per-frame sector/portal traversal, from render_world_scene 0x28a79] Two mutually-exclusive bodies gated by g_render_sector_walk_mode (0x853d3). MODE 0 (==0): first-person wall-clip pass — starts at g_player_sector (0x90c12, the camera's current sector) and walks the sector graph through portals (es=g_surface_record_selector 0x852c8), per sector reading WALL_COUNT (sector+0xd) + wall-array (sector+0xe), each wall's vertex indices (es:[wall+0]/[wall+2]) and the vertices' TRANSFORMED view coords (gs:[vtx+0]/[vtx+4] dwords, gs=g_vertex_selector 0x852cc), clipping each via clip_sector_walls_to_view (0x2d793). MODE 1 (!=0): flat sector-array bbox-cull — iterates the sector array (stride 0xd), projects each sector's view-X/depth extent to screen columns and writes the visible ones into g_visible_extent_list (0x85224, count g_visible_extent_count 0x85220); SELF-PATCHES two immediates from g_sector_cull_coord (0x852fa). ABI: no GP-register inputs; GS must be caller-preloaded to g_vertex_selector, ES is loaded internally from g_surface_record_selector; real output is the clip-region write-set (no meaningful register return). (Whole-scene flood/dedup is the separate build_sector_render_tree_recursive 0x29830 pipeline.)"),
		new NamedFunction(0x2d793L, "clip_sector_walls_to_view",
			"[render-geometry: recursive portal/wall clip] For a sector's walls, clips each wall edge against the view-depth plane g_view_clip_plane (0x85264) by interpolating the vertices' transformed view coords (gs:[vtx+0] / gs:[vtx+4] dwords); recurses through portals. Output feeds walk_visible_sectors. ABI (dropped-register case — corpus loses both, cf. the multi-reg-return gotcha): takes ESI = sector ptr as a REGISTER INPUT and returns status in CF (stc;ret at 0x2daec = 'continue / cross the portal'); the decomp's bVar14-after-call in walk_visible_sectors is that dropped CF. Reached from walk_visible_sectors + recursively."),
		new NamedFunction(0x28dbeL, "render_world_face_list_subpass",
			"[world face-list renderer, main-frame twin of render_world_face_list 0x2ad21 — IDENTICAL callee set] Sets g_world_render_subpass_kind (0x90a48)=0xff, loads the view selectors (fs=0x85294, es=0x852c8), walks the visible face list (count 0x85302) and per face emits via draw_world_face_projected_spans/draw_world_face_clipped_spans (-> emit_world_span_record -> rasterize_world_spans_scanline) and the 3 secondary-surface wrappers (0x2b333/0x2b36f/0x2b407 -> render_world_secondary_surface). Reached from the MAIN gameplay frame (run_gameplay_frame->render_world_view->render_world_scene); render_world_face_list (0x2ad21) is the other path's twin."),
		new NamedFunction(0x2ad21L, "render_world_face_list",
			"[MED-HIGH] Main world face-list renderer candidate, called from the 3D render loop at "
			+ "0x2876c, 0x28954, and 0x2938a. It walks face/surface records and selects the active "
			+ "world remap base/selector: default g_world_shading_table_ptr (0x86d28), face bit "
			+ "0x0002 -> g_world_tint_table_ptr (0x86d1c), face bit 0x0040 plus 0x8a355&0x49 -> "
			+ "g_world_glow_table_ptr (0x86d18). Stores the selected values to g_active_world_remap_selector "
			+ "(0x8a2a8) and g_active_world_remap_base (0x8a2ac). Does not directly read the 0x85d08 "
			+ "blend-table pointer."),
		new NamedFunction(0x2cbb0L, "draw_world_face_clipped_spans",
			"[MED-HIGH] Face span drawer (FUN_0002cbb0). Takes a colour arg in AX; FS = the geometry "
			+ "selector and BX = the face record. Derives the four screen-X span coords by edge-slope "
			+ "math (imul g_perspective_scale 0x85288 / idiv edge-slope) with vertical-band clipping "
			+ "against [0x852b6 (g_world_span_top) .. 0x852b4 (g_world_span_bottom)] via the inner builder "
			+ "build_world_face_edge_spans (0x2cc48). If g_current_surface_render_flags (0x90a2e) bit0 is "
			+ "set it runs a base+overlay multipass: set 0x90cc2=3, call 0x2c250, draw base with flags "
			+ "masked &0xfa, then restore. Per-span colorkey reject via g_world_span_colorkey (0x90a2c). "
			+ "Pairs with draw_world_face_projected_spans (0x2cf60)."),
		new NamedFunction(0x2cc48L, "build_world_face_edge_spans",
			"[MED-HIGH] Inner span builder called by draw_world_face_clipped_spans. FS:BX = geometry "
			+ "record: word[0] -> g_span_gouraud_colour_a (0x852c2), edge slopes at fs:[bx+0x0c]/[bx+0x20], "
			+ "per-face flags at fs:[bx+0x12]. NOTE the fs:[bx] read at 0x2cc53 is the geometry record, "
			+ "NOT the blend selector. Computes top and bottom span coords (0x852a4/a6/a8/aa) clamped to "
			+ "[-0x3ffe,0x3ffe], rejects faces whose colour == g_world_span_colorkey, then calls "
			+ "emit_world_span_record (0x2d130) per edge."),
		new NamedFunction(0x2cf60L, "draw_world_face_projected_spans",
			"[MED-HIGH] Face span drawer (FUN_0002cf60), sibling of draw_world_face_clipped_spans. "
			+ "DIRECT/pre-projected variant: reads the four screen-X span coords straight out of the "
			+ "geometry record (fs:[bx+4]->0x852a4, fs:[bx+6]->0x852a8, fs:[bx+0x18]->0x852a6, "
			+ "fs:[bx+0x1a]->0x852aa) with no slope interpolation/clip. Gouraud colours: fs:[bx]->0x852c2, "
			+ "AX arg->0x852c4. Colorkey reject via 0x84f24 vs g_world_span_colorkey (0x90a2c). Then "
			+ "either the (g_current_surface_render_flags & 0x09)==0x09 overlap/split two-pass (calls "
			+ "0x2c250) or emits a single span directly to emit_world_span_record (0x2d130). For faces "
			+ "whose corners are already projected/clipped in the record."),
		new NamedFunction(0x2d130L, "emit_world_span_record",
			"[MED-HIGH] Shared span emitter for the face drawers. Reads g_current_surface_render_flags "
			+ "(0x90a2e) at 0x2d137 and composes the rasterizer fill-mode word at [0x84f18+0x16] (bits "
			+ "0x04 and 0x10 select submodes), which is what selects the span-writer (and thus whether a "
			+ "blend-capable writer that loads g_transparency_blend_selector 0x90be2 is reached). Builds "
			+ "the vertex list from the gouraud colours (0x852c2/0x852c4) and clamped coords "
			+ "(0x852a4/a6/a8/aa) via 0x2d29a, then calls the rasterizer 0x366cb with es/fs/gs pushed."),
		new NamedFunction(0x2d2ddL, "emit_world_span_clipped",
			"[world-span emitter variant, called by the face renderers 0x28dbe/0x2ad21] Builds the span record at g_world_span_record (0x84f18) and rasterizes it (rasterize_world_spans_scanline) with the CLIP path on: copies g_span_clip_source (0x90a28) into g_column_clip_mode (0x90970). Finalizes via the 0x2d200/0x2d24d clamp pair. The clipped, non-indexed variant."),
		new NamedFunction(0x2d3d0L, "emit_world_span_unclipped",
			"[world-span emitter variant] Like emit_world_span_clipped but UNCLIPPED: leaves g_column_clip_mode, sets the record's clip bound +0x28 = 0x7fff (no clamp). Finalizes via 0x2d29a. Non-indexed."),
		new NamedFunction(0x2d4b5L, "emit_world_span_clipped_indexed",
			"[world-span emitter variant] Clipped variant that selects a specific edge from the caller's array (EBX): offset = (CL-1)*0x14, so it renders one 0x14-byte edge record. Sets g_column_clip_mode from g_span_clip_source; finalizes via 0x2d200/0x2d24d."),
		new NamedFunction(0x2d5b0L, "emit_world_span_unclipped_indexed",
			"[world-span emitter variant] Unclipped + edge-indexed (EBX + (CL-1)*0x14). The unclipped companion of emit_world_span_clipped_indexed; finalizes via 0x2d29a."),
		new NamedFunction(0x2b333L, "render_secondary_surface_list",
			"[secondary-surface pass, called by the face renderers] Iterates the secondary-surface descriptor list g_secondary_surface_list (0x84b18, 0x10-byte records, count g_secondary_surface_count 0x85318), gated on g_has_secondary_surfaces (0x853d0). Per record sets up 0x85264/0x85260/0x85268 and calls render_world_secondary_surface (0x2bc3c). The base/plain pass (no subpass marker). Secondary surfaces = mid-textures / transparent walls."),
		new NamedFunction(0x2b36fL, "render_secondary_surface_pass1",
			"[secondary-surface SUBPASS 1] Same g_secondary_surface_list walk, but marks the subpass: g_secondary_subpass_id (0x853f9)=1, g_secondary_subpass_flags (0x853d2)|=1, and swaps the clip bound 0x852b4 <- 0x84940. Dispatches per record type byte (+8: 0/1/else) before render_world_secondary_surface."),
		new NamedFunction(0x2b407L, "render_secondary_surface_pass2",
			"[secondary-surface SUBPASS 2] Companion of render_secondary_surface_pass1: g_secondary_subpass_id=2, g_secondary_subpass_flags|=2, clip bound 0x852b6 <- 0x84942. Same per-record type dispatch."),
		new NamedFunction(0x366cbL, "rasterize_world_spans_scanline",
			"[MED-HIGH] Per-scanline span rasterizer dispatch, called by emit_world_span_record (0x2d130) "
			+ "with es/fs/gs pushed. Walks the surface/DAS-id cursor g_current_das_entry_id (0x90a78, "
			+ "bounded by 0x1200) and reads a WORD per entry from g_das_entry_status_table (0x86d30): low "
			+ "byte 0xfd/0xfe = control codes (0xfd flat-fill; 0xfe = redirect via 0x90944, id then in the HIGH "
			+ "byte), else the low byte = the DAS cache-slot index. For a real slot it indexes g_das_cache_slots (0x89930, 6-byte slots: "
			+ "dword block-ptr + word tick), refreshes g_das_cache_tick, and derefs the DAS block to source "
			+ "the surface texture (a zero slot hits int3 at 0x36845). The actual per-column draw fn is then "
			+ "selected from g_world_span_variant_table / _g_floorceil_span_fn (NOT from the DAS cache; the "
			+ "0x89930 slots hold texture blocks, not span-writer fn-ptrs). "
			+ "SURFACE-TYPE DISPATCH (0x369ff): this is the top of the renderer's per-surface fan-out — by "
			+ "g_world_surface_draw_flags (0x9093c): bit 0x20 -> tail-jmp draw_scaled_sprite_spans (0x39610, "
			+ "sprites/scaled objects), bit 0x200 OR classify_surface_floorceil (0x38b54)!=0 -> "
			+ "draw_floorceil_surface (0x3a84e, floor/ceiling), else fall through to the WALL path "
			+ "draw_world_surface_spans (0x36b39/0x36b68). These are the three SMC span drivers; all reached "
			+ "by jmp (registers/globals flow through). See ROTH_renderer_notes.md 'Renderer dispatch architecture'."),
		// DAS texture cache (0x40d7c/0x41385/0x413fd + globals 0x86d30/0x89930/0x8c940/0x90c0a).
		// Reconciled 2026-06-20 from stale "scanline/span-writer" names to the DAS-cache names that the
		// loader code proves. These also exist in ROTHApplyDasTypes.java (frozen 06-11, NOT run in the
		// current workflow) — engine-names is the live source of truth, so the correct names live HERE.
		// Keep the two scripts' names identical if DAS-types is ever revived. See
		// RECONCILE_das_cache_vs_scanline_globals.RESOLVED.md.
		new NamedFunction(0x40d7cL, "load_das_block_for_fat_index",
			"[DAS texture cache; identity confirmed by int21 LSEEK+read] Loads/resolves the DAS data block "
			+ "for a FAT index: select_das_fat_entry, reserve a cache slot, pool-alloc from "
			+ "g_das_cache_heap_handle, int 0x21 (0x4200 LSEEK + read_das_block_payload) the .DAS record off "
			+ "disk, then stamp g_das_entry_status_table[id] with the slot index. The texture resolver "
			+ "int3-stubs this on a cache miss; the 0xfd special-status / flat-fill writes also live here. "
			+ "(Was mislabeled advance_scanline_span_list.)"),
		new NamedFunction(0x41385L, "evict_das_cache_slot",
			"[DAS texture cache] Chooses the oldest occupied DAS cache slot by g_das_cache_tick delta and "
			+ "releases it (LRU eviction) to free room in g_das_cache_slots. (Was mislabeled "
			+ "find_or_alloc_span_writer_slot.)"),
		new NamedFunction(0x413fdL, "release_das_cache_slot_resources",
			"[DAS texture cache] Marks the g_das_entry_status_table entry unloaded (0xff) and frees the "
			+ "slot's DPMI selector/allocations via the DAS cache heap (g_das_cache_heap_handle 0x85c3c); "
			+ "reused by the post-frame sweep at 0x3001b. (Was mislabeled evict_span_writer_slot.)"),
		new NamedFunction(0x2d040L, "finalize_world_span_overlay",
			"[MED] Thin overlay/finalize wrapper used by draw_world_face_clipped_spans after the base "
			+ "pass: clears the span-kind marker 0x90cc2 and calls 0x3d03c (also small). Does NOT compose "
			+ "the fill-mode word g_span_fill_mode_word (0x84f2e); that is built only in "
			+ "emit_world_span_record (0x2d130) at 0x2d137."),
		new NamedFunction(0x36b39L, "draw_world_surface_spans",
			"[MED] The WALL-column span driver (size 0xd1c, ends 0x37855) — one of the three renderers "
			+ "tail-jumped from rasterize_world_spans_scanline (0x366cb); sprite=draw_scaled_sprite_spans, "
			+ "floor=draw_floorceil_surface. Sets gs=g_active_world_remap_selector (0x8a2a8) colormap + "
			+ "es=screen, builds a clip-flag from the wall-corner Y bounds, projects the 4 wall-edge corners "
			+ "to screen rows via project_wall_edge_y (0x38c46 x4 -> g_wall_proj_y0..3) and builds the vertical "
			+ "texture-coordinate endpoint steppers (g_span_endpoint_a/_b 0x8a2cc/0x8a2d4 + colsteps). Then a "
			+ "variant index built from g_world_surface_draw_flags (0x9093c bits 0/3/7 + the 0x8a352/0x8a31c "
			+ "mode flags) selects a VERTICAL span inner-loop from the pair table g_world_span_variant_table "
			+ "(0x71f80, 8-byte entries) into g_world_span_fn (0x8a2bc) + _alt/_2; main bank = index|0x40. "
			+ "Per-COLUMN loop (count g_wall_column_count 0x8a348): computes the per-column source-texel offset "
			+ "via compute_wall_column_source_offset (0x378dc), and for columns above the horizon (sky surface, "
			+ "g_parallax_sky_active) fills them via render_parallax_sky_columns (0x38d6c); advances "
			+ "the per-column accumulators, then calls dispatch_world_span_column (0x3778b) which tail-jmps the "
			+ "installed mapper (render_world_span_390ac etc.). Variants route translucency through "
			+ "g_transparency_blend_selector (0x90be2) on signed/high-bit texels. ret 0x375e7."),
		new NamedFunction(0x2bc3cL, "render_world_secondary_surface",
			"[MED, provisional] Secondary world-surface/mid-texture renderer candidate reached from "
			+ "render_world_face_list via 0x2b333 and related clipping paths. Sets up draw globals and "
			+ "calls draw_world_surface_spans. A surface word +0x0a bit 0x8000 branches to the special "
			+ "0x2bf6a path, which initializes internal DAS pointers, protects the cache allocation, "
			+ "and calls 0x2d70c; this is a strong special-surface/translucency candidate but not yet "
			+ "confirmed as the portal path."),
		new NamedFunction(0x4f2b7L, "memcpy_return_dest",
			"[HIGH] Small memcpy-like helper. EAX = destination, EDX = source, EBX = byte count. "
			+ "Copies EBX bytes and returns the original destination in EAX."),
		new NamedFunction(0x1f3d3L, "layout_timed_message_text",
			"[MED-HIGH] Builds wrapped/centered timed-message line records. Inputs: EAX = line metadata "
			+ "array (normally 0x824c9), EDX = output text buffer (normally 0x825e1), EBX = source "
			+ "ASCII string, ECX = max width, stack arg = max lines. Emits control-coded lines "
			+ "starting with 0x01/color and 0x02/x-offset. Interprets doubled '^' as a newline."),
		new NamedFunction(0x1f859L, "queue_timed_message_color",
			"[HIGH] Queues a centered timed in-game message: EAX = source string, DL = color. "
			+ "Stores the color at g_timed_message_color, lays the text out through "
			+ "layout_timed_message_text, sets g_timed_message_timer to 0x8c, and stores the "
			+ "active line count."),
		new NamedFunction(0x1f88cL, "show_timed_message",
			"[HIGH] Default-color timed-message wrapper. EAX = source string; loads DL from "
			+ "g_default_message_color and calls queue_timed_message_color. Used by F3 status "
			+ "messages and the F8/debug-message path."),
		new NamedFunction(0x1ed9cL, "render_active_timed_message",
			"[HIGH] Renders the queued timed-message overlay while g_timed_message_timer is positive. "
			+ "Timer is decremented by g_frame_time_scale; when it expires the active line count is "
			+ "cleared. Each laid-out line is drawn with draw_text_to_buffer."),
		new NamedFunction(0x1ec78L, "render_dialogue_text_panel",
			"[HIGH] Renders multi-line dialogue/story text records from 0x827fd. It centers the "
			+ "panel vertically using g_screen_height, saves/registers the affected framebuffer "
			+ "region, optionally applies the fade/highlight rectangle effect, and draws each "
			+ "control-coded line with draw_text_to_buffer."),
		new NamedFunction(0x1efa4L, "render_choice_text_panel",
			"[HIGH] Renders choice/menu text records from 0x83189. It centers the panel around "
			+ "0x83ae1 with height 0x83ad9, applies per-line fade/highlight using 0x83ae5, and "
			+ "draws each control-coded line with draw_text_to_buffer."),
		new NamedFunction(0x1f0e8L, "render_text_ui",
			"[MED-HIGH] Per-frame text/UI overlay dispatcher. If g_timed_message_line_count is nonzero "
			+ "it calls render_active_timed_message, then continues through other menu/conversation "
			+ "text paths. ALSO drives the active-monologue line SEQUENCER (advance + per-line dwell via "
			+ "g_move_freeze_gate==0x6ffff) and the choice panel — see ROTH_text_rendering_notes.md "
			+ "(Monologue/choice state machine)."),
		new NamedFunction(0x13062L, "save_framebuffer_region",
			"[HIGH] Allocates a heap record and copies an aligned framebuffer rectangle into it. "
			+ "Args are register-based rectangle origin/size; the saved record stores source ptr, "
			+ "width, height, then copied pixels. Used by text/menu panels before dirty-region "
			+ "updates."),
		new NamedFunction(0x12c36L, "apply_ui_palette_rect",
			"[MED-HIGH] Applies a palette/ramp remap over a framebuffer rectangle using "
			+ "g_text_color_ramp_selector and a stack fade/level arg. Used for UI text-panel "
			+ "highlight/fade rectangles."),
		new NamedFunction(0x15b5bL, "register_dirty_rect",
			"[MED-HIGH] Clips/aligns a rectangle and records it in the dirty-region table at "
			+ "0x7f57c.. for later redraw/update. Called after text/menu panel region changes."),
		new NamedFunction(0x1754dL, "render_dev_map_selector_ui",
			"[HIGH] Render-side half of the hidden W map selector. Builds the menu text with "
			+ "build_map_selector_menu, then calls draw_text_to_buffer at g_render_target_buffer+0x0a "
			+ "using g_screen_pitch and the hi-res text flag."),
		// --- Snapshot / screen-grab system (see ROTH_snapshot_notes.md) ---
		new NamedFunction(0x11135L, "take_snapshot",
			"[HIGH] Saves the current video mode, switches to text mode 3, runs the snapshot menu, "
			+ "then restores the graphics mode (VESA/mode13h) and reloads the palette. Gated by "
			+ "g_snapshot_enabled (0x76840)."),
		new NamedFunction(0x111a0L, "snapshot_menu_and_save",
			"[HIGH] Interactive '[1] Single / [2] Anim type snapshot' menu (DOS int21h AH=09h, "
			+ "string at 0x705e0); prompts 'Filename :' and saves one frame or a numbered sequence."),
		new NamedFunction(0x11500L, "build_snapshot_anim_filename",
			"[HIGH] Builds base+name+frameNumber+'.lbm' for animation frames "
			+ "(number->ASCII via num_to_decimal_digits 0x1155f)."),
		new NamedFunction(0x3cb85L, "write_snapshot_lbm",
			"[HIGH] Writes the current screen as a Deluxe Paint IFF 'FORM PBM ' file "
			+ "(BMHD width [0x85498] x height [0x854a0], 8 planes; CMAP 768-byte palette expanded "
			+ "from VGA 6-bit; BODY = ByteRun1-RLE). Filename C:\\SnapNNNN.lbm via g_snapshot_counter."),
		new NamedFunction(0x3cf30L, "rle_compress_byterun1",
			"[HIGH] ByteRun1/PackBits compressor for the LBM BODY chunk (runs up to 0x80, negative "
			+ "count byte for runs)."),
		new NamedFunction(0x11077L, "cmd_snap_toggle",
			"[MED-HIGH] Handler for the 'SNAP' entry in the startup switch/command table (~0x704a0): "
			+ "not byte [g_snapshot_enabled]. Enables the snapshot tool."),
		new NamedFunction(0x11124L, "check_snapshot_key",
			"[HIGH] Bound to scancode 0x30 (the 'B' key) in the keyboard dispatch (~0x19be1, also "
			+ "from a keybinding table at 0x7097a): cmp byte [g_snapshot_enabled],0 ; je skip ; "
			+ "else call take_snapshot. So 'B' opens the snapshot menu when SNAP is enabled."),
		new NamedFunction(0x1155fL, "num_to_decimal_digits",
			"[MED] Writes a 16-bit number as ASCII decimal digits (div 1000/100/10) into a buffer."),
		// --- Player movement / look / jump (see ROTH_movement_spec.md) ---
		new NamedFunction(0x12520L, "player_movement_tick",
			"[HIGH, decompiler-verified] Per-frame player movement update (entry 0x12520). Computes the "
			+ "run-mode toggle (g_run_toggle 0x7e8dc -> g_run_active 0x7e8e0), bumps frame counters, then "
			+ "gated on g_player_movement_enabled (0x7674a)==1: DECAY runs only when "
			+ "g_player_move_rate_counter (0x90bda) UNDERFLOWS (dec; if <0) - reload to "
			+ "g_move_speed_immediate, then for g_player_vel_accum_x/y: if |v|<=0x20 snap to 0 (deadzone), "
			+ "then unconditional sar 1 (0>>1 stays 0, so equivalent to deadzone-or-halve). INPUT is "
			+ "applied EVERY tick (clears g_move_input_bits, calls the input builders and "
			+ "apply_player_movement_input). Then the resulting velocity is ENQUEUED into the active "
			+ "displacement ring buffer (g_vel_queue_a 0x90abe / g_vel_queue_b 0x90b42, selected by "
			+ "0x90bd6, cap 0x10 entries of 8 bytes). RUN/SPRINT MECHANIC: when g_run_active (0x7e8e0) is "
			+ "set (or g_move_input_bits bit 0x80), the same velocity is enqueued a SECOND time, so the "
			+ "integrator applies two displacement steps - this is how running doubles movement per tick. "
			+ "Net: higher MOVE_SPEED = rarer halving = higher sustained speed; high MOVE_SPEED also makes "
			+ "per-tick steps big enough to outrun the collision substepping."),
		new NamedFunction(0x12750L, "apply_player_movement_input",
			"[HIGH] Turns input into velocity (called from player_movement_tick at 0x125c6). MOUSE path "
			+ "(when [0x7e932]==1 and mouse-look active [0x7e8d0]!=0 - the advanced hold-both-buttons "
			+ "mode): mouse dx g_mouse_dx (clamped +/-0x10) turns g_player_angle; mouse dy g_mouse_dy "
			+ "(clamped +/-0x18) is forward speed; impulse = speed*sincos(angle)>>2 added to "
			+ "g_player_vel_accum_x/y. KEYBOARD path: g_move_speed_accum (0x7e8d8) ramps +1/tick to cap "
			+ "0x10 (acceleration); direction = g_player_angle + g_kbd_dir_offset_table[g_move_input_bits "
			+ "& 0xf]; impulse = 6*sincos(...) added to the accumulators."),
		new NamedFunction(0x3c1f3L, "sincos_lookup",
			"[HIGH] Signed sine/cosine lookup. `and ebx,0x3fe; movsx edx,[ebx+g_sincos_table]`. The arg "
			+ "is 2*angle, so the angle domain is 0x200 (512) = 360 deg (0x80 = 90 deg); cosine is taken "
			+ "by adding 0x100 to the doubled arg (i.e. +0x80 in angle units). Drives movement and aim "
			+ "vectors."),
		new NamedFunction(0x1c5f9L, "key_a_jump",
			"[HIGH] The 'A' key = JUMP. Bound via the held-key (polled) movement table g_held_key_move_table "
			+ "(0x707f1), scancode 0x1e - NOT the discrete keymap. Sets g_player_locomotion_flags (0x819c0) "
			+ "bit 0 (jump pressed); if grounded (0x819c1==0) and the stance counter (0x819d1) is in range, "
			+ "sets bit 0x10 (jump initiate). The jump arc itself is integrated by "
			+ "entity_apply_vertical_movement (0x43187)."),
		new NamedFunction(0x1c5d0L, "key_z_crouch",
			"[MED-HIGH] The 'Z' key = crouch/duck (held-key table scancode 0x2c). Sets "
			+ "g_player_locomotion_flags (0x819c0) bits 2 and 0x20 depending on jump/air sub-state "
			+ "(0x819c1/0x819c5/0x819cd)."),
		new NamedFunction(0x12686L, "move_input_forward",
			"[HIGH] Held-key handler for forward (default Up arrow, scancode 0x48). OR g_move_input_bits "
			+ "bit 1 (dir offset 0 deg), subject to a freeze gate (0x83aea/0x83125)."),
		new NamedFunction(0x12668L, "move_input_backward",
			"[HIGH] Held-key handler for backward (default Down arrow, scancode 0x50). OR g_move_input_bits "
			+ "bit 4 (dir offset 180 deg)."),
		new NamedFunction(0x126a4L, "move_input_strafe_right",
			"[MED] Held-key strafe handler (default '.' scancode 0x34). OR g_move_input_bits bit 2 "
			+ "(dir offset 270 deg). Left/right labelling provisional."),
		new NamedFunction(0x126adL, "move_input_strafe_left",
			"[MED] Held-key strafe handler (default ',' scancode 0x33). OR g_move_input_bits bit 8 "
			+ "(dir offset 90 deg). Left/right labelling provisional."),
		new NamedFunction(0x126b6L, "turn_input_left",
			"[HIGH] Held-key turn handler (default Left arrow, scancode 0x4b). Ramps g_turn_accum "
			+ "(0x90bd8) toward +max (8, or 0xd while running) and OR g_move_input_bits bit 0x10; the "
			+ "accumulator is applied to g_player_angle in apply_player_movement_input."),
		new NamedFunction(0x12703L, "turn_input_right",
			"[HIGH] Held-key turn handler (default Right arrow, scancode 0x4d). Ramps g_turn_accum "
			+ "(0x90bd8) toward -max and OR g_move_input_bits bit 0x10."),
		new NamedFunction(0x12927L, "look_pitch_up",
			"[MED-HIGH] Look up (default Home, scancode 0x47): g_view_pitch (0x90a74) += 2, mirrored to "
			+ "0x8c108."),
		new NamedFunction(0x12939L, "look_pitch_down",
			"[MED-HIGH] Look down (default End, scancode 0x4f): g_view_pitch (0x90a74) -= 2."),
		new NamedFunction(0x1294bL, "look_pitch_recenter_down",
			"[MED] Pitch step toward centre then -8 (default PgDn, scancode 0x51)."),
		new NamedFunction(0x1296fL, "look_pitch_recenter_up",
			"[MED] Pitch step toward centre then +8 (default PgUp, scancode 0x49)."),

		// --- Main loop / game-state (2026-06-14) ---
		new NamedFunction(0x179eeL, "game_play_loop",
			"[HIGH] The per-frame game loop (only roth_main_sequence callee reaching the renderer). "
			+ "Outer do{} = level/restart loop; FUN_00026628 yields a transition code (1=quit->ret 2; "
			+ "3..4 -> load_savegame_file 0x22129 = the LOAD action). Inner do{}while(DAT_0007f360==0) = the "
			+ "per-frame loop, frame-time-scaled via g_frame_time_scale, exits when DAT_0008a0f0<1. "
			+ "Dispatches on g_player_movement_enabled (1=gameplay, 3=UI/inventory, 5=dialogue)."),
		new NamedFunction(0x1792cL, "gameplay_frame_step",
			"[HIGH] Gameplay-mode (g_player_movement_enabled==1) per-frame step: ticks entities "
			+ "(reaches tick_dynamic_entities 0x42d74) AND renders the 3D world (reaches "
			+ "draw_world_surface_spans 0x36b39). The heart of the gameplay frame."),
		new NamedFunction(0x26965L, "load_disk_path_config",
			"[startup] Loads the multi-disk install/CD path config (RENAMED from load_or_init_game_state — it does "
			+ "NOT read save-state; the real save reader is read_raw_state_stream 0x214b9). build_game_path opens a "
			+ "DBASE300-dir file (retry-prompt loop on failure), allocates DAT_00083ea8 via pool_alloc_handle, and "
			+ "parse_config_keywords parses the 'DISK1 A DISK2 A DISK3 A DISK4 A' template (string @0x76057) into it = "
			+ "the DISK1..DISK4 path table consumed by the GDV/cutscene disk resolver (find_gdv_error_index / "
			+ "show_cutscene_error_box). Returns -1 to abort start if the file is absent + the user declines retry. "
			+ "Called by roth_main_sequence before game_play_loop."),
		new NamedFunction(0x26628L, "run_main_menu",
			"The front-end MAIN MENU (descriptor &DAT_00071bbd: Play the game / Load a game / Replay Intro "
			+ "/ Settings / Quit to DOS), shown over the frozen game frame and run from game_play_loop's "
			+ "outer loop; returns the resulting play-loop transition code (e.g. 10=play, 1=quit). Routes "
			+ "Load -> slot list, Settings -> run_settings_menu, Replay Intro -> the playback/movie menu."),
		new NamedFunction(0x22129L, "load_savegame_file",
			"[savegame — CORRECTED 2026-06-18; was mislabeled 'menu_dialogue_state_machine'] The .SAV slot LOADER: "
			+ "read counterpart of write_savegame_file (0x21dc6). sprintf's SAVE<slot>.SAV (template 0x75ee5) + "
			+ "build_game_path, dos_open_file (read), then a CHUNK LOOP: dos_read_items(&hdr, 4) reads the {u16 id, "
			+ "u16 size} header and the 'jump table 0x220f1' (the author's mislabel) is actually the CHUNK-ID SWITCH "
			+ "— each case dos_read_items the payload into its global (e.g. id 7 -> g_inventory_slots then recount "
			+ "0x80c2c + rebuild_weapon_inventory_list; id 0xe -> g_current_dbase300_chunk_id; cursor/dbase100 chunks "
			+ "likewise), until a short read ends the stream; then dos_close_handle. 'Transition codes 3..4' from "
			+ "game_play_loop = the options-menu LOAD action. See docs/reference/ROTH_savegame_format.md."),

		// --- HMI SOS audio driver subsystem (2026-06-14) ---
		new NamedFunction(0x15813L, "sos_audio_init",
			"[MED-HIGH] Audio init (called by roth_main_sequence). Drives sos_load_driver to install "
			+ "the configured SOS sound driver(s)."),
		new NamedFunction(0x15ac8L, "sos_audio_shutdown",
			"[MED-HIGH] Audio shutdown (called by roth_main_sequence cleanup); drives sos_unload_driver."),
		new NamedFunction(0x15290L, "sos_load_driver",
			"[MED-HIGH] Installs an HMI SOS sound driver by type code DAT_0007f3ac (0xA00x). For "
			+ "0xa00a loads Gravis MIDI patches (\"LOADPATS /Q /I MIDI GRAVIS.INI\"); calls "
			+ "install_sos_driver_vtables (0x443a7) then sos_alloc_driver_slot (0x44553)."),
		new NamedFunction(0x15702L, "sos_unload_driver",
			"[MED] Tears down an installed SOS sound driver (mirror of sos_load_driver)."),

		// --- HMI SOS music-driver model + timer service (2026-06-17 audio deep-dive) ---
		// The SOS exposes up to 5 driver slots (g_sos_driver_type_ids 0x920f0). Each slot holds a
		// 0x48-byte record at g_sos_driver_vtable (0x92f9c) = 12 x 6-byte FAR method pointers (only
		// methods 0..4 are populated): m0=event_out (hot path), m1=open, m2=close, m3=stop, m4=control.
		// Three driver templates are installed by type id: 0xa003 = external/General-MIDI passthrough,
		// 0xa005 / 0xa007 = DMA-driven software-synth MIDI cards, 0xa00a = Gravis wavetable (loads patches).
		new NamedFunction(0x443a7L, "install_sos_driver_vtables",
			"[AUDIO] Installs the three SOS music-driver method TEMPLATES (5 far-ptr methods each) into the "
			+ "global template tables: a003 @0x93198 (passthrough: 0x50450/80/99/b2/cb), a005 @0x93c10 "
			+ "(0x50544/0x5091f/0x50ad0/0x50b4b/0x50b78), a007 @0x970d4 (0x5322c/0x536df/0x5389a/0x53915/"
			+ "0x53942). sos_alloc_driver_slot later copies the matching template into the slot's 0x48-byte "
			+ "record at g_sos_driver_vtable (0x92f9c). Sets g_sos_drivers_installed (0x93194)=1."),
		new NamedFunction(0x44a81L, "sos_free_driver_slot",
			"[AUDIO] Closes a driver slot: if active, calls driver method 2 (close, [vtable+0xc]); for a005/a007 "
			+ "runs synth cleanup 0x5189d, for a00a the digital-mixer teardown sos_timer_remove_event-twin "
			+ "0x49ca4; then clears the slot tables (g_sos_driver_type_ids 0x920f0, active 0x920b4, 0x9204c/"
			+ "0x92094). EAX=slot, EDX=do-extra-cleanup flag."),
		new NamedFunction(0x44ba6L, "sos_reset_driver_channels",
			"[AUDIO] Silences a driver: for all 16 MIDI channels sends CC#121 (0x79 Reset-All-Controllers) and "
			+ "CC#123 (0x7b All-Notes-Off) via driver method 0 (event-out, msg class 3), then calls driver "
			+ "method 3 (stop, [vtable+0x12]). EDX=slot."),
		new NamedFunction(0x44cadL, "sos_driver_call_m4",
			"[AUDIO] Thin wrapper that invokes driver method 4 ([vtable+0x18] = control/query) and returns its "
			+ "result. EAX=slot, CX/EBX/EDX = method args. For a003 method4 (0x504cb) registers the external "
			+ "MIDI output far-callback (g_extmidi_out_callback 0x931b8)."),
		new NamedFunction(0x44dc4L, "sos_sequencer_timer_isr",
			"[AUDIO] Tiny FAR (retf) SOS timer callback: just sets g_sos_timer_tick_flag (0x951d0)=1. Registered "
			+ "via sos_timer_register_event; the main loop / driver polls the flag to pace per-tick work."),
		new NamedFunction(0x49923L, "sos_timer_register_event",
			"[AUDIO — CORRECTED, was mislabeled a 'codec helper'] HMI SOS sosTIMERRegisterEvent: registers a "
			+ "periodic FAR callback in the 16-entry timer-event table (g_sos_timer_event_table 0x979c4 offset / "
			+ "0x979c8 selector / 0x97a24 rate, stride 6/4). EAX=rate(Hz), CX=callback selector, EBX=callback "
			+ "offset. Computes the 8253 PIT reload divisor as 0x1234dc(=1193180)/rate and reprograms the timer "
			+ "to the fastest registered rate (g_sos_timer_base_rate 0x741f8). Returns 0xb if the table is full."),
		new NamedFunction(0x49ca4L, "sos_timer_remove_event",
			"[AUDIO — CORRECTED, was 'codec helper'] HMI SOS sosTIMERRemoveEvent: clears timer-event slot EAX "
			+ "(g_sos_timer_event_table 0x979c4/0x979c8) and recomputes the timer reload from the remaining "
			+ "events' max rate. Twin of sos_timer_register_event (0x49923)."),
		new NamedFunction(0x49eafL, "sos_timer_dispatch",
			"[AUDIO] The SOS PIT timer tick service (int8/IRQ0). Each tick it walks the 16-entry timer-event "
			+ "table (g_sos_timer_event_table 0x979c4/0x979c8, count g_sos_timer_event_count 0x97b64), decrements "
			+ "each event's countdown (g_sos_timer_event_countdown 0x741fc) and FAR-calls every due callback "
			+ "(`call far [+0x979c4]`) — e.g. the MIDI sequencer tick sos_sequence_timer_tick (0x51ad5) and the "
			+ "digital-mixer poll. This is what actually clocks both music and digital audio."),
		new NamedFunction(0x51ad5L, "sos_sequence_timer_tick",
			"[AUDIO] The MIDI music PLAYBACK tick — the FAR callback armed by step_audio_sequence via "
			+ "sos_timer_register_event at the driver's tick rate. Advances the sequence delta-time clock and "
			+ "fires every due MIDI event through emit_audio_sequence_event (0x4627d) -> sos_dispatch_midi_event "
			+ "(0x44e0d); on song end calls sos_timer_remove_event (0x49ca4) to disarm itself. Context = "
			+ "g_sos_sequence_ctx_table (0x72908[track])."),

		// SOS music-driver method tables (vtable layout: m0 event_out / m1 open / m2 close / m3 stop / m4 control).
		// a003 = external/General-MIDI passthrough driver (forwards assembled MIDI bytes to g_extmidi_out_callback).
		new NamedFunction(0x50450L, "sos_drv_a003_m0_event_out",
			"[AUDIO] a003 (passthrough) method 0: forwards the 3 assembled MIDI bytes to the registered external "
			+ "MIDI output far-callback g_extmidi_out_callback (0x931b8). FAR (retf)."),
		new NamedFunction(0x50480L, "sos_drv_a003_m1_open",
			"[AUDIO] a003 method 1 (open): stub, returns 0 (no hardware to init for passthrough). FAR."),
		new NamedFunction(0x50499L, "sos_drv_a003_m2_close",
			"[AUDIO] a003 method 2 (close): stub, returns 0. FAR."),
		new NamedFunction(0x504b2L, "sos_drv_a003_m3_stop",
			"[AUDIO] a003 method 3 (stop/flush): stub, returns 0. FAR."),
		new NamedFunction(0x504cbL, "sos_drv_a003_m4_set_output",
			"[AUDIO] a003 method 4 (control): registers the downstream MIDI-out far-callback — stores arg "
			+ "offset->g_extmidi_out_callback (0x931b8), arg selector->0x931bc. FAR."),
		// a005 = DMA-driven software-synth MIDI driver (programs the ISA DMA controller; full MIDI interpreter).
		new NamedFunction(0x50544L, "sos_drv_a005_m0_event_out",
			"[AUDIO] a005 (DMA synth) method 0: full MIDI-message interpreter (splits status into channel/command "
			+ "then a per-command switch) that renders notes to the DMA-driven DAC. FAR (retf)."),
		new NamedFunction(0x5091fL, "sos_drv_a005_m1_open",
			"[AUDIO] a005 method 1 (open/init the synth + DMA). FAR."),
		new NamedFunction(0x50ad0L, "sos_drv_a005_m2_close",
			"[AUDIO] a005 method 2 (close/stop DMA). FAR."),
		new NamedFunction(0x50b4bL, "sos_drv_a005_m3_stop",
			"[AUDIO] a005 method 3 (stop/flush voices). FAR."),
		new NamedFunction(0x50b78L, "sos_drv_a005_m4_control",
			"[AUDIO] a005 method 4 (control/query — volume/ioctl; role inferred). FAR."),
		// a007 = second DMA-driven software-synth MIDI driver (same vtable shape as a005).
		new NamedFunction(0x5322cL, "sos_drv_a007_m0_event_out",
			"[AUDIO] a007 (DMA synth) method 0: full MIDI-message interpreter -> DMA-driven DAC. FAR (retf)."),
		new NamedFunction(0x536dfL, "sos_drv_a007_m1_open",
			"[AUDIO] a007 method 1 (open/init). FAR."),
		new NamedFunction(0x5389aL, "sos_drv_a007_m2_close",
			"[AUDIO] a007 method 2 (close). FAR."),
		new NamedFunction(0x53915L, "sos_drv_a007_m3_stop",
			"[AUDIO] a007 method 3 (stop/flush). FAR."),
		new NamedFunction(0x53942L, "sos_drv_a007_m4_control",
			"[AUDIO] a007 method 4 (control/query; role inferred). FAR."),

		// --- From recomp chat (verified vs disasm 2026-06-14) ---
		new NamedFunction(0x1299aL, "input_ring_dequeue",
			"[HIGH] Dequeues one byte from the input ring buffer (base 0x90c1c). tail=0x7e91e, "
			+ "head=0x7e91c, size-mask=0x7e91a. Returns 0 (ZF set) when empty; else reads byte at "
			+ "tail, advances tail&mask. Called by keymap_dispatch."),
		new NamedFunction(0x2fbbcL, "set_filename_extension",
			"[HIGH] Finds the extension slot of a filename (scans for the last '.' after the last "
			+ "'\\\\' path separator) and rewrites it. EAX = filename pointer."),
		new NamedFunction(0x54ddfL, "string_copy",
			"[HIGH, oracle-verified lift] strcpy: EAX=dst, EDX=src; copies including the NUL "
			+ "(2-byte unrolled), returns dst."),
		new NamedFunction(0x226c6L, "resolve_reloc_ptr",
			"[oracle-verified lift; name MED] Base-relative pointer resolve: base=DAT_0007f56c; if "
			+ "base==0 return 0, else return *(base+EAX)+base (table offset -> absolute pointer)."),
		new NamedFunction(0x12ceaL, "clear_framebuffer_rect",
			"[HIGH, oracle-verified lift] Zero a W*H framebuffer rect: EAX=x, EDX=y, EBX=width, "
			+ "ECX=height; addr=g_framebuffer_ptr(0x90a98)+x+y*g_screen_pitch(0x85498); hires flag "
			+ "(0x90cbd) doubles the y-offset AND the row count."),
		new NamedFunction(0x2a898L, "rotate_point_2d",
			"[oracle-verified lift; name MED] 2D point transform. EBP = ptr to {int16 x@+0, y@+2, "
			+ "flags@+4}; RETURNS A PAIR in EAX+EDX (the corpus decompile only captured EAX). If "
			+ "(flags & 0x1ff): rotate via sin=DAT_85310/cos=DAT_85312 -> EAX=(y*s-x*c)>>6, "
			+ "EDX=(x*s+y*c)>>6; else EAX=y<<8, EDX=x<<8."),

		// --- From recomp chat, batch 13 (oracle-verified lifts, 2026-06-15) ---
		new NamedFunction(0x560faL, "abs_i32",
			"[HIGH, oracle-verified lift] returns |EAX| (32-bit absolute value)."),
		new NamedFunction(0x2ad14L, "signext_852f2_to_909a4",
			"[oracle-verified lift] movsx copy: sign-extends word [0x852f2] into dword [0x909a4]."),
		new NamedFunction(0x4f313L, "geom_find_matches",
			"[oracle-verified lift] AX=key id, EBX=cap, EDX=out buffer: builds a list of geometry "
			+ "records matching the id (a gather_faces_by_id 0x34c38 variant / the alternate gather)."),
		// --- Raw-state / map-geometry record subsystem (game logic linked at high VA; 2026-06-20).
		//     Data model: g_map_geometry_buffer (0x90aa8) header has u16 section offsets at +4 (SECTOR
		//     records, stride 0x1a, group-id @+0x14, flags @+0x16, wall-count @+0xd / wall-array @+0xe),
		//     +6 (FACE records, stride 0xc, id @+4), +8 (raw-state records, var 14/10B, key @+0xc). Each
		//     section is preceded by a u16 count at [section-2]. Confirmed against walk_visible_sectors.
		new NamedFunction(0x4f2e0L, "find_geometry_record",
			"[map-geometry] Single-match sibling of geom_find_matches (0x4f313): scans the SECTOR section "
			+ "(g_map_geometry_buffer +4, stride 0x1a) for the first record whose group-id (+0x14)==AX, "
			+ "returns its buffer-relative offset (0 if none). Parallels find_raw_state_record."),
		new NamedFunction(0x4f567L, "find_face_record",
			"[map-geometry] Scans the FACE section (g_map_geometry_buffer +6, stride 0xc) for the first "
			+ "record whose id (+4)==AX, returns its buffer-relative offset (0 if none). Single-match face "
			+ "finder; callers: cmd_change_face_texture / cmd_open_door / cmd_face_emits_damage."),
		new NamedFunction(0x4f477L, "clear_geometry_visited_flags",
			"[map-geometry] Clears the flood-fill VISITED bit (+0x16 &= ~0x4) on every SECTOR record; "
			+ "called by collect_connected_geometry_group before a traversal."),
		new NamedFunction(0x4f42dL, "flood_fill_geometry_neighbors",
			"[map-geometry] Recursive connected-sector flood-fill: marks the current sector visited "
			+ "(+0x16 |= 4), appends it to the out list, then walks its walls (count +0xd @ array +0xe, "
			+ "stride 0xc) and recurses across each non-blocked portal (wall+0xa bit0x8 clear) into the "
			+ "neighbor sector (wall+8, -1 = solid) if unvisited. Core of collect_connected_geometry_group."),
		new NamedFunction(0x4f3d0L, "collect_connected_geometry_group",
			"[map-geometry] Builds the list of sectors connected to a seed: stores the key, finds the seed "
			+ "via find_geometry_record, clears visited flags (clear_geometry_visited_flags), flood-fills "
			+ "neighbors (flood_fill_geometry_neighbors), writes the count to out[0] and returns it. Gated "
			+ "on g_geometry_selector. Callers: cmd_cycle_texture / tick_move_floorceil / alloc_*_effect."),
		new NamedFunction(0x4f4a4L, "apply_light_delta_to_record_list",
			"[map-geometry] For each record offset in a match list (param[0]=count, param[2..]=offsets), if "
			+ "the record's light byte (+0xb) is nonzero, adds the signed delta (param_2); returns the "
			+ "count modified. Gated on g_geometry_selector. Lighting-tick helper (tick_change_lighting)."),
		new NamedFunction(0x4f4e8L, "apply_flag_mask_to_record_list",
			"[map-geometry] For each record offset in a match list, clears a bit-mask then sets bits in the "
			+ "record flag byte (+0xa): byte = (byte & ~mask) | set. Returns the list count. Gated on "
			+ "g_geometry_selector. Light-switch / state-tick helper (tick_light_switch / tick_cmd_45)."),
		new NamedFunction(0x4f221L, "flag_sectors_with_objects",
			"[map-geometry; disasm-confirmed args EAX=g_map_geometry_buffer, EDX=g_map_objects_buffer] "
			+ "Caches the sector section offset (->g_sector_section_offset 0x91dfc) and count (->g_sector_count "
			+ "0x91df8) from the geometry header (+4), then sets sector flag bit 0x2 (+0x16 |= 2) for each "
			+ "sector whose per-sector object-list entry in g_map_objects_buffer is nonzero (the sector has "
			+ "objects). Called during raw-state release (release_raw_state_and_setup_sfx)."),
		new NamedFunction(0x4f1a0L, "init_sector_object_state",
			"[map-geometry] Map-load variant of flag_sectors_with_objects (same args/caching + 'has-objects' "
			+ "sector flag), and for each such sector clears the +0xc/+0xd runtime bytes of every object in "
			+ "its list (objects = 0x10-stride records in g_map_objects_buffer). Called by init_loaded_map_state."),
		new NamedFunction(0x4f263L, "resolve_object_owner_sector",
			"[map-geometry] Given an object-record pointer, scans the per-sector object-list-offset table in "
			+ "g_map_objects_buffer (count g_sector_count) for the largest list-start <= the object's buffer "
			+ "offset, and returns the OWNING sector's record offset (index*0x1a + g_sector_section_offset). "
			+ "Called by spawn_entity_into_state_pool_a, which stores it as the entity's owner-sector link "
			+ "(state-pool-A slot +0x16)."),
		new NamedFunction(0x4f0abL, "resolve_face_surface_id",
			"[renderer; the EBX return is dropped by Ghidra's decomp] Resolves a face's surface/texture DAS "
			+ "id during emit_world_face_spans (0x2c720). Reads the face's type/draw flags ([EBX+8]) and "
			+ "selects the matching texture id from the face record's per-variant id array (ESI+EAX+0x14 "
			+ "default, else +4/+0x24/+0x34/+0x44 or fixed +0x54.. by type bits 0x20/0x40/0x8/0x80/==5/"
			+ "0x20000). Returns the id in EBX -> stored to g_current_das_entry_id (0x90a78); bit 0x8000 = "
			+ "horizontal flip (xors g_world_surface_draw_flags bit1). Feeds the g_das_entry_status_table lookup."),

		// --- From recomp chat, batch 11 (oracle-verified lifts, 2026-06-15) ---
		new NamedFunction(0x210ecL, "split_path",
			"[HIGH, oracle-verified lift] _splitpath: EAX=src, EDX=dir-out, EBX=name-out, ECX=ext-out; "
			+ "splits on the last '\\\\' and '.'."),
		new NamedFunction(0x2f42bL, "reset_renderer_tables",
			"[oracle-verified lift] rep-stosw init of three render/DAS-cache globals incl. "
			+ "g_das_entry_status_table (0x86d30, 0x1600 words = 0xff each, marking every DAS entry "
			+ "not-resident)."),
		new NamedFunction(0x2f962L, "init_render_struct_89ed0",
			"[oracle-verified lift] Populates the struct at 0x89ed0 from selector/buffer globals "
			+ "(0x90be8/0x90bea …)."),
		new NamedFunction(0x13106L, "blit_descriptor_rows",
			"[oracle-verified lift] EAX = ptr-to-ptr to a blit descriptor {+0 dst, +4 width-bytes, "
			+ "+8 rows, …}; blits the described rows."),
		new NamedFunction(0x2d29aL, "emit_vertex_bbox",
			"[oracle-verified lift] AX=x, DX=y, EBX=index-out, EDI=vertex-record, ESI=bbox; stores "
			+ "the vertex (x@+0xc, y@+0xe) and expands the bbox."),
		new NamedFunction(0x277b6L, "find_free_slot_83ed4",
			"[oracle-verified lift] Scans 16 records of stride 0x9a at 0x83ed4 for the first free "
			+ "one (first dword == 0)."),
		new NamedFunction(0x1dda8L, "scan_tag4_chunk",
			"[oracle-verified lift; = the OnInspect block locator, TRACE-confirmed 2026-06-17] EAX=def/template; "
			+ "if (def[+4] & 0x40)==0 return 0 (not inspectable); stores def id (def[+2]) to 0x81efa, then walks "
			+ "the trigger-block list at def+0x14 comparing each block header's high byte (>>0x18) to 4 = the "
			+ "TRIGGER 0x04 OnInspect block; on match stores the block ptr to 0x81efe and returns it (else 0). "
			+ "Called by dispatch_dialogue_ui_action (the INVENTORY right-click inspect entry), "
			+ "load_dbase300_resource_at_offset (loads the inspect close-up image), and find_oninspect_block_by_id."),
		new NamedFunction(0x1ddebL, "find_oninspect_block_by_id",
			"[OnInspect helper] EAX = def/template id; resolves the def via g_dbase100_inventory_table (0x81e20) + "
			+ "g_dbase100_base (0x81e1c) then runs scan_tag4_chunk to locate its trigger-0x04 OnInspect block. The "
			+ "by-id wrapper around scan_tag4_chunk; used by the world examine path (examine_object_under_cursor)."),
		new NamedFunction(0x10cb3L, "examine_object_under_cursor",
			"[world RIGHT-CLICK examine handler; TRACE-confirmed 2026-06-17; called from run_gameplay_frame's RMB path after render_world_view] Locates the object/sector under the cursor via 0x34f5a (camera-relative pos 0x7e904/0x7e908 - 0x85ce0/0x85ce4); if found -> examine_world_object (0x35235); else for an object of type 4 resolves its def (obj+0xe, id obj[+4]) and finds its OnInspect block via find_oninspect_block_by_id. The RMB sibling of activate_targeted_object (LMB use)."),
		new NamedFunction(0x35235L, "examine_world_object",
			"[world examine action; TRACE-confirmed 2026-06-17] EAX/ESI = target object. Starts the object's dialogue/monologue record (obj+0xa via eval_dialogue_record_by_id 0x1dc73) AND fires its OnInteract/OnInspect trigger chain (fire_trigger_on_interact 0x31ffe -> walk_command_chain_flow). This is what plays the hero's monologue when you right-click a world object."),
		new NamedFunction(0x3ded2L, "rotate_quad",
			"[oracle-verified lift] EDI=record; rotates 4 points by angle byte[edi+3] via the 0x72080 "
			+ "sine table (same table as sincos_pair)."),
		new NamedFunction(0x51995L, "identity_passthrough",
			"[oracle-verified lift; name LOW] EAX in -> EAX out (compiler-emitted identity; also "
			+ "re-emits DX in EDX low 16)."),

		// --- From recomp chat, batch 10 (oracle-verified lifts, 2026-06-15) ---
		new NamedFunction(0x54dfeL, "string_concat",
			"[HIGH, oracle-verified lift] strcat: appends src onto the end of dst (sibling of "
			+ "string_copy 0x54ddf)."),
		new NamedFunction(0x55bd0L, "string_length",
			"[HIGH, oracle-verified lift] strlen: length of the NUL-terminated string."),
		new NamedFunction(0x35fd9L, "block_payload_size",
			"[oracle-verified lift; name LOW] `ptr ? *(u32*)(ptr+4) - 0x10 : 0` — looks like an "
			+ "allocation's payload size = stored size minus a 0x10 header."),
		new NamedFunction(0x361e7L, "obj_counter12_inc",
			"[oracle-verified lift; name MED] increments the byte counter at [ptr+0x12], returns "
			+ "the new value."),
		new NamedFunction(0x361efL, "obj_counter12_dec",
			"[oracle-verified lift; name MED] decrements the byte counter at [ptr+0x12], returns "
			+ "the new value."),
		new NamedFunction(0x560c2L, "get_errno_ptr",
			"[oracle-verified lift] `mov eax, &errno(0x97d44); ret` — the Watcom CRT errno accessor "
			+ "(errno macro expands to *get_errno_ptr()). IDENTIFIED: callers dereference and compare "
			+ "*p to errno codes (==1/==9, the not-found class) in the PATH-search exec spawnvpe "
			+ "(0x4f799 / 0x57774), and set_errno (0x55ba1) writes through it. Was get_ptr_dat97d44."),
		new NamedFunction(0x55ba1L, "set_errno",
			"[CRT] Watcom errno setter: `*get_errno_ptr() = value`. Stores the (reg-passed) code into "
			+ "errno (0x97d44). Called throughout the spawn/PATH-search path, e.g. set_errno(9) on too "
			+ "many args, set_errno(2) on a failed temp alloc, set_errno(0) to clear before a retry."),
		new NamedFunction(0x18147L, "get_dbase100_inventory_entry",
			"[oracle-verified lift] Resolves a DBASE100 inventory ENTRY pointer by item index: "
			+ "AX=index -> g_dbase100_inventory_table(0x81e20)[AX] + g_dbase100_base(0x81e1c); 0 if "
			+ "idx<=0 or empty slot. The base resolver the per-field accessors build on. "
			+ "(recomp proposed the generic name resolve_indexed_handle.)"),
		new NamedFunction(0x3bdd2L, "sincos_pair",
			"[HIGH, oracle-verified lift] EBX=angle -> sin in CX, cos in BX, sine-table base in "
			+ "ESI (a multi-register return the corpus C drops to `return;`). Reads the 512-entry "
			+ "sine table at 0x72080; cos = tab[(angle+0x80)&0x1ff] (90deg quarter-phase). Both "
			+ "16-bit zero-extended. Sibling of the single-output sincos_lookup (0x3c1f3)."),
		new NamedFunction(0x3d018L, "find_record_by_id",
			"[oracle-verified lift; name MED] DI=key -> CARRY flag (0=found / 1=not). Scans "
			+ "count=byte[0x8b3f4] records of stride 0x1f6 from 0x8b3f8, comparing each record's "
			+ "first u16 to the key."),
		new NamedFunction(0x18e2cL, "resolve_reloc_ptr_dup",
			"[HIGH, oracle-verified lift] Byte-identical DUPLICATE of resolve_reloc_ptr (0x226c6): "
			+ "same base DAT_0007f56c, `*(base+off)+base`; this copy is leaner (preserves only EDX)."),
		// --- Sprite render queue (2026-06-15; see ROTH_DAS_loader_notes.md) ---
		new NamedFunction(0x3b1b1L, "draw_sprite_render_queue",
			"[HIGH] Walks the visible-sprite render queue (linked list, node+0 = next) and calls "
			+ "render_world_sprite on each node."),
		new NamedFunction(0x3c294L, "init_sprite_render_queue",
			"[MED-HIGH] Resets the per-frame sprite-node pool (g_sprite_node_pool 0x8aad0, cap "
			+ "0x800) and the list head g_sprite_render_queue_head (0x8b340)."),
		new NamedFunction(0x3c2bdL, "project_sprite_to_render_queue",
			"[MED] Projects a source object into a sprite-queue node (uses g_sprite_view_angle "
			+ "0x909f8 + screen-center 0x90a04/0x90a06); the node carries the das-block ref "
			+ "(+0x30/+0x36) and pose (+0x1c). Calls FUN_0003bdf3."),
		new NamedFunction(0x3c477L, "finalize_sprite_render_queue",
			"[MED] Sorts/links the sprite nodes and returns the list head (g_sprite_render_queue_head)."),

		// --- Entity sprite binding (2026-06-15; see ROTH_DAS_loader_notes.md) ---
		new NamedFunction(0x36651L, "render_world_sprite",
			"[MED-HIGH] Selects + animates + draws an object's DAS sprite. For a directional grouped "
			+ "block (block+0x10 bit 0x40): picks the sub-image (table at block+0x12) by camera angle "
			+ "(bit 0x8000: (0x120-g_sprite_view_angle 0x909f8)>>5 & 0xe = 8 facings) or by the "
			+ "render-node pose byte +0x1c (bit 0x4000: idle/walk/attack/death). Sub-image bit 0x8000 = "
			+ "horizontal mirror (X-flip flag 0x9093c). Resolves grouped child (<<4), sets "
			+ "g_render_source_base_ptr (0x84980), animates via advance_das_sprite_animation_frame."),

		// --- Inventory / item system (2026-06-15; see ROTH_inventory_notes.md) ---
		new NamedFunction(0x1cedcL, "give_item",
			"[HIGH] Adds item (param_1=id) to the carried inventory. Validates id<=base[+0x10]; if "
			+ "the stackable type ((entry[+4]>>8)&0xf==2) stacks, else find_free_inventory_slot + "
			+ "writes {id,qty}. Returns 0 if full (count>0xff) or invalid."),
		new NamedFunction(0x1ce43L, "find_free_inventory_slot",
			"[HIGH] Scans g_inventory_slots (0x80c30) for the first empty slot (id==0; max 256), "
			+ "bumps g_inventory_count (0x80c2c), returns the slot ptr; 0 if full."),
		new NamedFunction(0x1ce14L, "stack_onto_inventory_slot",
			"[MED] Increments the quantity of an existing matching stackable inventory slot."),
		new NamedFunction(0x1ce6bL, "remove_inventory_item",
			"[HIGH] Removes an inventory slot (param_1=slot ptr). Deselects it if it was "
			+ "g_selected_item_primary/secondary (rebuilds UI 0x1bb4b/0x184ab); tracks special item "
			+ "0x811e4. Stack-aware: qty-- if stackable & qty>1, else clear id + g_inventory_count--."),
		new NamedFunction(0x1ccf7L, "query_player_inventory",
			"[HIGH] param_1=item id, param_2=flags (bit0: check selected slots first; bit1: easy "
			+ "select). Scans g_inventory_slots counting matches; returns quantity for a single "
			+ "stackable match. Used by RAW cmd 0x27 If-Not-Item + DBASE100 item-count compares. "
			+ "SINGLE EAX return (recomp 2026-07-01): count-mode (bit0 clear) = number of matching "
			+ "slots, or that quantity for exactly one stackable match (rec+5 & 0x20); select-mode "
			+ "(bit0 set) = 0/1. Side effects: g_item_autoselected_flag (found), g_selected_item_primary "
			+ "(selected slot on a scan match). ASYMMETRY: the primary-match fast path clears "
			+ "g_held_item_slide_timer; the secondary-match path deliberately does not (jumps past the clear)."),
		new NamedFunction(0x1c57eL, "reset_inventory",
			"[MED] Clears g_inventory_slots + g_inventory_count=0; called during level/game init."),
		new NamedFunction(0x44553L, "sos_alloc_driver_slot",
			"[MED-HIGH] Claims a free slot in the 5-slot SOS driver pool (0x920f0), copies the "
			+ "driver type's far-ptr method vtable (type 0xa005@0x93c10 / 0xa003@0x93198 / "
			+ "0xa007@0x970d4) into the slot record at 0x92f9c+slot*0x48, then far-calls slot1 "
			+ "(driver init). See ROTH_dispatch_edges.md (sos_sound_driver_vtable)."),

		// --- Dynamic-entity pools (2026-06-14) ---
		new NamedFunction(0x4263eL, "reset_entity_pools",
			"[HIGH] Clears both per-level dynamic-entity pools to empty: the projectile/dynamic "
			+ "table (g_dynamic_entity_table 0x90fe4, count 0x90fe0, 0x1c-byte records) and the "
			+ "saved-state actor pool (g_state_pool_a_records 0x91e04, count g_state_pool_a_count 0x91e00, 0x22-byte records). "
			+ "Called at level/state init."),

		// --- Player damage / combat core (2026-06-14) ---
		new NamedFunction(0x32023L, "apply_damage_to_player",
			"[HIGH] Central player-damage applicator. EAX=base damage (byte from the source), "
			+ "EDX=type (if set, scales by g_frame_time_scale 0x85324 = continuous/DoT), ECX=0..0x100 "
			+ "distance falloff. Bumps the damage-flash g_damage_flash_level (0x89f3b, cap 0x164), "
			+ "sets the redraw/hit flag 0x83e7c, then `sub g_player_health(0x8a0f0), dmg` clamped at "
			+ "0 (death). Large hits (>0xc8) get an extra <<7 scale; damage cap ~0x35c6."),
		new NamedFunction(0x320c6L, "apply_reduced_damage_to_player",
			"[player damage variant — disasm-verified; called by update_dynamic_entities 0x42872 = enemy contact] "
			+ "Applies param_1 damage to the player AFTER reducing it by g_value_reduction_factor "
			+ "(dmg -= dmg*g_value_reduction_factor>>11; if the result <1 and dmg<0x35c6 it no-ops). Then runs the same "
			+ "tail as apply_damage_to_player: redraw/hit flag 0x83e7c=1, bump g_damage_flash_level (cap 0x164), "
			+ "g_player_health -= dmg (clamp 0). The armor/attrition-reduced enemy-attack path."),
		new NamedFunction(0x32058L, "apply_direct_damage_to_player",
			"[player damage variant — disasm-verified; called by 0x1c648 <- 0x3ecfe] Applies param_1 damage to the "
			+ "player with NO falloff or reduction: the bare shared tail of apply_damage_to_player (set 0x83e7c, bump "
			+ "g_damage_flash_level cap 0x164, g_player_health -= dmg clamp 0)."),
		new NamedFunction(0x427f3L, "compute_projectile_hit_damage",
			"[MED] In the projectile-vs-entity collision path of update_dynamic_entities: computes "
			+ "the damage a projectile deals to the entity it hit (reads attributes off the "
			+ "target/projectile records, +0x2c/+0x2e). Result is RNG-scaled by the caller, then "
			+ "subtracted from the target's health (entity record +0xc)."),
		new NamedFunction(0x4271cL, "resolve_projectile_target_entity",
			"[MED] Resolves the entity record hit by a projectile (collision path of "
			+ "update_dynamic_entities). Caller then does `entity[+0xc] -= damage` (monster HEALTH) "
			+ "and sets entity[+0x21]=0x18 (hit-reaction); health underflow = death."),
		new NamedFunction(0x344c9L, "register_damage_emitter",
			"[MED-HIGH] Allocates a damage-emitter node (heap helper 0x360f9 over g_object table "
			+ "0x85c3c) and links it at the head of the active list g_damage_emitter_ptr (0x8a120) "
			+ "via `xchg`; inits node +0=next, +5/+6=0. Called from the command/effect path "
			+ "(FUN_000310bc) — i.e. map commands/effects spawn the radius damage zones that "
			+ "damage_player_from_emitter applies per frame."),
		new NamedFunction(0x34579L, "damage_player_from_emitter",
			"[MED-HIGH] Per-frame radius-damage tick (called via FUN_0003464c from "
			+ "tick_dynamic_entities). Walks the active damage-emitter at g_damage_emitter_ptr "
			+ "(0x8a120): if the player is within the emitter's radius (+0xa), applies its damage "
			+ "(+7) via apply_damage_to_player. This is how hazards / monster attacks hurt the "
			+ "player (register a damage emitter -> this tick applies it when the player is near)."),

		// ---- Watcom CRT: errno/_doserrno + process-spawn cluster (runtime, not game logic) ----
		new NamedFunction(0x560c8L, "get_doserrno_ptr",
			"[CRT] `mov eax, &_doserrno(0x97d48); ret` — sibling of get_errno_ptr (0x560c2). Returns the "
			+ "address of the raw-DOS-error global. Used only by set_doserrno (0x55bc4)."),
		new NamedFunction(0x55bc4L, "set_doserrno",
			"[CRT] `*get_doserrno_ptr() = value`. Sets _doserrno (0x97d48). Paired with set_errno on DOS "
			+ "failures (e.g. set_errno(2)+set_doserrno(10) in the spawn path)."),
		new NamedFunction(0x4f799L, "spawn_exec_path",
			"[CRT] spawn a program at an exact path: builds the command tail / env, tries the file with "
			+ ".COM/.EXE suffixes (DAT_760c0/760c5/760bb) and COMSPEC for batch, exec via spawn_exec_attempt "
			+ "(0x4f766); retries the next suffix only while errno is in the not-found class (==1/==9). "
			+ "Returns the child status or -1. Watcom spawnv-style core."),
		new NamedFunction(0x57774L, "spawn_search_path",
			"[CRT] PATH-searching spawn (spawnvp-style): tries spawn_exec_path (0x4f799) directly, and if "
			+ "that fails not-found (errno 1/9) and the name isn't absolute, walks the ';'-separated PATH "
			+ "dirs (FUN_00057da2 finds ';'), prepends each + '\\\\', and retries. Returns child status or -1."),
		new NamedFunction(0x4f766L, "spawn_exec_attempt",
			"[CRT] thin exec helper for spawn_exec_path: builds the command tail (build_dos_command_tail "
			+ "0x55a33) then runs it (dos_exec_program 0x55a86). One attempt at running an exact path."),
		new NamedFunction(0x55a86L, "dos_exec_program",
			"[CRT] DOS EXEC core: INT 21h AH=0x4B (load & execute a child program). Fills the EXEC "
			+ "parameter block (globals 0x755d4..0x755fa), sets the child-running flag g_dos_child_running "
			+ "(0x7255c)=1 around the call, then maps the result via map_dos_error_to_errno (0x5612f). "
			+ "The actual spawn/system primitive."),
		new NamedFunction(0x55a33L, "build_dos_command_tail",
			"[CRT] Flattens an argv array into a command line (args joined by ' ', via string_copy_bytewise). "
			+ "Two modes: C-mode NUL-terminates; DOS-mode writes the PSP command-tail format — a leading "
			+ "length byte + a trailing '\\r' (the format DOS EXEC expects at PSP:0x80)."),
		new NamedFunction(0x558fbL, "build_exec_param_block",
			"[CRT] Sizes and allocates (malloc 0x55be9) the child's environment + command-tail buffer for "
			+ "EXEC; walks the env array (or environ 0x755cc). On OOM: set_errno(5)+set_doserrno(8)."),
		new NamedFunction(0x560ceL, "spawn_exec_default_env",
			"[CRT] Thin wrapper: spawn_exec_path with the default environ (0x755cc) — the COMSPEC re-exec "
			+ "tail of the spawn search."),
		new NamedFunction(0x5612fL, "map_dos_error_to_errno",
			"[CRT] On a failed DOS call (carry/param!=0): stores the raw code into _doserrno, maps the DOS "
			+ "error to an errno value through the table at PTR_0x75620, sets errno, returns -1. Watcom "
			+ "__doserror-to-errno. (Pass-through of the value when no error.)"),
		new NamedFunction(0x55be9L, "malloc",
			"[CRT] Heap allocator (Watcom malloc/_nmalloc). Rounds size up to 4 (min 0xc), walks the heap "
			+ "free-list (0x75610/0x75614/0x75618) with sub-allocators 0x56912/0x56eb6/0x5707f; returns a "
			+ "block ptr or 0 (size 0 or > ~4GB-0x2c => 0). Used throughout for buffer allocation."),
		new NamedFunction(0x55cccL, "free",
			"[CRT] Heap free (Watcom). Returns the block to the free-list (heap_insert_free_block 0x569ba), "
			+ "updates the coalescing cursor 0x97d40 and the high-water mark 0x75618. No-op on null."),
		new NamedFunction(0x56912L, "heap_carve_block",
			"[CRT] Boundary-tag first-fit carve within one heap segment (control struct in EBX): walks the "
			+ "address-ordered free-list for a block >= rounded size, splits it (remainder relinked) or "
			+ "consumes it whole if the slack <0x10, sets the in-use low bit (`*p|=1`), returns p+1. The "
			+ "core of malloc; returns 0 if nothing fits (updates the largest-free hint at +0x14)."),
		new NamedFunction(0x56eb6L, "heap_grow",
			"[CRT] Grow the near heap: compute_heap_grow_size (0x57002), request more from the OS "
			+ "(os_grow_brk 0x57b52), link the new region into the free-list coalescing with the previous "
			+ "segment if physically adjacent, then free() it to merge. Returns 1 on success, 0 if the OS "
			+ "won't give more. (Realmode/alt path forwards to FUN_00056e06.)"),
		new NamedFunction(0x5707fL, "heap_grow_far_stub",
			"[CRT] `return 0;` — the secondary heap-grow strategy (far/DGROUP expand), disabled in this "
			+ "flat-model build. malloc's outer loop treats 0 as 'cannot grow further'."),
		new NamedFunction(0x569baL, "heap_insert_free_block",
			"[CRT] free()'s worker: clears the in-use bit, forward-coalesces with the next physical block "
			+ "if free, finds the address-ordered insertion point and back-coalesces with the previous "
			+ "block if adjacent (boundary-tag merge). Keeps the free-list counters (+0x18/+0x1c) updated."),
		new NamedFunction(0x57b52L, "os_grow_brk",
			"[CRT] Request more program memory from DOS (INT 21h AH=0x4A SETBLOCK / the DPMI path; gated "
			+ "by the memory-mode flag 0x72562), advancing the break g_heap_brk (0x72534). Returns the old "
			+ "break, or sets errno=5 and returns -1 on failure. The sbrk under heap_grow."),
		new NamedFunction(0x57002L, "compute_heap_grow_size",
			"[CRT] Rounds a requested allocation up (overhead + page alignment, per memory mode) to the "
			+ "number of bytes heap_grow should request from os_grow_brk. Returns false if it rounds to 0."),
		new NamedFunction(0x568f5L, "crt_write_runtime_error",
			"[CRT] Writes a runtime-error string to the console (FUN_0004f5b0, fallback FUN_00043a6d). "
			+ "Used for fatal CRT messages e.g. 'Stack Overflow!' (from check_stack_overflow)."),
		new NamedFunction(0x55775L, "stack_bytes_remaining",
			"[CRT] Returns &stack - g_stack_limit(0x72544) = free stack bytes; used to decide stack-alloca "
			+ "vs heap-malloc for scratch buffers in the spawn path."),
		new NamedFunction(0x55b6fL, "check_stack_overflow",
			"[CRT] Watcom __STK stack probe: if the requested frame would cross g_stack_limit (0x72544) and "
			+ "SS matches, raises 'Stack Overflow' (FUN_000568f5) and aborts."),
		new NamedFunction(0x55b5cL, "stack_check_thunk",
			"[CRT] LOCK/UNLOCK-wrapped entry to check_stack_overflow (0x55b6f); pass-through of its arg."),

		// ---- DOS low-level file/dir I/O (INT 21h handle calls; siblings of the already-named
		//      dos_close_handle 0x41b41 / dos_read_items 0x41b53 / dos_write_items 0x41b7a) ----
		new NamedFunction(0x41ae5L, "dos_open_file",
			"[CRT/DOS] open(name, mode): INT 21h AH=3Dh. mode 0 = read-only (AX=3D00), mode 2 = "
			+ "read-write (AX=3D02) then lseek to 0. Special-case: a 'CON:' path returns handle 2 (stderr). "
			+ "Returns the handle, or 0 on failure. The opener used across savegame/dbase/voice/dialogue."),
		new NamedFunction(0x41b9aL, "dos_lseek",
			"[CRT/DOS] lseek(handle=EAX, offset=EDX, whence=BL): INT 21h AH=42h. Returns the new 32-bit "
			+ "file position (DX:AX). offset split lo/hi into CX:DX per the DOS ABI."),
		new NamedFunction(0x41ad4L, "dos_delete_file",
			"[CRT/DOS] unlink(name): INT 21h AH=41h (delete file). Returns 0 ok / -1 on carry."),
		new NamedFunction(0x41be5L, "dos_make_directory",
			"[CRT/DOS] mkdir(name): if the path can't be opened as a file (dos_open_file fails), creates a "
			+ "directory via INT 21h AH=39h; returns 0 ok / -1 if a file by that name already exists."),
		new NamedFunction(0x41c14L, "dos_find_first",
			"[CRT/DOS] findfirst: sets the DTA to g_dos_dta (0x90f4c) once (INT 21h AH=1Ah, guarded by "
			+ "g_dta_initialized 0x90f48), then INT 21h AH=4Eh. Returns a ptr to the matched name field "
			+ "in the DTA (0x90f6a) or 0."),
		new NamedFunction(0x41c46L, "dos_find_next",
			"[CRT/DOS] findnext: INT 21h AH=4Fh against the active DTA. Returns the matched-name ptr "
			+ "(0x90f6a) or 0. Pairs with dos_find_first."),

		// ---- printf/sprintf family: the game's own format engine (routes to DOS stdout) ----
		new NamedFunction(0x27ca0L, "vsprintf_engine",
			"[CRT-style] The %-format core (shared loop at 0x27ca6). fmt in ESI, output in EDI, varargs "
			+ "via EBP; returns the written length. Handles %c %s %d %D %l %x %X with optional width digits, "
			+ "sign/thousands separators (flags in g_format_flags 0x8491d), and '\\n' -> CRLF (0x0a0d). "
			+ "Hex via g_hex_digits_lower/upper (0x71d94/0x71da4). Three entry points adjust EBP then merge."),
		new NamedFunction(0x27c98L, "vsprintf_entry_sprintf",
			"[CRT-style] Alt entry to vsprintf_engine (ebp=esp+0x30) used by sprintf (0x27c53); jmps into "
			+ "the shared loop 0x27ca6."),
		new NamedFunction(0x27c91L, "vsprintf_entry_printf",
			"[CRT-style] Alt entry to vsprintf_engine (caller-set ebp += 0xc) used by printf (0x27c6d); "
			+ "jmps into the shared loop 0x27ca6."),
		new NamedFunction(0x27c53L, "sprintf",
			"[CRT-style] sprintf(dest, fmt, ...): EDI=dest, ESI=fmt (from stack), formats via "
			+ "vsprintf_entry_sprintf. The game's string builder — 6 callers in the text/dialogue UI."),
		new NamedFunction(0x27c6dL, "printf",
			"[CRT-style] printf(fmt, ...): formats into a 0x100-byte stack buffer (vsprintf_entry_printf) "
			+ "then emits it via dos_print_string (DOS stdout). Debug/console output path."),
		new NamedFunction(0x27c48L, "dos_print_string",
			"[CRT/DOS] INT 21h AH=09h — write a string to DOS stdout. printf's output sink."),

		// ---- mem/string + misc CRT leaves (siblings of string_copy 0x54ddf etc.) ----
		new NamedFunction(0x54db7L, "memcpy",
			"[CRT] memcpy(dst, src, n): dword-unrolled copy (n>>2 dwords + n&3 byte tail), returns dst. "
			+ "Sibling of the EBX-count memcpy_return_dest (0x4f2b7)."),
		new NamedFunction(0x55240L, "memset",
			"[CRT] memset(dst, byte, n): aligns to 4 (rotating the fill pattern), then memset_fill_dwords "
			+ "(0x55277) for the bulk, byte tail. General form of zero_memory (0x41616)."),
		new NamedFunction(0x55277L, "memset_fill_dwords",
			"[CRT] The 32-byte-aligned, 8-dwords/iteration unrolled fill loop that does the bulk of memset."),
		new NamedFunction(0x5607bL, "stricmp",
			"[CRT] Case-insensitive string compare: folds A-Z->a-z on both operands, returns the signed "
			+ "byte difference at the first mismatch (0 if equal). Used in the spawn ext/COMSPEC matching."),
		new NamedFunction(0x56101L, "isatty",
			"[CRT/DOS] Device check via INT 21h AH=44h AL=0 (IOCTL get-device-info); returns true if the "
			+ "handle is a character device (DX bit 7)."),
		new NamedFunction(0x551e1L, "close_fd",
			"[CRT/DOS] close(fd): validates fd against the handle-table cap (0x7563c), INT 21h AH=3Eh, then "
			+ "clears the table slot (store_indexed_dword_flagged). errno=4 (EBADF) on a bad/closed fd."),
		new NamedFunction(0x560ecL, "spawn_vp_default_env",
			"[CRT] spawnvp-style: spawn_search_path (0x57774, PATH search) with the default environ. The "
			+ "public PATH-searching spawn entry."),

		// ---- program startup / CRT init (entry chain: watcom_runtime_startup 0x43854 ->
		//      watcom_call_program_entry 0x4f5d6 -> main 0x15110 -> roth_game_startup 0x10010) ----
		new NamedFunction(0x15110L, "main",
			"[HIGH] C main(argc,argv,envp). Installs the exception handler (install_exception_handler 8, "
			+ "0x10345), grabs the big game heap (alloc_largest_heap_block -> g_game_heap_handle), and "
			+ "aborts with 'Not enough memory to run ROTH' if <3MB (warns if <4MB). Then "
			+ "install_critical_error_handler / roth_game_startup / restore_critical_error_handler, and "
			+ "frees the heap. Called by watcom_call_program_entry (0x4f5d6)."),
		new NamedFunction(0x416d3L, "install_exception_handler",
			"[CRT, MED] Installs a CPU exception/signal handler via DPMI INT 31h (AX=0202/0203). "
			+ "main calls it as (8, handler 0x10345). Saves SS/DS/stack context into 0x90cf0.. for the "
			+ "fault frame."),
		new NamedFunction(0x436e8L, "install_critical_error_handler",
			"[CRT/DOS, MED-HIGH] Hooks the DOS critical-error vector INT 24h (IVT entry at linear 0x90): "
			+ "allocates a block, copies a 10-dword real-mode stub from 0x60000, installs it via a DPMI "
			+ "real-mode callback, saving the old vector to g_saved_int24_vector (0x911d0). Suppresses the "
			+ "'Abort, Retry, Fail?' prompt during the game."),
		new NamedFunction(0x43775L, "restore_critical_error_handler",
			"[CRT/DOS, MED-HIGH] Undo of install_critical_error_handler: restores INT 24h from "
			+ "g_saved_int24_vector (0x911d0), frees the DPMI real-mode callback (INT 31h AX=0205) and the "
			+ "stub block. Called at game exit by main."),
		new NamedFunction(0x35ff9L, "alloc_largest_heap_block",
			"[MED] Allocates the main game memory pool (main passes 0x25800); the actual usable size is "
			+ "read back via block_payload_size and checked against the 3MB/4MB minimums. Root of the "
			+ "game's block allocator."),
		new NamedFunction(0x35bfaL, "free_heap_block",
			"[MED] Frees a block from the game block allocator (main frees g_game_heap_handle at exit)."),

		// ---- game block allocator: DPMI-backed OS blocks in a doubly-linked list (head g_block_list_head
		//      0x8a270), 0x14-byte header {prev,next,selector,size,type} before the user ptr ----
		new NamedFunction(0x35a12L, "alloc_dos_block",
			"[MED-HIGH] Allocate a DOS conventional-memory block (DPMI AX=0100h), wrap it in the 0x14-byte "
			+ "header (type=2, selector in +8), link at g_block_list_head (0x8a270), return user ptr "
			+ "(base+0x14). Used when the game needs <1MB memory addressable by real-mode interop."),
		new NamedFunction(0x35a74L, "alloc_dpmi_block",
			"[MED-HIGH] Allocate an extended-memory block (DPMI AX=0501h), same 0x14-byte header (type=1), "
			+ "link at g_block_list_head, return base+0x14. The general game allocation (vs alloc_dos_block)."),
		new NamedFunction(0x35b0aL, "free_os_block",
			"[MED-HIGH] Free a block from alloc_dos_block/alloc_dpmi_block: unlink from g_block_list_head, "
			+ "then DPMI free — AX=0502h (extended) or AX=0101h (DOS mem) per the type bit at header-4."),
		new NamedFunction(0x35af2L, "free_os_block_guarded",
			"[MED] Same as free_os_block but only frees when the guard DAT_0008a274 is 0 (defer-free flag)."),
		// game 'Pool' allocator: a handle-based sub-heap inside an OS block. Descriptor has the magic
		// 'Pool' (0x506f6f6c) @+0, {largest-free @+4, free-bytes @+8, header-size @+0xc, round-robin
		// cursor @+0x10, full-flag @+0x12, used-count @+0x14, handle table @+0x18, chunk region @+0xc..}.
		// Each chunk carries a back-ref to its handle (chunk[-6]) so blocks stay relocatable.
		new NamedFunction(0x35b68L, "pool_init",
			"[MED-HIGH] Pool constructor over a memory block: writes the 'Pool' magic (0x506f6f6c) at +0, "
			+ "sets {free=size @+4/+8, header-size @+0xc, cursor=0 @+0x10, full=0 @+0x12, used-count=1 "
			+ "@+0x14}, and zeroes the handle table (@+0x18, (hdrSize-0x18)/4 entries). Returns the pool."),
		new NamedFunction(0x36088L, "pool_create",
			"[MED] pool_create(block, nHandles): computes header size = nHandles*4 + 0x18 and calls "
			+ "pool_init. Thin front for pool_init."),
		new NamedFunction(0x30114L, "init_das_cache_heap",
			"[MED-HIGH] Builds the DAS sprite/animation cache pool (called once from roth_main_sequence): "
			+ "game_heap_alloc() a big OS block, pool_create it sized (block - 0x32000), store to "
			+ "g_das_cache_heap_handle (0x85c3c). That pool is the sole Pool instance — the DAS cache."),

		// ---- DAS resource cache loaders (read a FAT entry [size:u32][data] into g_das_cache_heap_handle).
		//      The DAS *file* loader + 68-byte header are already named: load_map_das_file 0x2f1b4 /
		//      g_das_header (DASP magic + v5) / read_das_palette. Resource records index via offset<<3. ----
		new NamedFunction(0x16087L, "load_dbase200_sprite_cached",
			"[MED-HIGH] Loads a dbase200 RLE sprite (e.g. an inventory item icon) into the single-slot cache "
			+ "g_cached_dbase200_sprite_handle (0x7f574), freeing the previous. Opens dbase200.dat "
			+ "(g_dbase200_filename 0x81f06), seeks the entry (index<<3, FAT-style 8-byte slots), reads "
			+ "[size:u32] then the frame data, then repair_das_rle_frame_count (the sprite frames are "
			+ "DAS-format data packed in the dbase200 container, not a .DAS file). Used by the per-frame "
			+ "UI/sprite path (0x1729c)."),
		new NamedFunction(0x1869bL, "load_das_cache_resource",
			"[MED-HIGH] Generic DAS-cache loader: load_das_cache_resource(index, fileHandle) — seek the FAT "
			+ "entry (index<<3), read [size:u32], pool_alloc_handle a chunk, read the data with CD-swap "
			+ "retry (0x2632a). Returns the pool handle (or 0). Multiple callers (0x1818d/0x1816a/0x20e98)."),
		new NamedFunction(0x196b9L, "load_dbase300_resource_at_offset",
			"[MED] Loads a map-DAS resource at a byte offset: opens g_dbase300_filename (0x81f86), seeks "
			+ "(offset + 0x14), reads a size then the data into the cache with CD-retry. Returns the handle. "
			+ "ALSO the INSPECT-WINDOW MODAL LOOP (opened by Space in update_inventory_screen): sets "
			+ "g_inspect_popup_active (0x7fec0)=1, loads the item's close-up image, lays out the popup via "
			+ "render_inspect_popup_window (0x18e9e), then runs its OWN blocking input loop "
			+ "(update_inspect_popup_choices 0x18ada + input_ring_dequeue 0x1299a) until dismissed. "
			+ "Popup KEYMAP (scancode): Esc(0x01)/'I'(0x17)/Space(0x39) = close / interrupt voice "
			+ "(try_interrupt_dialogue_voice); Enter(0x1c) = advance monologue / ACCEPT the highlighted "
			+ "choice (choice_accept_selected 0x1fbba); Up(0x48) = choice_select_prev (0x1fb1e); "
			+ "Down(0x50) = choice_select_next (0x1fc16); Left/Right(0x4b/0x4d) = scroll the close-up "
			+ "image; 'B'(0x30) = screenshot. The choice nav/accept is gated on choices OPEN (g_choice_interaction_mode "
			+ "0x83acd==1). FINDING (2026-06-17): there is NO keyboard scancode that OPENS the choices "
			+ "(the info-button effect) - that is MOUSE-ONLY: handle_cursor_click -> "
			+ "hit_test_dialogue_ui_action returns action 4 (info button, gated on g_inspect_info_available "
			+ "0x81188) -> dispatch action 4 records the click pos and opens the topics. So keyboard can "
			+ "navigate/pick topics once open, but the info button itself needs a click."),
		new NamedFunction(0x18e9eL, "render_inspect_popup_window",
			"[inventory inspect close-up window layout/render; TRACE-confirmed, called by load_dbase300_resource_at_offset] Lays out the examine popup: a slot table at g_inspect_popup_layout (0x80b42, 8-byte entries, count 6 — the close-up sprite area + text-panel slots, sizes 0x1c/0x14), measures the item-name text width (0x1f91f) to size the window (>= 0x38+0x28), positions it at 0x810d4/0x810d8, and draws the close-up image + name. Companion update_inspect_popup_choices handles the choice menu."),
		new NamedFunction(0x18adaL, "update_inspect_popup_choices",
			"[inventory inspect popup: choice-menu + open/close animation; called by load_dbase300_resource_at_offset] When the inspect dialogue has topics (g_choice_interaction_mode 0x83acd==2) builds the choice list via build_available_choice_menu (0x1f950); steps the window slide animation (counter 0x80b34, via 0x1c512) and renders the dialogue text (render_text_ui path)."),
		// ---- game-file parsers (file -> loader inventory) ----
		new NamedFunction(0x10458L, "load_roth_res",
			"[MED-HIGH] Parses the ROTH.RES master config (the @roth.res response file, or the arg in "
			+ "g_response_file_arg 0x72538). Reads keyword settings via parse_config_keywords (0x41c5c) "
			+ "against the template at 0x1049b ('VERSION A HIRES F BLUR F VESA F ...') plus the map/DAS "
			+ "mappings. Called from roth_game_startup. Tokenizer FUN_00010920."),
		new NamedFunction(0x1dfc2L, "init_game_databases",
			"[MED-HIGH] Loads the DBASE data archives at startup: build_game_path the DAS filenames "
			+ "(g_dbase200_filename, g_dbase300_filename), open_dialogue_script (dbase400.dat), then "
			+ "opens dbase100.dat, game_heap_alloc's it into g_dbase100_base, and resolves its section "
			+ "offsets (header +0x14 -> g_dbase100_inventory_table, +0x1c -> 0x81e24, +0xc -> count). "
			+ "DBASE100 = inventory/template DB."),
		new NamedFunction(0x41c5cL, "parse_config_keywords",
			"[MED] Token parser used by load_roth_res / read_roth_ini: matches input tokens against a "
			+ "keyword template string (keyword + type letter, e.g. 'HIRES F' = flag, 'VERSION A' = ascii) "
			+ "and fills a result struct. The sscanf-like config reader. Per-line: parse_config_line (0x41d44) -> "
			+ "parse_config_typed_value (0x41dec)."),
		new NamedFunction(0x41d44L, "parse_config_line",
			"[config — disasm-verified; called by parse_config_keywords 0x41c5c] Tokenizes one CONFIG.INI line: skips "
			+ "whitespace (<0x21) and ';' comments, isolates the keyword, then dispatches the value to "
			+ "parse_config_typed_value by the template's type letter. (Format like \"SOUNDVOLUME=S;VIEWSIZE=S;HIRES=F\".)"),
		new NamedFunction(0x41decL, "parse_config_typed_value",
			"[config — disasm-verified] Parses one CONFIG.INI value into param_2 per its TYPE LETTER (param_1): "
			+ "'C'=byte, 'S'=short(word), default/'L'=long(dword) — all via parse_config_number; 'A'=ascii string, "
			+ "'P'=path string (appends a trailing '\\\\' if missing); 'F'=flag (sets 0xffffffff). String parsing handles "
			+ "double-quotes and {...} brace-quoted values, collapsing whitespace and skipping ';' comments inside."),
		new NamedFunction(0x41ed1L, "parse_config_number",
			"[config — disasm-verified; leaf of parse_config_typed_value] Parses an integer from a config value string: "
			+ "if it starts \"0x\"/\"0X\" (char[1]&0xdf=='X') reads hex digits, else reads decimal digits; stops at "
			+ "whitespace/';'. Returns the value."),
		new NamedFunction(0x1602eL, "load_icons_all",
			"[MED] Loads ICONS.ALL (build_game_path + FUN_000143b0) as the relocatable resource blob into "
			+ "g_reloc_base (DAT_7f56c) — the base that resolve_reloc_ptr (0x226c6) indexes. So ICONS.ALL "
			+ "is the reloc-table data."),
		new NamedFunction(0x16164L, "load_backdrop_raw",
			"[MED] Loads BACKDROP.RAW (the menu/title backdrop, build_game_path 0x763b0) into a "
			+ "framebuffer-sized cache block and blits it (uses g_framebuffer_ptr/g_screen_pitch/height). "
			+ "Distinct from the .RAW map files."),
		new NamedFunction(0x267f4L, "read_roth_ini",
			"[MED] Reads ROTH.INI in-game settings: parse_config_keywords against the template "
			+ "'SPEECHSUB A SPEECHAUD A MOVIESUB ...' (subtitle/speech/movie options) -> the settings "
			+ "globals (0x71b34/0x71b40/0x71b4c/...)."),
		new NamedFunction(0x266ecL, "write_roth_ini",
			"[MED] Writes ROTH.INI: selects ON/OFF-style strings from the current settings flags "
			+ "(0x83e9c/0x83e98/g_voice_decode_suspended ...) and serializes them back to the file."),
		new NamedFunction(0x1384dL, "rescale_das_frame",
			"[MED] Post-load fixup of a cached DAS sprite frame: if the frame's scale tag (param[0]) differs "
			+ "from g_das_render_scale (0x85404, ref 0x9b=155), walks the sub-image frames (header flag "
			+ "&0x10 = compressed/sub-image) and rescales each dimension by (dim * scale)/0x9b for the "
			+ "current render resolution. Called by load_dbase200_sprite_cached after the read."),
		new NamedFunction(0x360f9L, "pool_alloc_handle",
			"[MED] Allocate a relocatable block from a Pool: take a free handle slot (round-robin from "
			+ "cursor @+0x10 over the handle table @+0x18), carve a chunk (pool_carve_chunk 0x35c1d), store "
			+ "the chunk ptr in the slot + the slot cursor in chunk[-6]. Returns the handle (slot ptr). "
			+ "The general-purpose relocatable-object Pool allocator (~26 call sites span the DAS cache, savegame, "
			+ "GDV cutscenes, effect pools, HUD, framebuffer/backdrop). All sites pass g_das_cache_heap_handle "
			+ "(0x85c3c) because it is the SOLE Pool instance — NOT because they all load DAS resources."),
		new NamedFunction(0x3618cL, "pool_alloc_handle_sized",
			"[MED] Variant of pool_alloc_handle that bounds the request by the pool's largest-free (+4)."),
		new NamedFunction(0x360b3L, "pool_free_handle",
			"[MED-HIGH] Free a relocatable block via its handle (pool, &handle): restore the slot cursor "
			+ "from chunk[-6] to +0x10, release the chunk (pool_release_chunk 0x35d96), clear the handle. "
			+ "34 callers — THE object free."),
		new NamedFunction(0x35f04L, "get_pool_descriptor",
			"[MED-HIGH] Resolve/validate a Pool descriptor: checks the 'Pool' magic (0x506f6f6c) at +0; "
			+ "returns the pool (or the arg unchanged when pool-checking g_pool_check_enabled 0x8a278 is off)."),
		new NamedFunction(0x35c1dL, "pool_carve_chunk",
			"[MED] First-fit carve within a Pool: scan the chunk region (@+0xc) for a free chunk >= "
			+ "(size+3 &~3)+0x10, split off the remainder (>=0x18) as a new free chunk, mark used, update "
			+ "free-bytes (+8) and used-count (+0x14). The pool's inner malloc."),
		new NamedFunction(0x35cb4L, "pool_find_free_chunk",
			"[MED] Scan a Pool's chunk list for a free chunk large enough for `size` (last-fit walk over"
			+ "the +0x14 used-count chunks). Returns the chunk or 0."),
		new NamedFunction(0x35d80L, "pool_free_chunk",
			"[MED] Free a Pool chunk and coalesce with adjacent free neighbours (forward + backward), "
			+ "returning its bytes to free (+8) and decrementing the used-count (+0x14)."),
		new NamedFunction(0x35d96L, "pool_release_chunk",
			"[MED] pool_free_handle's worker: clears the chunk's in-use flags and coalesces it back into "
			+ "the Pool free space. Sibling of pool_free_chunk."),
		new NamedFunction(0x361f7L, "pool_coalesce_free",
			"[MED] Walk a whole Pool merging all adjacent free chunks (compaction of the free list); "
			+ "recomputes the free totals."),

		// ---- DOS-extender / DPMI service wrappers (INT 31h AX=function#). One canonical wrapper per
		//      service; the compiler emitted several byte-identical duplicates left as FUN_xxxx. ----
		new NamedFunction(0x40a34L, "dpmi_alloc_dos_memory",
			"[DPMI] INT 31h AX=0100h — allocate a DOS (<1MB) memory block; returns the real-mode segment "
			+ "and the protected-mode selector. Used to get conventional memory for real-mode interop."),
		new NamedFunction(0x40a50L, "dpmi_free_dos_memory",
			"[DPMI] INT 31h AX=0101h — free a DOS memory block by its selector."),
		new NamedFunction(0x40adfL, "dpmi_get_segment_base",
			"[DPMI] INT 31h AX=0006h — get the 32-bit linear base address of an LDT selector (CX:DX)."),
		new NamedFunction(0x412edL, "refresh_das_block_selector_base",
			"[DPMI] INT 31h AX=0007h — set the linear base address of an LDT selector."),
		new NamedFunction(0x2fdfcL, "dpmi_set_segment_limit",
			"[DPMI] INT 31h AX=0008h — set the limit of an LDT selector (used to size far-data windows)."),
		new NamedFunction(0x41191L, "setup_das_block_selector",
			"[DPMI] INT 31h AX=0000h — allocate LDT descriptor(s); returns the base selector."),
		new NamedFunction(0x40acdL, "dpmi_free_descriptor",
			"[DPMI] INT 31h AX=0001h — free an LDT descriptor/selector."),
		new NamedFunction(0x4fb95L, "dpmi_lock_linear_region",
			"[DPMI] INT 31h AX=0600h — lock a linear address range (page it in / pin for DMA)."),
		new NamedFunction(0x4fbd2L, "dpmi_unlock_linear_region",
			"[DPMI] INT 31h AX=0601h — unlock a previously locked linear range."),
		new NamedFunction(0x28387L, "dpmi_map_physical_address",
			"[DPMI] INT 31h AX=0800h — map a physical address region into linear space (e.g. VGA LFB). "
			+ "Sibling helper at 0x28350."),
		new NamedFunction(0x41742L, "dpmi_get_exception_handler",
			"[DPMI] INT 31h AX=0202h — get the current protected-mode exception handler vector."),
		new NamedFunction(0x417a1L, "dpmi_set_exception_handler",
			"[DPMI] INT 31h AX=0203h — set a protected-mode exception handler vector."),
		new NamedFunction(0x41674L, "restore_exception_handler_and_report",
			"[startup/shutdown — disasm-verified; called by roth_game_startup] Calls dpmi_set_exception_handler, then if "
			+ "the saved-handler flag 0x90d1c is set, restores the original exception vector (INT31h AX=0203h with "
			+ "0x90cec/0x90d1e) and — when param_1 bit0 is set and an error is pending (0x90ce4) — formats a message "
			+ "(vsprintf_engine -> 0x90d44) and prints it via INT21h AH=09h. The exception-handler restore + fatal-error "
			+ "reporter. [hedged: install-vs-restore.]"),
		new NamedFunction(0x27eecL, "dpmi_simulate_real_int",
			"[DPMI] INT 31h AX=0300h — simulate a real-mode interrupt (call a real-mode ISR with a "
			+ "register block; used for BIOS/DOS services like VGA/mouse from protected mode)."),

		// ---- recomp verified-lift batch (16-19): leaf setters/getters + small helpers ----
		new NamedFunction(0x124ddL, "reset_movement_velocity_queues",
			"[recomp lift] No args: zeroes the movement velocity ring cursors/arrays — word[0x90b42]=0, "
			+ "word[0x90abe]=0, dword[0x90a84]=0, dword[0x90a80]=0 (the queues player_movement_tick uses)."),
		new NamedFunction(0x1a37bL, "compute_viewport_half_extents",
			"[recomp lift] No args: sets the shared UI panel anchor — g_ui_panel_anchor_y (0x80b28) = "
			+ "(uint)g_screen_height(0x8549c) >> 1; g_ui_panel_anchor_x (0x80b24) = ((uint)g_screen_pitch"
			+ "(0x85498) - 0x130[=304]) >> 1, i.e. the left margin that CENTERS a 304px-wide panel. "
			+ "draw_panel_slot_tile + the inventory/dialogue layout add g_ui_slot_layout_table offsets to "
			+ "these. Called when (re)positioning a non-modal panel."),
		new NamedFunction(0x561f9L, "store_indexed_dword_flagged",
			"[recomp lift] EAX=index, EDX=value. (*(void**)0x75690)[EAX] = EDX | 0x4000 (forces bit 14). Void."),
		new NamedFunction(0x2acfcL, "set_909a4_save_old_to_852f2",
			"[recomp lift] AX=new. saves old word[0x909a4] low16 to word[0x852f2], then [0x909a4] = "
			+ "(int32)(int16)AX. Inverse/sibling of signext_852f2_to_909a4 (0x2ad14)."),
		new NamedFunction(0x558ecL, "string_copy_bytewise",
			"[recomp lift] strcpy (byte-by-byte incl. NUL); EAX=dst, EDX=src. Separate compiler-emitted "
			+ "copy from the 2-byte-unrolled string_copy (0x54ddf)."),
		new NamedFunction(0x1426fL, "copy_nonzero_bytes",
			"[recomp lift] EAX=dst, EBX=count, EDX=src. Copies `count` bytes but SKIPS zero source bytes "
			+ "(leaves dst) = transparent row blit. Indices count-1..0; no-op when count<=1."),
		new NamedFunction(0x50e1dL, "noop_passthrough_50e1d",
			"[recomp lift] No observable effect; EAX passes through, all GP regs preserved. Stub/placeholder "
			+ "(like identity_passthrough 0x51995)."),
		new NamedFunction(0x1e76eL, "set_voice_sample_rate",
			"[recomp lift; refined] EAX=value -> g_voice_sample_rate (0x82041). The setter for the voice "
			+ "playback rate read by decode_voice_block / programmed into the SOS descriptor by prime_voice_clip."),
		new NamedFunction(0x20597L, "set_71388",
			"[recomp lift] EAX=value -> dword[0x71388]. Single-global setter."),
		new NamedFunction(0x26b60L, "set_71d84",
			"[recomp lift] EAX=value -> dword[0x71d84]. Single-global setter."),
		new NamedFunction(0x283a7L, "set_8495c",
			"[recomp lift] EAX=value -> dword[0x8495c]. Single-global setter (near the SOS/voice globals)."),
		new NamedFunction(0x58503L, "get_72540",
			"[recomp lift] Returns dword global [0x72540]."),
		new NamedFunction(0x1c5c8L, "clear_819c0_bits",
			"[recomp lift] byte[0x819c0] &= 0xfa (clears bits 0 and 2). No args."),
		new NamedFunction(0x108d4L, "set_90bf8_ffff",
			"[recomp lift] word[0x90bf8] = 0xffff. No args (reset/invalidate of a 16-bit field)."),
		new NamedFunction(0x283a0L, "xchg_849a4",
			"[recomp lift] EAX in/out: atomic xchg — returns old dword[0x849a4], stores EAX into it."),
		new NamedFunction(0x4ee93L, "emit_biased_byte",
			"[recomp lift] DL=value, EDI=dest. *EDI = DL + 0x80; EDI++ (returned); EDX=0. Stream-emit helper "
			+ "(writes a +0x80-biased byte, advances cursor) near the literal/skip delta codec (0x4eeXX)."),
		new NamedFunction(0x15b50L, "set_default_mouse_button_swap",
			"[recomp lift] g_mouse_button_swap (0x7feb8) = 1. Called from game_play_loop init -> the DEFAULT mouse mode is swapped (RIGHT drives g_cursor_primary_action_flag). Toggleable in settings (0x17fd2)."),
		new NamedFunction(0x35fe4L, "block_size_field8",
			"[recomp lift] EAX=ptr -> EAX ? *(u32*)(ptr+8) - 0x10 : 0. Sibling of block_payload_size "
			+ "(0x35fd9, reads +4); shares its null-case ret."),
		new NamedFunction(0x2e35fL, "halve_eax_if_90bd4",
			"[recomp lift] EAX in/out: if (byte[0x90bd4] & 1) EAX = (int32)EAX >> 1. Hi-res/scale conditional."),
		new NamedFunction(0x583d1L, "nibble_to_hex_char",
			"[recomp lift] EAX in/out: EAX += 0x30; if ((int32)EAX > 0x39) EAX += 0x27. Nibble 0-15 -> "
			+ "lowercase ASCII hex char ('0'-'9'/'a'-'f')."),
		new NamedFunction(0x115ddL, "load_dword_to_76878_7687c",
			"[recomp lift] EAX=ptr. v = *(u32*)EAX; dword[0x76878]=v; dword[0x7687c]=v; returns v "
			+ "(mirrors a dword into two adjacent globals)."),
		new NamedFunction(0x2ab21L, "copy_word_90bcc_to_8532a",
			"[recomp lift] word[0x8532a] = word[0x90bcc]. No args (mirrors a 16-bit global)."),

		// ---- map-geometry record helpers (recomp verified lifts; first selector/far-data lifts) ----
		new NamedFunction(0x2ec1aL, "mark_geom_sentinel_entries",
			"[MED] (recomp VERIFIED lift; proposed mark_geom_entries_ffff). ES = the geometry selector "
			+ "at 0x490be8. ebx=word[seg+6]; count=word[seg+(u16)(ebx-2)]; for `count` records of stride "
			+ "0xc from seg+ebx: if word[+8]==0xffff set bit 0x20 in byte[+0xa]. Flags geometry entries "
			+ "whose +8 field is the 0xffff sentinel. Called from the level-load / reset paths "
			+ "(roth_main_sequence 0x100f6, 0x1096f, 0x1107e)."),
		new NamedFunction(0x293a3L, "clear_es_geom_record_field4",
			"[LOW-MED] (recomp VERIFIED lift; proposed clear_es_record_field4). ES preset by the caller "
			+ "(case-2 trampoline; loads no segreg itself). off=(u16)es:[4]; count=(u16)es:[off-2]; for "
			+ "`count` records of stride 0x1a from off, clear the u16 at es:[off+4]. Geometry-record reset "
			+ "leaf called from 0x284df/0x2885d/0x28a79. +4 field semantics unknown (name = what it clears)."),

		// ---- AUDIO / speech-voice streaming subsystem (see docs/reference/ROTH_audio_notes.md) ----
		new NamedFunction(0x30051L, "alloc_audio_stream_buffers",
			"[audio init — disasm-verified; called by load_sound_effect_bank 0x26b66] Lazily allocates the voice/speech "
			+ "streaming buffers (only if g_audio_decode_buffer_a 0x8548c is unallocated): two 32KB decode double-buffers "
			+ "g_audio_decode_buffer_a/_b (0x8548c/0x85490 -> assigned to the SOS streamer in prime_voice_clip) + an 8KB "
			+ "silence primer g_audio_silence_buffer (0x85494, filled with 0x80 = 8-bit unsigned PCM silence, or 0x00 when "
			+ "g_audio_signed_samples 0x7f478 is set). Then, if g_resource_pool is unallocated, sizes the main DAS resource "
			+ "pool from free RAM (query_free_memory - 0x32000 -> 0x64000/0xc8000/0x190000 = 400KB/800KB/1.6MB; "
			+ "g_resource_pool_small_flag 0x89f41) and inits it via init_resource_chunk_pool (0x35b53)."),
		new NamedFunction(0x30162L, "free_audio_stream_buffers",
			"[audio teardown — disasm-verified; called by free_resource_buffers 0x26c8c] Frees the three voice-stream "
			+ "buffers g_audio_decode_buffer_a/_b/g_audio_silence_buffer (0x8548c/0x85490/0x85494) and g_resource_pool "
			+ "(zeroing each handle first). Exact inverse of alloc_audio_stream_buffers (0x30051)."),
		new NamedFunction(0x30149L, "release_das_and_geometry_buffers",
			"[shutdown — disasm-verified; called by roth_main_sequence] Frees the DAS cache heap "
			+ "(g_das_cache_heap_handle, atomically cleared first) then calls free_scene_geometry_buffers (0x2a93c)."),
		new NamedFunction(0x2a8e9L, "release_map_geometry_selector",
			"[geometry teardown — disasm-verified] If the map-geometry DPMI selector g_map_geometry_selector (0x85294) "
			+ "is allocated, releases it (via 0x4cXXX) and clears it. Called by free_geometry_buffer_and_selector."),
		new NamedFunction(0x40bc7L, "free_geometry_buffer_and_selector",
			"[geometry teardown — disasm-verified; called by roth_main_sequence] Frees the passed geometry buffer (if "
			+ "non-null, via game_free_if_not_null) and releases the map-geometry selector via "
			+ "release_map_geometry_selector (0x2a8e9)."),
		new NamedFunction(0x2a93cL, "free_scene_geometry_buffers",
			"[shutdown — disasm-verified] Frees the map-geometry DPMI selector (DAT_85294, via free_dpmi_selector) and "
			+ "the door/scene worklist g_door_worklist. Called only from release_das_and_geometry_buffers (0x30149)."),
		new NamedFunction(0x1e54dL, "prime_voice_clip",
			"[HIGH] start_voice_stream(record_offset). Guards on g_audio_decode_buffer_b (0x85490)!=0 && "
			+ "g_voice_stream_state(0x8200c)!=1. Opens dbase500.dat -> g_voice_file_handle (0x82010), "
			+ "seeks record_offset<<3, reads the 0x2c-byte clip header, decodes the first two blocks "
			+ "into the double buffers (decode_voice_block 0x1e3df), installs the SOS completion "
			+ "callback (install_voice_sos_callback 0x27c0e with offset=voice_stream_sos_callback "
			+ "0x1e487, sel=cs), submits the first DMA buffer, sets g_voice_stream_state=1. Returns 1 "
			+ "on success / 0 if no clip data. Driven per dialogue line by read_next_dialogue_line."),
		new NamedFunction(0x1e487L, "voice_stream_sos_callback",
			"[HIGH] The far user-callback the virtual HMI/SOS driver fires (installed at "
			+ "g_voice_sos_callback (0x84900 off / 0x84904 sel); fired via `call ptr[0x84900]` in the "
			+ "trampoline 0x27501). Arg [ebp+0x14] = message type: 0 = a queued buffer drained -> "
			+ "re-queue the pre-decoded alternate half (SOS queue 0x15a92) and flag "
			+ "g_voice_refill_pending(0x820b9)=1 so the per-frame pump decodes the next disk block; "
			+ "2 = end-of-stream -> g_voice_stream_state(0x8200c)=2. THE host must deliver these "
			+ "messages or chunk N+1 never advances."),
		new NamedFunction(0x1e9b5L, "voice_stream_pump",
			"[HIGH] Per-frame voice service (called from both main-loop modes at 0x17c1b & 0x18b01). "
			+ "If a buffer was consumed (g_voice_refill_pending 0x820b9!=0) and bytes remain "
			+ "(g_voice_bytes_remaining 0x82018), decode_voice_block (0x1e3df) the next <=0x8000 block "
			+ "from dbase500.dat into the spare half, then swap_voice_double_buffers (0x1e3b0). Detects "
			+ "clip end (g_voice_stream_state==2 -> reset 0) and clears g_dialogue_busy_flag (0x83aea) "
			+ "when idle. The disk half of the double-buffer refill; pairs with voice_stream_sos_callback."),
		new NamedFunction(0x1e8ccL, "read_next_dialogue_line",
			"[HIGH] read_next_dialogue_line(buf=eax, maxlen=edx, filepos=ebx, play_voice=ecx). Seeks "
			+ "filepos in the dialogue script dbase400.dat (g_dialogue_script_handle 0x824c5), reads the "
			+ "8-byte record {voice_offset>>3:u32, text_len:u16, color:u8}, copies text_len bytes of "
			+ "subtitle into buf and sets g_timed_message_color (0x82040 — the shared UI text-color slot; dialogue subtitles reuse the timed-message color, default ' '). If play_voice "
			+ "and voice_offset!=0, calls prime_voice_clip(voice_offset) to start that line's clip. "
			+ "Called by the DBASE dialogue interpreter (0x1a673/0x1b170/0x1b2f6/0x1b30b/0x1c12c/0x1c13d)."),
		new NamedFunction(0x1e874L, "open_dialogue_script",
			"[MED] Lazily opens dbase400.dat (the dialogue text+voice-directory archive) into "
			+ "g_dialogue_script_handle (0x824c5) if not already open."),
		new NamedFunction(0x1e8aeL, "close_dialogue_script",
			"[MED] Closes g_dialogue_script_handle (0x824c5 / dbase400.dat) and zeroes it."),
		new NamedFunction(0x1e3b0L, "swap_voice_double_buffers",
			"[MED] Ping-pongs the streaming double buffer: swaps ptr pair 0x8201c<->0x82020 and "
			+ "pending-size pair 0x82024<->0x82028. Called after each disk refill in voice_stream_pump."),
		new NamedFunction(0x1e3dfL, "decode_voice_block",
			"[MED] decode_voice_block(dest, maxbytes) -> srcBytesRead. Gated on g_voice_decode_suspended "
			+ "(0x83e94)==0 && g_voice_sample_rate (0x82041)>=0x80 (else returns 0 -> silence/EOF). If "
			+ "g_voice_is_dpcm (0x82034): reads maxbytes/2 raw bytes into the buffer's UPPER half, then "
			+ "decode_dpcm_block (0x4e4cd) expands them in place to maxbytes of s16 PCM (predictor carried "
			+ "in g_voice_dpcm_predictor 0x82038). Else: raw read of up to maxbytes straight into dest."),
		new NamedFunction(0x4e4cdL, "decode_dpcm_block",
			"[MED] decode_dpcm_block(predictor, dest_s16*, count) — the voice codec. For each of `count` "
			+ "source bytes (src ptr in EBX): predictor += g_dpcm_step_table[byte]; *dest++ = (s16)predictor. "
			+ "Returns updated predictor. 8-bit delta-PCM -> 16-bit signed PCM; src is the upper half of the "
			+ "same buffer (in-place expand, read ptr stays ahead of write ptr)."),
		new NamedFunction(0x4bb62L, "build_dpcm_step_table",
			"[MED] One-time builder of g_dpcm_step_table (0x918a4, int32[256]). table[0]=0; parabolic "
			+ "generator (u=0x40,d=0x2d; acc+=u>>5; u+=d; d+=2) fills pairs table[2k+1]=+acc, table[2k+2]=-acc "
			+ "up to table[255]. 'already built' is self-guarded by reusing table[50] (0x9196c): nonzero once "
			+ "built. Called from prime_voice_clip when the clip header format tag == 0x2a."),
		new NamedFunction(0x27c0eL, "install_voice_sos_callback",
			"[MED] Copies a far callback descriptor (off @+0x1c, sel @+0x20) into g_voice_sos_callback "
			+ "(0x84900 off / 0x84904 sel), tags the SOS event class (+0x18 |= 0xed00), then registers "
			+ "the cs:0x27501 trampoline via SOS install 0x15a4a. Called by prime_voice_clip."),
		new NamedFunction(0x27501L, "sos_user_callback_trampoline",
			"[MED] Far SOS event trampoline (retf). On a driver event it queries the SOS event class "
			+ "(0x15a79); if class==0xedXX it forwards to the registered user callback "
			+ "`call ptr[g_voice_sos_callback 0x84900]` with (esi,ebx=type,ecx). Bridges the host SOS "
			+ "buffer-complete path (recomp 0x4e394) to voice_stream_sos_callback."),
		new NamedFunction(0x1f6ccL, "dialogue_voice_stop_all",
			"[MED] Tears down an active dialogue line: zeroes the action queue count (0x81e3e), "
			+ "force-ends the voice (dialogue_voice_force_end 0x1f671), clears g_dialogue_busy_flag "
			+ "(0x83aea) and the subtitle word state (0x83115/0x83125)."),
		new NamedFunction(0x1f671L, "dialogue_voice_force_end",
			"[MED] If a voice is streaming (g_voice_stream_state==1) issues the SOS stop (0x15a65 on "
			+ "g_voice_stop_handle 0x82014) and forces g_voice_stream_state=2; also advances the "
			+ "subtitle word-highlight position (0x83125 vs 0x6ffff sentinel via 0x1f71d)."),
	};

	private final NamedAddress[] engineGlobals = new NamedAddress[] {
		// --- Globals formalized from comment cross-references (consistency audit 2026-06-21) ---
		// These were named de-facto in comments (so decompiles showed bare [0xVA]); now defined.
		// Evidence = the referencing functions cited per entry. Addresses confirmed undefined in
		// both this script and ROTHApplyDasTypes.java.
		new NamedAddress(0x7f56cL, "g_reloc_base",
			"[DAS reloc] Base used to relocate baked-in DAS image pointers; read by blit_reloc_das_image (0x18e68), resolve_reloc_record_fields (0x1c06b), and the menu/cursor blit path."),
		new NamedAddress(0x90bccL, "g_frame_tick_counter",
			"[timing] Master per-frame / PIT tick counter; copied each frame into g_anim_clock (0x8532a) and read as the frame clock by update_frame_time_scale / wait_one_timer_tick."),
		new NamedAddress(0x8a120L, "g_damage_emitter_ptr",
			"[world/effects] Pointer to the active damage-emitter record: set by register_damage_emitter (0x344c9), consumed by damage_player_from_emitter (0x34579), cleared in free_effect_pools, walked by tick_world_effects."),
		new NamedAddress(0x85cd8L, "g_view_w",
			"[render] Render viewport WIDTH; part of the {w,h,x,y} view rect (0x85cd8/0x85cdc/0x85ce0/0x85ce4) recomputed by recompute_view_region_offsets (0x10e4e) / configure_render_viewport."),
		new NamedAddress(0x85cdcL, "g_view_h",
			"[render] Render viewport HEIGHT (see g_view_w 0x85cd8)."),
		new NamedAddress(0x85ce0L, "g_view_x",
			"[render] Render viewport X origin (see g_view_w 0x85cd8)."),
		new NamedAddress(0x85ce4L, "g_view_y",
			"[render] Render viewport Y origin (see g_view_w 0x85cd8)."),
		new NamedAddress(0x85270L, "g_view_params_block",
			"[render] View camera parameters block populated by apply_view_camera_params (0x2a952)."),
		new NamedAddress(0x8526cL, "g_view_bounds_rect",
			"[render] View bounds rect set by apply_view_camera_params (0x2a952)."),
		new NamedAddress(0x8497cL, "g_view_floor_clearance",
			"[render] View floor-clearance value computed by compute_floor_clearance_for_render (0x29403)."),
		new NamedAddress(0x89f38L, "g_render_active",
			"[render] Set to 0xff while a world-view render is in progress (render_world_view_pass 0x287b6); restored after."),
		new NamedAddress(0x909b2L, "g_floor_tex_caps",
			"[render] Floor/ceiling texture caps/flags read by draw_floorceil_surface (0x3a84e) and the render_floorceil_* span variants."),
		new NamedAddress(0x81030L, "g_left_hand_item",
			"[inventory] The player's LEFT-hand item (cursor-entry ptr). Drawn RED/ORANGE-tinted (shade row byte[0x7675e]) wherever its icon appears — its inventory grid cell (render_inventory_grid) AND the left hand slot (draw_equipped_item_left). Swapped with g_right_hand_item by swap_inventory_entries (0x1b007)."),
		new NamedAddress(0x8103cL, "g_right_hand_item",
			"[inventory] The player's RIGHT-hand item (cursor-entry ptr). Drawn GREEN/TEAL-tinted (shade row byte[0x76763]) wherever its icon appears — its inventory grid cell + the right hand slot (draw_equipped_item_right). Companion of g_left_hand_item (0x81030)."),
		new NamedAddress(0x810c0L, "g_inspect_popup_state",
			"[inventory] Inventory inspect close-up popup state (referenced alongside g_inspect_info_available 0x81188)."),
		new NamedAddress(0x82014L, "g_voice_stop_handle",
			"[audio] SOS handle used to stop the active speech voice; used by dialogue_voice_force_end (0x1f671). See docs/reference/ROTH_audio_notes.md."),
		new NamedAddress(0x7276cL, "g_rng_state",
			"[rng] PRNG state advanced by rng_next (0x4b4cb)."),
		new NamedAddress(0x7fe08L, "g_rng_state2",
			"[rng] Secondary PRNG state used by rng_range (0x16d79)."),
		new NamedAddress(0x93194L, "g_sos_drivers_installed",
			"[audio/SOS] Flag set once the SOS driver vtable templates are installed (install_sos_driver_vtables 0x443a7)."),
		new NamedAddress(0x8c194L, "g_collision_sector_stack",
			"[collision] Sector recursion stack for point/ray-vs-wall collision (collide_point_walls_recursive 0x3f0e0 / collide_ray_walls_recursive); paired with g_collision_sector_stack_count."),
		new NamedAddress(0x90f6aL, "g_dos_dta_name",
			"[DOS] Filename field within the DOS DTA (g_dos_dta) populated by INT 21h FindFirst/FindNext (dos_find_first / dos_find_next)."),
		// Migrated from the (frozen) ROTHApplyDasTypes.java so these survive an EngineNames-only re-apply;
		// SAME name+address as DasTypes -> idempotent, no cross-script conflict. Both are in recomp names.json.
		new NamedAddress(0x85c3cL, "g_das_cache_heap_handle",
			"[DAS cache] The sole 'Pool' handle-allocator instance (magic 0x506f6f6c) backing the DAS cache; chunks are relocatable via the handle slot. Referenced ~16x. See [[das-cache-pool]] / ROTH_DAS_loader_notes.md."),
		new NamedAddress(0x86d14L, "g_das_remap_chunk_4000_ptr",
			"[DAS] Pointer to the 0x4000-entry shade/remap chunk used by the DAS blit/shade path (shade_remap_blit 0x13ecb)."),
		new NamedAddress(0x91d00L, "g_gdv_user_callback",
			"[GDV] GDV per-frame user callback pointer, invoked by gdv_invoke_user_callback (0x4dd71). First of the GDV decoder state globals (0x91d00-0x91df0)."),
		new NamedAddress(0x91d2cL, "g_gdv_audio_buf_size",
			"[GDV audio] Size of the GDV audio output buffer; used by gdv_audio_init_silence_buffer (0x4e4f1)."),
		new NamedAddress(0x91d50L, "g_gdv_audio_stream_base",
			"[GDV audio] Base of the GDV audio stream ring buffer (gdv_audio_begin_playback / gdv_audio_stream_callback)."),
		new NamedAddress(0x91dc8L, "g_gdv_audio_enabled",
			"[GDV audio] Nonzero when GDV cutscene audio is enabled (gdv_audio_begin_playback 0x4e066)."),
		new NamedAddress(0x91dcaL, "g_gdv_audio_format",
			"[GDV audio] GDV audio format flags (8/16-bit + stereo) read by gdv_audio_start_voice (0x55670)."),
		new NamedAddress(0x91df4L, "g_gdv_audio_end",
			"[GDV audio] Set by gdv_audio_stream_callback (0x4e394) at end-of-stream (SOS message type 2)."),
		new NamedAddress(0x8a0f8L, "g_active_object",
			"The object the player is currently interacting with / pointing at (offset into g_map_objects_buffer); the primary target for use/door/particle commands, distinct from g_command_source_object (0x8a100, the chain's source). Cleared when a sector trigger fires."),
		new NamedAddress(0x8a0dcL, "g_pending_command_record",
			"[.RAW commands] Staged 'run if next conditional fails' command record ptr. cmd_dbase100_if_next_fails "
			+ "(0x31326, RAW cmd 0x36) writes the current command record here and returns 0 (does NOT run it); "
			+ "flush_pending_command_record (0x31963) later checks it (!=0 and g_item_autoselected_flag==0) and runs it "
			+ "via run_command_dbase100_record (0x3540b), then clears it. (cmd 0x2B runs its record immediately and just "
			+ "clears this; the staging is only the 0x36 deferred path.)"),
		new NamedAddress(0x91864L, "g_particle_pool",
			"Head of the active-particle linked list (blood/spark/debris). Record: +0 next, +4 sector, +0x18 z-velocity, +0x1c/+0x20 x/y velocity, +0x24/+0x28/+0x2c 16.16 position, +0x31 active flag, +0x32 lifetime. Filled by spawn_particle, advanced (gravity+bounce) by tick_particles."),
		new NamedAddress(0x89fa8L, "g_last_item_record",
			"The most-recently given/removed item record (set by cmd_give_item = give_item's return, defaulted-to by cmd_remove_item / cmd_if_not_item when their cmd+8 id is 0). Threads item context across a command chain. (recomp's lift proposes g_last_inventory_item; same global — it carries the last given/removed item id/handle.)"),
		new NamedAddress(0x89facL, "g_item_drop_position",
			"[.RAW items] Drop-position struct cmd_give_item fills + passes to give_item when spawning the item into the world at the source object's midpoint: +0 (0x89fac)=x, +2 (0x89fae)=y, +4 (0x89fb0)=0, +0xa (0x89fb6)=z. (recomp oracle-proven role, RAW_COMMANDS handoff §3.)"),
		new NamedAddress(0x89f64L, "g_if_item_list_count",
			"[.RAW cmd 0x27 If-Not-Item] Count (bounded < 0x10) of the accumulated item-id list g_if_item_list (0x89f68); the rec[6]&8 'append' path pushes cmd+8 ids and bumps this, then passes the list to find_or_autoselect_inventory_item. (recomp oracle-proven, RAW_COMMANDS handoff §3.)"),
		new NamedAddress(0x89f68L, "g_if_item_list",
			"[.RAW cmd 0x27 If-Not-Item] u32[0x10] accumulator of item ids built by the cmd_if_not_item rec[6]&8 append path (count = g_if_item_list_count 0x89f64); &g_if_item_list is passed to find_or_autoselect_inventory_item. (recomp oracle-proven, RAW_COMMANDS handoff §3.)"),
		new NamedAddress(0x8a100L, "g_command_source_object",
			"The 'current/source' object for the active .RAW command chain (offset into g_map_objects_buffer). Set by cmd_spawn_object etc.; used as the implicit target when a command's object id is 0 (resolve_command_objects) and as the damage source for cmd_apply_damage."),
		new NamedAddress(0x8b3f8L, "g_door_pool",
			"Pool of active swinging doors (max 6 records, stride 0x1f6=502 bytes), keyed by sector id. Record: +0 door sector id, +2 state (bit1=open), +3 current swing angle (byte, fed to rotate_quad via g_sincos_table), +0x10 paired sector, +0x1c/+0x24 swing-range (0x80/0x40=90deg), +0x1e timer, +0x2e snapshotted 4 corner verts relative to the hinge pivot. A door = a sector FACE/quad rotated about a corner. Init by init_door_pool, populated by cmd_open_door->register_door_swing, read by the renderer."),
		new NamedAddress(0x8b3f4L, "g_door_count",
			"Number of active door records in g_door_pool (0..6); incremented by setup_door_swing_geometry, reset by init_door_pool."),
		new NamedAddress(0x7fea8L, "g_pending_game_action",
			"[bitfield] Pending end-of-frame game-action request, polled + cleared each frame by game_play_loop (0x179ee). Bits: 0x01 = map warp/transition (cmd_map_transition -> process_map_warp_or_load; target map 0x85484 at g_warp_dest_a/b 0x8547c/0x85480), 0x02 = quick save/load (key_quicksave/key_quickload; 0x7feac selects: <2 = load+warp, ==2 = save), 0x04 = apply selected video resolution (set_resolution_index_and_cycle_display g_selected_video_mode), 0x08 = mode-3 / quit-to-menu. Also raised by the inventory options menu (update_inventory_screen). (Was mislabeled g_map_transition_pending — that is only bit 0x01.)"),
		new NamedAddress(0x8547cL, "g_warp_dest_a",
			"Destination param A for a pending map transition (cmd_map_transition stores .RAW command +0xa here); consumed by the map-load path when g_pending_game_action is set. Likely the entry position/point [HYP]."),
		new NamedAddress(0x85480L, "g_warp_dest_b",
			"Destination param B for a pending map transition (cmd_map_transition stores .RAW command +0xe here). Companion to g_warp_dest_a [HYP: entry coords/flags]."),
		new NamedAddress(0x8a118L, "g_active_effect_pool",
			"Head of the per-frame ACTIVE-EFFECT linked list (the .RAW command runtime effects: moving sectors, lights, flashing, texture cycles). Record: +0 next, +4 = COMMAND_BASE (selects the tick handler), +8 = target/back-ptr. Registered by command handlers via alloc_active_effect/alloc_effect_record, walked + advanced each frame by tick_world_effects (0x3464c), removed when a tick handler reports done."),
		new NamedAddress(0x8a11cL, "g_effect_list_b",
			"Head of the SECOND runtime effect linked list (companion to g_active_effect_pool 0x8a118). Records are "
			+ "allocated from the DAS-cache heap by alloc_effect_record_list_b (0x34499, used by tick_move_floorceil) and "
			+ "freed by free_effect_pools (0x343f5). Holds auxiliary per-frame effect state (e.g. moving-cell carry "
			+ "records)."),
		new NamedAddress(0x3088cL, "g_command_tick_dispatch_table",
			"Per-frame TICK dispatch table for active-effect commands (parallel to the EXECUTE table "
			+ "g_command_dispatch_table 0x30780): tick_world_effects calls tick_table[COMMAND_BASE]() each frame to "
			+ "advance an effect. FULLY MAPPED (cross-verified vs the EXECUTE table, same base->command): [0x02]="
			+ "tick_light_switch, [0x03]=tick_modify_sector, [0x07]=tick_change_height, [0x09]=tick_moving_sector, "
			+ "[0x0a]=tick_change_floor_texture, [0x0b]=tick_change_floor_texture_b, [0x0c]=tick_change_face_texture_adv, "
			+ "[0x0d]=tick_change_object_texture, [0x0e]=tick_scroll_sector_texture, [0x0f]=tick_scroll_face_texture, "
			+ "[0x11]=tick_flash_lights, [0x12]=tick_delay_timer, [0x1d]=tick_change_lighting, [0x23]="
			+ "tick_change_object_height, [0x24]=tick_rotate_object, [0x45]=tick_cmd_45, [0x46]=tick_move_floorceil; "
			+ "all other bases = cmd_default_nop (0x30ab0) = INSTANT commands with no per-frame tick. (Address = "
			+ "&command_table[0x43]; the tick handlers follow the execute handlers in the table region.)"),
		new NamedAddress(0x7f578L, "g_selected_video_mode",
			"Display-mode value chosen in the Screen settings list (run_settings_menu 0x24c72 case 3): standard modes 1/2 vs hi-res 7/8 (list ids 0x3a..0x3d). When the pick is 7 or 8 AND the current framebuffer is standard-size (g_framebuffer_bytes 0x85478 <= 0x3e7ff), the 'Reload game to take effect' warning box (0x7194c, text id 0x36) is shown."),
		new NamedAddress(0x85478L, "g_framebuffer_bytes",
			"Current screen/framebuffer allocation size, compared to 0x3e7ff (~256000, the standard-vs-hi-res boundary) by the Screen-settings handler to decide whether switching to a hi-res mode (7/8) needs a reload (the 'Reload game to take effect' string 0x36 warning). [name slightly HYP - confirmed role is the reload-decision size threshold]."),
		new NamedAddress(0x72730L, "g_ai_wander_rng",
			"Self-contained LCG state (state = state*0x5e5 + 0x29) used by update_actor_movement_ai to randomly flip an actor's wander/turn flag — the source of monster idle/patrol direction randomness."),
		new NamedAddress(0x7272cL, "g_entity_damage_rng",
			"LCG state (state = state*0x5e5 + 0x29, same algorithm as g_ai_wander_rng, separate seed) used by "
			+ "update_dynamic_entities to randomize projectile/contact damage. ASM-VERIFIED formula (0x42a34/0x42a83): "
			+ "final = (base + (rng16*base >> 16)) >> 1 = base*(1 + rng16/65536)/2, uniform over [base/2, base) — a "
			+ "2x min-to-max spread. base = proj damage (proj+0x16) * target multiplier from compute_projectile_hit_"
			+ "damage (0 = immune via resist list def+0x2c, 1 = normal, 2 = weak via vuln list def+0x46). PLAYTEST-"
			+ "CONFIRMED (Alex, Cheat Engine): in-game damage ranges [V, 2V) where V = the DBASE100-authored bullet "
			+ "value, i.e. base = 2V (the authored value is the MINIMUM; engine rolls up to 2x). Same formula on both "
			+ "the player-hit (apply_reduced_damage_to_player) and entity-hit paths."),
		new NamedAddress(0x90fdcL, "g_projectile_collision_width",
			"[entity collision] The current moving projectile/entity's collision width; check_projectile_sector_clearance "
			+ "uses width>>1 as the half-band when testing whether the projectile fits the sector's floor/ceiling gap. "
			+ "Set from the entity byte+9 each tick in update_dynamic_entities."),
		new NamedAddress(0x71f48L, "g_command_rng",
			"LCG state for the .RAW command system (state = state*0x5e5 + 0x29, same algorithm as g_ai_wander_rng but a "
			+ "separate seed). Used by exactly three command handlers to randomize their effect: cmd_player_rotation "
			+ "(0x30acb, random turn delta), cmd_delay_timer (0x32195, random delay) and init_command_timer_countdown "
			+ "(0x30b45, random repeat count)."),
		new NamedAddress(0x72738L, "g_ai_anim_rng_seed",
			"Seed for the actor animation-frame LCG (g_ai_anim_rng = seed*0x5e5 + 0x29); used by the pool-A tick to pick a random current frame for an actor's animation list."),
		new NamedAddress(0x72734L, "g_ai_anim_rng",
			"Output of the actor animation-frame LCG (see g_ai_anim_rng_seed); low byte scales into the entity's animation-frame count (geom+0x18) to choose the displayed/sound-triggering frame."),
		new NamedAddress(0x72740L, "g_actor_move_rate",
			"Per-actor movement/phase rate for the current pool-A tick, loaded from the entity geometry record (+0xc); update_actor_movement_ai adds it to the move-phase counter each tick (faster actors accumulate phase quicker)."),
		new NamedAddress(0x72744L, "g_actor_tick_rate",
			"Per-actor animation/scheduler rate for the current pool-A tick, from entity geometry (+0xe); forced to 10000 for type-5 actors. Fed to the FUN_0004355a scheduler."),
		new NamedAddress(0x7273cL, "g_actor_anim_scheduler",
			"Per-tick countdown accumulator that gates when update_actor_movement_ai re-rolls the animation frame (g_ai_anim_rng) and emits frame sound events; reloaded from a frame-count-scaled value."),
		new NamedAddress(0x8c1d6L, "g_player_sector_cache",
			"Last-known player sector, updated by collide_substep_track_sector when the player crosses into a new sector during a move substep."),
		new NamedAddress(0x8c0dcL, "g_collision_move_entity",
			"Pointer to the entity record currently being moved by move_entity_with_collision; read by collide_entity_and_steer to apply the steer/bearing change and blocked-flag on a wall hit."),
		new NamedAddress(0x8c0d8L, "g_collision_move_entity_geom",
			"Pointer to the moving entity's position/geometry sub-record (entity+4), companion to g_collision_move_entity; collide_entity_and_steer writes the new facing into it (+6)."),
		new NamedAddress(0x8c1e2L, "g_collision_step_active",
			"Collision query mode flag: 1 = swept-step substep in progress (resolve_collisions_in_sector runs test_ray_reached_target + collide_ray_entities + recursive walls), 0 = point-in-sector test (FUN_0003f0e0 walls + FUN_000401cf entities). Set per substep by sweep_move_with_collision, cleared after each sector pass."),
		new NamedAddress(0x8c190L, "g_collision_portal_continue",
			"Portal-continuation flag: set by the wall trace (collide_ray_walls_recursive) to tell resolve_collisions_in_sector to iterate into the next portal-linked sector; cleared at the top of each sector pass. 0 ends the per-sector loop."),
		new NamedAddress(0x8c12cL, "g_collision_entity_count",
			"Count of collidable objects in the current collision query (g_door_worklist list); resolve_collisions_in_sector skips the entity pass when 0. Driven by collide_ray_entities (0x4066f)."),
		new NamedAddress(0x8c192L, "g_collision_sector_stack_count",
			"Visited-sector stack depth for the recursive wall trace (paired list at 0x8c194, max 0x1e); reset to 0 by collide_sector_walls before each trace, dedup-checked + incremented in collide_ray_walls_recursive."),
		new NamedAddress(0x8c0ecL, "g_collision_target_radius",
			"Hit radius (max|dx|,|dy|) used by test_ray_reached_target to decide whether the swept ray reached the active target point (0x90a8c/0x90a94); part of the 0x8c0xx collision-query state block. Derived from g_collision_velocity_mag + 0x20."),
		new NamedAddress(0x8c0f0L, "g_collision_target_active",
			"Nonzero when a destination/target point is active for the swept query; gates test_ray_reached_target. Seeded from the entity's field +0x1a by sweep_move_with_collision."),
		new NamedAddress(0x90ab4L, "g_collision_restore_x",
			"Saved query X to roll back to when the swept ray hits something (resolve_collisions_in_sector / collide_ray_walls_recursive restore g_locate_query_x from here on hit). Snapshot of the pre-step position."),
		new NamedAddress(0x90ab8L, "g_collision_restore_y",
			"Saved query Y companion to g_collision_restore_x; restored into g_locate_query_y on a collision hit."),
		new NamedAddress(0x8a3c0L, "g_floorceil_span_fn",
			"Function pointer to the active floor/ceiling span inner-loop (the render_floorceil_* variant). setup_floorceil_span computes the U/V texture steppers then tail-jumps (*g_floorceil_span_fn)(step,rem) for the main textured path; the variants tail-call back into setup_floorceil_span -> span-chain driver. Selected by render mode."),
		new NamedAddress(0x8a3c4L, "g_floorceil_span_fn_alt",
			"Alternate floor/ceiling span inner-loop fn-ptr used by setup_floorceil_span for the special-case paths (DAT_0008a354 jumptable mode + the same-texel/flat shortcut). Companion to g_floorceil_span_fn."),
		new NamedAddress(0x8a3dcL, "g_floorceil_accum_a",
			"Primary interleaved U/V fixed-point ACCUMULATOR (EBP) for the floor/ceiling fill family. Per-span init written by draw_floorceil_surface (byte-packed at 0x8a3dd = [span+6]<<2); the inner loops do 'ebx = ebp ror 0xb; and ebx,mask; or bl,shade; bl=fs:[ebx]' then 'ebp += g_floorceil_step_a'."),
		new NamedAddress(0x8a3e0L, "g_floorceil_accum_b",
			"Secondary interleaved fixed-point accumulator (EDX) for the floor/ceiling fill family; init at 0x8a3e0/0x8a3e3 (byte-packed from [span+4]/[span+2]). Stepped by g_floorceil_step_b with carry from g_floorceil_accum_a."),
		new NamedAddress(0x8a3f4L, "g_floorceil_step_a",
			"Per-pixel step added to g_floorceil_accum_a (ESI in the fill loops). Computed per span by draw_floorceil_surface: ([span+0x12]-[span+6])<<0xa / span_pixel_count (idiv at 0x3aba0). The U/V perspective stepper."),
		new NamedAddress(0x8a3f8L, "g_floorceil_step_b",
			"Per-pixel step added to g_floorceil_accum_b (EAX in the fill loops), overlapping the byte-packed 0x8a3f7/0x8a3fa the driver writes. Companion of g_floorceil_step_a."),
		new NamedAddress(0x8a2bcL, "g_world_span_fn",
			"Function pointer to the active world WALL-column span inner-loop (the render_world_span_* variant); loaded from pair table 0x71f80 col0 by draw-flags index and jumped by FUN_0003778b. Wall-render counterpart of g_floorceil_span_fn."),
		new NamedAddress(0x8a2c4L, "g_world_span_fn_alt",
			"Alternate world wall-column span inner-loop fn-ptr (pair table 0x71f80 second column); companion to g_world_span_fn."),
		new NamedAddress(0x8a2c0L, "g_world_span_fn2",
			"Main-bank col1 world-span fn-ptr = table[idx|0x40 + 4] (0x71f84). Jumped on the no-clip path of dispatch_world_span_column (jmp [0x8a2c0] at 0x378a8). Companion to g_world_span_fn (col0)."),
		new NamedAddress(0x8a2c8L, "g_world_span_fn_alt2",
			"Alt-bank col1 world-span fn-ptr = table[idx + 4] (0x71f84). Companion to g_world_span_fn_alt; installed alongside it at 0x37376."),
		new NamedAddress(0x71f80L, "g_world_span_variant_table",
			"Pair table of WALL-column span inner-loop fn-ptrs (8-byte entries: [+0]=col0, [+4]=col1). draw_world_surface_spans indexes it by a variant id built from g_world_surface_draw_flags to install g_world_span_fn/_alt; the main bank is index|0x40 (8 entries up)."),
		new NamedAddress(0x8a348L, "g_wall_column_count",
			"Number of screen columns in the current wall segment; the per-column loop counter in draw_world_surface_spans (mov bx,[0x8a348]; ... dec ecx; jg). Set during the wall-edge projection setup."),
		new NamedAddress(0x90948L, "g_wall_proj_y0",
			"Projected screen-row of a wall corner (top, near edge), output of project_wall_edge_y. With g_wall_proj_y1..3 (0x9094a/4c/4e) these are the 4 projected wall-quad corner rows that draw_world_surface_spans differences into the vertical span endpoint steppers g_span_endpoint_a/_b."),
		new NamedAddress(0x9094aL, "g_wall_proj_y1",
			"Projected wall-corner screen row (companion of g_wall_proj_y0); (y1-y0)<<8 -> g_span_endpoint_a colstep."),
		new NamedAddress(0x9094cL, "g_wall_proj_y2",
			"Projected wall-corner screen row (companion of g_wall_proj_y3); part of the g_span_endpoint_b stepper pair."),
		new NamedAddress(0x9094eL, "g_wall_proj_y3",
			"Projected wall-corner screen row; (y2-y3)<<8 / column-count -> g_span_endpoint_b colstep in draw_world_surface_spans."),
		new NamedAddress(0x8a334L, "g_wall_render_flags",
			"Per-wall-segment render flags word for draw_world_surface_spans (bit 0 from g_world_surface_draw_flags, bit 0x8000 = texture-wrap span). Set at the driver entry from the corner-Y clip test."),
		new NamedAddress(0x8a336L, "g_wall_segment_width",
			"Wall segment screen width (right-left+1), computed at draw_world_surface_spans entry (0x36c1e) from the projected X bounds 0x90958/0x90960."),
		new NamedAddress(0x8a2e4L, "g_wall_vstep",
			"Vertical texture-coordinate interpolation step for the wall columns = (y-delta<<0x10)/column-count (idiv at 0x373f2); SMC-patched into the per-column setup (0x375b0). Companion 0x8a2e8 set alongside."),
		new NamedAddress(0x8a2ccL, "g_span_endpoint_a",
			"Interpolated texture-coord endpoint A (near/left edge accumulator) for the world-column mappers. Per-column advanced by g_span_endpoint_a_colstep; its low word seeds g_span_accum_init. dispatch_world_span_column (0x3778b) computes the per-pixel step = (B-A)/count."),
		new NamedAddress(0x8a2d4L, "g_span_endpoint_b",
			"Interpolated texture-coord endpoint B (far/right edge) for the world-column mappers. Per-column advanced by g_span_endpoint_b_colstep. g_span_pixel_step = (g_span_endpoint_b - g_span_endpoint_a)/count via idiv ecx in dispatch_world_span_column."),
		new NamedAddress(0x8a2d0L, "g_span_endpoint_a_colstep",
			"Per-COLUMN advance of g_span_endpoint_a: 0x8a2cc += this after each column in dispatch_world_span_column (0x37865). Gives perspective/sloped texture interpolation across the wall run."),
		new NamedAddress(0x8a2d8L, "g_span_endpoint_b_colstep",
			"Per-COLUMN advance of g_span_endpoint_b: 0x8a2d4 += this after each column (0x37870). Companion to g_span_endpoint_a_colstep."),
		new NamedAddress(0x8a2e0L, "g_span_pixel_step",
			"Per-PIXEL texture step for the world-column mappers = (g_span_endpoint_b - g_span_endpoint_a)/count (idiv ecx at 0x377c6). The mapper shifts it <<16 and patches it into its own SMC 'add ebp,imm32'. If 0, the flat/same-texel shortcut at 0x37851 is taken (degenerate guard)."),
		new NamedAddress(0x8a2dcL, "g_span_accum_init",
			"Word seed for the EBP fractional accumulator in the world-column mappers = low word of g_span_endpoint_a (mov [0x8a2dc],bx at 0x377db). High byte = g_span_shade_seed. Mapper does mov ebp,[0x8a2dc]; shl ebp,0x10."),
		new NamedAddress(0x8a2ddL, "g_span_shade_seed",
			"High byte of the g_span_accum_init word = the depth-cue colormap ROW (shade/light level) the mapper ramps AL from per pixel. Computed in the 0x37803 branch of dispatch_world_span_column: (2*[0x8a304])/[0x8a300] (a 1/Z perspective divide), halved, complemented, clamped into [0,0x1f]+0x20. Feeds gs:[(shade<<8)|texel]."),
		new NamedAddress(0x8a2e2L, "g_span_eax_step_lo",
			"Low byte of the EAX-accumulator step for the world-column mappers; merged with the caller's AX<<16 and patched into the SMC 'adc eax,imm32'. The EAX accumulator drives the shade ramp (its AL byte -> BH colormap row)."),
		new NamedAddress(0x8a344L, "g_span_eax_accum_init",
			"Integer init of the EAX shade-ramp accumulator in the world-column mappers (mov eax,[0x8a344]; shl eax,0x10; mov al,bh). Low byte then overwritten by the caller's BH seed."),
		new NamedAddress(0x8a338L, "g_span_src_wrap_base",
			"Source row-start texel offset for the current column (esi += masked_coord * g_span_src_row_width at 0x37527). Also the tail-pixel wrap reference: the odd-pixel clamp tests (esi - srcbase - 0x8a338) against g_span_src_row_width."),
		new NamedAddress(0x8a2ecL, "g_span_texU_accum",
			"[wall span] U-coordinate endpoint accumulator for the column walk; stepped by the colstep each column "
			+ "(add [0x8a2ec], <colstep> @0x375aa). Integer part read at 0x8a2ee. See "
			+ "lift_handoffs/wall_mappers_SMC_and_classification.md."),
		new NamedAddress(0x8a2f0L, "g_span_texV_accum",
			"[wall span] V-coordinate endpoint accumulator for the column walk; stepped by its colstep "
			+ "(add [0x8a2f0], <colstep> @0x375b4). Integer part read at 0x8a2f2."),
		new NamedAddress(0x8a316L, "g_span_round_half",
			"[wall span] Fixed-point rounding bias, initialized to 0x8000 (= 0.5 in 16.16); compared/reset during "
			+ "the perspective-correct span setup."),
		new NamedAddress(0x8a34cL, "g_span_draw_mode_flags",
			"[wall span] Draw-mode flag byte for the column mappers (e.g. test [0x8a34c],3 selects the "
			+ "shaded/blend/wrap path). Part of the wall working-set."),
		new NamedAddress(0x90978L, "g_span_src_row_width",
			"Source texture row stride / wrap extent used by the world-column mappers. Multiplier when computing g_span_src_wrap_base; the tail-pixel wrap clamp compares the running source offset against it (0x39177)."),
		new NamedAddress(0x9097cL, "g_span_src_wrap_reoffset",
			"Source wrap re-base added back when the tail pixel runs past g_span_src_row_width: esi = 0x9097c + srcbase + g_span_src_wrap_base (0x3917f). Implements horizontal texture wrap for the final odd pixel."),
		new NamedAddress(0x8a368L, "g_sprite_column_fn",
			"Active span inner-loop fn-ptr for draw_scaled_sprite_spans (0x39610): the mode ladder stores one of 0x39fcd/0x3a000/0x3a0b1/0x3a100/0x3a220/0x3a368/0x3a4f8/0x3a700 here, then the per-span loop does 'jmp [0x8a368]' (0x39e4c/0x39fb2). Sprite/object analogue of g_world_span_fn (walls)."),
		new NamedAddress(0x90a30L, "g_sprite_render_mode",
			"Render-mode selector read by draw_scaled_sprite_spans (cmp [0x90a30],1 / ,2): picks the span inner-loop variant (1/2/default ladders). Combined with g_column_clip_mode and the 0x9093c/0x8a352/0x8a354 flags."),
		new NamedAddress(0x90970L, "g_column_clip_mode",
			"Shared wall/sprite clip flag (0/1). Gates the clipped vs unclipped span/column variant in BOTH dispatch_world_span_column (cmp [0x90970],0 at entry) and draw_scaled_sprite_spans (variant ladder). 1 = edge-clipped path."),
		new NamedAddress(0x90a24L, "g_sprite_fill_index",
			"Solid fill color index for the untextured sprite-span variants. render_sprite_span_fill_39fcd writes it raw (rep stosw); render_sprite_span_solid_3a000 / _gradient_3a0b1 use it as the low byte of the gs colormap lookup (gs:[(shade<<8)|index])."),
		new NamedAddress(0x8a3baL, "g_sprite_span_shade",
			"Current span's shade/light level (colormap row), set per span by draw_scaled_sprite_spans (0x39cbe/0x39cd0/0x39d5c) from the interpolated intensity. Read as the high byte of the gs/remap colormap index by every sprite-span variant. 0x1f path = full-bright shortcut (render_sprite_span_fill_39fcd)."),
		new NamedAddress(0x8a358L, "g_sprite_span_remaining",
			"Remaining-span counter for draw_scaled_sprite_spans, decremented per span (0x39bef) and used as the divisor for the perspective reciprocal (div at 0x39c36 -> g_sprite_perspective_step). Drives the per-span U/V step recompute."),
		new NamedAddress(0x8a35cL, "g_sprite_perspective_step",
			"Per-span perspective reciprocal = <patched imm>/g_sprite_span_remaining (0x39c36). Multiplied by the source U/V deltas (g_sprite_tex_du/_dv) to build the per-pixel steppers g_sprite_tex_step_u/_v."),
		new NamedAddress(0x8a374L, "g_sprite_src_coord",
			"Source texture coordinate accumulator (init) for the sprite-span mappers = word[span_record+2]<<8 (0x39c91); becomes the EBP accumulator init. Stepped per pixel by g_sprite_src_coord_step."),
		new NamedAddress(0x8a378L, "g_sprite_src_coord_step",
			"Per-pixel source-coordinate step for the sprite-span mappers = (word[rec+0xe]<<8 - g_sprite_src_coord)/count via idiv (0x39c9c). Patched into the inner loops' 'add ebp,imm' / 'adc edx,imm'."),
		new NamedAddress(0x8a3acL, "g_sprite_span_flip",
			"Span direction/sign flag (set from the U-step sign). The textured variants test 'cmp [0x8a3ac],0; jl' to pick the forward sub-loop vs the reversed sub-loop (e.g. render_sprite_span_tex_shaded_3a4f8 0x3a4f8 forward / 0x3a604 reversed, which uses rotated-dword steppers + fs:[ebx])."),
		new NamedAddress(0x8a372L, "g_sprite_span_width",
			"Span width (pixel count) used by draw_scaled_sprite_spans as the idiv divisor when computing the texture steppers g_sprite_tex_step_u/_v (0x39d85/0x39d92). Must be >=2 for the textured path."),
		new NamedAddress(0x8a38cL, "g_sprite_tex_step_u",
			"Per-pixel U texture step (reciprocal form) for the textured sprite-span variants = <patched imm>/g_sprite_span_width (0x39d87); shifted <<0xc and split (low byte -> 0x8a393, rest patched into the inner loop's add/adc immediates)."),
		new NamedAddress(0x8a390L, "g_sprite_tex_step_u2",
			"Second U-component step for the textured sprite-span variants = <patched imm>/g_sprite_span_width (0x39d92); patched alongside g_sprite_tex_step_u into the inner loops."),
		new NamedAddress(0x8a394L, "g_sprite_tex_step_v",
			"Per-pixel V texture step for the textured sprite-span variants = (g_sprite_perspective_step * 0x8a37c) >> 2 (0x39da8); shifted <<0xc and split (low byte -> 0x8a39b)."),
		new NamedAddress(0x8a398L, "g_sprite_tex_step_v2",
			"Second V-component step = (g_sprite_perspective_step * 0x8a380) >> 2 (0x39dbc); the EBP-init companion to g_sprite_tex_step_v in the textured sprite-span inner loops."),
		new NamedAddress(0x8a360L, "g_sprite_tex_step_frac",
			"Fractional sub-step patched into the textured sprite-span inner loops (e.g. 0x3a193/0x3a1b9, 0x3a5b9/0x3a5e0). Part of the SMC step-immediate set with g_sprite_tex_step_u/_v."),
		new NamedAddress(0x8a36cL, "g_current_span_record",
			"Active span/column descriptor used by the renderer span handlers. render_world_span_39e52's alt path swaps its texture-coord fields (+2 <-> +0xe). Referenced by the floor/ceiling + sprite span setup."),
		new NamedAddress(0x8a370L, "g_sprite_column_loop_guard",
			"SMC loop-guard accumulator decremented each span in the draw_scaled_sprite_spans loop tail (sub [0x8a370], <patched imm> at 0x39e55). The 0x12345678 in the disasm is the placeholder immediate the setup overwrites."),
		new NamedAddress(0x7fdd0L, "g_weapon_fire_lock",
			"Weapon fire-in-progress lock: trigger_weapon_fire(0x1768a) bails while nonzero and sets it -1 when a shot is committed; gates re-fire until the fire sequence completes."),
		new NamedAddress(0x7fdf4L, "g_pending_weapon_def",
			"Latched weapon definition for the queued shot: set by trigger_weapon_fire, consumed by fire_pending_weapon_shot(0x16da2) which passes it to spawn_projectile_from_aim(0x42400). 0 = no shot pending."),
		new NamedAddress(0x7fe10L, "g_pending_fire_aim",
			"Latched aim parameters for the queued shot (0x7fe10 = param_1, 0x7fe14 = param_2 of trigger_weapon_fire); read by fire_pending_weapon_shot when spawning the projectile."),
		new NamedAddress(0x8c1e0L, "g_collision_hit_flags",
			"Swept-collision result flags written by the collide_* routines: bit0 = wall/portal hit (collide_ray_walls_recursive / probe_collision_step), bit1 = entity or target hit (collide_ray_entities / test_ray_reached_target). Read back by sweep_move_with_collision into the result struct."),
		new NamedAddress(0x8c0f4L, "g_collision_hit_entity",
			"Pointer to the entity/object the swept ray collided with (set by collide_ray_entities 0x4066f; cleared on a wall-only or target-point hit). Part of the 0x8c0xx swept-collision query state block."),
		new NamedAddress(0x852baL, "g_face_span_top",
			"Renderer scratch: top (min) Y extent of the world-face span being set up (compute_face_span_extents 0x2c250)."),
		new NamedAddress(0x852b8L, "g_face_span_bottom",
			"Renderer scratch: bottom (max) Y extent of the world-face span being set up (compute_face_span_extents 0x2c250)."),
		new NamedAddress(0x83ea0L, "g_menu_frontend_flag",
			"Menu context flag: 1 = front-end/main-menu (set by run_main_menu), 0 = in-game (set by run_options_menu). run_settings_menu uses it to pick the Settings descriptor: 0 (in-game) -> 0x71a58 WITH 'Screen settings'; 1 (front-end) -> 0x71a9c WITHOUT (confirmed by playtest: Screen settings only reachable from a running game). PIN: string 0x36 'Reload game to take effect' is NOT shown for the screen option per playtest - its actual trigger is unconfirmed."),
		new NamedAddress(0x71d46L, "g_gdv_error_strings",
			"Table of 4 GDV/cutscene load-error message pointers ('No errors.','Alloc_Mem_DISPLAY','Load_SPR','Load_RAW'); indexed by show_cutscene_error_box 0x26aef."),
		// GDV streaming-codec decoder state (see the gdv_* functions; 0x29111994 magic).
		new NamedAddress(0x91d14L, "g_gdv_context",
			"[GDV codec] Pointer to the active decoder context struct (param to gdv_decoder_open): +4 input "
			+ "callback, +8 decode-buffer ptr, +0xc buffer size, +0x18 stream flags, +0x44/+0x48/+0x4c/+0x50 "
			+ "output fields. Held across the open/decode/close calls."),
		new NamedAddress(0x91d0cL, "g_gdv_stream_flags",
			"[GDV codec] Stream/format flags copied from g_gdv_context+0x18: bit2=direct-read source, "
			+ "bit4=embedded, bit8=DPCM audio, bit0x1000=embedded-file (skip close), bit0x2000/0x10000 set the "
			+ "decode mode (0x91de2). Tested throughout the decoder."),
		new NamedAddress(0x91d34L, "g_gdv_decode_buffer",
			"[GDV codec] Base of the allocated decode buffer (gdv_alloc_decode_buffer); partitioned by "
			+ "gdv_setup_decode_buffers into audio (0x91d38) and video/work (0x91d3c/0x91d40/0x91d50) regions."),
		new NamedAddress(0x91ddcL, "g_gdv_decoder_active",
			"[GDV codec] 0xff while a decoder is open (set by gdv_decoder_open, cleared by gdv_decoder_close); "
			+ "gdv_decode_frame is a no-op unless set."),
		new NamedAddress(0x91ddeL, "g_gdv_end_of_stream",
			"[GDV codec] Set when the GDV stream is exhausted; makes gdv_decode_frame return 0x100 (EOS) so the "
			+ "player loop stops."),
		new NamedAddress(0x85320L, "g_last_frame_tick",
			"Tick-counter value at the previous frame; update_frame_time_scale 0x24f5e diffs g_frame_tick_counter against it to get g_frame_time_scale."),
		new NamedAddress(0x8532aL, "g_anim_clock",
			"[renderer/animation] Free-running 16-bit animation clock = a copy of g_frame_tick_counter (0x90bcc, via "
			+ "copy_word_90bcc_to_8532a 0x2ab21). select_surface_anim_frame uses (g_anim_clock & 0x7fff) / surface "
			+ "period[+0x14] %% frame-count[+0x22] to pick the current frame of a free-running animated wall/floor "
			+ "texture (water, fire, energy, ...)."),
		new NamedAddress(0x71b34L, "g_vol_soundfx",
			"Sound-FX volume (12-bit, ROTH.INI SoundFXVol). Applied by apply_audio_volume_settings 0x2626f."),
		new NamedAddress(0x71b40L, "g_vol_speech",
			"Speech volume (12-bit, ROTH.INI SpeechVol)."),
		new NamedAddress(0x71b4cL, "g_vol_movie",
			"Movie volume (12-bit, ROTH.INI MovieVol)."),
		new NamedAddress(0x71b58L, "g_vol_music",
			"Music volume (12-bit, ROTH.INI MusicVol)."),
		new NamedAddress(0x719fcL, "g_mouse_speed",
			"Mouse speed setting (12-bit, ROTH.INI MouseSpeed)."),
		new NamedAddress(0x81e24L, "g_dbase100_dialogue_table",
			"dbase100 section at header+0x1c (resolved in init_game_databases): the dialogue/command record table indexed by record id (eval_dialogue_record_by_id 0x1dc73)."),
		new NamedAddress(0x81e28L, "g_dbase100_record_bitmap",
			"Active-record bitmap for dbase100 (allocated in init_game_databases, sized by record count). Tested by test_dbase100_record_flag 0x1cb35."),
		new NamedAddress(0x71366L, "g_bit_mask_lut",
			"8-entry bit-mask lookup {1,2,4,8,16,32,64,128} indexed by (n & 7); used for bitmap bit tests (e.g. test_dbase100_record_flag)."),
		new NamedAddress(0x7f46cL, "g_current_dbase300_chunk_id",
			"Index of the dbase300 chunk currently loaded in g_dbase300_chunk_buf (load_dbase300_chunk 0x15492 skips a reload when unchanged)."),
		new NamedAddress(0x7f450L, "g_dbase300_chunk_buf",
			"Buffer holding the current decompressed/streamed dbase300 chunk (filled by load_dbase300_chunk, processed by process_audio_sequence_chunk)."),
		new NamedAddress(0x7f468L, "g_audio_sequence_progress",
			"[AUDIO] Progress bitfield for the sound/music sequence (process_audio_sequence_chunk): bit0=active, "
			+ "bit1=inited, bit2=done. Gates the init/step/finalize lifecycle."),
		new NamedAddress(0x7f444L, "g_audio_sequence_ctx",
			"[AUDIO] Sequencer context for the sound/music sequence chunk (set by init_audio_sequence 0x464f9, "
			+ "stepped by step_audio_sequence, consumed by emit_audio_sequence_event). GS stream cursor + state."),
		new NamedAddress(0x7370cL, "g_sound_channel_volume",
			"[AUDIO] Per-MIDI-channel VOLUME table for the music sequencer (sos_dispatch_midi_event 0x44e0d): all "
			+ "0x7f (full) at rest; controller-7 (channel volume) values are scaled `v*vol>>7`, then by master "
			+ "0x73708. (Was mislabeled an 'intensity/fade' table.)"),
		new NamedAddress(0x951b4L, "g_sos_midi_message",
			"[AUDIO] The 4-byte assembled MIDI message staged for the SOS music driver (0x951b4=status, "
			+ "0x951b5=data1, 0x951b6=data2, 0x951b7=data3). sos_dispatch_midi_event (0x44e0d) fills it from the "
			+ "event stream and passes ds:0x951b4 to driver method 0 (event-out). (Mode flag = 0x951cc.)"),
		new NamedAddress(0x951ccL, "g_sos_voice_alloc_mode",
			"[AUDIO] sos_dispatch_midi_event mode: 0 = send the MIDI event straight to the driver; !=0 = run "
			+ "dynamic virtual-channel allocation first (map logical->physical voice + replay saved controllers)."),
		new NamedAddress(0x951d0L, "g_sos_timer_tick_flag",
			"[AUDIO] Set to 1 by the FAR timer ISR sos_sequencer_timer_isr (0x44dc4); polled to pace per-tick work."),
		new NamedAddress(0x92f9cL, "g_sos_driver_vtable",
			"[AUDIO] Per-slot SOS music-driver method records (5 slots x 0x48 bytes). Each record = 12 x 6-byte "
			+ "FAR method ptrs; only m0..m4 used: m0=event_out, m1=open, m2=close, m3=stop, m4=control. Filled "
			+ "by sos_alloc_driver_slot from the templates installed by install_sos_driver_vtables."),
		new NamedAddress(0x920f0L, "g_sos_driver_type_ids",
			"[AUDIO] Per-slot driver type id (dword[5]): 0xa003=passthrough MIDI, 0xa005/0xa007=DMA software "
			+ "synth, 0xa00a=Gravis wavetable. 0=free slot. Set by sos_alloc_driver_slot."),
		new NamedAddress(0x920b4L, "g_sos_driver_active",
			"[AUDIO] Per-slot driver active flag (dword[5]); set after open, cleared by sos_free_driver_slot."),
		new NamedAddress(0x979c4L, "g_sos_timer_event_table",
			"[AUDIO] 16-entry SOS timer-event table: per entry far-callback offset @+0 (0x979c4) + selector @+4 "
			+ "(0x979c8), stride 6; parallel rate[] at 0x97a24 (stride 4). Managed by sos_timer_register_event/"
			+ "sos_timer_remove_event."),
		new NamedAddress(0x741f8L, "g_sos_timer_base_rate",
			"[AUDIO] Current SOS master timer rate (Hz) = max of all registered timer-event rates; drives the "
			+ "8253 PIT reload (0x1234dc/rate)."),
		new NamedAddress(0x741fcL, "g_sos_timer_event_countdown",
			"[AUDIO] Per-event tick countdown (parallel to g_sos_timer_event_table); sos_timer_dispatch fires the "
			+ "event when it reaches its reload and reloads it (rate-divider scheduling)."),
		new NamedAddress(0x97b64L, "g_sos_timer_event_count",
			"[AUDIO] Number of active SOS timer events (loop bound in sos_timer_dispatch; max 0x10)."),
		new NamedAddress(0x931b8L, "g_extmidi_out_callback",
			"[AUDIO] Far-ptr (offset 0x931b8 / selector 0x931bc) of the external MIDI output sink used by the "
			+ "a003 passthrough driver (set by its method 4 sos_drv_a003_m4_set_output, called by its method 0)."),
		new NamedAddress(0x72908L, "g_sos_sequence_ctx_table",
			"[AUDIO] Per-track MIDI sequence playback context (passed to the tick ISR sos_sequence_timer_tick)."),
		new NamedAddress(0x93164L, "g_sos_driver_descriptor",
			"[AUDIO] Far-ptr (offset 0x93164 / selector 0x93168, per track *6) to the active driver's capability "
			+ "descriptor: +0x38 = sequence tick rate (Hz), +0x40 = per-channel voice capability table."),
		new NamedAddress(0x73708L, "g_sound_master_volume",
			"[AUDIO] Master music volume scalar applied after the per-channel volume in sos_dispatch_midi_event."),
		new NamedAddress(0x729d8L, "g_midi_logical_to_physical_chan",
			"[AUDIO] Virtual-channel allocator map: logical MIDI channel -> allocated physical voice/channel "
			+ "(0xff = unallocated). Indexed by [track<<7 | song<<4 | channel]. Used when g_sos_voice_alloc_mode!=0."),
		new NamedAddress(0x736b8L, "g_midi_physical_chan_busy",
			"[AUDIO] Physical-voice busy/usage table scanned to allocate a free voice (per driver, 16 entries)."),
		new NamedAddress(0x72ca8L, "g_midi_physical_to_logical_chan",
			"[AUDIO] Reverse map: physical voice -> logical MIDI channel (0xff = free)."),
		new NamedAddress(0x72cf8L, "g_midi_physical_chan_device",
			"[AUDIO] Reverse map: physical voice -> owning song/device index."),
		new NamedAddress(0x72d48L, "g_midi_channel_saved_state",
			"[AUDIO] Saved per-logical-channel MIDI controller state (program @0x72d4b, plus controllers at "
			+ "0x72d48/49/4a/4c: volume/pan/etc, 0xff=unset). Replayed onto a freshly allocated voice so it "
			+ "inherits the channel's program/volume/pan before the triggering event is sent."),
		new NamedAddress(0x73388L, "g_midi_channel_patch",
			"[AUDIO] Per-(track,channel) instrument patch/bank used during voice allocation."),
		new NamedAddress(0x7372cL, "g_midi_channel_raw_volume",
			"[AUDIO] Per-(slot,channel) raw (pre-scale) channel volume captured on a CC#7 volume event."),
		new NamedAddress(0x83ed4L, "g_active_sound_handles",
			"[SFX] Active sound-effect handle table (stride 0x9a). Handle fields seen: +0 emitter/name ptr, +4 "
			+ "id/vol, +5 voice/sample slot, +6 pan side, +0x22 emitter param, +0x26 SOS voice struct. Slot via "
			+ "find_free_slot_83ed4 (0x277b6); per-frame vol/pan by update_active_sounds (0x27b05)."),
		new NamedAddress(0x848f4L, "g_sound_sample_table",
			"[SFX] Loaded sound-sample descriptor table (stride 0xc); +0xb = mixer-sample slot. Indexed by "
			+ "resolve_sound_sample (0x27951); populated by load_sound_sample (0x277db)."),
		new NamedAddress(0x848fcL, "g_sound_sample_count",
			"[SFX] Number of entries in g_sound_sample_table (bounds check in resolve_sound_sample)."),
		new NamedAddress(0x84874L, "g_sound_voice_descriptors",
			"[SFX] Per-loaded-sample voice descriptor pointers (stride 4), indexed by sound-handle+5; start_sound_voice "
			+ "reads sample length/data here before submitting to the SOS mixer."),
		new NamedAddress(0x7f550L, "g_sound_enabled",
			"[AUDIO] Sound-system enabled flag (0xffffffff at sos init 0x15988, 0 at shutdown). play_sound_effect "
			+ "and friends no-op when 0."),
		new NamedAddress(0x7f4dcL, "g_sos_digital_device",
			"[AUDIO] The SOS DIGITAL voice device handle (slot) used by sos_submit_voice/sos_stop_voice for SFX + "
			+ "speech voices (distinct from the music driver slots)."),
		new NamedAddress(0x71d05L, "g_message_box_state",
			"Message-box descriptor/state struct passed to show_message_box 0x2508f (set up by show_resource_error_box 0x2632a)."),
		new NamedAddress(0x811b4L, "g_active_weapon_attrs",
			"Active weapon WeaponAttributes struct (dword[0x14]), filled by activate_weapon_item 0x184ab / apply_weapon_action_attributes from the equipped item's 0x05 WeaponAction block. Fields (dword index): [0]=anim, [1]=ammo cap (=0x811b8), [2]=bullet/projectile def id, [3]=bullet delay, [4]=fire SFX, [0xc]=ammo item id (=g_active_weapon_ammo_id 0x811e4), [0x12]=UI icon. trigger_weapon_fire reads it to fire."),
		new NamedAddress(0x811e4L, "g_active_weapon_ammo_id",
			"Field [0xc] of g_active_weapon_attrs = the AMMO item id the weapon consumes (0 = no ammo / melee). activate_weapon_item passes it to query_player_inventory to get the carried count (g_active_weapon_ammo); trigger_weapon_fire checks it vs the cap. The flag byte at +1 (0x811e5, bit 0x80) marks the infinite/special-ammo case."),
		new NamedAddress(0x83e6cL, "g_active_weapon_ammo",
			"Current carried ammo COUNT for the active weapon (set by activate_weapon_item via query_player_inventory of g_active_weapon_ammo_id; the HUD ammo number). trigger_weapon_fire blocks the shot when this is 0."),
		new NamedAddress(0x83e70L, "g_active_weapon_item_id",
			"Item id of the currently-equipped weapon (set by activate_weapon_item + trigger_weapon_fire). The selected weapon slot itself is g_selected_item_secondary (0x81038)."),
		new NamedAddress(0x83e74L, "g_active_weapon_ammo_cap",
			"Ammo capacity / max for the active weapon (0x100, 1, or from the 0x05 SetAmmoCap field). Compared against g_active_weapon_ammo_id usage in trigger_weapon_fire."),
		new NamedAddress(0x7fe00L, "g_active_weapon_ptr",
			"Pointer to g_active_weapon_attrs (0x811b4); the indirection trigger_weapon_fire / fire helpers dereference for the active weapon."),
		new NamedAddress(0x7fe0cL, "g_pending_shot_scale",
			"DAMAGE multiplier for the pending shot (NOT velocity — corrected; field +0x16 = the projectile's damage, "
			+ "read by compute_projectile_hit_damage / the player-hit path). trigger_weapon_fire computes it as a COUNT "
			+ "(loop at 0x17762: while ammo word[def+2] >= cost bx { scale++; ammo -= cost }) — i.e. how many pellets/"
			+ "ammo-units the shot fires; fire_pending_weapon_shot then does proj+0x16 *= scale and clears it. So a shot "
			+ "of N units deals N x the per-unit damage (before the [1/2,1) damage RNG). PLAYTEST-CONFIRMED via the "
			+ "g_entity_damage_rng [V,2V] reconciliation."),
		new NamedAddress(0x819d8L, "g_entity_def_cache_head",
			"Head ptr of the entity-definition attribute LRU cache list (entity_def_cache_lookup 0x1e2f6). Node+0 = next."),
		new NamedAddress(0x81e14L, "g_entity_def_cache_count",
			"Entry count of the entity-definition attribute LRU cache (max 10; append vs evict-tail boundary)."),
		new NamedAddress(0x819dcL, "g_entity_def_cache_nodes",
			"Node storage for the entity-definition attribute LRU cache: 10 x 0x6c-byte records."),
		new NamedAddress(0x763b0L, "g_dir_data",
			"Asset data-dir path prefix (set by parse_config_ini_paths 0x10f6c from CONFIG.INI "
			+ "DESTINATIONPATH). Prepended by build_game_path for ICONS.ALL, BACKDROP.RAW, DAS files."),
		new NamedAddress(0x764f0L, "g_dir_gdv",
			"Cutscene-video dir prefix = SOURCEPATH + 'GDV\\' (CONFIG.INI). GDV files open as "
			+ "<g_dir_gdv><name>.GDV; player entry 0x2059d."),
		new NamedAddress(0x76400L, "g_dir_midi",
			"MIDI-music dir prefix = DESTINATIONPATH + 'MIDI\\' (set by parse_config_ini_paths 0x10f6c)."),
		new NamedAddress(0x76450L, "g_dir_digi",
			"Digital-audio dir prefix = DESTINATIONPATH + 'DIGI\\' (set by parse_config_ini_paths 0x10f6c)."),
		new NamedAddress(0x701ecL, "g_cfg_file_arg",
			"ROTH.RES/cmdline FILE=<name> value (handler 0x10801); also sets flag word 0x76750."),
		new NamedAddress(0x7023cL, "g_cfg_das_arg",
			"ROTH.RES/cmdline DAS=<name> value (handler 0x10832): DAS asset base name/path."),
		new NamedAddress(0x7028cL, "g_cfg_snd_arg",
			"ROTH.RES/cmdline SND=<name> value (handler 0x10851): the .SFX sound-bank filename "
			+ "(default 'test.sfx' baked here; retail FX22.SFX). .SFX extension applied by set_cfg_asset_name."),
		new NamedAddress(0x702dcL, "g_cfg_das2_arg",
			"ROTH.RES @-block DAS2=<name> value (+.DAS): secondary DAS archive filename."),
		new NamedAddress(0x90a8eL, "g_player_x",
			"[HIGH] Player world X. Initialised from map metadata INIT_X_POS; read by movement, "
			+ "collision, rendering, and aiming."),
		new NamedAddress(0x90a96L, "g_player_y",
			"[HIGH] Player world Y. Initialised from map metadata INIT_Y_POS."),
		new NamedAddress(0x90a92L, "g_player_z",
			"[HIGH] Player world Z / height. Initialised from map metadata INIT_Z_POS."),
		new NamedAddress(0x90a8aL, "g_player_angle",
			"[HIGH] Player facing angle (16-bit). Initialised from map metadata INIT_ROTATION; "
			+ "indexes g_sincos_table to build movement and view vectors."),
		new NamedAddress(0x72080L, "g_sincos_table",
			"[HIGH] Signed sine lookup table, 256 entries of 0x200-masked angle (word each). "
			+ "Cosine is read from the same table at a +0x80 entry (quarter-phase) offset. "
			+ "Movement reads scale table values down by 'sar 8' per frame."),
		new NamedAddress(0x8aa46L, "g_atan_table",
			"[HIGH, lift-confirmed 2026-06-14] Arctangent lookup table (int16[], ~0x41 entries) used "
			+ "by atan2_bearing (0x3c201): after octant-folding to the first octant, it searches this "
			+ "table for the entry closest to (lo*0x4000)/hi to get the angle index. Distinct from "
			+ "isqrt_fixed's table at 0x8a446."),
		new NamedAddress(0x90a9cL, "g_image_surface",
			"[image/surface] Global 0x18-byte image-surface descriptor (built by init_backdrop_image_surface 0x2fd21 via "
			+ "alloc_image_view_descriptor from the 0x71ef8 header). A blit-surface/clip-view over a fullscreen image "
			+ "(likely the backdrop)."),
		new NamedAddress(0x90aa8L, "g_map_geometry_buffer",
			"[HIGH] Base pointer of the loaded .RAW geometry blob (header + vertices + sectors + "
			+ "faces + texture maps + map metadata). The dominant map-geometry consumer global."),
		new NamedAddress(0x90aa4L, "g_map_objects_buffer",
			"[HIGH] Base pointer of the loaded .RAW objects section (object containers / entities)."),
		new NamedAddress(0x91df8L, "g_sector_count",
			"[map-geometry] Cached count of SECTOR records in the current map. Set from the geometry-buffer "
			+ "header by flag_sectors_with_objects / init_sector_object_state; read by resolve_object_owner_sector."),
		new NamedAddress(0x91dfcL, "g_sector_section_offset",
			"[map-geometry] Cached buffer-relative offset of the SECTOR section within g_map_geometry_buffer "
			+ "(its header +4). Set by flag_sectors_with_objects / init_sector_object_state; resolve_object_owner_sector "
			+ "adds it to index*0x1a to get a sector record offset."),
		new NamedAddress(0x8c120L, "g_locate_query_x",
			"[MED-HIGH] X of the query point for the point-in-sector search, written (<<0x10 to 16.16) by "
			+ "locate_sector_at_position (0x3ee4b) and read by the search helpers (0x3eceb/0x3edf0)."),
		// ---- Collision bound block (0x8c130..0x8c144) + current-edge endpoints (read by clip_query_circle_to_edge 0x3fe2d).
		//      The bound block = the moving entity's ±radius reach, set by move_player/entity_with_collision. ----
		new NamedAddress(0x8c130L, "g_collision_box_max",
			"[collision bound block] Upper bound of the moving entity's collision reach (= +radius, signed) used by "
			+ "clip_query_circle_to_edge for the AABB reject vs an edge. Set by move_player/entity_with_collision "
			+ "(player radius 0x1c)."),
		new NamedAddress(0x8c134L, "g_collision_box_min",
			"[collision bound block] Lower bound of the moving entity's collision reach (= -radius). Pair of "
			+ "g_collision_box_max."),
		new NamedAddress(0x8c138L, "g_collision_radius_sq",
			"[collision bound block] Collision radius SQUARED — compared against the perpendicular distance^2 from the "
			+ "query circle to the edge in clip_query_circle_to_edge (penetration test). (0x8c13c = a sibling radius^2 "
			+ "used as the slide push-out numerator.)"),
		new NamedAddress(0x8c140L, "g_collision_corner_radius_sq",
			"[collision bound block] Radius^2 threshold for the rounded-corner case: if the query is within this of an "
			+ "edge ENDPOINT, clip_query_circle_to_edge pushes it radially around the corner (atan2_bearing + g_sincos_table)."),
		new NamedAddress(0x8c144L, "g_collision_radius",
			"[collision bound block] The (linear) collision radius — multiplied by unit sin/cos to offset the query "
			+ "position in the corner-rounding branch of clip_query_circle_to_edge."),
		new NamedAddress(0x8c1efL, "g_collision_edge_ax",
			"[collision] X of endpoint A of the wall/object edge currently being tested by clip_query_circle_to_edge "
			+ "(0x3fe2d); staged per-edge by clip_locate_query_to_object. Edge = A(0x8c1ef,0x8c1f1) -> B(0x8c1f3,0x8c1f5)."),
		new NamedAddress(0x8c1f1L, "g_collision_edge_ay",
			"[collision] Y of endpoint A of the current collision edge (see g_collision_edge_ax)."),
		new NamedAddress(0x8c1f3L, "g_collision_edge_bx",
			"[collision] X of endpoint B of the current collision edge (see g_collision_edge_ax)."),
		new NamedAddress(0x8c1f5L, "g_collision_edge_by",
			"[collision] Y of endpoint B of the current collision edge (see g_collision_edge_ax)."),
		new NamedAddress(0x90cc0L, "g_turn_view_scale_state",
			"[render] Current turn-view-scale state byte managed by update_turn_view_scale (0x3e22c): 0 = full-res "
			+ "viewport, +8/-8 = scaled (low-detail) viewport engaged while turning. Gated by g_blur_flag."),
		new NamedAddress(0x90bdeL, "g_max_step_height",
			"[collision] Max height the mover can STEP UP over an object/door box in resolve_collisions_against_objects "
			+ "(0x401cf): if the blocking box top is within this of the mover's feet, the move is allowed (step-over) "
			+ "instead of blocked. [hedged: exact unit = world Z]."),
		new NamedAddress(0x8c16cL, "g_collision_blocker_object",
			"[collision] Set to the object/door record that blocked the move in resolve_collisions_against_objects "
			+ "(0x401cf) when g_collision_hit_flags bit 2 is raised. The 'what stopped me' pointer."),
		new NamedAddress(0x8c128L, "g_locate_query_y",
			"[MED-HIGH] Y of the point-in-sector query position (see g_locate_query_x)."),
		new NamedAddress(0x8c124L, "g_locate_query_z",
			"[MED-HIGH] Z of the point-in-sector query position (see g_locate_query_x)."),
		new NamedAddress(0x90be8L, "g_geometry_selector",
			"[MED-HIGH] DPMI selector covering the geometry blob; sector records are accessed "
			+ "through it (e.g. in fixup_raw_sectors_after_load)."),
		new NamedAddress(0x85c50L, "g_das_collision_buffer",
			"[MED] Pointer to a per-entity definition/radius table; entry+2 holds the contact "
			+ "radius used by check_entity_player_contact."),
		new NamedAddress(0x90fe0L, "g_dynamic_entity_count",
			"[MED] Count of live dynamically spawned entities; capped at 0x10 in "
			+ "spawn_entity_at_position."),
		new NamedAddress(0x12570L, "g_move_speed_immediate",
			"[HIGH] The whole-game player MOVE_SPEED. This address is the IMMEDIATE OPERAND of the "
			+ "instruction at 0x12569 (`mov word [g_player_move_rate_counter], imm`). "
			+ "init_movement_tuning_from_first_map self-patches it from the first map's metadata "
			+ "+0x08. xref shows EXACTLY ONE writer (0x2f80a) and ZERO data readers: nothing after "
			+ "the first map can change the player's base speed (no item/script can raise it)."),
		new NamedAddress(0x90bdaL, "g_player_move_rate_counter",
			"[HIGH] Player movement-rate countdown. Each tick: dec; while >=0 just process velocity; "
			+ "on underflow reload to g_move_speed_immediate and apply decay (clamp +/-0x20 then "
			+ "halve) to the velocity accumulators. Higher MOVE_SPEED = decay applied less often = "
			+ "velocity persists longer = faster sustained motion (and bigger per-tick steps)."),
		new NamedAddress(0x90a80L, "g_player_vel_accum_x",
			"[HIGH] Player X velocity accumulator (input-driven, 16.16). On a decay tick (timer "
			+ "underflow): if |v|<=0x20 it snaps to 0 (deadzone), otherwise it is halved (sar 1). "
			+ "Input impulse is added every tick by apply_player_movement_input. The decay+input balance "
			+ "is the 'coast then settle' feel."),
		new NamedAddress(0x90a84L, "g_player_vel_accum_y",
			"[HIGH] Player Y velocity accumulator. See g_player_vel_accum_x."),
		new NamedAddress(0x8c110L, "g_player_height",
			"[MED-HIGH] Player height = metadata PLAYER_HEIGHT (+0x0a) * 2. Read by the movers "
			+ "(e.g. 0x422b6). Set once by init_movement_tuning_from_first_map."),
		new NamedAddress(0x8c148L, "g_max_climb",
			"[MED] Max step-up height = metadata MAX_CLIMB (+0x0c) * 2 + 1. Set once on new game."),
		new NamedAddress(0x90be0L, "g_min_fit",
			"[MED] Minimum opening the player fits through = metadata MIN_FIT (+0x0e) * 2. "
			+ "Set once on new game."),
		new NamedAddress(0x7674aL, "g_player_movement_enabled",
			"[MED] Gate for the player movement/velocity block at 0x12553 (runs when == 1)."),
		new NamedAddress(0x85484L, "g_map_first_load_flag",
			"[MED] First-load/new-map flag; -1 selects the default-spawn position reset path in "
			+ "the map orchestrator (0x10bbe)."),
		new NamedAddress(0x8a124L, "g_player_move_delta_x",
			"[HIGH, decompiler-verified] Per-frame player X translation, committed by "
			+ "commit_player_position_delta. ONLY writer is tick_moving_sector (store at 0x32cf0): the "
			+ "delta = g_frame_time_scale * platform speed_byte (sector+7), placed on X when the sector's "
			+ "+6 bit0x40 is set (else on Y). Carries the player when a scripted sector/platform moves, with "
			+ "no walk-substep collision -> the platform-carry wall-clip vector."),
		new NamedAddress(0x8a128L, "g_player_move_delta_y",
			"[HIGH, decompiler-verified] Per-frame player Y translation (see g_player_move_delta_x); "
			+ "receives the step when the moving sector's +6 bit0x40 is clear."),
		new NamedAddress(0x8a12cL, "g_player_move_delta_z",
			"[HIGH, decompiler-verified] Per-frame player Z translation (carry). tick_moving_sector "
			+ "forces this to 0 (horizontal movers); nonzero Z carry comes from the vertical mover path."),
		new NamedAddress(0x90aacL, "g_sector_geom_base",
			"[HIGH, decompiler-verified] Base pointer of the runtime sector geometry coordinate array. "
			+ "tick_moving_sector indexes it by the mover record's +0xe/0x10/0x12/0x14 word offsets to "
			+ "translate a moving sector's vertex/edge coordinates each frame."),
		new NamedAddress(0x85264L, "g_view_clip_plane",
			"View-depth clip plane value used by clip_sector_walls_to_view (0x2d793): walls are clipped where a "
			+ "vertex's transformed view coord gs:[vtx+4] crosses this plane (near-plane / horizon depth)."),
		new NamedAddress(0x85310L, "g_camera_sin",
			"Camera yaw sine, computed by transform_world_vertices (0x2a814) from g_sprite_view_angle via "
			+ "floorceil_rotation_sincos; used with g_camera_cos in rotate_point_2d to rotate world vertices into view space."),
		new NamedAddress(0x85312L, "g_camera_cos",
			"Camera yaw cosine (companion of g_camera_sin); the 2D rotation basis for the per-frame vertex transform."),
		new NamedAddress(0x90a04L, "g_view_offset_x",
			"Camera->world X translation added to each vertex's world X (vtx+8) by transform_world_vertices before rotation (makes coords camera-relative). Effectively -cameraX."),
		new NamedAddress(0x90a06L, "g_view_offset_y",
			"Camera->world Y translation added to each vertex's world Y (vtx+0xa) by transform_world_vertices before rotation. Companion of g_view_offset_x."),
		new NamedAddress(0x85324L, "g_frame_time_scale",
			"[HIGH, decompiler-verified] Per-frame time/delta scalar. Multiplies the platform speed byte "
			+ "in tick_moving_sector (step = scale * speed) and also drives the time-scaled head-bob "
			+ "(eye-height routine near 0x3ed8d) - so platform carry distance is frame-time normalized, "
			+ "not a fixed per-tick step."),
		new NamedAddress(0x90c12L, "g_player_sector",
			"[HIGH, decompiler-verified] Index of the sector the player currently stands in. "
			+ "apply_moving_sector_carry (0x34a8e) only carries the player when a moving sector's index "
			+ "equals this - the membership gate for the platform-carry clip."),
		// --- Save / load state stream (see ROTH_speedrun_leads.md) ---
		new NamedAddress(0x85c30L, "g_object_table_header",
			"[HIGH, decompiler-verified] Pointer to the live object/entity table header. Layout: +0 magic "
			+ "word 0x7533, +4 (word) offset to the first object record, +6 (word) active object COUNT. "
			+ "Records are VARIABLE-LENGTH (each prefixed by a size word at +0), packed contiguously from "
			+ "+4. read_raw_state_stream / write_raw_state_stream iterate exactly header[+6] objects. The "
			+ "save/load glitch hinges on this being the LIVE count (incl. a just-fired projectile), with "
			+ "the loader patching in place rather than reconciling the table.\n"
			+ "UNIFICATION (2026-06-13): this is ALSO the .RAW COMMANDS section. load_raw_map_file carves "
			+ "the region 0x85c30 up to 0x85c44 at exactly COMMANDS_SECTION_SIZE (header+0x1a). The records "
			+ "here are .RAW commands (BTI RAW.md): record +0 SIZE, +2 COMMAND_MODIFIER, +3 COMMAND_BASE "
			+ "(the opcode -- THIS is the 'TYPE byte at +3' the save/load uses), +4 NEXT_COMMAND (1-based "
			+ "index resolved via g_object_ptr_array), +6.. ARGS. The HEADER fields double as the command "
			+ "section header: +6 COMMAND_COUNT, +8 ENTRY_COMMAND_COUNTS (15x4: {offset,count} per trigger "
			+ "category; category 1 at +8/+0xa = bases 0x08 & 0x02). FUN_000303ff (left-click trigger) walks "
			+ "category 1 and dispatches on `cmp byte[rec+3],0x02/0x08`. So 'object table' and 'command "
			+ "table' are the same buffer; +3 is the COMMAND_BASE/record-type. RENAME CANDIDATE: "
			+ "g_map_command_table (pending Alex confirm vs the dynamic-entity append behaviour)."),
		new NamedAddress(0x30780L, "g_command_dispatch_table",
			"[HIGH] The RAW map-command dispatch table (in the code segment, data-in-code). 128 4-byte "
			+ "function pointers indexed by COMMAND_BASE & 0x7f; called by execute_command_chain (0x3065a). "
			+ "64 slots implemented, rest = cmd_default_nop (0x30ab0). DUAL-USE: low bases 0x02..0x42 = "
			+ "map COMMAND handlers (called by execute_command_chain with the command record in ESI); high "
			+ "bases 0x45..0x67 = engine-INTERNAL active-effect ticks (called by the per-frame effect-pool "
			+ "loop with the effect record in EAX, advanced by g_frame_time_scale 0x85324; e.g. "
			+ "0x4c=tick_moving_sector) - NOT map-authorable. In-range undocumented: 0x06 (inert stub), "
			+ "0x0b (alias of 0x0a), 0x14/0x21 (real authorable texture commands). Full enumeration in "
			+ "ROTH_command_system_notes.md."),
		new NamedAddress(0x8a268L, "g_command_chain_interrupt",
			"[MED] Chain-interrupt flag. A command handler sets this to 1 to make execute_command_chain "
			+ "(0x3065a) break out after the current command (so multi-frame/animated commands like 0x21 "
			+ "advance one step per tick). Cleared when the animation reaches its end value."),
		new NamedAddress(0x8a104L, "g_anim_step_mode",
			"[MED] Index into g_anim_step_fn_table (0x71f30) selecting how an animated-texture counter "
			+ "(cmd 0x21) progresses (linear / ping-pong / etc). Set up by the animation command, "
			+ "cleared on completion."),
		new NamedAddress(0x71f30L, "g_anim_step_fn_table",
			"[MED] Table of counter-step functions (in the header/rodata region) indexed by "
			+ "g_anim_step_mode (0x8a104); called as (g_anim_step_fn_table[mode])(value) by the animated "
			+ "texture-counter command (0x21) to advance its counter."),
		new NamedAddress(0x8a0d8L, "g_object_ptr_array",
			"[HIGH, decompiler-verified] Pointer to the array of object-record pointers, built lazily by "
			+ "rebuild_object_pointer_array (0x33ea1) by walking the variable-length records. Doubles as "
			+ "the COMMAND-INDEX -> POINTER table: NEXT_COMMAND (command rec+4, 1-based) indexes this to "
			+ "resolve the next command in a chain (see g_object_table_header note). "
			+ "*g_object_ptr_array is the base; each entry -> one object record (obj+2 = state/flags byte "
			+ "restored for all objects, obj+3 = TYPE byte that selects which fields the save/load restores). "
			+ "When NULL it is rebuilt on demand - the indirection point between appending a new object "
			+ "(e.g. a fired projectile) and that object becoming addressable/iterable."),
		new NamedAddress(0x90fe4L, "g_dynamic_entity_table",
			"[HIGH] Base of the dynamic entity record array (0x1c-byte slots, cap 0x10), counted by "
			+ "g_dynamic_entity_count (0x90fe0) immediately preceding it. Allocated by "
			+ "spawn_entity_at_position (0x4254e), updated each frame by update_dynamic_entities (0x42872), "
			+ "saved/restored by load_state_dynamic_entities (0x4ef61). These are the engine's MOVING "
			+ "entities (e.g. projectiles). Slot layout (0x1c bytes): +0 dword -> the object record (0x10-"
			+ "byte RAW object) in the secondary buffer; +4 word heading (hi byte = angle index for "
			+ "sincos_lookup, decremented to turn on a blocked move); +6 word current sector index; +8 byte "
			+ "state flags (bit1 = inactive/skip, bit2 = timed/dying); +0xa word fractional-X accumulator; "
			+ "+0xc word fractional-Y accumulator; +0x10 dword self-pointer; +0x18 byte speed (<<2; spawn "
			+ "sets 8); +0x1a word lifetime/age counter (destroyed at 0x100)."),
		new NamedAddress(0x85c28L, "g_object_buffer_free",
			"[MED] Free-space gauge for the object/state buffer. spawn_entity_at_position requires it to "
			+ "be >= 0x12 (one object record) before allocating, else calls reserve_object_buffer_space."),
		new NamedAddress(0x8499cL, "g_current_proc_tag",
			"[MED, provisional] Debug/trace breadcrumb: several routines store their own (near-)address "
			+ "here on entry (spawn_entity_at_position writes 0x4254d). Looks like a 'last function "
			+ "entered' marker for crash diagnostics."),
		new NamedAddress(0x91e00L, "g_state_pool_a_count",
			"[MED] Active count of save/load pool A (see g_state_pool_a_records); reset and rebuilt by "
			+ "load_state_dynamic_entities (0x4ef61)."),
		new NamedAddress(0x91e04L, "g_state_pool_a_records",
			"[MED] Save/load pool A: array of 0x22-byte records with two relocatable pointer fields (+0 "
			+ "into base 0x85cf4, +4 into g_raw_state_secondary_buffer) and a sector re-link via 0x1e2f6. "
			+ "Restored alongside the dynamic entity table by load_state_dynamic_entities (0x4ef61)."),
		new NamedAddress(0x85c44L, "g_sfx_nodes",
			"[RESOLVED 2026-06-21] The map's SFX-node (placed sound-emitter) section, loaded from the .RAW "
			+ "file right after the command section. Header at 0x85c44: count = word[+2] (= high word of "
			+ "*0x85c44); 0x12-byte nodes from +4 (BTI RAW.md SFX node: key @+6, flags @+8, params @+0xc/+0xe). "
			+ "Bit 0x80 of byte[node+8] = ACTIVE/sounding flag: configured by setup_sfx_nodes (0x43c46), toggled "
			+ "by cmd_activate_sfx_node (.RAW cmd 0x10 — which calls stop_sound_handle_voice when it clears the "
			+ "bit, i.e. a real playing sound), looked up by find_sfx_node_by_key / collect_sfx_nodes_by_key, and "
			+ "persisted across save/load by save/load_sfx_node_active_state (0x43d53 / 0x43d98). Was mislabeled "
			+ "g_toggle_flag_records — the save-code looked like generic switch/secret toggles in isolation, but "
			+ "the active-bit drives actual sound voices = SFX. See lift_handoffs/NAME_CORRECTIONS.md."),
		new NamedAddress(0x89f5cL, "g_state_record_list_count",
			"[MED] Counter reset by load_state_record_list (0x3580c) before walking the chunk-4 record "
			+ "stream (incremented per record processed by load_state_object_links 0x35839)."),
		new NamedAddress(0x8a0e4L, "g_state_link_obj_ptr",
			"[MED] Link-context pointer restored by the chunk-4 header record (load_state_object_links, "
			+ "0x35839): saved as an offset, relocated on load by += g_object_table_header, so it points "
			+ "into the live object table. Companion to g_state_link_buf_ptr / g_state_link_word_a/b."),
		new NamedAddress(0x8a13cL, "g_state_link_buf_ptr",
			"[MED] Link-context pointer restored by the chunk-4 header record; relocated on load by += "
			+ "g_raw_state_primary_buffer (points into the primary RAW state buffer)."),
		new NamedAddress(0x8a0e8L, "g_state_link_word_a",
			"[MED] Companion word restored by the chunk-4 header record (purpose TBD; stored raw, no "
			+ "relocation)."),
		new NamedAddress(0x8a0ecL, "g_state_link_word_b",
			"[MED] Companion word restored by the chunk-4 header record (purpose TBD; stored raw)."),
		// --- Hidden developer mode (see ROTH_devmode_notes.md) ---
		new NamedAddress(0x7f560L, "g_dev_mode_flag",
			"[HIGH] Hidden dev/debug master enable, bit 0. BSS, zero in the shipped game. Set by "
			+ "enable_dev_mode (0x14464, never called) or a memory poke. Gates the map selector "
			+ "(W), the maphack overlay (L), and a sibling toggle. Read at 0x1444c/0x17fa4/0x3df9f."),
		new NamedAddress(0x7fe28L, "g_map_menu_active",
			"[HIGH] Map-selector menu on/off; toggled by dev_toggle_map_menu (the 'W' action)."),
		new NamedAddress(0x76710L, "g_map_list_ptr",
			"[MED] Pointer to the loaded map list the selector iterates."),
		new NamedAddress(0x7fe30L, "g_map_menu_selected_index",
			"[MED] Current map-selector selection; 0x173ab increments (wraps), 0x173d9 decrements."),
		new NamedAddress(0x7fe2cL, "g_map_menu_count",
			"[MED] Number of selectable maps in the dev map selector."),
		new NamedAddress(0x7fe34L, "g_map_menu_selected_entry",
			"[MED, lift-confirmed 2026-06-14] Pointer to the currently-selected map entry in "
			+ "g_map_list_ptr. WRITTEN by build_map_selector_menu (0x17453) when it emits the "
			+ "highlight marker for the selected item; READ by the Use/Enter handler "
			+ "(use_enter_key_handler 0x173f4) which copies it to the pending-map global 0x76630 "
			+ "to perform the warp."),
		new NamedAddress(0x7675dL, "g_map_menu_marker_selected",
			"[MED, lift-confirmed 2026-06-14] Glyph byte build_map_selector_menu (0x17453) emits "
			+ "(after a 0x01 text-style control byte) to mark the SELECTED map in the dev selector. "
			+ "Runtime-set (statically 0)."),
		new NamedAddress(0x76765L, "g_map_menu_marker_normal",
			"[MED, lift-confirmed 2026-06-14] Glyph byte build_map_selector_menu (0x17453) emits "
			+ "(after a 0x01 control byte) to mark NON-selected maps. Runtime-set (statically 0)."),
		new NamedAddress(0x81e34L, "g_object_select_easy_flag",
			"[MED-HIGH] Toggled by the F3 'game easy/hard' key (scancode 0x3d -> 0x1801c): "
			+ "'Automatic object select (easy)' (0x75e0b) vs 'Manual object select (normal)' "
			+ "(0x75ded). An aim/targeting assist."),
		new NamedAddress(0x7093dL, "g_keymap_table",
			"[HIGH] In-game keypress dispatch table: {u8 scancode, u32 handler} records, 5 bytes "
			+ "each, ending at 0x709f6. Walked by keymap_dispatch (0x14525). Decoded fully in "
			+ "ROTH_keymap.md (B=snapshot, W=map menu, L=dev toggle, T=vestigial, F7=no-op, etc.)."),
		new NamedAddress(0x7f36aL, "g_render_mode",
			"[HIGH] 3-state render mode toggled by the 'M' key: 0=textured, 1=flat color, "
			+ "2=unfinished (stays flat). Applied by apply_render_mode (0x14506)."),
		new NamedAddress(0x90cc4L, "g_flat_shading_flag",
			"[HIGH] When 0xff, the texture resolver (0x40dc4) skips each face's DAS texture and "
			+ "tags the surface with marker 0xfd + a flat color, so faces draw as a single colour."),
		new NamedAddress(0x85d14L, "g_texture_flat_color_table",
			"[MED] Per-index representative colour byte for the FLAT-shading path. Loaded from disk at "
			+ "runtime (0x2f323: mov edx,0x85d14; mov ecx,0x1000; mov ah,0x3f; int 21 reads 0x1000 bytes), "
			+ "so it is empty in the static EXE image. Read as byte[index + 0x85d14] at 0x40dcd, where it "
			+ "becomes the high byte of a 0xfd-tagged g_das_entry_status_table entry -> consumed as a flat "
			+ "fill colour (stored to 0x90a24 at 0x367ac), NOT as a DAS cache-slot index. Textured/"
			+ "blend spans use cache-slot indices < 0xfd from a separate (selector-relative) scan-conversion write."),
		// --- In-game text rendering globals (see ROTH_text_rendering_notes.md) ---
		new NamedAddress(0x70f12L, "g_font_descriptor",
			"[HIGH, decompiler-verified] Embedded game-font descriptor/data used by draw_text_to_buffer "
			+ "and measure_font_char_advance. Header: +0 max char (0x00ff), +2 line step/height "
			+ "(0x000b), +4 default advance (0x0003), followed by signed 16-bit per-character glyph "
			+ "offsets at +6+char*2. Nonzero offsets point to packed glyph records near the descriptor."),
		new NamedAddress(0x90a98L, "g_framebuffer_ptr",
			"[HIGH] Active framebuffer/screen buffer pointer used by positioned text, timed messages, "
			+ "menus, and screen capture."),
		new NamedAddress(0x85498L, "g_screen_pitch",
			"[HIGH] Current framebuffer pitch / screen width in bytes. Used by text rendering, UI "
			+ "drawing, snapshots, and framebuffer address calculations."),
		new NamedAddress(0x854a0L, "g_screen_height",
			"[MED-HIGH] Current screen height; snapshot writer stores this in the IFF/PBM BMHD."),
		new NamedAddress(0x90cbdL, "g_hires_line_doubling_flag",
			"[MED-HIGH] Nonzero hi-res/double-scanline mode flag used by text/UI paths. "
			+ "draw_text_at_screen_xy doubles Y and bumps text flags when this is set."),
		new NamedAddress(0x90bf4L, "g_render_viewport_height",
			"[renderer] 3D view-window height in scanlines, computed by configure_render_viewport (0x408d1) and "
			+ "clamped to 200. Read throughout render_world_scene (0x2868d/0x286ea/0x28792/0x2b538...) to bound the "
			+ "vertical span loops. Cf. g_render_width (0x90bf2) / g_render_height (0x90bf6)."),
		new NamedAddress(0x90bf2L, "g_render_width",
			"[renderer] 3D view-window WIDTH in pixels (configure_render_viewport). setup_render_projection_scale uses "
			+ "it for g_view_center_x = width>>1 and the g_image_surface clip bound (+0xe = width-1)."),
		new NamedAddress(0x90bf6L, "g_render_height",
			"[renderer] 3D view-window HEIGHT used for projection/centering: g_view_center_y = height>>1, and the "
			+ "vertical centering g_viewport_top_margin = (200 - height)/2. (g_render_viewport_height 0x90bf4 is the "
			+ "clamped-to-200 height used to bound the span loops.)"),
		new NamedAddress(0x90a70L, "g_view_center_x",
			"[renderer] Projection center X (= g_render_width >> 1) — the screen column the perspective LUT is built "
			+ "around. Set by setup_render_projection_scale; also feeds the world vertex transform."),
		new NamedAddress(0x90a72L, "g_view_center_y",
			"[renderer] Projection center Y / horizon row (= g_render_height >> 1). Set by setup_render_projection_scale; "
			+ "read by update_view_transform_params (-> 0x89ee6)."),
		new NamedAddress(0x90a34L, "g_span_callback",
			"[renderer] Optional per-span function pointer invoked by invoke_span_callback (0x39093) with the column/"
			+ "span index; 0 = no hook. A span post-process/debug seam."),
		new NamedAddress(0x90c0cL, "g_viewport_top_margin",
			"[renderer] Vertical centering offset of the 3D view in the 200-line screen = (200 - g_render_height)/2, "
			+ "computed by rebuild_projection_table."),
		new NamedAddress(0x8c200L, "g_projection_build_dir",
			"[renderer] Direction/stride (+1 or -1) the projection-LUT builder/interpolator walks — used to build the "
			+ "two horizon halves (above/below) of g_render_column_source_table. Set by build_projection_table."),
		new NamedAddress(0x8c204L, "g_projection_table_backup",
			"[renderer] Snapshot/backup copy of the perspective projection LUT g_render_column_source_table, taken after "
			+ "a full build; restored (mode 1) or narrow-copied (mode 2) by build_projection_table without rebuilding."),
		new NamedAddress(0x90bfcL, "g_render_viewport_reconfig",
			"[renderer] Pending projection-rebuild mode read+cleared by rebuild_projection_table: 0 = full rebuild, "
			+ "1 = restore from g_projection_table_backup, 2 = narrow-copy."),
		new NamedAddress(0x90bd4L, "g_view_scale_flags",
			"[renderer/video] View-window scale flags from the video mode: bit0 = halve viewport width, bit1 = halve "
			+ "viewport height (used by configure_render_viewport 0x408d1 and the renderer setup 0x2db4x/0x28aae). "
			+ "Aka the aspect/scale conditional in the recomp lift at 0x2625."),
		new NamedAddress(0x71dc4L, "g_vesa_page_bank_offset",
			"[video/VESA] Number of VESA banks between the on-screen page and the off-screen/second video page; "
			+ "set_vesa_bank_page2 (0x2e104) adds it to g_current_vesa_bank (0x71dc6) to reach the back page. Read by "
			+ "the banked present/double-buffer paths (0x11bd5/0x14bbd/0x2e0xx)."),
		new NamedAddress(0x90be6L, "g_video_mode_flags",
			"[video] Raw video-mode flag word. bit2 (0x4) selects the taller double-height VGA variant in "
			+ "program_vga_display_mode; low 2 bits index the Misc-Output sync table 0x71dc0; also drives the "
			+ "line-doubling recompute. Set from the mode word 0x90be4-family during mode init."),
		new NamedAddress(0x90be4L, "g_vga_mode_configured",
			"[video] Latch: 0 = the VGA CRTC/Sequencer mode has not yet been programmed this mode-set. "
			+ "program_vga_display_mode sets it to 1 (0xffff in raw/blocked modes); blank_active_video_page/"
			+ "configure_render_viewport check it to (re)program on demand."),
		new NamedAddress(0x90c1aL, "g_render_shade_level",
			"[renderer] Current global lighting/shade level index, set by set_render_shade_level (0x2d6a8) which "
			+ "SMC-patches the matching shade constants into the span rasterizers. Indexes the per-level constant "
			+ "tables 0x71db4/0x71dba."),
		new NamedAddress(0x71db4L, "g_shade_const_table_a",
			"[renderer] Per-shade-level constant table (word per level). set_render_shade_level (0x2d6a8) reads "
			+ "word[idx*2] and SMC-patches its low byte into 0x36d4f/0x36d5f and high byte into 0x399d8 in the span "
			+ "drivers. Parallel to g_shade_const_table_b (0x71dba)."),
		new NamedAddress(0x71dbaL, "g_shade_const_table_b",
			"[renderer] Per-shade-level constant table (word per level), parallel to g_shade_const_table_a. "
			+ "set_render_shade_level patches its low byte into 4 floor/ceil span sites and high byte into 6 more "
			+ "(0x37062/0x370a4/0x3b7xx/0x3b8xx). See lift_handoffs/2d6a8_set_render_shade_level.md."),
		new NamedAddress(0x8c1f8L, "g_dos_transfer_buffer_linear",
			"[OS/DPMI] Linear (protected-mode) address of the 64KB conventional-memory DOS transfer buffer, "
			+ "computed as realModeSeg<<4 by ensure_dos_transfer_buffer (0x40b08). 0 until first allocated. Used to "
			+ "stage data for real-mode INT 21h file I/O under DOS/4GW."),
		new NamedAddress(0x8c1fcL, "g_dos_transfer_buffer_selector",
			"[OS/DPMI] Real-mode segment / DPMI selector returned by dpmi_alloc_dos_memory for the DOS transfer "
			+ "buffer (paired with g_dos_transfer_buffer_linear 0x8c1f8). Set once by ensure_dos_transfer_buffer."),

		// --- Floor/ceiling edge-walker data structures (handoff lift_handoffs/3b1c1_floorceil_edge_walker.md) ---
		// --- Map overlay render state (render_map_geometry 0x2e954) ---
		new NamedAddress(0x7f36eL, "g_debug_map_enabled",
			"[map / DEV] On/off toggle for the dev wireframe map overlay. The per-frame refresh (0x103bf) draws the "
			+ "map (draw_map_overlay) only when this is nonzero. Toggled by the 'L' dev-key handler (0x1444c) — but "
			+ "ONLY when g_dev_mode_flag (0x7f560) bit0 is set; otherwise that handler forces it to 0. Shipped game "
			+ "leaves dev mode off, so this stays 0 and the overlay never shows. (Adjacent 0x7f36c/0x7f36f are "
			+ "vestigial dev toggles — written by the same key cluster but never read.)"),
		new NamedAddress(0x85438L, "g_map_buffer_pitch",
			"[map] Row pitch (bytes/scanline) of the map destination buffer; = g_screen_pitch when drawing the "
			+ "overhead map into g_render_target_buffer. Row stride in draw_bresenham_line."),
		new NamedAddress(0x8543cL, "g_map_buffer_base",
			"[map] Base pointer of the map destination buffer (= g_render_target_buffer for the on-screen map)."),
		new NamedAddress(0x85440L, "g_map_scale_x",
			"[map] World->map horizontal scale (16.x fixed) computed by render_map_geometry to fit the world into "
			+ "the map rect."),
		new NamedAddress(0x85444L, "g_map_scale_y",
			"[map] World->map vertical scale, paired with g_map_scale_x (aspect-corrected by the rect +0x12/+0x13)."),
		new NamedAddress(0x8545aL, "g_map_world_center_x",
			"[map] World-space X the map is centered on (the player/view center, from the descriptor +2)."),
		new NamedAddress(0x8545cL, "g_map_world_center_y",
			"[map] World-space Y the map is centered on (descriptor +6)."),
		new NamedAddress(0x85460L, "g_map_screen_center_x",
			"[map] Map-rect center X in screen pixels (half the rect width) — the pivot the scaled world maps onto."),
		new NamedAddress(0x8545eL, "g_map_screen_center_y",
			"[map] Map-rect center Y in screen pixels (half the rect height)."),
		new NamedAddress(0x85458L, "g_map_draw_color",
			"[map] Current map line color (low byte); high byte 0xff selects XOR draw mode in draw_bresenham_line."),
		new NamedAddress(0x8bfc0L, "g_secondary_door_pool",
			"[world/doors] Secondary door pool (max 6, stride 0x2c), distinct from the animating g_door_pool. "
			+ "Allocated by alloc_secondary_door_record (0x3d7b9); record[0]=sector id."),
		new NamedAddress(0x8bfbcL, "g_secondary_door_count",
			"[world/doors] Live count in g_secondary_door_pool (0x8bfc0)."),
		new NamedAddress(0x84944L, "g_current_decoded_frame",
			"[DAS/animation] The frame index most recently decoded by decode_das_anim_frame (0x2c5c5); "
			+ "select_surface_anim_frame (0x2b5ea) compares against it to detect a frame change and invalidate the "
			+ "cached entry."),
		new NamedAddress(0x8c944L, "g_floorceil_vertex_count",
			"[renderer floor/ceil] u16 vertex count, immediately precedes g_floorceil_vertex_records (0x8c946). "
			+ "Set by build_floorceil_vertex_records (0x3bbb0)."),
		new NamedAddress(0x820c1L, "g_message_cache_head",
			"[UI/text cache] Head of the 32-node MRU timed-message text cache (each node 0x20 bytes: +0 next, +4 key, "
			+ "+8 len, +0xa color, +0xc text). Built by init_freelist_820c1; get/put = lookup_cached_timed_message "
			+ "(0x1e7c3) / store_cached_timed_message (0x1e827)."),
		new NamedAddress(0x8a436L, "g_clip_boundary",
			"[renderer floor/ceil clip] The current boundary value clip_one_boundary (0x3b506) clips the polygon "
			+ "vertex list against (Sutherland-Hodgman); the enter/leave-crossing emitters compute each vertex's "
			+ "distance relative to it."),
		new NamedAddress(0x8a3ccL, "g_clip_output_vertex_count",
			"[renderer floor/ceil clip] Output vertex counter for the Sutherland-Hodgman clip pass — incremented by "
			+ "the crossing emitters/interpolator (0x3b5a8/0x3b5c2/0x3b5d2) as clip_one_boundary writes the clipped "
			+ "polygon into its output buffer."),
		new NamedAddress(0x8c946L, "g_floorceil_vertex_records",
			"[renderer floor/ceil] Projected polygon-vertex record array, stride 0xc: +0 screenX, +2 screenY, +4 "
			+ "depth, +6 shade idx, +8 texcoordB, +0xa texcoordA (textured path). A vertex RING — the edge-walk "
			+ "treats consecutive elements as edges (next vertex's +0/+2 = this +0xc/+0xe). Produced by 0x3bbb0, "
			+ "consumed by rasterize_floorceil_polygon (0x3b1c1)."),
		new NamedAddress(0x8cd0cL, "g_floorceil_span_records",
			"[renderer floor/ceil] Per-scanline span table, stride 0x18, indexed by Y. Two 0xc-byte halves: LEFT @ "
			+ "+0, RIGHT @ +0xc (aliased as 0x8cd18). Each half: +0 edgeX, +2 texcoord, +4 texU, +6 texV, +8 texW "
			+ "(dword). Edge X written by the 0x3b1c1 edge-walk; texcoords by 0x3b8b7/0x3badf/0x3b84a; read by the "
			+ "floor/ceil span driver per scanline."),
		new NamedAddress(0x854a8L, "g_scanline_dest_offset_table",
			"[renderer/video] dword[Y] = Y * g_screen_pitch (0x85498) = framebuffer byte offset of scanline Y. Built "
			+ "by build_scanline_dest_offset_table (0x2fb49); read by all three span drivers (wall 0x374xx, sprite "
			+ "0x39ba5, floor/ceil 0x3ab39) to find each scanline's destination."),
		new NamedAddress(0x8a434L, "g_floorceil_clip_flags",
			"[renderer floor/ceil] Polygon clip flags set by rasterize_floorceil_polygon: low byte 0xff = clipped on "
			+ "the X (left/right) bounds, high byte 0xff00 = clipped on Y (top/bottom). Drives build_floorceil_clip_edges "
			+ "(0x3b4a2)."),
		new NamedAddress(0x8a440L, "g_floorceil_edge_emitted",
			"[renderer floor/ceil] Set to -1 once the edge-walk has written at least one real edge into the span "
			+ "table (0 = none yet); used to handle degenerate single-point polygons."),
		new NamedAddress(0x8a43aL, "g_floorceil_edge_orientation",
			"[renderer floor/ceil] Per-edge orientation passed to the texcoord interpolators: 0/1 = steep edge "
			+ "(by slope sign), 2 = shallow/near-horizontal. Selects the half-step rounding direction in "
			+ "interp_floorceil_edge_texcoords (0x3b8b7)."),
		new NamedAddress(0x8a43cL, "g_floorceil_edge_x_end",
			"[renderer floor/ceil] Scratch: the current edge's END screen X (next vertex), written into the span "
			+ "table at the edge's far scanline by the edge-walk."),
		new NamedAddress(0x8a43eL, "g_floorceil_edge_x_start",
			"[renderer floor/ceil] Scratch: the current edge's START screen X (current vertex), written at the "
			+ "edge's near scanline by the edge-walk."),
		new NamedAddress(0x90a1eL, "g_floorceil_depth_clip_bias",
			"[renderer floor/ceil] Near-plane/depth clip threshold used by project_floorceil_edge_texcoord (0x3b724): "
			+ "8 by default, or g_column_clip_mode-0x78 when column-clipping is active."),
		new NamedAddress(0x90a20L, "g_floorceil_clip_scale",
			"[renderer floor/ceil] Secondary clip scale derived from the column-clip mode "
			+ "(-(((g_column_clip_mode-0x7c)>>2)-0x20)); paired with g_floorceil_depth_clip_bias (0x90a1e)."),
		new NamedAddress(0x90a22L, "g_render_textured_flag",
			"[renderer floor/ceil] Toggle: !=0 = textured floor/ceiling (run the full texcoord interpolation path), "
			+ "0 = flat-shaded (edge-walk fills X only, driver paints a solid shade). Gates 0x3bbb0/0x3b8b7/0x3b84a. "
			+ "(0x90a23 is the adjacent texture sub-mode byte.)"),
		new NamedAddress(0x90968L, "g_view_bound_right",
			"[renderer] View-window clip bbox, max X: a surface whose min X (rec+0x28) >= this is culled. Tested by "
			+ "rasterize_floorceil_polygon; pairs with g_view_bound_left (0x9096a)."),
		new NamedAddress(0x9096aL, "g_view_bound_left",
			"[renderer] View-window clip bbox, min X: a surface whose max X (rec+0x2c) < this is culled."),
		new NamedAddress(0x9096cL, "g_view_bound_bottom",
			"[renderer] View-window clip bbox, max Y: a surface whose min Y (rec+0x2a) > this is culled."),
		new NamedAddress(0x9096eL, "g_view_bound_top",
			"[renderer] View-window clip bbox, min Y: a surface whose max Y (rec+0x2e) <= this is culled."),
		new NamedAddress(0x90c0eL, "g_text_color_ramp_selector",
			"[HIGH] DPMI selector/base used by draw_text_to_buffer to load the 12-byte colour ramp "
			+ "for a control-code 0x01 colour byte. This is the source of the light/dark text gradient."),
		new NamedAddress(0x7675eL, "g_default_message_color",
			"[MED-HIGH] Default colour byte loaded by show_timed_message before queueing an in-game "
			+ "timed message."),
		new NamedAddress(0x82040L, "g_timed_message_color",
			"[HIGH] Current timed-message colour byte, copied into the control-coded output text by "
			+ "layout_timed_message_text. Also set per dialogue line from the dbase400.dat record's "
			+ "color field by read_next_dialogue_line (defaults to ' '/0x20) — a subtitle is a timed message."),
		new NamedAddress(0x824c9L, "g_timed_message_lines",
			"[HIGH] Timed-message line metadata array. Records are 0x14 bytes and include text "
			+ "bounds/position plus a pointer into g_timed_message_text_buffer."),
		new NamedAddress(0x825e1L, "g_timed_message_text_buffer",
			"[HIGH] Output buffer containing the control-coded timed-message strings emitted by "
			+ "layout_timed_message_text."),
		new NamedAddress(0x827e1L, "g_timed_message_line_count",
			"[HIGH] Number of active laid-out timed-message lines. render_text_ui calls "
			+ "render_active_timed_message only when this is nonzero."),
		new NamedAddress(0x827e5L, "g_timed_message_timer",
			"[HIGH] Timed-message lifetime counter. Queue functions set it (0x8c or 0x46); "
			+ "render_active_timed_message subtracts g_frame_time_scale and clears the line count "
			+ "on expiry."),
		new NamedAddress(0x83149L, "g_choice_option_records",
			"[HIGH] Array of pointers to the source choice records accepted by build_available_choice_menu. "
			+ "Maps visible choice index back to the underlying variable-length node record."),
		new NamedAddress(0x83189L, "g_choice_line_records",
			"[HIGH] Choice/menu text line-record array, 0x14-byte records consumed by "
			+ "render_choice_text_panel."),
		new NamedAddress(0x832c9L, "g_choice_text_buffer",
			"[HIGH] Control-coded choice/menu text buffer emitted by layout_timed_message_text from "
			+ "build_available_choice_menu."),
		new NamedAddress(0x83ac9L, "g_choice_line_count",
			"[HIGH] Active choice/menu line count. build_available_choice_menu writes it; "
			+ "render_choice_text_panel consumes it."),
		new NamedAddress(0x83acdL, "g_choice_interaction_mode",
			"[MED-HIGH] Dialogue/choice UI mode. 0 = inactive/normal, 1 = active choice hover/select "
			+ "mode, 2 = selected/activated state after activate_selected_choice_record."),
		new NamedAddress(0x71370L, "g_choice_selected_index",
			"[MED-HIGH] Current highlighted dialogue/choice index. -1 means no current keyboard "
			+ "selection; up/down handlers wrap it through the active line count."),
		new NamedAddress(0x81304L, "g_pending_choice_accept_index",
			"[MED-HIGH] 1-based visible choice index queued for activation. The frame code reads this, "
			+ "calls activate_selected_choice_record, then clears it."),
		new NamedAddress(0x83115L, "g_active_dialogue_context",
			"Active monologue: the LINE/SEGMENT COUNT of the current monologue (0 = none), returned by "
			+ "layout_timed_message_text (0x1f3d3, which builds the per-line segment records at "
			+ "g_dialogue_segments 0x827fd) and stored by dbase100_open_dialogue_window (0x1eabc) / _alt "
			+ "(0x1ebb4). render_text_ui (0x1f0e8) iterates segments 0..count-1 via g_dialogue_segment_index "
			+ "(0x83121). Paired with g_move_freeze_gate (the per-segment dwell timer). NOTE the name is a "
			+ "slight misnomer: it is a count, but != 0 == 'a monologue is showing'."),
		new NamedAddress(0x83121L, "g_dialogue_segment_index",
			"Current monologue segment/line index (render_text_ui 0x1f0e8), 0..g_active_dialogue_context-1. "
			+ "When the per-segment dwell g_move_freeze_gate expires, this increments and the next segment's "
			+ "dwell is computed; when it reaches the count, the monologue is cleared (g_active_dialogue_context=0)."),
		new NamedAddress(0x827fdL, "g_dialogue_segments",
			"Monologue segment record array (stride 0x14), built by layout_timed_message_text (0x1f3d3) from "
			+ "the dialogue text. Each record holds the line's screen rect (+0/+4/+8 used by render_text_ui) and "
			+ "a dwell weight (+0xc, summed into g_dialogue_dwell_divisor). g_active_dialogue_context = the record "
			+ "count."),
		new NamedAddress(0x83119L, "g_dialogue_line_dwell",
			"Per-line base dwell = (text_size * 0x46) / metric (0x1ec06); fed into the per-segment timer "
			+ "g_move_freeze_gate = g_dialogue_line_dwell * g_dialogue_timer_rate / g_dialogue_dwell_divisor. "
			+ "0 -> the segment uses the 0x7ffff wait-for-input state instead of an auto-timer."),
		new NamedAddress(0x82809L, "g_dialogue_timer_rate",
			"Runtime-set timer-rate constant (0 in the static image) used in the monologue dwell formula: "
			+ "g_move_freeze_gate = g_dialogue_line_dwell * THIS / g_dialogue_dwell_divisor. Calibrates the "
			+ "auto-advance speed to real time (so the per-line dwell, e.g. the ~2s inspect prompt, is "
			+ "frame-rate independent). This is why the keyboard choice-lock duration is the line's spoken "
			+ "dwell, NOT a hardcoded constant."),
		new NamedAddress(0x8311dL, "g_dialogue_dwell_divisor",
			"Sum of the segment dwell weights (g_dialogue_segments[i]+0xc) for the current monologue; the "
			+ "divisor in the per-segment dwell formula (so each line's dwell is its share of the total)."),
		new NamedAddress(0x83125L, "g_move_freeze_gate",
			"[MED-HIGH, lift-confirmed 2026-06-14] Dialogue/text line-advance timer AND movement "
			+ "freeze gate (one global, dual role). render_text_ui (0x1f0e8) uses it as the dialogue "
			+ "state: == 0x6ffff means the dialogue panel is showing (render_dialogue_text_panel); "
			+ "otherwise it is a per-line dwell COUNTDOWN decremented by g_frame_time_scale (dwell = "
			+ "DAT_00083119*DAT_00082809/DAT_0008311d), with 0x7ffff = waiting; when it hits <1 the "
			+ "next dialogue line is shown. BECAUSE of this, move_input_forward/backward (0x12686/"
			+ "0x12668) and the Use/Enter handler (0x173f4) suppress player input while "
			+ "g_dialogue_busy_flag (0x83aea) != 0 AND this == 0x6ffff — i.e. movement is "
			+ "frozen while a dialogue panel is up. (Paired with g_dialogue_busy_flag.)"),
		new NamedAddress(0x83129L, "g_dialogue_reveal_ramp",
			"Monologue text-panel reveal ramp: render_text_ui (0x1f0e8) ramps it from 4 (set by "
			+ "dbase100_open_dialogue_window) up to 0x20 by g_frame_time_scale each frame; "
			+ "render_dialogue_text_panel reads it to grow/reveal the monologue text window. Frame-rate "
			+ "scaled, so the reveal is time-based not frame-count."),
		new NamedAddress(0x83ae5L, "g_choice_reveal_ramp",
			"Choice-menu reveal ramp: set to 2 when the topics open (0x1f950), ramped to 0x20 by "
			+ "g_frame_time_scale each frame in render_choice_text_panel (0x1efa4), which uses it for the "
			+ "choice lines' vertical slide-in. RELEVANT TO THE KEYBOARD-DELAY QUESTION: the mouse hover "
			+ "(hit_test_dialogue_ui_action) highlights whatever line is under the cursor each frame "
			+ "regardless of this ramp, but the keyboard nav (choice_select_prev/next 0x1fb1e/0x1fc16) "
			+ "additionally no-ops while g_active_dialogue_context != 0 AND g_move_freeze_gate != 0x6ffff "
			+ "(the segment hasn't settled). So for the first few frames after topics appear, keyboard is "
			+ "suppressed while mouse works = the 'small delay' (~the ramp from 2 to 0x20 at "
			+ "g_frame_time_scale per frame)."),
		new NamedAddress(0x81eb2L, "g_dbase100_pending_topic",
			"[MED, 2026-06-14] Pending value staged by DBASE100 action opcode 0x1b (0x1d711, from "
			+ "0x7f46c) and committed by finalize_dbase100_chain (0x1d25e) at chain end (gated on "
			+ "[0x83c4c]==2). Looks like a deferred 'set information topic/id' commit. Near the "
			+ "DBASE100 queue state (0x81e18..0x81ef6)."),
		new NamedAddress(0x81e1cL, "g_dbase100_base",
			"[HIGH, 2026-06-14] Runtime base pointer of the loaded DBASE100 file. Section offset "
			+ "tables are read relative to it; e.g. the inventory offset table is g_dbase100_inventory_table "
			+ "(0x81e20). Used by init_inventory_item_object (0x18598) and the action interpreter's "
			+ "queue/callback paths (0x81e18..0x81ef6 region)."),
		new NamedAddress(0x81e20L, "g_dbase100_inventory_table",
			"[HIGH, 2026-06-14] Pointer to the DBASE100 inventory offset table (array of 4-byte entry "
			+ "offsets relative to g_dbase100_base 0x81e1c). init_inventory_item_object (0x18598) indexes "
			+ "it by inventory index to find an item entry."),
		new NamedAddress(0x81e30L, "g_value_reduction_factor",
			"[MED, 2026-06-14] Global value-reduction/scale factor (units 1/2048). The entity/health "
			+ "helper 0x320c6 computes v -= v*[0x81e30] >> 11 (v capped at 0x35c6); reset to 0 at "
			+ "level/frame init (0x17aa6/0x17bc6); also read/written in the 0x3e1xx path. DBASE100 "
			+ "action opcode 0x37 (0x1d72d) ADDS its operand to this — a script-tunable difficulty/"
			+ "damage-style scaling knob."),
		// --- DBASE100 choice/random state + deferred queue (2026-06-24, disasm-verified from execute_dbase100_chain 0x1d430) ---
		new NamedAddress(0x81e42L, "g_dialogue_action_queue",
				"[HIGH, 2026-06-24] Deferred DBASE100 action queue: up to 8 12-byte records "
				+ "{payload_ptr@+0, dword_count@+4, mode@+8}. eval_or_queue_dialogue_record_commands "
				+ "(0x1daea) appends here when g_dialogue_action_queue_count (0x81e3e) is active instead "
				+ "of running 0x1d430 immediately; drained by run_dialogue_action_queue (0x1d2aa). "
				+ "Parallel arrays: counts at 0x81e46, modes at 0x81e4a (stride 12)."),
		new NamedAddress(0x81ea2L, "g_dbase100_choice_cursor",
				"[HIGH, 2026-06-24] Saved record-stream cursor for the pending multiple-choice prompt, "
				+ "staged by the Choice-String handler (op 0x08, 0x1d4c3) so the interpreter can resume "
				+ "after the player picks. Set with g_dbase100_choice_remaining (0x81ea6), "
				+ "g_dbase100_choice_mode (0x81eaa), g_dbase100_choice_count (0x81eae)."),
		new NamedAddress(0x81ea6L, "g_dbase100_choice_remaining",
				"[HIGH, 2026-06-24] Saved remaining 4-byte-record count (ESI) for the pending DBASE100 "
				+ "choice prompt; restored when the choice resumes. See g_dbase100_choice_cursor (0x81ea2)."),
		new NamedAddress(0x81eaaL, "g_dbase100_choice_mode",
				"[HIGH, 2026-06-24] Saved eval-context/mode word ([ebp-0x8] of 0x1d430) for the pending "
				+ "DBASE100 choice prompt. See g_dbase100_choice_cursor (0x81ea2)."),
		new NamedAddress(0x81eaeL, "g_dbase100_choice_count",
				"[HIGH, 2026-06-24] Number of choices gathered for the pending DBASE100 prompt. If 1, "
				+ "execute_dialogue_branch (0x1dc02) auto-selects; if >1, dbase100_open_dialogue_window "
				+ "(0x1eabc) presents the menu. See g_dbase100_choice_cursor (0x81ea2)."),
		new NamedAddress(0x81eb6L, "g_dbase100_choice_record_indices",
				"[HIGH, 2026-06-24] Array mapping each displayed choice ordinal -> its source record "
				+ "index within the action chain (the [ebp-0x10] cursor ordinal). Filled by the "
				+ "Choice-String handler (op 0x08) as it appends each choice text; lets the engine "
				+ "resume at the chosen record after the menu returns."),
		new NamedAddress(0x707b3L, "g_mouse_x",
			"[MED-HIGH] Current mouse/cursor X coordinate. Used by cursor drawing and UI hit-tests."),
		new NamedAddress(0x707b7L, "g_mouse_y",
			"[MED-HIGH] Current mouse/cursor Y coordinate. Used by cursor drawing and UI hit-tests."),
		new NamedAddress(0x7fef0L, "g_current_cursor_entry",
			"[MED-HIGH] Pointer to the active 12-byte cursor/interaction entry, or 0 for no special "
			+ "cursor. draw_current_mouse_cursor_sprite reads this; dispatch_dialogue_ui_action writes it. "
			+ "THIS IS THE PICKED-UP / HELD-ON-CURSOR INVENTORY ITEM: left-click on a slot with nothing "
			+ "held sets it (0x1b99c, pick up); clicking another slot while held -> combine_held_item_with_target "
			+ "(0x1b26d), clicking the SAME slot (self) -> use_item_on_self (0x1b141, consume e.g. potion)."),
		new NamedAddress(0x7fef4L, "g_cursor_entry_table",
			"[MED] Base of 12-byte cursor/interaction entries used by the UI/action dispatcher "
			+ "(g_current_cursor_entry 0x7fef0 points at the active one; selected in FUN_0001b26d). "
			+ "Entries carry a sprite pointer and action metadata; exact struct still provisional. "
			+ "NOTE (per Alex, NOT a bug): the hand cursor over a dialogue subtitle is the AUDIO-SUBTITLE "
			+ "dismissal hand — a subtitle auto-dismisses on the audio-completion callback, so when NO "
			+ "audio is playing the cursor becomes a HAND to let the user manually close it (hand-vs-arrow "
			+ "keys on audio-playing state, not choice-hover)."),
		new NamedAddress(0x80af4L, "g_cursor_entry_count",
			"[MED] Number of entries in g_cursor_entry_table for the CURRENT tab/context = the count "
			+ "build_inventory_entry_list (0x19d30) produced by filtering g_inventory_slots to this "
			+ "tab's item-type category. When > 10 (the visible 5x2 grid), the scroll arrows appear "
			+ "(render_inventory_grid 0x1c163)."),
		new NamedAddress(0x80b38L, "g_cursor_active_list",
			"Active cursor-entry CONTEXT / inventory category (0x80b38): the item-type nibble currently "
			+ "displayed (build_inventory_entry_list filters g_inventory_slots by template[+5]&0xf == "
			+ "this). Indexes the per-context cursor (g_cursor_list_positions 0x80afc) and scroll "
			+ "(g_cursor_scroll_offsets 0x80b10) arrays. SET from g_inventory_active_tab (0x80b70) via "
			+ "g_inventory_tab_context_map (0x7123c). 5 contexts exist (the arrays hold 5); earlier note "
			+ "'0=items/1=weapons/2=third' undercounted."),
		new NamedAddress(0x80afcL, "g_cursor_list_positions",
			"Per-context cursor index array (5 dwords): g_cursor_list_positions[g_cursor_active_list] is "
			+ "the selected entry index into g_cursor_entry_table. Read/advanced by "
			+ "update_inventory_screen; when the cursor leaves the visible 10-cell window the paired "
			+ "g_cursor_scroll_offsets entry is bumped by 5 (one grid row)."),
		new NamedAddress(0x80b10L, "g_cursor_scroll_offsets",
			"Per-context inventory SCROLL OFFSET array (5 dwords, paired with g_cursor_list_positions "
			+ "0x80afc): g_cursor_scroll_offsets[ctx] = index of the FIRST visible item; the 5x2 grid "
			+ "shows entries [offset .. offset+9]. Steps by 5 (one row). render_inventory_grid (0x1c163) "
			+ "uses it to map entries onto cells and to gate the arrows: UP arrow when offset>0, DOWN "
			+ "arrow when offset < roundup5(g_cursor_entry_count)-10. update_inventory_screen adjusts it "
			+ "on cursor-move / arrow-click."),
		new NamedAddress(0x80b70L, "g_inventory_active_tab",
			"Current inventory TAB index (0..4), cycled by the tab key in update_inventory_screen "
			+ "(wraps at 5). select_inventory_tab (0x1a2b5) maps it through g_inventory_tab_context_map "
			+ "(0x7123c = {0,1,3,4,2}) into g_cursor_active_list (the displayed item-type category) and "
			+ "rebuilds the entry list."),
		new NamedAddress(0x7123cL, "g_inventory_tab_context_map",
			"5-byte tab->context map = {0,1,3,4,2}: g_cursor_active_list = "
			+ "g_inventory_tab_context_map[g_inventory_active_tab]. Sits immediately after the 13-entry "
			+ "g_ui_slot_layout_table (0x71208)."),
		new NamedAddress(0x811a0L, "g_inventory_arrow_state",
			"Bitmask of which inventory scroll arrows are currently drawn (render_inventory_grid "
			+ "0x1c163): bit0 = UP arrow shown, bit1 = DOWN arrow shown. Used to draw the active tile "
			+ "(0xa8 up / 0xb8 down) once and swap to the inactive tile (0xb0 / 0xc0) when scrolling "
			+ "hits an end, avoiding redundant redraws."),
		new NamedAddress(0x80bc4L, "g_inventory_hotspot_list",
			"Inventory hit-test/draw list built by render_inventory_grid (0x1c163): 8-byte records "
			+ "{x:word @+0, y:word @+2, w:byte @+4, h:byte @+5, action:word @+6}. The 10 grid cells get "
			+ "w/h 0x1c/0x1c (28px) and action 0x1c+slot (0x1c..0x25); the UP arrow gets w/h 9/0x18 and "
			+ "action 0x28, the DOWN arrow action 0x29. The action codes are what "
			+ "hit_test_dialogue_ui_action returns and dispatch_dialogue_ui_action routes (cells -> "
			+ "select, 0x28/0x29 -> scroll +/-5). Terminated by a 0-word."),
		new NamedAddress(0x80b30L, "g_inventory_ui_action",
			"Pending SYNTHETIC cursor-action mode for update_inventory_screen (keyboard equivalent of a "
			+ "mouse click on the current cell): 0 = none, 1 = SELECT/pickup (the 'S' key), 2 = USE (the "
			+ "'U' key; also sets g_inventory_synthetic_primary). Consumed next frame by "
			+ "hit_test_dialogue_ui_action (0x1ad2f), which converts it to the current cell's action code "
			+ "(cursor-scroll based) and clears it. Cleared to 0 at entry."),
		new NamedAddress(0x812fcL, "g_inventory_synthetic_primary",
			"Synthetic 'primary mouse button' flag for keyboard cell-activation. Set by "
			+ "hit_test_dialogue_ui_action (0x1ad2f) when g_inventory_ui_action==2 ('U' key). In the cell "
			+ "handler inside dispatch_dialogue_ui_action (0x1b82c) it stands in for "
			+ "g_cursor_primary_action_flag, so a keyboard 'use' fires use_item_on_self (0x1b141) / "
			+ "combine_held_item_with_target (0x1b26d) without a real click."),
		new NamedAddress(0x7fec0L, "g_inspect_popup_active",
			"Set to 1 by the inspect-popup modal loop (load_dbase300_resource_at_offset 0x196b9) while the item "
			+ "close-up window is open; 0 otherwise. Gates hit_test_dialogue_ui_action (0x1ad2f): when set, "
			+ "the hit-test skips the inventory-region test and (if the item has topics, "
			+ "g_inspect_info_available) returns action 4 = the INFO button. update_ui_overlay also keys "
			+ "off the dialogue state to defer the inventory panel."),
		new NamedAddress(0x81188L, "g_inspect_info_available",
			"Inspect-window INFO-button state / availability. Nonzero when the current item has discussion "
			+ "topics (so the 'I' speech-bubble info button is shown). hit_test_dialogue_ui_action returns "
			+ "action 4 only when this is set; dispatch action 4 (0x1b63d) drives the button's open-choices "
			+ "state machine (with g_inspect_popup_state 0x810c0) and records the click position "
			+ "(0x8118c/0x81190). Reset to 0 when the popup opens."),
		new NamedAddress(0x811acL, "g_ui_panel_scratch_handle",
			"DAS-cache-pool handle (g_das_cache_heap_handle 0x85c3c) for the active UI panel's scratch / "
			+ "background-save buffer. render_inventory_panel (0x1a399) allocates ~0x1130 bytes here, fills "
			+ "the 296x88 panel background and saves the framebuffer behind it, then releases it (via "
			+ "0x360b3) when the panel closes. Also read by show_message_box as an optional pre-composited "
			+ "box image. CORRECTION 2026-06-17: previously mislabeled a 'speaker portrait' - it is a "
			+ "render scratch buffer; ROTH has no NPC dialogue portraits."),
		new NamedAddress(0x80b3cL, "g_inventory_inspect_request",
			"Pending INSPECT request: pointer to the g_cursor_entry_table entry whose item close-up "
			+ "should be shown. Set by the Space key (scancode 0x39) in update_inventory_screen to the "
			+ "highlighted entry; the function tail resolves the item template, and if it has a close-up "
			+ "resource (template[+8], a dbase300 offset) calls load_dbase300_resource_at_offset (0x196b9) -> render_inspect_popup_window "
			+ "(0x18e9e) to open the inspect close-up window, then clears this to 0. (This is the inventory "
			+ "INSPECT close-up window (render_inspect_popup_window 0x18e9e) — distinct from the main inventory panel render_inventory_panel 0x1a399.)"),
		new NamedAddress(0x7febcL, "g_inventory_options_request",
			"Set to 1 by update_inventory_screen when the player presses the options key ('D', scancode "
			+ "0x20); the function tail then clears it and calls run_options_menu (0x26501). The menu's "
			+ "return value is decoded via the 0x1a8cd jump table into the new-game/load/save/quit request "
			+ "flags."),
		new NamedAddress(0x80b42L, "g_inspect_popup_layout",
			"Layout slot table for the item inspect popup (render_inspect_popup_window): 8-byte entries (+0 x-pos word, +4 size/flags word) starting at 0x80b42; ~6 slots = the close-up sprite area + the text-panel rows (0x80b46=0x1c, 0x80b4e/56/66/6e=0x14)."),
		new NamedAddress(0x80b24L, "g_ui_panel_anchor_x",
			"Shared UI panel anchor X (horizontal). Set per-window: compute_viewport_half_extents "
			+ "(0x1a37b) = (g_screen_pitch 0x85498 - 0x130[=304])>>1 to CENTER a 304px-wide panel; also "
			+ "written by show_message_box (0x2540e) and a menu path (0x26241). All origin-relative UI "
			+ "elements add this: e.g. draw_panel_slot_tile (0x19ee6) computes slotX = "
			+ "g_ui_slot_layout_table[i].x + g_ui_panel_anchor_x. (Saved/restored around nested boxes.)"),
		new NamedAddress(0x80b28L, "g_ui_panel_anchor_y",
			"Shared UI panel anchor Y (vertical). compute_viewport_half_extents (0x1a37b) = "
			+ "g_screen_height (0x8549c)>>1; also written by show_message_box (0x2541d) / menu (0x26249). "
			+ "draw_panel_slot_tile adds it: slotY = g_ui_slot_layout_table[i].y + g_ui_panel_anchor_y."),
		new NamedAddress(0x71208L, "g_ui_slot_layout_table",
			"Non-modal UI panel slot layout: array of {x:word @+0, y:word @+2} (stride 4), positions "
			+ "RELATIVE to g_ui_panel_anchor_x/y. Read by draw_panel_slot_tile (0x19ee6). The inventory "
			+ "panel: slots 0-9 = a 5-col x 2-row item GRID (x=123,154,185,216,247 step 31; y=15 row0 / "
			+ "y=46 row1), slots 10-11 = two hand/equipped cells (x=58/89, y=15), slot 12 = top-left "
			+ "corner (4,4). Each cell drawn with the 28x28 slot tile (ICONS.ALL dir off 0x110); item "
			+ "icons are then blitted in by draw_inventory_entry_label (0x1c020)."),
		new NamedAddress(0x7e938L, "g_cursor_primary_action_flag",
			"[MED] One-frame cursor/action edge flag, set by the mouse poll FUN_00011fae and cleared at "
			+ "dispatch_dialogue_ui_action exit. Drives INSPECT / COMBINE / use-on-self. BUTTON MAPPING: "
			+ "the poll applies a swap gated on g_mouse_button_swap (0x7feb8, DEFAULT 1) -> with the default, "
			+ "this flag is driven by the RIGHT mouse button (LEFT drives g_cursor_secondary_action_flag). "
			+ "If g_mouse_button_swap is toggled off, it reverts to LEFT=primary."),
		new NamedAddress(0x7e939L, "g_cursor_secondary_action_flag",
			"[MED] Second one-frame cursor/action edge flag (companion of g_cursor_primary_action_flag). "
			+ "Drives FIRE/INTERACT / pick-up / move-swap and trigger_weapon_fire (gated at 0x16c22). "
			+ "With the default g_mouse_button_swap=1 this flag is driven by the LEFT mouse button."),
		new NamedAddress(0x7feb8L, "g_mouse_button_swap",
			"The F5 'Mouse Buttons A-B / B-A' control option (DEFAULT 1 = A-B, set by "
			+ "set_default_mouse_button_swap from game_play_loop; toggled at 0x17fd2, which then shows display "
			+ "string 7 vs 8 = the two labels). In the default A-B mode the mouse poll FUN_00011fae shifts the "
			+ "INT 33h button mask (bl<<1; right also sets bit0) so the RIGHT button drives "
			+ "g_cursor_primary_action_flag (inspect) and the LEFT drives g_cursor_secondary_action_flag "
			+ "(interact). B-A reverses it. THIS is why the inventory combine/inspect branches read the "
			+ "'primary' flag yet fire on the right button in the default game. (Weapon fire itself is "
			+ "LEFT-click only while the cursor is over a fireable target -> red-dot cursor; otherwise Ctrl.)"),
		new NamedAddress(0x85414L, "g_render_target_buffer",
			"[MED] Render-target buffer pointer used directly by the dev map-selector text path "
			+ "(render_dev_map_selector_ui draws at this buffer + 0x0a). Exact relationship to "
			+ "g_framebuffer_ptr needs more renderer pass mapping."),
		// --- World renderer / remap tables (see ROTH_renderer_notes.md) ---
		new NamedAddress(0x85d08L, "g_das_remap_chunk_10000_ptr",
			"[HIGH] Linear pointer to the 256x256 PALETTE BLEND (translucency) table (0x10000 bytes): "
			+ "table[(dst<<8)|src] = the palette index that approximates drawing palette colour `src` "
			+ "translucently over background colour `dst`. PRECOMPUTED OFFLINE and shipped in the map DAS file — "
			+ "load_map_das_file (0x2f1b4) reads it straight in via INT21h/3Fh (after the palette + the 0x4000 "
			+ "shading colormap). Allocated by allocate_das_worker_buffers, freed by free_render_color_selectors. "
			+ "World/sprite span code reaches it through g_transparency_blend_selector, not this pointer."),
		new NamedAddress(0x90be2L, "g_transparency_blend_selector",
			"[HIGH] DPMI selector (ES) covering g_das_remap_chunk_10000_ptr. A wall/floor/sprite TEXEL is blended when its "
			+ "value has bit 0x80 set (texel 0 = fully transparent/skip; otherwise opaque). The blend per pixel is: "
			+ "bl = gs:[ (shade<<8)|texel ] (depth-shaded SOURCE colour); bh = [edi] (DESTINATION/background pixel); "
			+ "bl = es:[ ebx ] = blend_table[(dst<<8)|src]; store. So the index is "
			+ "(DESTINATION<<8) | (shaded SOURCE) — CORRECTED: the high byte is the destination, NOT the source "
			+ "(asm-verified at 0x391ac). The source is already colormap-shaded before the translucent lookup."),
		new NamedAddress(0x86d28L, "g_world_shading_table_ptr",
			"[HIGH] Default world shading/remap table base selected by render_world_face_list when "
			+ "no tint/glow face flags override it."),
		new NamedAddress(0x86d1cL, "g_world_tint_table_ptr",
			"[MED-HIGH] Tinted world remap table base selected by render_world_face_list when face "
			+ "word +0x0a has bit 0x0002 set."),
		new NamedAddress(0x86d18L, "g_world_glow_table_ptr",
			"[MED-HIGH] Glow/single-table remap base selected by render_world_face_list when face "
			+ "word +0x0a has bit 0x0040 set and the animation/global gate 0x8a355 & 0x49 is nonzero."),
		new NamedAddress(0x8a2a8L, "g_active_world_remap_selector",
			"[MED-HIGH] Active remap selector chosen by render_world_face_list and consumed by "
			+ "draw_world_surface_spans as GS."),
		new NamedAddress(0x8a2acL, "g_active_world_remap_base",
			"[MED-HIGH] Active remap table base chosen by render_world_face_list and consumed by "
			+ "draw_world_surface_spans/variants before writing world texels."),
		new NamedAddress(0x90a2aL, "g_parallax_sky_active",
			"[render] Per-face PARALLAX-SKY flag: render_world_face_list(_subpass) sets it 0xff when the face's "
			+ "g_current_surface_render_flags & 0x40 (sky surface), else 0. When set, the wall driver "
			+ "draw_world_surface_spans fills the open region ABOVE the wall top (vs the horizon g_view_bound_top "
			+ "0x9096e) with sky columns via render_parallax_sky_columns (0x38d6c) — a view-angle-parallaxed "
			+ "read of the per-map sky texture g_das_special_fat_index (0x89f34). PLAYTEST-CONFIRMED. See "
			+ "ROTH_renderer_notes.md 'Parallax sky'."),
		new NamedAddress(0x90a2eL, "g_current_surface_render_flags",
			"[HIGH] Per-surface render flags byte loaded at 0x2afed/0x2902b from surface/texture "
			+ "record +0x08 (== decomp _g_current_surface_render_flags). Bits observed: 0x01 enters "
			+ "overlap/split paths (0x2cbb0 takes it iff 0x01; 0x2cf60 iff (flags & 0x09)==0x09), "
			+ "0x08 affects overlap setup, 0x20 affects texture-coordinate width setup, 0x40 = a PARALLAX-SKY "
			+ "surface (sets g_parallax_sky_active 0x90a2a -> sky-column fill above the wall). The whole byte is "
			+ "re-read at 0x2d137 (mov cl,[0x90a2e]) to "
			+ "compose the rasterizer fill-mode word at [0x84f18+0x16] (bits 0x04 and 0x10 select "
			+ "submodes), which is what selects the span-writer (and thus whether the blend writer "
			+ "that loads g_transparency_blend_selector is reached)."),
		new NamedAddress(0x90a2cL, "g_world_span_colorkey",
			"[MED-HIGH] Transparent colour-key compared against the face colour index in the span "
			+ "builders (e.g. 0x2cd07 cmp dx,[0x90a2c]; je skip, and 0x2cc0f/0x2ce51/0x2cfcc/0x2d0bb). "
			+ "A span whose colour equals this is skipped as fully transparent. Set at 0x2ac26. Distinct "
			+ "from the render-flags byte at the adjacent 0x90a2e."),
		new NamedAddress(0x852c2L, "g_span_gouraud_colour_a",
			"[MED] First gouraud endpoint colour/shade for the current face span. Loaded from the "
			+ "geometry record word[0] via fs:[bx] at 0x2cc53 (0x2cf78 in 0x2cf60). Paired with the "
			+ "clamped screen-X coords and emitted as span vertices by 0x2d130/0x2d29a. NOTE: the fs "
			+ "used here is the geometry selector, NOT g_transparency_blend_selector."),
		new NamedAddress(0x852c4L, "g_span_gouraud_colour_b",
			"[MED] Second gouraud endpoint colour/shade for the current face span. Comes from the "
			+ "colour argument passed into the span builder (stored at 0x2cc4d). Consumed alongside "
			+ "g_span_gouraud_colour_a by 0x2d130/0x2d29a when building the projected span vertices."),
		new NamedAddress(0x852b6L, "g_world_span_top",
			"[MED] Top (minimum screen-Y) of the current vertical clip band for face span drawing. "
			+ "build_world_face_edge_spans (0x2cc48) rejects an edge when projected Y <= this and clamps "
			+ "the opposite edge up to it; the smaller of the pair with g_world_span_bottom (0x852b4)."),
		new NamedAddress(0x852b4L, "g_world_span_bottom",
			"[MED] Bottom (maximum screen-Y) of the current vertical clip band for face span drawing. "
			+ "build_world_face_edge_spans (0x2cc48) rejects an edge when projected Y >= this and clamps "
			+ "the opposite edge down to it; the larger of the pair with g_world_span_top (0x852b6)."),
		new NamedAddress(0x85288L, "g_perspective_scale",
			"[MED] Projection scale numerator used in the face span coordinate math: each clamped "
			+ "coord = (coord * g_perspective_scale) / edge_slope + g_screen_center (0x909a4), in "
			+ "build_world_face_edge_spans (0x2cc48) and the draw_world_face_* drawers."),
		new NamedAddress(0x84f2eL, "g_span_fill_mode_word",
			"[MED-HIGH] Fill-mode word at [0x84f18+0x16] consumed by the span machinery to select the "
			+ "writer variant. Built ONLY in emit_world_span_record (0x2d130) at 0x2d137 from the "
			+ "render-flags byte g_current_surface_render_flags (0x90a2e): w = (cl & 0x83); if (cl&4)==0 "
			+ "w|=0x100; if (cl&0x10)==0 w|=0x40; w|=0x18; if [0x84f25]&0x80 w&=0xfff7. NOT produced by "
			+ "finalize_world_span_overlay (0x2d040)."),
		// DAS texture cache globals — see the matching note in engineFunctions[]. Live names HERE
		// (engine-names is the run script); ROTHApplyDasTypes.java is the frozen 06-11 reference.
		new NamedAddress(0x86d30L, "g_das_entry_status_table",
			"[DAS texture cache] 0x1600-entry WORD table tracking each DAS FAT id's cache/status: low byte "
			+ "= g_das_cache_slots index, high byte 0xfc/0xfd/0xfe/0xff = special markers (0xfd flat-fill, "
			+ "0xff not-resident). Indexed by g_current_das_entry_id (0x90a78) in the span walk. (Was "
			+ "mislabeled g_scanline_span_buffer — it is the texture cache status table, not a span buffer.)"),
		new NamedAddress(0x89930L, "g_das_cache_slots",
			"[DAS texture cache] 0xf0 cache-slot records, 6 bytes each: +0 dword DAS block-ptr, +4 word "
			+ "age/tick (g_das_cache_tick). The renderer derefs the slot block-ptr to source the surface "
			+ "texture; the resolver fills/evicts via load_das_block_for_fat_index / evict_das_cache_slot. "
			+ "(Was mislabeled g_span_writer_table — it holds texture blocks, NOT span-writer fn-ptrs; the "
			+ "real span dispatch is g_world_span_variant_table / _g_floorceil_span_fn.)"),
		new NamedAddress(0x8c940L, "g_current_das_cache_slot_index",
			"[DAS texture cache] Index of the DAS cache slot just reserved/selected, stamped into "
			+ "g_das_entry_status_table on the textured load path. (Was mislabeled g_current_span_writer_id.)"),
		new NamedAddress(0x90a78L, "g_current_das_entry_id",
			"[RENDER] Current DAS entry / surface-texture id being processed by the span walk — the "
			+ "rasterize_world_spans_scanline (0x366cb) / emit_world_face_spans (0x2c720) cursor that "
			+ "indexes g_das_entry_status_table (0x86d30). 0xfe-tagged status words redirect it through the "
			+ "indirection table 0x90944; the resolved id is stamped into the subpass surface record (+0xa). "
			+ "Bounded by 0x1200. (Was mislabeled g_scanline_dispatch_index; 0x86d30/0x89930/0x8c940 are the "
			+ "DAS texture cache, not a scanline/span-writer structure.)"),
		new NamedAddress(0x90c0aL, "g_das_cache_tick",
			"[DAS texture cache] 16-bit DAS-cache age/LRU clock; incremented once per frame in "
			+ "setup_frame_render_context (0x2aa3e) and copied into a cache slot's +4 tick field on "
			+ "alloc/access, so evict_das_cache_slot can pick the oldest. (Was mislabeled "
			+ "g_current_draw_selector — it is a per-frame tick, not a per-surface selector. If a real "
			+ "per-surface draw selector exists it is a DIFFERENT, still-unnamed address.)"),
		new NamedAddress(0x84b18L, "g_secondary_surface_list",
			"Descriptor list of secondary world surfaces (mid-textures / transparent walls), 0x10-byte records: +0/+0xc = the coord pair copied to 0x85264/0x85260, +8 = type byte, +0xa = param. Walked by render_secondary_surface_list/_pass1/_pass2."),
		new NamedAddress(0x85318L, "g_secondary_surface_count",
			"Number of records in g_secondary_surface_list; the per-record loop counter in the render_secondary_surface_* passes."),
		new NamedAddress(0x853d0L, "g_has_secondary_surfaces",
			"Gate flag: the render_secondary_surface_* passes bail immediately (ret) when this is 0. Set when the current view collected any secondary (mid-texture/transparent) surfaces."),
		new NamedAddress(0x853d2L, "g_secondary_subpass_flags",
			"Bitmask of active secondary-surface subpasses: render_secondary_surface_pass1 OR-sets bit 1, pass2 bit 2. Consumed downstream when compositing the transparent passes."),
		new NamedAddress(0x853f9L, "g_secondary_subpass_id",
			"Current secondary-surface subpass id (1 = pass1, 2 = pass2); 0 for the base render_secondary_surface_list pass."),
		new NamedAddress(0x84f18L, "g_world_span_record",
			"The scratch world-span descriptor that the emit_world_span_* helpers populate (fill-mode word at +0x16, clip bound at +0x28, vertex/coord fields at +0x34/+0x36) before calling rasterize_world_spans_scanline. Shared by emit_world_span_record and the 4 emit_world_span_clipped/unclipped[_indexed] variants."),
		new NamedAddress(0x90a28L, "g_span_clip_source",
			"Source value copied into g_column_clip_mode (0x90970) by the CLIPPED span emitters (emit_world_span_clipped / _clipped_indexed). Selects the edge-clipped column path for the current span."),
		new NamedAddress(0x848f8L, "g_sound_bank_file_handle",
			"[SOUND] DOS file handle for the open digital sound bank ('SFX0' file); opened in load_sound_effect_bank, "
			+ "gated by play_sound_sequence_group. 0 = closed/unavailable."),
		new NamedAddress(0x83e04L, "g_weapon_hud_anim_count",
			"[HUD] Number of active weapon-HUD value animations (table g_weapon_hud_anim_table 0x83d84); driven by "
			+ "tick_weapon_hud_ammo_anim."),
		new NamedAddress(0x83e08L, "g_weapon_hud_anim_accum",
			"[HUD] Fixed-step accumulator (threshold 0x10) advanced by g_frame_time_scale for the weapon-HUD ammo "
			+ "animation in tick_weapon_hud_ammo_anim."),
		new NamedAddress(0x83d84L, "g_weapon_hud_anim_table",
			"[HUD] Array of weapon-HUD value animators (stride 8: value ptr, target/rate words) consumed by "
			+ "tick_weapon_hud_ammo_anim; g_weapon_hud_anim_count 0x83e04 entries."),
		new NamedAddress(0x83d6cL, "g_hud_weapon_das_handle",
			"[HUD] Cached DAS handle for the weapon-view imagery; freed by free_hud_weapon_das_handle."),
		new NamedAddress(0x83d74L, "g_hud_panel_das_handle0",
			"[HUD] Cached HUD-panel DAS handle (slot 0); freed by free_hud_panel_das_handles."),
		new NamedAddress(0x83d78L, "g_hud_panel_das_handle1",
			"[HUD] Cached HUD-panel DAS handle (slot 1); freed by free_hud_panel_das_handles."),
		new NamedAddress(0x83ea4L, "g_playback_menu_scroll_anchor",
			"[MENU] Saved scroll/selection anchor for the cutscene Playback menu (show_cutscene_playback_menu)."),
		new NamedAddress(0x82006L, "g_cutscenes_seen_count",
			"[CUTSCENE] Running count of distinct cutscene/story records SEEN (the FMV-playback registry size): init=1, "
			+ "recomputed in load_savegame_file as max(record playback-index)+1, and bumped by play_record_gdv_cutscene which "
			+ "assigns each newly-seen record the next playback index (record+0x10 high byte, guarded by record[0x13]). "
			+ "Bounds the list in show_cutscene_playback_menu."),
		new NamedAddress(0x89f3aL, "g_framebuffer_from_dos_block",
			"[VIDEO] 1 if the framebuffer surface was allocated from a DOS conventional-memory block (alloc_dos_block), 0 if from the game heap. Set by alloc_framebuffer_surface (0x2fbe8); selects the matching free path in free_framebuffer_surface (0x2fce9)."),
		new NamedAddress(0x89f28L, "g_render_target_selector_secondary",
			"[VIDEO/DPMI] Second framebuffer DPMI selector (paired with the primary render-target selector). Allocated by 0x2fd7c/0x2fdbc, freed by 0x2fe77; used for the secondary/lower-viewport render target."),
		new NamedAddress(0x89f2cL, "g_render_target_secondary_size",
			"[VIDEO] Byte size of the secondary render target (0=hi-res / 64000 for 320x200); set alongside the secondary selector in 0x2fd7c/0x2fdbc."),
		new NamedAddress(0x89f2aL, "g_render_target_secondary_height",
			"[VIDEO] Scanline height of the secondary render target (0=hi-res / 200 for 320x200); set alongside the secondary selector in 0x2fd7c/0x2fdbc."),
		new NamedAddress(0x81f02L, "g_object_template_flags",
			"[dbase100/spawn] Flags dword (+4) of the last template resolved by resolve_object_template_record "
			+ "(0x1de59). cmd_spawn_object_adv (0x30d10) gates the spawn on bit0x20 (renderable)."),
		new NamedAddress(0x83c70L, "g_cutscene_overlay_active",
			"[cutscene] Nonzero while the fullscreen cutscene/splash overlay is up (set 1 in play_gdv_cutscene 0x2059d). "
			+ "exit_cutscene_overlay_mode (0x20905) gates its teardown on this; present_cutscene_frame is invoked when set."),
		new NamedAddress(0x83c74L, "g_cutscene_image_handle",
			"[cutscene] DAS-cache handle of the current decoded cutscene/splash frame image. Remapped+blitted then freed "
			+ "by present_cutscene_frame (0x20a8a); also freed in exit_cutscene_overlay_mode (0x20905)."),
		new NamedAddress(0x8b3faL, "g_door_state_table",
			"[DOOR] Base of the door state/record array indexed by door id in toggle_door_open_state (0x3d93f): "
			+ "byte[id] = door flags (bit2 = opening); parallel fields at +0x412 (sound id), +0x416 (loop handle), "
			+ "+0x41e (open-sound id), +0x40c (position). Overlaps the g_door_pool region (0x8b3f8)."),
		new NamedAddress(0x911cbL, "g_spawn_projectile_is_player",
			"[OBJECT-POOL] Flag set (=1) by spawn_player_projectile_flagged (0x422ec) around "
			+ "spawn_object_projectile_at_player so the spawned projectile is tagged as belonging to the player."),
		new NamedAddress(0x911c5L, "g_object_table_dirty",
			"[OBJECT-POOL] Dirty byte for the GS-segment per-sector object table: set = 0xff whenever the table is "
			+ "mutated (reserve_object_buffer_space 0x420e1, relocate_sector_object_offsets 0x4222b), the companion of "
			+ "the generation counter g_object_table_generation (0x911c7)."),
		new NamedAddress(0x911c7L, "g_object_table_generation",
			"[OBJECT-POOL] Generation/version counter for the GS-segment per-sector object table. BUMPED (++) "
			+ "whenever the table is mutated: reserve_object_buffer_space (0x420e1), relocate_sector_object_offsets "
			+ "(0x4222b), remove_secondary_state_record (0x42056) — each also sets the companion dirty byte "
			+ "g_object_table_dirty (0x911c5 = 0xff). The per-object state effects (cmd_change_object_height/texture, "
			+ "cmd_rotate_object, register_object_state_effect) STAMP the current generation into their effect chunk+0xc, "
			+ "and their per-frame TICK (tick_change_object_height 0x33091 / _texture 0x3286b / tick_rotate_object 0x33188) "
			+ "re-resolves + re-stamps when (short)g_object_table_generation != chunk[0xc] = the object array relocated. "
			+ "It is NOT a countdown timer. (recomp's RAW_COMMANDS §3 proposed g_object_state_base — corrected: it's a "
			+ "generation counter, not a base ptr.)"),
		new NamedAddress(0x911e0L, "g_sfx_query_result_count",
			"[SFX/TRIGGER] Number of emitter records collected by query_sfx_emitters_in_range (0x43b3b) into the "
			+ "proximity result list."),
		new NamedAddress(0x911dcL, "g_sfx_query_capacity",
			"[SFX/TRIGGER] Remaining capacity counter (seeded from the caller's max) used by query_sfx_emitters_in_range "
			+ "(0x43b3b) to bound how many emitter records it collects."),
		new NamedAddress(0x8a352L, "g_span_textured_mode_flag",
			"[wall/sprite span] Render-mode selector flag tested (cmp [0x8a352],0) by both draw_world_surface_spans (0x36b39) and draw_scaled_sprite_spans (0x39610) when choosing the span inner-loop variant (textured vs untextured path). Paired with g_span_blend_mode_flag (0x8a354) and g_render_x_flip_flag (0x8a356)."),
		new NamedAddress(0x8a354L, "g_span_blend_mode_flag",
			"[wall/sprite span] Render-mode selector flag tested (cmp [0x8a354],0) by draw_world_surface_spans (0x36b39) and draw_scaled_sprite_spans (0x39610) to pick the BLEND/translucent column variant. Companion of g_span_textured_mode_flag (0x8a352) and g_render_x_flip_flag (0x8a356)."),
		new NamedAddress(0x7e8e4L, "g_saved_int8_offset",
			"[INPUT/TIMER] Saved offset of the original INT 08h (PIT) vector, captured by install_timer_int8 (0x12437) and restored by restore_timer_int8 (0x124b5)."),
		new NamedAddress(0x7e914L, "g_saved_int8_segment",
			"[INPUT/TIMER] Saved segment of the original INT 08h (PIT) vector (install_timer_int8 0x12437); nonzero gates restore_timer_int8 (0x124b5)."),
		new NamedAddress(0x7e8e8L, "g_saved_int9_offset",
			"[INPUT] Saved offset of the original INT 09h keyboard vector (install_keyboard_int9 0x1246a / restore_keyboard_int9 0x12498)."),
		new NamedAddress(0x7e916L, "g_saved_int9_segment",
			"[INPUT] Saved segment of the original INT 09h keyboard vector (install_keyboard_int9 0x1246a); nonzero gates restore_keyboard_int9 (0x12498)."),
		new NamedAddress(0x7e8d4L, "g_frame_tick_callback",
			"[TIMER] Optional per-tick callback function pointer invoked by vsync_timer_tick (0x122e3) at the end of each timer tick when non-null."),
		new NamedAddress(0x90a48L, "g_world_render_subpass_kind",
			"[MED] World renderer subpass/path marker (low byte = per-emission kind; high byte 0x90a49 = the producer's "
			+ "copy, read by the render_world_scene-tail CONSUMER which special-cases ==3). render_world_face_list_subpass "
			+ "(0x28dbe) sets it 0xff on entry then stamps the kind before each span emit: 1=primary surface UPPER-edge span, "
			+ "2=primary LOWER-edge span, 3=primary wall FACE (draw_world_face_*_spans), 4=secondary/special-surface list "
			+ "build (mirror/reflective set), 7=secondary UPPER-edge, 8=secondary LOWER-edge (5/6 = floor/ceil driver "
			+ "secondary write-out, TBD). The span driver's secondary write-out (0x37b8d et al.) records the descriptor "
			+ "0x90a48..0x90a6c tagged with this kind. See lift_handoffs/RESPONSE_28dbe_subpass_consumer.md."),
		new NamedAddress(0x852c8L, "g_surface_record_selector",
			"[RENDER] DPMI selector (es) for the runtime per-wall SURFACE-RECORD section (stride 0xc; the records "
			+ "render_world_face_list_subpass and the subpass consumer dereference, e.g. surfrec+4/+0x14/+1). Loaded by "
			+ "load_raw_map_file; distinct from the DAS texture cache g_das_cache_slots (0x89930)."),
		new NamedAddress(0x852ccL, "g_vertex_selector",
			"[RENDER] DPMI selector loaded into GS for the TRANSFORMED-vertex table (the view-space coords "
			+ "transform_world_vertices 0x2a814 writes: gs:[vtx+0]=view X, gs:[vtx+4]=depth). Callers preload GS from "
			+ "this before walk_visible_sectors (0x294c0) / clip_sector_walls_to_view (0x2d793) read the verts. "
			+ "Sibling of g_surface_record_selector (0x852c8, the ES surface-record selector)."),
		new NamedAddress(0x852faL, "g_sector_cull_coord",
			"[RENDER] The camera/view-Z coordinate used by walk_visible_sectors mode-1 as the bbox-cull/projection "
			+ "reference: mode-1 reads it as -view_z and SELF-PATCHES two of its own bbox-compare immediates with it "
			+ "(SMC at 0x29656/0x29663 — note for static-disasm readers). Also the sprite projector subtracts it as "
			+ "the per-record vertical bias. (Name aligned to recomp's lift g_sector_cull_coord; = the -view_z bias.)"),
		new NamedAddress(0x853d3L, "g_render_sector_walk_mode",
			"[RENDER] Mode gate for walk_visible_sectors (0x294c0): 0 = first-person wall-clip pass (single forward "
			+ "portal chain from g_player_sector 0x90c12, calling clip_sector_walls_to_view per sector); nonzero = "
			+ "flat sector-array bbox-cull that projects each sector's view-X/depth extent to screen columns and "
			+ "emits the g_visible_extent_list. (The whole-scene flood/dedup is a separate pipeline, "
			+ "build_sector_render_tree_recursive 0x29830.)"),
		new NamedAddress(0x85220L, "g_visible_extent_count",
			"[RENDER] Count of entries in g_visible_extent_list (0x85224), the per-visible-sector screen-column "
			+ "clip-region write-set produced by walk_visible_sectors mode-1 and consumed by the clip-restricted "
			+ "scene-tree render pass."),
		new NamedAddress(0x85224L, "g_visible_extent_list",
			"[RENDER] Per-visible-sector clip-region list written by walk_visible_sectors (0x294c0) mode-1; "
			+ "stride 3 shorts (6 bytes): +0 sector record ptr (low word), +2 screen-top Y, +4 screen-bottom Y "
			+ "(clamped to g_view_bound_right hi/lo). Count = g_visible_extent_count (0x85220); read by the "
			+ "clip-restricted scene-tree render pass as the visible-column extents."),
		new NamedAddress(0x85340L, "g_reflection_view_count",
			"[RENDER/mirror] Count of pending reflection/mirror sub-views (max 0x10) in g_reflection_view_list; built by "
			+ "add_reflection_view_entry, consumed by render_reflection_subviews."),
		new NamedAddress(0x85344L, "g_reflection_view_list",
			"[RENDER/mirror] List of reflection/mirror sub-views to render (stride 8) — each a portal/mirror to re-render "
			+ "the scene through. Walked by render_reflection_subviews (0x284df)."),
		new NamedAddress(0x90a50L, "g_subpass_surfrec_ref",
			"[RENDER/subpass] Deferred-surface descriptor field: dword reference to the SURFACE RECORD (low=offset, hi word "
			+ "@0x90a52) dereferenced through es=g_surface_record_selector (0x852c8). The render_world_scene-tail consumer "
			+ "reads es:[ref+4] (sub-record ptr), es:[ref+0x14] (->g_subpass_reflect_param_b). Part of the mirror/reflection "
			+ "descriptor 0x90a48..0x90a6c; see RESPONSE_28dbe_subpass_consumer.md."),
		new NamedAddress(0x90a5aL, "g_subpass_reflect_param_a",
			"[RENDER/subpass] Consumer-filled descriptor field (only for pass-kind 3): 0, or es:[subrec+0xc] when the "
			+ "sub-record's +1 byte has bit 0x80 (the 'surface carries reflect params' flag). A reflection/blend source param."),
		new NamedAddress(0x90a5cL, "g_subpass_reflect_param_b",
			"[RENDER/subpass] Consumer-filled descriptor field = es:[g_subpass_surfrec_ref+0x14]. Second reflection/blend "
			+ "source param the mirror mapper consumes."),
		new NamedAddress(0x90a68L, "g_subpass_persp_step",
			"[RENDER/subpass] Deferred-surface perspective step. Producer writes (2*[0x8a304]<<[0x38c8a])/[0x8a300]; the "
			+ "render_world_scene-tail consumer RE-PROJECTS it by the horizontal screen-center offset "
			+ "(+= (abs([0x84948]-[0x909a0])<<7) / g_view_w[0x85cd8]) so the reflected texel samples correctly."),
		new NamedAddress(0x8a356L, "g_render_x_flip_flag",
			"[RENDER/subpass] X-flip flag that the 0x38964 span-mapper branches on to render the horizontally-FLIPPED "
			+ "texture = the mirror reflection. Set for secondary/mirror surfaces."),
		new NamedAddress(0x90bfeL, "g_subpass_patch_gate",
			"[RENDER/subpass] When non-zero, the render_world_scene tail re-runs setup_surface_render_constants (0x2abfb, "
			+ "the 0x38c94/0x3b794 SMC patcher) to re-arm the subpass mapper."),
		new NamedAddress(0x9093cL, "g_world_surface_draw_flags",
			"[MED] Packed draw flags consumed by draw_world_surface_spans. Bits select projected-span "
			+ "variants and are also cleared/masked in nonzero g_world_render_subpass_kind paths."),
		new NamedAddress(0x909aeL, "g_world_alt_render_flags",
			"[MED] Secondary packed render flags; render_world_face_list sets/clears high bit 0x8000 "
			+ "for some tinted paths, and draw_world_surface_spans consults it when selecting span variants."),
		// --- Player movement / look / jump globals (see ROTH_movement_spec.md) ---
		new NamedAddress(0x819c0L, "g_player_locomotion_flags",
			"[HIGH] Player locomotion-state bitfield driving the jump/crouch state machine. bit0 = jump "
			+ "key pressed (set by key_a_jump 0x1c5f9); bit 0x10 = jump initiate (set when grounded); "
			+ "bit2/bit0x20 = crouch (key_z_crouch 0x1c5d0). Consumed by the vertical mover "
			+ "(entity_apply_vertical_movement 0x43187)."),
		new NamedAddress(0x819c1L, "g_player_airborne",
			"[MED] Jump/air sub-state; key_a_jump only initiates a jump when this is 0 (grounded)."),
		new NamedAddress(0x90a74L, "g_view_pitch",
			"[MED-HIGH] Look up/down pitch angle, adjusted by the look keys (look_pitch_up/down 0x12927/"
			+ "0x12939, recenter 0x1294b/0x1296f) and mirrored to the applied-pitch global 0x8c108."),
		new NamedAddress(0x8c108L, "g_view_pitch_applied",
			"[MED-HIGH, lift-confirmed 2026-06-14] Applied look pitch: the value actually consumed by "
			+ "the view transform. look_pitch_up/down (0x12927/0x12939) mirror g_view_pitch into this; "
			+ "look_pitch_recenter_down (0x1294b) dumps g_view_pitch here, zeroes the accumulator, then "
			+ "decrements this by 8 (recenter-toward-zero step). 32-bit."),
		new NamedAddress(0x7e920L, "g_move_input_bits",
			"[HIGH] Per-tick polled movement bitfield, rebuilt each tick (cleared at 0x125b3). bit1 = "
			+ "forward, bit4 = backward, bit2/bit8 = strafe, bit0x10 = turning. The low 4 bits index "
			+ "g_kbd_dir_offset_table to get the movement-direction angle offset."),
		new NamedAddress(0x90bd8L, "g_turn_accum",
			"[HIGH] Turn-rate accumulator. Turn keys ramp it toward +/-max (8, or 0xd while running); "
			+ "apply_player_movement_input adds it to g_player_angle, so held turns accelerate."),
		new NamedAddress(0x7e8d8L, "g_move_speed_accum",
			"[HIGH] Keyboard movement-speed accumulator: ramps +1/tick up to a cap of 0x10 while a move "
			+ "key is held (acceleration), giving the ~16-tick ramp to full walk speed."),
		new NamedAddress(0x7e8dcL, "g_run_toggle",
			"[MED-HIGH] Run-mode flag toggled by CapsLock (keymap handler 0x17fed). Read at the top of "
			+ "player_movement_tick to derive g_run_active; widens turn/move maxima. (PLAYTEST-CONFIRMED: CapsLock = "
			+ "sprint toggle.)"),
		new NamedAddress(0x7fe38L, "g_help_overlay_enabled",
			"[UI] On-screen HELP overlay (keybind list) toggle — flipped by the 'H' keymap handler (0x17fc0). "
			+ "PLAYTEST-CONFIRMED: H shows/hides the help text overlay with keybinds."),
		new NamedAddress(0x89f12L, "g_gamma_level",
			"[VIDEO] Gamma/brightness level — raised by 'C' (key_gamma_increase 0x14601) and lowered by 'V' "
			+ "(key_gamma_decrease 0x145ec), each followed by a palette refresh. PLAYTEST-CONFIRMED: C/V = gamma up/down."),
		new NamedAddress(0x7f372L, "g_display_type",
			"[VIDEO] Display/render-mode selector toggled by the F4/F6 keymap handlers (0x147a8/0x14794), which re-apply "
			+ "the mode via 0x2e609. PLAYTEST-CONFIRMED: F4/F6 cycle between display types."),
		new NamedAddress(0x767c0L, "g_version_string",
			"[UI] Buffer holding the ROTH version string, shown as an on-screen overlay by the F8 keymap handler "
			+ "(0x14c9c -> message display 0x1f88c). PLAYTEST-CONFIRMED: F8 displays the ROTH version."),
		new NamedAddress(0x7e8e0L, "g_run_active",
			"[HIGH, decompiler-verified] Effective run flag for this tick (g_run_toggle, optionally "
			+ "inverted via 0x90c42 bit 0x40 / 0x819cd). When set, player_movement_tick enqueues the "
			+ "per-tick velocity TWICE into the displacement queue - the sprint speed-doubling."),
		new NamedAddress(0x90abeL, "g_vel_queue_a",
			"[HIGH, decompiler-verified] Player displacement ring buffer A: word count at +0, then up to "
			+ "0x10 entries of {int dx, int dy} (8 bytes each). player_movement_tick pushes the post-decay "
			+ "velocity here each tick (twice when running). Consumed by the position integrator."),
		new NamedAddress(0x90b42L, "g_vel_queue_b",
			"[HIGH, decompiler-verified] Player displacement ring buffer B (same layout as g_vel_queue_a). "
			+ "g_vel_queue_select (0x90bd6) chooses which buffer is active."),
		new NamedAddress(0x90bd6L, "g_vel_queue_select",
			"[MED-HIGH] Selects the active displacement queue: g_vel_queue_a when 0, else g_vel_queue_b."),
		new NamedAddress(0x76870L, "g_mouse_dx",
			"[MED] Accumulated mouse X delta; consumed (and zeroed) by apply_player_movement_input to "
			+ "turn the player in the advanced hold-both-buttons mouse-look mode. Clamped +/-0x10/tick."),
		new NamedAddress(0x76874L, "g_mouse_dy",
			"[MED] Accumulated mouse Y delta; forward/back speed in mouse-look mode. Clamped +/-0x18/tick."),
		new NamedAddress(0x707c9L, "g_kbd_dir_offset_table",
			"[HIGH] 16-word movement-direction offset table indexed by g_move_input_bits & 0xf. Valid "
			+ "entries are the 8 compass directions at 45 deg spacing in angle units (0x200 = 360 deg): "
			+ "0/0x40/0x80/0xc0/0x100/0x140/0x180/0x1c0; 0xffff = no movement. Added to g_player_angle "
			+ "to get the move heading."),
		new NamedAddress(0x707f1L, "g_held_key_move_table",
			"[HIGH] Held-key (continuously-polled) movement binding table: {u8 scancode, u32 handler} "
			+ "records, stride 5, separate from the discrete keymap_dispatch table. Defaults: Up/Down "
			+ "move, Left/Right turn, ','/'.' strafe, A=jump (0x1c5f9), Z=crouch (0x1c5d0), "
			+ "Home/End/PgUp/PgDn look. See ROTH_keymap.md."),
		new NamedAddress(0x90c3cL, "g_key_state_bitmap",
			"[MED-HIGH] Key-down bitmap (1 bit per scancode): byte [scancode>>3], bit (scancode&7). "
			+ "Polled to drive the held-key movement handlers; tested via g_keybit_mask_table + xlatb."),
		new NamedAddress(0x707e9L, "g_keybit_mask_table",
			"[MED] 8-byte bit-mask lookup (1,2,4,...,0x80) used with xlatb to test individual bits of "
			+ "g_key_state_bitmap."),
		// --- Snapshot / screen-grab system (see ROTH_snapshot_notes.md) ---
		new NamedAddress(0x76840L, "g_snapshot_enabled",
			"[HIGH] Snapshot feature flag; toggled by cmd_snap_toggle (the 'SNAP' startup switch). "
			+ "Gates take_snapshot (checked at 0x11124)."),
		new NamedAddress(0x72480L, "g_snapshot_counter",
			"[HIGH] 4-digit counter substituted for '?' in C:\\Snap?.lbm; increments per saved frame."),
		new NamedAddress(0x70746L, "g_snapshot_anim_frame",
			"[MED] Animation-mode frame counter used to build numbered snapshot filenames."),
		new NamedAddress(0x8b370L, "g_snapshot_filename_buf",
			"[MED] Buffer that the snapshot filename is assembled into."),
		new NamedAddress(0x8b35cL, "g_snapshot_work_buf",
			"[MED] 64KB work/compress buffer allocated for LBM output (palette + RLE staging)."),

		// --- Startup display-config flags (set by the config-directive handlers, 2026-06-14) ---
		new NamedAddress(0x90bfaL, "g_antialias_mode",
			"[MED] Anti-alias mode, set by the ALIAS/ALIAS2/ALIAS3 (/A,/A2,/A3) directives to "
			+ "-1 / 1 / -2 respectively (handlers 0x108b6/0x108c0/0x108ca)."),
		new NamedAddress(0x90bf8L, "g_blur_flag",
			"[MED] Blur enable, set to 0xffff by the BLUR (/B) directive (handler 0x108d4)."),
		new NamedAddress(0x90c08L, "g_rawscreen_flag",
			"[MED] 'Raw screen' flag, set to 0xff by RAWSCREEN (/S) (handler 0x10870); gates how "
			+ "HIRES masks the video-flags word 0x90be6."),

		// --- Player combat state (2026-06-14) ---
		// --- Dialogue cursor gate (2026-06-15; recomp dialogue-cursor #11 lead) ---
		new NamedAddress(0x81e3eL, "g_dialogue_action_queue_count",
			"[MED-HIGH] Count of pending deferred dialogue/action records (0xc-byte records at the "
			+ "queue 0x81e42). Gates mouse clicks in FUN_0001691c and the dialogue-cursor state."),
		new NamedAddress(0x83aeaL, "g_dialogue_busy_flag",
			"[MED-HIGH] Dialogue/action-chain busy/freeze flag; read widely by the dialogue UI + movement "
			+ "input to gate interaction (and the hand-vs-arrow cursor). Cursor hit-testing returns action "
			+ "code 0x27 while this is nonzero; cleared by voice_stream_pump when the line goes idle."),

		// --- Sprite render queue (2026-06-15) ---
		new NamedAddress(0x8aad0L, "g_sprite_node_pool",
			"[MED] Per-frame pool of visible-sprite render-queue nodes (cap 0x800); reset by "
			+ "init_sprite_render_queue."),
		new NamedAddress(0x8b340L, "g_sprite_render_queue_head",
			"[MED-HIGH] Head of the visible-sprite render queue (linked list of nodes drawn by "
			+ "draw_sprite_render_queue → render_world_sprite)."),

		// --- Entity sprite binding (2026-06-15) ---
		new NamedAddress(0x909f8L, "g_sprite_view_angle",
			"[MED] Camera-relative angle used by render_world_sprite to pick a directional sprite's "
			+ "facing: bucket = (0x120 - this) >> 5 & 0xe (8 directions)."),
		new NamedAddress(0x84980L, "g_render_source_base_ptr",
			"[MED] Pointer to the current DAS sprite frame pixels (block child +0x10) selected by "
			+ "render_world_sprite / advance_das_sprite_animation_frame for the renderer to draw."),

		// --- Inventory state (2026-06-15; see ROTH_inventory_notes.md) ---
		new NamedAddress(0x80c30L, "g_inventory_slots",
			"[HIGH] Carried-inventory array: 256 slots x 4-byte record {item_id:u16 @+0, "
			+ "quantity:u16 @+2}; id==0 = empty. (0x80c30..0x81030)."),
		new NamedAddress(0x80c2cL, "g_inventory_count",
			"[HIGH] Number of occupied g_inventory_slots entries."),
		new NamedAddress(0x81044L, "g_selected_item_primary",
			"[MED-HIGH] Pointer to the currently-selected primary item slot (0 = none)."),
		new NamedAddress(0x81038L, "g_selected_item_secondary",
			"[MED-HIGH] Pointer to the selected secondary item slot."),
		new NamedAddress(0x8a0f0L, "g_player_health",
			"[HIGH] Player health. Set at level/game init (0x17ab0/0x17bbf), decremented by "
			+ "apply_damage_to_player (0x32023, clamped at 0 = death), healed by add at 0x320b1 / "
			+ "set at 0x320bf (DBASE100 0x26 SetHealthOrHeal), force-killed via =0 at 0x1d9ac. "
			+ "Damage cap reference ~0x35c6."),
		new NamedAddress(0x89f3bL, "g_damage_flash_level",
			"[HIGH] Red damage-flash overlay accumulator (capped 0x164). Bumped by "
			+ "apply_damage_to_player on a hit; decayed each frame in gameplay_frame_step "
			+ "(`-= g_frame_time_scale*4`)."),

		new NamedAddress(0x97d44L, "errno",
			"[CRT] The Watcom C runtime `errno` (int). Accessed via get_errno_ptr (0x560c2) / written "
			+ "via set_errno (0x55ba1). Read as the not-found-class status (==1/==9) by the PATH-search "
			+ "exec (spawnvpe 0x4f799, 0x57774). Identified while de-placeholdering get_ptr_dat97d44."),
		new NamedAddress(0x97d48L, "_doserrno",
			"[CRT] Watcom raw-DOS-error global (int), adjacent to errno. Accessed via get_doserrno_ptr "
			+ "(0x560c8) / written via set_doserrno (0x55bc4); set alongside errno on DOS failures."),
		new NamedAddress(0x755ccL, "environ",
			"[CRT] The C runtime environment pointer (char**). Default env passed to the spawn path "
			+ "(build_exec_param_block / spawn_exec_default_env) when the caller passes none."),
		new NamedAddress(0x72544L, "g_stack_limit",
			"[CRT] Watcom stack low-limit; stack_bytes_remaining (0x55775) and check_stack_overflow "
			+ "(0x55b6f) measure against it."),
		new NamedAddress(0x7255cL, "g_dos_child_running",
			"[CRT] Set to 1 by dos_exec_program (0x55a86) around the INT 21h/4Bh EXEC, 0 after — marks a "
			+ "child process is executing."),
		new NamedAddress(0x75610L, "g_heap_free_list",
			"[CRT] Head of the Watcom near-heap free-list (boundary-tag, doubly-linked). Walked by "
			+ "heap_carve_block (malloc) / heap_insert_free_block (free); grown by heap_grow."),
		new NamedAddress(0x72534L, "g_heap_brk",
			"[CRT] Current heap break (top of OS-granted program memory); advanced by os_grow_brk."),
		new NamedAddress(0x72562L, "g_crt_memory_mode",
			"[CRT/DPMI] DOS-extender mode, set by watcom_runtime_startup from the INT 21h AH=30h "
			+ "signature: 0='DX' DOS/4GW path / 1=raw DPMI host (INT 31h AX=6 probe) / 9='CB' extender "
			+ "(0x4243, the special branch in os_grow_brk/compute_heap_grow_size/0x558a6). Branches across "
			+ "the heap + I/O runtime key on it."),
		new NamedAddress(0x90f4cL, "g_dos_dta",
			"[CRT/DOS] The Disk Transfer Area buffer for findfirst/findnext (set via INT 21h AH=1Ah by "
			+ "dos_find_first). The matched filename lives at +0x1e (g_dos_dta_name 0x90f6a)."),
		new NamedAddress(0x90f48L, "g_dta_initialized",
			"[CRT/DOS] One-shot guard so dos_find_first only issues the Set-DTA (AH=1Ah) on the first call."),
		new NamedAddress(0x71d94L, "g_hex_digits_lower",
			"[CRT-style] \"0123456789abcdef\" digit table for %x in vsprintf_engine."),
		new NamedAddress(0x71da4L, "g_hex_digits_upper",
			"[CRT-style] \"0123456789ABCDEF\" digit table for %X in vsprintf_engine."),
		new NamedAddress(0x8491dL, "g_format_flags",
			"[CRT-style] Per-conversion flag byte in vsprintf_engine (bit0 signed/decimal, bit1 special, "
			+ "bit3 width-given, 0x40 digit-emitted, 0x20 negative). Reset per %-spec."),
		new NamedAddress(0x911d0L, "g_saved_int24_vector",
			"[CRT/DOS] Saved original DOS critical-error (INT 24h) vector; stashed by "
			+ "install_critical_error_handler and restored at exit by restore_critical_error_handler."),
		new NamedAddress(0x8a270L, "g_block_list_head",
			"[MED-HIGH] Head of the game block allocator's doubly-linked list of OS-allocated blocks "
			+ "(alloc_dos_block/alloc_dpmi_block link here; free_os_block unlinks)."),
		new NamedAddress(0x8a278L, "g_pool_check_enabled",
			"[MED] When nonzero, get_pool_descriptor validates the 'Pool' magic (0x506f6f6c) of pool "
			+ "descriptors; 0 = trust the pointer as-is."),
		new NamedAddress(0x7f574L, "g_cached_dbase200_sprite_handle",
			"[MED] Pool handle for the single-slot cached dbase200 RLE sprite (set by load_dbase200_sprite_cached, "
			+ "freed before each reload). 0 = none cached."),
		new NamedAddress(0x81f06L, "g_dbase200_filename",
			"[MED] Filename buffer holding \"dbase200.dat\" (built at runtime by build_game_path with the "
			+ "ROTH.INI data dir). The RLE-sprite resource container opened by load_dbase200_sprite_cached. "
			+ "NOTE: holds DAS-format sprites but the FILE is dbase200.dat, not a standalone .DAS."),
		new NamedAddress(0x81f86L, "g_dbase300_filename",
			"[MED] Filename buffer holding \"dbase300.dat\" (built at runtime by build_game_path). The image/"
			+ "media resource container opened by load_dbase300_chunk (dbase300 chunks), "
			+ "load_and_center_fullscreen_image (fullscreen cutscene/splash images) and "
			+ "load_dbase300_resource_at_offset (inventory INSPECT close-ups, GDV-decoded when the resource is GDV). "
			+ "The earlier \"map DAS\" label was a misnomer: the FILE is dbase300.dat, not a standalone .DAS."),
		new NamedAddress(0x72538L, "g_response_file_arg",
			"[MED] Command-line response-file argument for the config loader; load_roth_res defaults to "
			+ "'@roth.res' (0x70010) when this is empty. REALMS.BAT launches ROTH with ROTH.RES."),
		new NamedAddress(0x85404L, "g_das_render_scale",
			"[MED] Sprite vertical render scale for the current resolution (reference value 0x9b=155). "
			+ "rescale_das_frame scales DAS frame dims by g_das_render_scale/0x9b."),

		// ---- AUDIO / speech-voice streaming (see docs/reference/ROTH_audio_notes.md) ----
		new NamedAddress(0x8200cL, "g_voice_stream_state",
			"[HIGH] Speech voice-stream state machine: 0=idle, 1=streaming, 2=ended. Set 1 by "
			+ "prime_voice_clip, 2 by voice_stream_sos_callback (end msg) / dialogue_voice_force_end, "
			+ "reset 2->0 by voice_stream_pump. prime_voice_clip refuses to start while ==1."),
		new NamedAddress(0x82010L, "g_voice_file_handle",
			"[HIGH] Open file handle for dbase500.dat (raw voice audio). 0 = closed. Opened/seeked by "
			+ "prime_voice_clip; read by decode_voice_block; closed at clip end."),
		new NamedAddress(0x824c5L, "g_dialogue_script_handle",
			"[HIGH] Open file handle for dbase400.dat (dialogue subtitle text + 8-byte voice-directory "
			+ "records). Opened by open_dialogue_script, walked by read_next_dialogue_line."),
		new NamedAddress(0x84900L, "g_voice_sos_callback",
			"[HIGH] Far pointer (offset here, selector @0x84904) to the SOS completion user-callback "
			+ "voice_stream_sos_callback (0x1e487). Installed by install_voice_sos_callback; fired via "
			+ "`call ptr[0x84900]` in the SOS trampoline 0x27501 on each buffer-complete / end event."),
		new NamedAddress(0x82018L, "g_voice_bytes_remaining",
			"[MED] Bytes left to stream in the current voice clip; decremented as decode_voice_block "
			+ "consumes the dbase500.dat record. Reaching 0 leads to the end-of-stream (state 2)."),
		new NamedAddress(0x820b9L, "g_voice_refill_pending",
			"[MED] Set 1 by voice_stream_sos_callback when a buffer drains; voice_stream_pump sees it, "
			+ "decodes the next disk block into the spare half and clears it. The ISR<->main-loop "
			+ "handshake that double-buffers a clip."),
		new NamedAddress(0x97440L, "g_sos_voice_table",
			"[MED] HMI/SOS digital-voice (mixer voices) table — mapped by the host/audio chat. "
			+ "Referenced by the SOS driver mixer path; documented here for cross-reference."),
		new NamedAddress(0x82034L, "g_voice_is_dpcm",
			"[MED] Clip codec flag: 1 = 8-bit DPCM (decode via decode_dpcm_block), 0 = raw PCM. Set from "
			+ "the clip header format tag (==0x2a -> 1) in prime_voice_clip. (Earlier mislabeled 'stereo'.)"),
		new NamedAddress(0x82038L, "g_voice_dpcm_predictor",
			"[MED] Running 16-bit DPCM predictor/accumulator carried across blocks; reset to 0 at clip "
			+ "start (prime_voice_clip) and updated by decode_dpcm_block."),
		new NamedAddress(0x918a4L, "g_dpcm_step_table",
			"[MED] int32[256] signed delta step table for the voice DPCM codec, built once by "
			+ "build_dpcm_step_table. Indexed by each raw source byte. Slot 50 (0x9196c) doubles as the "
			+ "'already built' guard."),
		new NamedAddress(0x82041L, "g_voice_sample_rate",
			"[MED] Voice playback sample rate (Hz). Decode requires >=0x80; prime_voice_clip programs the "
			+ "SOS buffer descriptor from it (and sets a rate flag when <0x7f00). Settable via 0x1e76e."),
		new NamedAddress(0x83e94L, "g_voice_decode_suspended",
			"[MED] When != 0, decode_voice_block produces 0 bytes (audio decode suspended -> silence/EOF). "
			+ "Set 0xffffffff at 0x26915; cleared at 0x1f8aa/0x25f7a/0x268cf (pause/resume around state changes)."),
		new NamedAddress(0x7f57cL, "g_dirty_rect_count",
			"[SCREEN] Number of accumulated dirty rectangles this frame (max 0x40). Built by add_dirty_rect, "
			+ "consumed+reset by flush_dirty_rects."),
		new NamedAddress(0x7f580L, "g_dirty_rects",
			"[SCREEN] Dirty-rectangle array (stride 0x10: left@+0, top@+4, right@+8, bottom@+0xc; up to 0x40). "
			+ "Kept non-overlapping by add_dirty_rect (0x15b69)."),
		new NamedAddress(0x7f980L, "g_prev_dirty_rect_count",
			"[SCREEN] Previous frame's dirty-rect count (flush re-blits these too for the double buffer)."),
		new NamedAddress(0x7f984L, "g_prev_dirty_rects",
			"[SCREEN] Previous frame's dirty-rect array (flush_dirty_rects rotates this frame's list here)."),
		new NamedAddress(0x90c04L, "g_flush_predraw_flag",
			"[SCREEN] When set, flush_dirty_rects runs flush_predraw_hook (0x3cf19) before presenting."),
		new NamedAddress(0x7e8c8L, "g_screen_busy_depth",
			"[SCREEN] Draw-busy / re-entrancy DEPTH: incremented on entering a draw/blit section "
			+ "(begin_screen_draw 0x11ca9, blit_dirty_rect_list 0x2dd85) and decremented on exit "
			+ "(end_screen_draw 0x11cc6). >0 = the screen is mid-update (gates overlapping cursor/flush work)."),
		new NamedAddress(0x7e928L, "g_mouse_buttons_held",
			"[INPUT] Accumulated mouse buttons pressed (OR'd each poll_mouse_input)."),
		new NamedAddress(0x7e929L, "g_mouse_buttons_prev",
			"[INPUT] Previous frame's mouse button state, for press-edge detection in poll_mouse_input."),
		new NamedAddress(0x7e93aL, "g_mouse_click_edges",
			"[INPUT] Per-poll mouse press-edge flags (bit0=left/primary pressed this frame, bit1=right/secondary)."),
		new NamedAddress(0x81034L, "g_displayed_item_left",
			"[INVENTORY] Pointer to the item record shown in the LEFT equipped/hand slot of the inventory panel "
			+ "(drawn by draw_equipped_item_left 0x1a2ef)."),
		new NamedAddress(0x81040L, "g_displayed_item_right",
			"[INVENTORY] Pointer to the item record shown in the RIGHT equipped/hand slot of the inventory panel "
			+ "(drawn by refresh_inventory_panel 0x1bf7b)."),
		new NamedAddress(0x71dc6L, "g_current_vesa_bank",
			"[VIDEO] Currently-selected VESA display window/bank (set_vesa_bank re-banks only on change)."),
		new NamedAddress(0x71dccL, "g_vesa_available",
			"[VIDEO] Nonzero if VESA Display Window Control (INT 10h 4F05h) is available; gates set_vesa_bank."),
		new NamedAddress(0x7f358L, "g_screen_resolution_index",
			"[VIDEO] Index of the active screen-resolution entry in the mode table at 0x1470c (0..9, or the special "
			+ "VGA/ModeX states). Advanced + applied by cycle_screen_resolution (0x1480c)."),
		new NamedAddress(0x146d8L, "g_linear_framebuffer_ptr",
			"[VIDEO] Mapped LINEAR VESA framebuffer base (DPMI map_physical_address result), or 0 when in a "
			+ "banked/Mode X layout. Non-zero selects the LinBase blit paths."),
		new NamedAddress(0x146dcL, "g_video_mode_width",
			"[VIDEO] Pixel width (XResolution) of the current VESA/linear mode; used as the row stride for linear-framebuffer blits."),
		new NamedAddress(0x146e0L, "g_current_vesa_mode",
			"[VIDEO] The VESA mode number last set via set_vesa_video_mode (passed to INT 10h 0x4F02)."),
		new NamedAddress(0x76634L, "g_video_linear_flag",
			"[VIDEO] Non-zero when the active layout is a wide/linear (non-320x200) mode; switches recompute_view_region_offsets "
			+ "and the blit family between the plain VGA-13h path and the scaled/linear paths."),
		new NamedAddress(0x8c1deL, "g_viewmodel_shade_level",
			"[VIDEO/HUD] Shade/fade level for the first-person viewmodel sprite: 0 (or >=0x80) = full-bright plain blit; "
			+ "1..0x7f selects the colormap-shaded blit variant in draw_player_viewmodel_sprite (used for weapon fade-in/dim)."),
		new NamedAddress(0x7f254L, "g_view_grayscale_lut",
			"[VIDEO] 256-entry luminance LUT applied over the whole 3D viewport by grayscale_background_view to desaturate "
			+ "the background view behind the inventory overlay; rebuilt by build_view_grayscale_lut (0x12be2) when "
			+ "g_view_grayscale_lut_valid is clear."),
		new NamedAddress(0x7f354L, "g_view_grayscale_lut_valid",
			"[VIDEO] When 0, grayscale_background_view rebuilds g_view_grayscale_lut via build_view_grayscale_lut before applying it."),
		new NamedAddress(0x70744L, "g_snapshot_name_seq",
			"[FILE] Numeric sequence field formatted (as decimal) into the configurable-path snapshot filename by "
			+ "build_screenshot_filename. Distinct from g_snapshot_counter (0x72480), the C:\\SnapNNNN.lbm index."),
		new NamedAddress(0x70738L, "g_snapshot_basename",
			"[FILE] Base file name for screenshots; build_screenshot_filename appends g_snapshot_counter + extension to it."),
		new NamedAddress(0x85488L, "g_palette_rgb_ptr",
			"[VIDEO] Pointer to the 256x3 (6-bit R/G/B) palette used by build_view_grayscale_lut to compute the view "
			+ "luminance remap."),
		new NamedAddress(0x7f355L, "g_rect_fill_color",
			"[VIDEO] Solid fill byte used by fill_rect_solid (0x12cd4)."),
		new NamedAddress(0x76878L, "g_saveunder_sprite_color_ptr",
			"[VIDEO/UI] Pointer to the color byte that draw_saveunder_sprite_recolored patches into blit_sprite_save_under's "
			+ "six layout SMC sites."),
		new NamedAddress(0x7684cL, "g_console_input_buffer",
			"[BOOT/CONSOLE] Destination buffer for the DOS text-input line editor (console_edit_text_field)."),
		new NamedAddress(0x76844L, "g_console_input_maxlen",
			"[BOOT/CONSOLE] Maximum character count accepted by console_edit_text_field."),
		new NamedAddress(0x76848L, "g_console_input_pos",
			"[BOOT/CONSOLE] Current cursor/length position within g_console_input_buffer in console_edit_text_field."),
		new NamedAddress(0x76854L, "g_console_input_numeric_only",
			"[BOOT/CONSOLE] When non-zero, console_edit_text_field accepts only digit characters."),
		new NamedAddress(0x7082eL, "g_scancode_translate_table",
			"[INPUT] Scancode->keycode table (stride 3: {scancode u8, value u16}, 0xff-terminated) used by "
			+ "dequeue_translated_key; bit 0x40 of g_key_modifier_flags selects the shifted byte."),
		new NamedAddress(0x90c42L, "g_key_modifier_flags",
			"[INPUT] Keyboard modifier/shift state; bit 0x40 selects the shifted scancode form in dequeue_translated_key."),
		new NamedAddress(0x76718L, "g_arg_token_buf",
			"[BOOT] Length-prefixed (byte 0 = count) uppercased command-line token built by copy_switch_token_upper and "
			+ "matched by dispatch_arg_command."),
		new NamedAddress(0x704a5L, "g_arg_command_table",
			"[BOOT] Startup command table (variable-stride records {u16 size, code* handler, keyword...}) scanned by "
			+ "dispatch_arg_command."),
		new NamedAddress(0x7e932L, "g_interaction_cursor_type",
			"[INTERACT] Cursor shape selected by classify_cursor_target_object for the object under the cursor (1/3/5 = "
			+ "the interact/inspect/blocked hand-cursor variants)."),
		new NamedAddress(0x7fdacL, "g_cursor_interaction_flags",
			"[INTERACT] Interaction state bits set by classify_cursor_target_object: bit2 = target has a command trigger, "
			+ "bit4 = blocked / out-of-range."),
		new NamedAddress(0x7fdbcL, "g_corner_icon_saveunder",
			"[HUD] Save-under framebuffer-region handle for the top-left character-portrait widget (draw_character_portrait_corner); "
			+ "freed on teardown (0x167d7)."),
		new NamedAddress(0x819bcL, "g_held_item_slide_timer",
			"[HUD] Slide-up animation timer for the bottom-right held-item icon (draw_held_item_icon); reset to 0 on a "
			+ "player interaction / inventory open / selection change so the icon slides fully into view."),
		new NamedAddress(0x81310L, "g_held_item_icon_spans",
			"[HUD] Encoded translucent-span data of the held-item icon, produced by encode_item_icon_to_spans "
			+ "(from update_selected_item_icon) and drawn by draw_held_item_icon / draw_translucent_icon_spans."),
		new NamedAddress(0x819b4L, "g_held_item_icon_width",
			"[HUD] Pixel width of the held-item icon span data; used by draw_held_item_icon and the encoder."),
		new NamedAddress(0x89f60L, "g_item_autoselected_flag",
			"[INVENTORY] Set to 1 when find_or_autoselect_inventory_item randomly auto-picks a matching item as the primary "
			+ "selection (cleared otherwise)."),
		new NamedAddress(0x89f54L, "g_player_speed_reduction_request",
			"[.RAW player-slow] Per-frame request written by cmd_set_player_speed_reduction (0x30ab3, RAW cmd 0x41) = "
			+ "the cmd+7 byte. tick_world_effects (0x3464c) latches it into g_player_speed_reduction_shift (0x89f58) each "
			+ "frame, then RESETS this to 0 — so the slow only persists while the command keeps firing (continuous while "
			+ "the player stands in the triggering sector). Value is a velocity right-SHIFT count, masked & 0x1f at use."),
		new NamedAddress(0x89f58L, "g_player_speed_reduction_shift",
			"[.RAW player-slow] Active velocity right-shift applied by player_movement_tick (0x12520): when nonzero, "
			+ "player_vel_accum_x/y >>= (this & 0x1f) before queuing the move (1=half speed, 2=quarter, ...). Latched each "
			+ "frame from g_player_speed_reduction_request (0x89f54). Arithmetic shift of a signed int = magnitude toward 0; "
			+ "CANNOT increase speed (no left-shift / no negative / mask caps at 31; a value that is a nonzero multiple of "
			+ "0x20 masks to shift 0 = full speed, a harmless no-op)."),
		new NamedAddress(0x810fcL, "g_inspect_page_count",
			"[UI] Number of pages in the current multi-page inspect/close-up document (load_inspect_document_page draws "
			+ "the prev/next arrows when >1)."),
		new NamedAddress(0x81184L, "g_inspect_current_page",
			"[UI] Current page index within the inspect document (load_inspect_document_page)."),
		new NamedAddress(0x7fed0L, "g_active_item_hud_icon",
			"[HUD] Close-up DAS handle of the player's active/held item, loaded by restore_active_held_item and drawn as "
			+ "the portrait-corner sub-icon by draw_character_portrait_corner."),
		new NamedAddress(0x7fec4L, "g_inventory_panel_open",
			"[INVENTORY] Non-zero while the full-screen inventory panel is open; repaint_hud_and_present closes it on "
			+ "return to gameplay."),
		new NamedAddress(0x7fd84L, "g_item_pickup_flags",
			"[PICKUP] LIVE 'pickup in progress' lock: bit0=active (a fly is playing), bit2=sub-mode. Set by "
			+ "begin_item_pickup_lock (on give_item), counted down + cleared after 0x1b frames by tick_item_pickup_lock, "
			+ "cleared on map load by reset_item_pickup_lock. READ by activate_targeted_object to block re-grabbing while "
			+ "the item flies. (Formerly mis-named g_camera_transition_flags; the sibling eased-position output 0x7114c is "
			+ "vestigial, but THIS flag is used.)"),
		new NamedAddress(0x85c40L, "g_resource_pool",
			"[POOL] Pool-allocator handle for object/DAS resource chunks (alloc 0x26b38 / free free_resource_chunk 0x26b4c)."),
		new NamedAddress(0x85294L, "g_map_geometry_selector",
			"[DPMI] LDT selector for the loaded map-geometry block; released on map-unload/shutdown by "
			+ "release_map_geometry_selector (0x2a8e9) and free_scene_geometry_buffers (0x2a93c)."),
		new NamedAddress(0x8548cL, "g_audio_decode_buffer_a",
			"[AUDIO] First of two 32KB voice/speech decode double-buffers (alloc_audio_stream_buffers 0x30051). "
			+ "prime_voice_clip stages it into the SOS streamer (-> 0x8201c); blocks of dbase500.dat voice data are "
			+ "decoded here and ping-ponged with g_audio_decode_buffer_b."),
		new NamedAddress(0x85490L, "g_audio_decode_buffer_b",
			"[AUDIO] Second 32KB voice/speech decode buffer (-> SOS streamer 0x82020). prime_voice_clip guards on this "
			+ "being allocated. (Earlier comments called this 'g_audio_buf2'.)"),
		new NamedAddress(0x85494L, "g_audio_silence_buffer",
			"[AUDIO] 8KB silence primer, filled with 0x80 (8-bit unsigned PCM silence; 0x00 if g_audio_signed_samples). "
			+ "voice_stream_sos_callback points the SOS source at it (-> 0x82045) to feed silence between/after clips."),
		new NamedAddress(0x7f478L, "g_audio_signed_samples",
			"[AUDIO] Sample-format flag read only by alloc_audio_stream_buffers: 0 = unsigned 8-bit (silence = 0x80), "
			+ "non-zero = signed (silence = 0x00)."),
		new NamedAddress(0x89f41L, "g_resource_pool_small_flag",
			"[POOL] Set to 1 by alloc_audio_stream_buffers when the DAS resource pool got the smallest (400KB) size "
			+ "tier (low free RAM); 0 for the 800KB/1.6MB tiers. Gates lower-detail resource behaviour."),
		new NamedAddress(0x7e8d0L, "g_mouse_relative_mode",
			"[INPUT] 1 = mouselook/relative mode (poll_mouse_motion feeds g_mouse_dx/dy to the camera); 0 = "
			+ "cursor/absolute mode (motion moves the pointer). Cleared by play_record_gdv_cutscene for modal UI."),
		new NamedAddress(0x76890L, "g_cursor_prev_x",
			"[CURSOR] Last drawn software-cursor X (update_software_cursor compares to detect motion; the "
			+ "0xffffff81 sentinel from force_cursor_redraw forces a repaint)."),
		new NamedAddress(0x76894L, "g_cursor_prev_y",
			"[CURSOR] Last drawn software-cursor Y (see g_cursor_prev_x)."),
		new NamedAddress(0x7f571L, "g_inventory_dirty_flags",
			"[INVENTORY] Dirty/state bits for the inventory panel (bit0=panel resources allocated, bit1, bit2 "
			+ "set by refresh_inventory_panel); close_inventory_panel frees the cached handles per these bits."),
		new NamedAddress(0x91de6L, "g_palette_dirty",
			"[VIDEO] Gate for write_vga_palette (0x4c334) — only pushes the palette to the DAC when set."),
		new NamedAddress(0x708e4L, "g_current_cursor_id",
			"[CURSOR] The resource id of the currently-loaded mouse pointer shape (set_cursor_shape skips a "
			+ "reload when unchanged)."),
		new NamedAddress(0x7e950L, "g_cursor_sprite",
			"[CURSOR] The decoded mouse-pointer sprite: width@+0, height@+1, pixels@+2. Loaded by "
			+ "set_cursor_shape; render state (ptrs/aux) at 0x7e93c..0x7e94c."),
		new NamedAddress(0x7f250L, "g_cursor_changed",
			"[CURSOR] Set by set_cursor_shape when the pointer shape actually changes this call."),
		new NamedAddress(0x84906L, "g_pending_sound_param",
			"[SFX] Per-call sound parameter staged before a play_* call (e.g. play_sound_effect sets 0x6e, "
			+ "play_entity_sound sets 0x20); consumed by the sound-handle setup."),
		new NamedAddress(0x83eb0L, "g_entity_sound_emitter",
			"[SFX] Shared scratch emitter record passed to play_object_sound by play_entity_sound (entity/"
			+ "attack/projectile one-shot positional sounds)."),
		new NamedAddress(0x8498cL, "g_door_worklist",
			"[COLLISION] Output cursor/list that gather_nearby_doors fills with {tag, door} pairs for the "
			+ "collision pass."),
		new NamedAddress(0x7f474L, "g_audio_sequence_pending",
			"[AUDIO] Pending/active audio-sequence counter, decremented by finalize_audio_sequence_ref (0x15689)."),
		new NamedAddress(0x83d18L, "g_screen_backup_handle",
			"[UI] DAS-cache handle holding the full-screen backup saved by play_record_gdv_cutscene (0x20c16) so the "
			+ "scene can be restored when the message/overlay closes."),
		new NamedAddress(0x83d28L, "g_message_resource_handle",
			"[UI] DAS-cache handle for the message record's associated dbase400 resource, loaded by "
			+ "play_record_gdv_cutscene; freed on the next message."),
		new NamedAddress(0x83d24L, "g_saved_movement_enabled",
			"[UI] Snapshot of g_player_movement_enabled taken by play_record_gdv_cutscene before freezing the player "
			+ "for a modal message; restored when it closes."),
		// Code LABEL (not a function) inside load_das_cache_resource [0x1869b,0x1874d): a shared multi-entry
		// epilogue. Labelled (not carved) so load_das_cache_resource stays one function. See flow_succ.
		new NamedAddress(0x18747L, "shared_epilogue_5reg",
			"Shared function EPILOGUE (leave; pop edi/esi/ecx/ebx; ret) - restores 5 regs (ebp+edi+esi+ecx+ebx). "
			+ "It is load_das_cache_resource's own return tail, ALSO reached by jumps from swap_inventory_entries "
			+ "(0x1b007) and draw_reloc_ui_row (0x1c512). NOT a standalone call target - a Watcom shared-code "
			+ "multi-entry tail; this is the flow_succ->0x1869b edge those two functions carry. (recomp 2026-07-01.)"),
	};

	public void run() throws Exception {
		if (currentProgram == null) {
			printerr("Open the ROTH program before running this script.");
			return;
		}

		applyGlobals();
		applyFunctions();

		println("Applied ROTH engine names: " + engineFunctions.length + " functions, "
			+ engineGlobals.length + " globals.");
		println("Player state: g_player_x/y/z/angle. Movement uses g_sincos_table.");
		println("See ROTH_engine_notes.md and ROTH_text_rendering_notes.md for subsystem notes.");
	}

	private void applyFunctions() throws Exception {
		for (NamedFunction item : engineFunctions) {
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

	private void applyGlobals() throws Exception {
		for (NamedAddress item : engineGlobals) {
			monitor.checkCancelled();
			Address addr = toAddr(item.address);
			createUserLabel(item.address, item.name);
			setPlateComment(addr, item.comment);
		}
	}

	private void createUserLabel(long offset, String name) throws Exception {
		Address addr = toAddr(offset);
		Namespace global = currentProgram.getGlobalNamespace();
		Symbol sym = currentProgram.getSymbolTable().getSymbol(name, addr, global);
		if (sym == null) {
			sym = currentProgram.getSymbolTable().createLabel(addr, name, global, SourceType.USER_DEFINED);
		}
		// Make this engine-names label PRIMARY (what the decompiler/export shows). createLabel only
		// ADDS a label; a label created earlier on this DB by another script (notably the frozen
		// ROTHApplyDasTypes.java, last run 06-11) stays primary, so without this our rename silently
		// becomes a non-primary alias and the corpus keeps the stale name. engine-names is the single
		// live source of truth, so its name must win for globals too — symmetric with setName() for
		// functions. (Added 2026-06-20; see RECONCILE_das_cache_vs_scanline_globals.RESOLVED.md.)
		if (sym != null && !sym.isPrimary()) {
			sym.setPrimary();
		}
	}
}
