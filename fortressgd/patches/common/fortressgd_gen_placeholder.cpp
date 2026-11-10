/**************************************************************************/
/*  fortressgd_gen_placeholder.cpp                                        */
/**************************************************************************/
/* Stand-in for the generated fortressgd_gen.cpp in a build image's        */
/* precompiled tree (DESIGN.md §18.4).                                     */
/**************************************************************************/

/* A build image compiles every Godot object once with this file in place of the
 * per-project fortressgd_gen.cpp. `fortressgd templates build` then mounts the
 * project's generated file over it, so only that one object is recompiled before
 * the relink.
 *
 * It holds no key and no dialect values. Every function traps, and
 * fortressgd_gen_shim.cpp calls them during static initialisation, so a template
 * linked against this placeholder by mistake stops at startup instead of running
 * with a known key or stock values. */

#include "fortressgd_gen_api.h"

void fgd_derive_key(uint8_t r_key[32]) {
	(void)r_key;
	__builtin_trap();
}

uint32_t fgd_pack_magic() {
	__builtin_trap();
}

void fgd_index_perm(uint8_t r_perm[4]) {
	(void)r_perm;
	__builtin_trap();
}

void fgd_opcode_tables(uint16_t r_map[FGD_OPCODE_COUNT], uint16_t r_unmap[FGD_OPCODE_COUNT]) {
	(void)r_map;
	(void)r_unmap;
	__builtin_trap();
}

void fgd_pack_pubkey(uint8_t r_pubkey[32]) {
	(void)r_pubkey;
	__builtin_trap();
}
