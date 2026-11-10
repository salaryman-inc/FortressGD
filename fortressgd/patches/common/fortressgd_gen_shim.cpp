/**************************************************************************/
/*  fortressgd_gen_shim.cpp                                               */
/**************************************************************************/
/* Fill the generator v2 runtime globals once at startup (DESIGN.md §18.3). */
/**************************************************************************/

#include "fortressgd_gen_shim.h"

/* The pack key is never a global: fortressgd_derive_key() decodes it into a
 * caller buffer and wipes it. The values below are the non-secret dialect data
 * (magic, index order, opcode tables, the public key); decoding them once into
 * globals keeps the VM dispatch a plain array load, as the v1 arrays were. */
uint32_t FGD_PACK_MAGIC = 0;
uint8_t FGD_INDEX_PERM[4] = { 0, 1, 2, 3 };
uint16_t FGD_OPCODE_MAP[FGD_OPCODE_COUNT] = {};
uint16_t FGD_OPCODE_UNMAP[FGD_OPCODE_COUNT] = {};
uint8_t FGD_PACK_PUBKEY[32] = {};

namespace {
struct FgdGenInit {
	FgdGenInit() {
		FGD_PACK_MAGIC = fgd_pack_magic();
		fgd_index_perm(FGD_INDEX_PERM);
		fgd_opcode_tables(FGD_OPCODE_MAP, FGD_OPCODE_UNMAP);
		fgd_pack_pubkey(FGD_PACK_PUBKEY);
	}
};
// Runs before main(); the globals are read only during pack access and VM
// execution, both well after startup, so cross-TU init order does not matter.
FgdGenInit fgd_gen_init;
} // namespace
