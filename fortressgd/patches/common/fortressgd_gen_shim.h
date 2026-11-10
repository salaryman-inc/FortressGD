/**************************************************************************/
/*  fortressgd_gen_shim.h                                                 */
/**************************************************************************/
/* Template-build dialect.gen.h for generator v2 (DESIGN.md §18.3).        */
/**************************************************************************/

/* `fortressgd templates build` installs this file as core/dialect.gen.h for a
 * template build, in place of the v1 data header. The patches reference the
 * FGD_* names below exactly as they referenced the v1 arrays; here they are
 * runtime globals filled once at startup by fortressgd_gen_shim.cpp from the
 * per-build routines in fortressgd_gen.cpp. The plaintext values are decoded at
 * runtime, so none is stored as a plain array in the binary.
 *
 * The editor build installs fortressgd_editor_dialect.h as core/dialect.gen.h
 * instead; it provides the same names from the environment and compiles in no
 * key. */

#ifndef FORTRESSGD_DIALECT_GEN_H
#define FORTRESSGD_DIALECT_GEN_H

#include <stdint.h>

#include "fortressgd_gen_api.h"

/* Decoded once at startup (fortressgd_gen_shim.cpp). */
extern uint32_t FGD_PACK_MAGIC;
extern uint8_t FGD_INDEX_PERM[4];
extern uint16_t FGD_OPCODE_MAP[FGD_OPCODE_COUNT];
extern uint16_t FGD_OPCODE_UNMAP[FGD_OPCODE_COUNT];
extern uint8_t FGD_PACK_PUBKEY[32];

/* FGD_REQUIRE_PACK_SIGNATURE (whether the template refuses unsigned packs) is
 * not defined here. It is a compile-time flag, never a stored value: in data one
 * flipped byte would turn the check off (§18.3). The build writes it into
 * core/fortressgd_variant.h, which only core/io/file_access_pack.cpp includes, so
 * turning sign_packs on or off recompiles that one file, not every file that
 * includes this header (§18.4). */

#endif /* FORTRESSGD_DIALECT_GEN_H */
