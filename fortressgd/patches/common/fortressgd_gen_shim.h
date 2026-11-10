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

/* Whether the template refuses unsigned packs. A compile-time flag, never a
 * stored value: in data one flipped byte would turn the check off (§18.3). The
 * build passes -DFGD_REQUIRE_PACK_SIGNATURE=1 for a signing template. */
#ifndef FGD_REQUIRE_PACK_SIGNATURE
#define FGD_REQUIRE_PACK_SIGNATURE 0
#endif

#endif /* FORTRESSGD_DIALECT_GEN_H */
