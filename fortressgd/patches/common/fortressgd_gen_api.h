/**************************************************************************/
/*  fortressgd_gen_api.h                                                  */
/**************************************************************************/

#pragma once

#include <cstddef>
#include <cstdint>

// Fixed boundary between patched Godot and the per-build generated code
// (DESIGN.md §18.3). Patched Godot calls only the functions declared here;
// it never includes generated content, so a new project's generated files
// never invalidate Godot's object files (§18.4).
//
// The generator emits fortressgd_gen.cpp (one or more files) with definitions
// of these functions. Each definition stores its value encoded and decodes it
// through generated routines; none holds the project secret, the salt or the
// signing seed. See fortressgd/generator/ for the producing side and its
// interpreter, which the tests check against the compiled output and FGD-KDF-1.
//
// The security switches (FGD_REQUIRE_PACK_SIGNATURE, dialect on/off, opcode map
// on/off) stay compile-time flags passed to the build, never values returned
// from here: in data one flipped byte would turn a check off.

// Number of GDScript VM opcodes the opcode tables cover. A compile-time
// constant so callers can size the buffers passed to fgd_opcode_tables().
#ifndef FGD_OPCODE_COUNT
#define FGD_OPCODE_COUNT 158
#endif

// Reconstruct the 32-byte pack AES key, FGD-KDF-1(secret, salt), into r_key.
// The decoded key lives only in the caller's buffer; wipe it when done.
void fgd_derive_key(uint8_t r_key[32]);

// The dialect pack magic (never the stock "GDPC" value 0x43504447).
uint32_t fgd_pack_magic();

// Permutation of the pack index record fields (ofs, size, md5, flags) into
// r_perm[4]: r_perm[i] is the stored position of original field i.
void fgd_index_perm(uint8_t r_perm[4]);

// Fill the GDScript VM opcode map and its inverse. Both buffers hold
// FGD_OPCODE_COUNT entries. r_map[original] is the stored opcode;
// r_unmap[stored] is the original. Decode once at startup into a heap table so
// VM dispatch cost is unchanged.
void fgd_opcode_tables(uint16_t r_map[FGD_OPCODE_COUNT], uint16_t r_unmap[FGD_OPCODE_COUNT]);

// The 32-byte Ed25519 public key that signed packs are verified against.
void fgd_pack_pubkey(uint8_t r_pubkey[32]);
