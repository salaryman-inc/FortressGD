/**************************************************************************/
/*  fortressgd_editor_dialect.h                                           */
/**************************************************************************/
/* The shared FortressGD export editor's dialect values (DESIGN.md §18.5). */
/**************************************************************************/

/* `fortressgd templates build --editor` installs this file as core/dialect.gen.h
 * in place of a generated header. The editor it builds is the same for every
 * project: nothing project-specific is compiled in.
 *
 * `fortressgd export` passes the project's pack magic and index-record field
 * order in FORTRESSGD_PACK_PARAMS for the length of one export:
 *
 *     FORTRESSGD_PACK_PARAMS=1:<magic, 8 lowercase hex digits>:<field order, 4 digits>
 *
 * for example 1:9f3c1a77:2013. The pack AES key arrives in
 * GODOT_SCRIPT_ENCRYPTION_KEY, as for a stock export. The editor needs no opcode
 * tables: a pack carries GDScript as tokens, and the template compiles them.
 *
 * Unset or empty: stock magic and field order, so the editor reads and writes
 * stock packs. Set but malformed: the editor exits with status 2 at startup,
 * before it opens a project, so it never writes a pack with the wrong values. */

#ifndef FORTRESSGD_DIALECT_GEN_H
#define FORTRESSGD_DIALECT_GEN_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define FORTRESSGD_PACK_PARAMS_ENV "FORTRESSGD_PACK_PARAMS"
#define FORTRESSGD_STOCK_PACK_MAGIC 0x43504447u

struct FortressgdPackParams {
	uint32_t magic;
	uint8_t perm[4];
};

/* Parses FORTRESSGD_PACK_PARAMS. Returns 0 and fills r_params, or returns 1 and
 * leaves the stock values in r_params. Reads p_text one character at a time and
 * stops at the first one that does not fit, so it never reads past the end. */
inline int fortressgd_parse_pack_params(const char *p_text, FortressgdPackParams *r_params) {
	r_params->magic = FORTRESSGD_STOCK_PACK_MAGIC;
	for (int i = 0; i < 4; i++) {
		r_params->perm[i] = (uint8_t)i;
	}
	if (p_text == nullptr || p_text[0] == 0) {
		return 0;
	}
	if (p_text[0] != '1' || p_text[1] != ':') {
		return 1;
	}
	const char *p = p_text + 2;
	uint32_t magic = 0;
	for (int i = 0; i < 8; i++) {
		const char c = p[i];
		uint32_t digit;
		if (c >= '0' && c <= '9') {
			digit = (uint32_t)(c - '0');
		} else if (c >= 'a' && c <= 'f') {
			digit = (uint32_t)(c - 'a' + 10);
		} else {
			return 1;
		}
		magic = (magic << 4) | digit;
	}
	p += 8;
	if (*p != ':') {
		return 1;
	}
	p++;
	uint8_t perm[4];
	unsigned seen = 0;
	for (int i = 0; i < 4; i++) {
		const char c = p[i];
		if (c < '0' || c > '3') {
			return 1;
		}
		const unsigned field = (unsigned)(c - '0');
		if (seen & (1u << field)) {
			return 1;
		}
		seen |= 1u << field;
		perm[i] = (uint8_t)field;
	}
	if (p[4] != 0) {
		return 1;
	}
	/* A dialect magic is never 0 or stock GDPC (generator/dialect.py). */
	if (magic == 0 || magic == FORTRESSGD_STOCK_PACK_MAGIC) {
		return 1;
	}
	r_params->magic = magic;
	for (int i = 0; i < 4; i++) {
		r_params->perm[i] = perm[i];
	}
	return 0;
}

/* Parsed once. The first call is at startup (below). */
inline const FortressgdPackParams &fortressgd_pack_params() {
	static const FortressgdPackParams params = []() {
		FortressgdPackParams parsed;
		if (fortressgd_parse_pack_params(getenv(FORTRESSGD_PACK_PARAMS_ENV), &parsed) != 0) {
			fprintf(stderr, "FortressGD: " FORTRESSGD_PACK_PARAMS_ENV " is malformed; refusing to read or write packs.\n");
			fflush(stderr);
			_Exit(2);
		}
		return parsed;
	}();
	return params;
}

/* Every file that includes this header checks the variable during static
 * initialisation, so a malformed value stops the editor before main(). The parse
 * itself runs once. */
[[maybe_unused]] static const bool fortressgd_pack_params_checked = (fortressgd_pack_params(), true);

#define FGD_PACK_MAGIC (fortressgd_pack_params().magic)
#define FGD_INDEX_PERM (fortressgd_pack_params().perm)

/* No pack key is compiled in. The editor's own pack reader gets the zero key, as
 * a stock editor built without SCRIPT_AES256_ENCRYPTION_KEY does; exporting
 * never reads an encrypted pack. */
static const volatile uint8_t FGD_KEY_MASKS[4][8] = {};
static const volatile uint8_t FGD_KEY_SHARDS[4][8] = {};

/* The editor is built without FORTRESSGD_SIGN_PACKS; `fortressgd export` signs
 * packs itself. These only satisfy the patches that name them. */
static const uint8_t FGD_PACK_PUBKEY[32] = {};
static const uint8_t FGD_REQUIRE_PACK_SIGNATURE = 0;

#endif /* FORTRESSGD_DIALECT_GEN_H */
