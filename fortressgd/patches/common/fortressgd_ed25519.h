/**************************************************************************/
/*  fortressgd_ed25519.h                                                  */
/**************************************************************************/

#pragma once

#include <cstddef>
#include <cstdint>

/* Verify Ed25519(sig) over message. Returns 1 if valid, 0 otherwise. */
int fortressgd_ed25519_verify(const uint8_t p_public[32], const uint8_t *p_msg, size_t p_msg_len, const uint8_t p_sig[64]);
