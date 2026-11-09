/**************************************************************************/
/*  fortressgd_kdf.h                                                      */
/**************************************************************************/

#pragma once

#include "core/string/ustring.h"

#include <cstddef>
#include <cstdint>

void fortressgd_wipe(void *p, size_t n);
void fortressgd_derive_key(uint8_t r_key[32]);
String fortressgd_msg_enc_dir();
String fortressgd_msg_enc_file();
String fortressgd_msg_enc_file_err();
