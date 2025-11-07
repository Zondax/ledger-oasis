/*******************************************************************************
 *   (c) 2019 Zondax GmbH
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <sigutils.h>
#include <stdbool.h>
#include <zxerror.h>
#include <zxmacros.h>

#include "coin.h"

extern uint32_t hdPath[MAX_BIP32_PATH];
extern uint8_t hdPathLen;
extern uint8_t chain_code;

uint16_t crypto_encodeAddress(char *addr_out, uint16_t addr_out_max, uint8_t *pubkey, address_kind_e kind);

zxerr_t crypto_fillAddress(uint8_t *buffer, uint16_t buffer_len, uint16_t *addrLen, address_kind_e kind);
zxerr_t crypto_fillEthAddress(uint8_t *buffer, uint16_t bufferLen, uint16_t *addrLen);
zxerr_t crypto_signEd25519(uint8_t *signature, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen,
                           uint16_t *sigSize);

zxerr_t crypto_signSecp256k1(uint8_t *signature, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen,
                             uint16_t *sigSize);

zxerr_t crypto_sign_sr25519(uint8_t *output, uint16_t outputLen, const uint8_t *data, size_t len, const uint8_t *ctx,
                            size_t ctx_len, uint16_t *sigSize);
zxerr_t crypto_sign_eth(uint8_t *buffer, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen,
                        uint16_t *sigSize);

zxerr_t keccak_digest(const unsigned char *in, unsigned int inLen, unsigned char *out, unsigned int outLen);
#ifdef __cplusplus
}
#endif
