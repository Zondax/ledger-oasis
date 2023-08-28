/*******************************************************************************
*  (c) 2019 Zondax GmbH
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

#include <stdint.h>
#include <stddef.h>

#define CLA                  0xF5
#define CLA_ETH              0xE0

#define HDPATH_LEN_DEFAULT     5
#define HDPATH_LEN_ADR0008     3
#define MAX_BIP32_PATH           10

#define HDPATH_0_DEFAULT     (0x80000000u | 0x2b)
#define HDPATH_1_DEFAULT     (0x80000000u | 0x1da)
#define HDPATH_1_ALTERNATIVE (0x80000000u | 0x3c)
#define HDPATH_1_ALTERNATIVE2 (0x80000000 | 0x162)
#define HDPATH_2_DEFAULT     (0x80000000u | 0u)
#define HDPATH_3_DEFAULT     (0u)
#define HDPATH_4_DEFAULT     (0u)

#define HDPATH_ETH_0_DEFAULT (0x80000000u | 0x2cu)
#define HDPATH_ETH_1_DEFAULT (0x80000000u | 0x3cu)

#define PK_LEN_ED25519          32u
#define PK_LEN_SECP256K1        33u
#define PK_LEN_SECP256K1_FULL   65u
#define SK_LEN_25519            64u
#define PK_LEN_ED25519          32u
#define PK_LEN_SR25519          32u

#define VIEW_ADDRESS_OFFSET_ED25519         (PK_LEN_ED25519)
#define VIEW_ADDRESS_OFFSET_SECP256K1       (PK_LEN_SECP256K1)

// eth address chain_code allowed valuec
#define P2_NO_CHAINCODE                 0x00
#define P2_CHAINCODE                    0x01
#define VIEW_ADDRESS_OFFSET_ETH             (PK_LEN_SECP256K1_FULL + 1 + 1)

#define VIEW_ADDRESS_ITEM_COUNT             2
#define VIEW_ADDRESS_LAST_PAGE_DEFAULT      0

#define CRYPTO_BLOB_SKIP_BYTES              1

#define MENU_MAIN_APP_LINE1 "Oasis"
#define MENU_MAIN_APP_LINE2 "Validator"
#define APPVERSION_LINE1 "Version"
#define APPVERSION_LINE2 APPVERSION

#define MAX_BECH32_HRP_LEN      83u

#define COIN_HRP            "oasis"
#define COIN_AMOUNT_DECIMAL_PLACES 9
#define COIN_RATE_DECIMAL_PLACES 5

#define MAX_RATES           10
#define MAX_CONTEXT_SIZE    64
#define MAX_ENTITY_NODES    16

#define COIN_DENOM          ""
#define COIN_ADDRESS_VERSION    0
#define COIN_ADDRESS_ED25519_CONTEXT    "oasis-core/address: staking"
#define COIN_ADDRESS_SR25519_CONTEXT    "oasis-runtime-sdk/address: sr25519"

#ifdef __cplusplus
}
#endif
