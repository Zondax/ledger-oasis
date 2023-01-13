/*******************************************************************************
*  (c) 2020 Zondax GmbH
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

#define MAINNET_GENESIS_HASH "b11b369e0da5bb230b220127f5e7b242d385ef8c6f54906243f30af63c815535"
#define TESTNET_GENESIS_HASH "50304f98ddb656620ea817cc1446c401752a05a249b36c9b90dba4616829977a"

#define CIPHER_MAIN_RUNID "000000000000000000000000000000000000000000000000e199119c992377cb"
#define CIPHER_TEST_RUNID "0000000000000000000000000000000000000000000000000000000000000000"
#define EMERALD_MAIN_RUNID "000000000000000000000000000000000000000000000000e2eaa99fc008f87f"
#define EMERALD_TEST_RUNID "00000000000000000000000000000000000000000000000072c8215e60d5bca7"
#define SAPPHIRE_MAIN_RUNID "000000000000000000000000000000000000000000000000f80306c9858e7279"
#define SAPPHIRE_TEST_RUNID "000000000000000000000000000000000000000000000000a6d1e3ebf60dff6c"

#define CIPHER_MAIN_TO_ADDR "oasis1qrnu9yhwzap7rqh6tdcdcpz0zf86hwhycchkhvt8"
#define CIPHER_TEST_TO_ADDR "oasis1qqdn25n5a2jtet2s5amc7gmchsqqgs4j0qcg5k0t"
#define EMERALD_MAIN_TO_ADDR "oasis1qzvlg0grjxwgjj58tx2xvmv26era6t2csqn22pte"
#define EMERALD_TEST_TO_ADDR "oasis1qr629x0tg9gm5fyhedgs9lw5eh3d8ycdnsxf0run"
#define SAPPHIRE_MAIN_TO_ADDR "oasis1qrd3mnzhhgst26hsp96uf45yhq6zlax0cuzdgcfc"
#define SAPPHIRE_TEST_TO_ADDR "oasis1qqczuf3x6glkgjuf0xgtcpjjw95r3crf7y2323xd"

#define SK_SECP256K1_SIZE       32
#define HASH_SIZE               64
#define PUB_KEY_SIZE            32
#define ETH_ADDR_LEN            20
#define ADDR_RAW                21
#define KECCAK256_HASH_LEN      32
#define RUNTIME_ID_BYTE_LEN     32
#define CHAIN_CONTEXT_BYTE_LEN  32
#define SIGCONTEXT_HASH_LEN     64
#define ORIG_TO_SIZE            42

typedef enum {
    addr_ed25519 = 0,
    addr_secp256k1 = 1,
} address_kind_e;

#if defined(APP_CONSUMER)
#include "consumer/coin_consumer.h"
#elif defined(APP_VALIDATOR)
#include "validator/coin_validator.h"
#else
#error "APP MODE IS NOT SUPPORTED"
#endif
