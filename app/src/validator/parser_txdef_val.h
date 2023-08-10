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

#define CBOR_PARSER_MAX_RECURSIONS 4

#include <coin.h>
#include <zxtypes.h>
#include <validator/vote.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#define ETH_ADDRESS_LEN 20
typedef struct {
    const uint8_t *ptr;
    uint8_t len;
    const uint8_t *suffixPtr;
    uint8_t suffixLen;
} context_t;

typedef enum {
    unknownType,
    txType,
    entityType,
    nodeType,
    consensusType
} oasis_blob_type_e;

typedef struct {
    context_t context;

    union {
        oasis_tx_vote_t voteTx;
    } oasis;

    oasis_blob_type_e type;
} parser_tx_t;

// simple struct that holds a bigint(256) 
typedef struct {
    uint32_t offset;
    // although bigInts are defined in 
    // ethereum as 256 bits,
    // it is possible that it is smaller.
    uint32_t len;
} eth_big_int_t;

// chain_id
typedef struct {
    uint32_t offset;
    uint32_t len;
} chain_id_t;

// ripemd160(sha256(compress(secp256k1.publicKey()))
typedef struct {
    uint8_t addr[ETH_ADDRESS_LEN];
} eth_addr_t;

// Type that holds the common fields 
// for legacy and eip2930 transactions
typedef struct {
    eth_big_int_t nonce;
    eth_big_int_t gas_price;
    eth_big_int_t gas_limit;
    eth_addr_t address;
    eth_big_int_t value;
    uint32_t data_at;
    uint32_t dataLen;
} eth_base_t;

// EIP 2718 TransactionType
// Valid transaction types should be in [0x00, 0x7f]
typedef enum eth_tx_type_t {
  eip2930 = 0x01,
  eip1559 = 0x02,
  // Legacy tx type is greater than or equal to 0xc0.
  legacy = 0xc0
} eth_tx_type_t;

typedef struct {
    eth_tx_type_t tx_type;
    chain_id_t chain_id;
    // lets use an anonymous 
    // union to hold the 3 possible types of transactions:
    // legacy, eip2930, eip1559
    union {
        eth_base_t legacy;
    };
 
} eth_tx_t;

#ifdef __cplusplus
}
#endif
