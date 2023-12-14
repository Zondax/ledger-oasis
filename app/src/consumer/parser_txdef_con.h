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

#include <cbor.h>
#include <coin.h>
#include <zxtypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#define ENTITY_METADATA_NAME_MAX_CHAR 50
#define ENTITY_METADATA_URL_MAX_CHAR 64
#define ENTITY_METADATA_EMAIL_MAX_CHAR 32
#define ENTITY_METADATA_HANDLE_MAX_CHAR 32

#define HANDLER_MAX_LENGTH 32
#define EPOCH_MAX_VALUE 0xFFFFFFFFFFFFFFFF
#define ETH_ADDRESS_LEN         20

typedef struct {
    const char *network;
    const char *runid;
    const char *address;
    uint8_t decimals;
    const char *name;
} rt_lookup_t;

typedef enum {
    unknownMethod,
    stakingTransfer,
    stakingBurn,
    stakingWithdraw,
    stakingAllow,
    stakingEscrow,
    stakingReclaimEscrow,
    stakingAmendCommissionSchedule,
    registryDeregisterEntity,
    registryUnfreezeNode,
    registryRegisterEntity,
    governanceSubmitProposal,
    governanceCastVote,
    accountsTransfer,
    consensusDeposit,
    consensusWithdraw,
    consensusDelegate,
    consensusUndelegate,
    contractsInstantiate,
    contractsCall,
    contractsUpgrade,
    transactionEncrypted,
    evmCall
} oasis_methods_e;

typedef enum{
    upgrade,
    cancelUpgrade
} submit_proposal_type;

typedef struct {
    const uint8_t *ptr;
    uint8_t len;
    const uint8_t *suffixPtr;
    uint8_t suffixLen;
} context_t;

typedef uint8_t publickey_t[32];

typedef struct {
    uint8_t buffer[64];
    size_t len;
} quantity_t;

typedef uint8_t address_raw_t[21];

typedef struct {
    uint8_t buffer[64];
    size_t len;
} string_t;

typedef struct {
    // one more for the zero termination
    uint8_t buffer[ENTITY_METADATA_NAME_MAX_CHAR+1];
    size_t len;
} name_t;

typedef struct {
    // one more for the zero termination
    uint8_t buffer[ENTITY_METADATA_URL_MAX_CHAR+1];
    size_t len;
} url_t;

typedef struct {
    // one more for the zero termination
    uint8_t buffer[ENTITY_METADATA_EMAIL_MAX_CHAR+1];
    size_t len;
} email_t;

typedef struct {
    // one more for the zero termination
    uint8_t buffer[ENTITY_METADATA_HANDLE_MAX_CHAR+1];
    size_t len;
} handle_t;

typedef uint8_t raw_signature_t[64];

typedef struct {
    quantity_t amount;
    string_t denom;
} token_t;


typedef struct {
    publickey_t public_key;
    raw_signature_t raw_signature;
} signature_t;

typedef uint64_t epochTime_t;

typedef struct {
    epochTime_t start;
    quantity_t rate;
} commissionRateStep_t;

typedef struct {
    epochTime_t start;
    quantity_t rate_max;
    quantity_t rate_min;
} commissionRateBoundStep_t;

typedef struct {
    CborParser parser;
    CborValue startValue;
} cbor_parser_state_t;

typedef struct {
    uint64_t descriptor_version;
    publickey_t id;
    // We are going to read dynamically like for stakingAmendCommissionSchedule
    size_t nodes_length;
} oasis_entity_internal_t;

typedef struct {
    // We keep parser and iterator
    cbor_parser_state_t cborState;
    oasis_entity_internal_t obj;
} oasis_entity_t;

typedef struct {
    uint64_t major;
    uint64_t minor;
    uint64_t patch;
} version_t;

typedef struct {
    version_t runtime_host_protocol;
    version_t runtime_committee_protocol;
    version_t consensus_protocol;
} protocol_version_t;

typedef struct {
    uint8_t handler[HANDLER_MAX_LENGTH];
    protocol_version_t target;
    epochTime_t epoch;
    uint64_t version;
} upgrade_descriptor_t;

typedef struct {
    uint64_t proposal_id;
} cancel_upgrade_descriptor_t;

typedef struct {
    uint64_t nonce;
    bool has_fee;
    uint64_t fee_gas;
    quantity_t fee_amount;
    oasis_methods_e method;

    // Union type will depend on method
    union {
        struct {
            address_raw_t to;
            quantity_t amount;
        } stakingTransfer;

        struct {
            quantity_t amount;
        } stakingBurn;

        struct {
            address_raw_t from;
            quantity_t amount;
        } stakingWithdraw;

        struct {
            address_raw_t beneficiary;
            quantity_t amount_change;
            bool negative;
        } stakingAllow;

        struct {
            address_raw_t account;
            quantity_t amount;
        } stakingEscrow;

        struct {
            address_raw_t account;
            quantity_t shares;
        } stakingReclaimEscrow;

        struct {
            size_t rates_length;
            size_t bounds_length;
        } stakingAmendCommissionSchedule;

        struct {
            publickey_t node_id;
        } registryUnfreezeNode;

        struct {
            publickey_t node_id;
        } deregisterEntity;

        struct {
            oasis_entity_t entity;
            signature_t signature;
        } registryRegisterEntity;

        struct {
            submit_proposal_type type;
            upgrade_descriptor_t upgrade;
            cancel_upgrade_descriptor_t cancel_upgrade;
        } governanceSubmitProposal;

        struct {
            uint64_t id;
            uint64_t vote;
        } governanceCastVote;

    } body;
} oasis_tx_t;

typedef struct {
  uint16_t v;
  uint64_t serial;
  name_t name;
  url_t url;
  email_t email;
  handle_t keybase;
  handle_t twitter;
} oasis_entity_metadata_t;

typedef struct {
    address_raw_t to;
    quantity_t amount;
    string_t denom;
    bool has_to;
    quantity_t shares;
} body_consensus_t;

typedef struct {
    string_t address;
    char data_hash[32];
} body_evm_t;

typedef struct {
    publickey_t pk;
    string_t nonce;
    char data_hash[32];
} body_encrypted_t;

typedef struct {
    uint64_t id;
    uint64_t code_id;
    uint8_t *dataPtr;
    size_t dataLen;
    cbor_parser_state_t cborState;
    bool dataValid;
    size_t tokensLen;
} body_contracts_t;

typedef struct {
    uint64_t format;
    oasis_methods_e method;
    union{
        body_consensus_t consensus;
        body_contracts_t contracts;
        body_encrypted_t encrypted;
        body_evm_t evm;
    }body;

    bool ro;
} runtime_call_t;

typedef struct {
    uint64_t consensus_msg;
    uint64_t gas;
    quantity_t amount;
    string_t denom;
} runtime_fee_t;

typedef struct {
    size_t n_si;
    uint64_t nonce;
    runtime_fee_t fee;
} runtime_auth_info_t;

typedef struct {
    const uint8_t chain_context[CHAIN_CONTEXT_BYTE_LEN * 2];
    const uint8_t runtime_id[RUNTIME_ID_BYTE_LEN * 2];
    const uint8_t orig_to[ORIG_TO_SIZE];
    bool has_orig_to;
} meta_t;

typedef struct {
    char sigcxt[200];
    size_t metaLen;
    uint16_t v;
    runtime_call_t call;
    runtime_auth_info_t ai;
    meta_t meta;
} oasis_runtime_t;


typedef enum {
    unknownType,
    txType,
    entityType,
    nodeType,
    consensusType,
    entityMetadataType,
    runtimeType
} oasis_blob_type_e;

typedef struct {
    context_t context;
    oasis_blob_type_e type;

    union {
        oasis_tx_t tx;
        oasis_entity_t entity;
        oasis_entity_metadata_t entity_metadata;
        oasis_runtime_t runtime;
    } oasis;
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
