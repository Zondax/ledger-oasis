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

typedef enum {
    unknownMethod,
    stakingTransfer,
    stakingBurn,
    stakingEscrow,
    stakingReclaimEscrow,
    stakingAmendCommissionSchedule,
    registryDeregisterEntity,
    registryUnfreezeNode,
    registryRegisterEntity,
    governanceSubmitProposal,
    governanceCastVote
} oasis_methods_e;

typedef struct {
    const uint8_t *ptr;
    uint8_t len;
    const uint8_t *suffixPtr;
    uint8_t suffixLen;
} context_t;

typedef uint8_t publickey_t[32];

typedef uint8_t address_raw_t[21];

typedef struct {
    uint8_t buffer[64];
    size_t len;
} quantity_t;

typedef uint8_t raw_signature_t[64];

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
    bool allow_entity_signed_nodes;
} oasis_entity_internal_t;

typedef struct {
    // We keep parser and iterator
    cbor_parser_state_t cborState;
    oasis_entity_internal_t obj;
} oasis_entity_t;

typedef struct {
    uint16_t major;
    uint16_t minor;
    uint16_t patch;
} version_t;

typedef struct {
    version_t runtime_host_protocol;
    version_t runtime_committee_protocol;
    version_t consensus_protocol;
} protocol_version_t;

typedef struct {
    uint8_t handler[64];
    protocol_version_t target;
    epochTime_t epoch;
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
            upgrade_descriptor_t upgrade;
            cancel_upgrade_descriptor_t cancel_upgrade;
        } governanceSubmitProposal;

        struct {
            uint64_t id;
            uint8_t vote;
        } governanceCastVote;

    } body;
} oasis_tx_t;

typedef enum {
    unknownType,
    txType,
    entityType,
    nodeType,
    consensusType
} oasis_blob_type_e;

typedef struct {
    context_t context;
    oasis_blob_type_e type;

    union {
        oasis_tx_t tx;
        oasis_entity_t entity;
    } oasis;
} parser_tx_t;

#ifdef __cplusplus
}
#endif
