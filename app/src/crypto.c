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

#include "crypto.h"
#include "coin.h"
#include "zxmacros.h"
#include "zxformat.h"
#include "apdu_codes.h"
#include "coin.h"
#include "sha512.h"
#include "rslib.h"
#include "ristretto.h"

#include <bech32.h>

uint32_t hdPath[HDPATH_LEN_DEFAULT];
uint8_t hdPathLen;

#include "cx.h"

static zxerr_t keccak(uint8_t *out, size_t out_len, uint8_t *in, size_t in_len){
    if (in == NULL || out == NULL || out_len < PUB_KEY_SIZE) {
        return zxerr_invalid_crypto_settings;
    }
    cx_sha3_t sha3;
    cx_keccak_init(&sha3, 256);
    cx_hash((cx_hash_t*)&sha3, CX_LAST, in, in_len, out, out_len);

    return zxerr_ok;
}
zxerr_t  crypto_extractPublicKeySr25519(const uint32_t path[HDPATH_LEN_DEFAULT], uint8_t *pubKey, uint16_t pubKeyLen) {
    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[32];

    if (pubKeyLen < PK_LEN_SR25519) {
        return zxerr_invalid_crypto_settings;
    }

    zxerr_t err = zxerr_ok;
    BEGIN_TRY
    {
        TRY
        {
            int mode = HDW_NORMAL;
            if(hdPathLen == HDPATH_LEN_ADR0008){
                mode = HDW_ED25519_SLIP10;
            }
            // Generate keys
            os_perso_derive_node_bip32_seed_key(
                    mode,
                    CX_CURVE_Ed25519,
                    path,
                    hdPathLen,
                    privateKeyData,
                    NULL,
                    NULL,
                    0);
            get_sr25519_sk(privateKeyData);
            crypto_scalarmult_ristretto255_base_sdk(pubKey, privateKeyData);
        }
        CATCH_ALL
        {
            err = zxerr_ledger_api_error;
        }
        FINALLY
        {
            MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
            MEMZERO(privateKeyData, 32);
        }
    }
    END_TRY;

    return err;
}

zxerr_t  crypto_extractPublicKeyEd25519(const uint32_t path[HDPATH_LEN_DEFAULT], uint8_t *pubKey, uint16_t pubKeyLen) {
    cx_ecfp_public_key_t cx_publicKey;
    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[32];

    if (pubKeyLen < PK_LEN_ED25519) {
        return zxerr_invalid_crypto_settings;
    }

    zxerr_t err = zxerr_ok;
    BEGIN_TRY
    {
        TRY {

            int mode = HDW_NORMAL;
            if(hdPathLen == HDPATH_LEN_ADR0008){
                mode = HDW_ED25519_SLIP10;
            }

            // Generate keys
            os_perso_derive_node_bip32_seed_key(
                    mode,
                    CX_CURVE_Ed25519,
                    path,
                    hdPathLen,
                    privateKeyData,
                    NULL,
                    NULL,
                    0);

            cx_ecfp_init_private_key(CX_CURVE_Ed25519, privateKeyData, 32, &cx_privateKey);
            cx_ecfp_init_public_key(CX_CURVE_Ed25519, NULL, 0, &cx_publicKey);
            cx_ecfp_generate_pair(CX_CURVE_Ed25519, &cx_publicKey, &cx_privateKey, 1);

            // Format pubkey
            for (int i = 0; i < 32; i++) {
                pubKey[i] = cx_publicKey.W[64 - i];
            }

            if ((cx_publicKey.W[32] & 1) != 0) {
                pubKey[31] |= 0x80;
            }
        }
        CATCH_ALL {
            err = zxerr_ledger_api_error;
        }
        FINALLY {
            MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
            MEMZERO(privateKeyData, 32);
        }
    }
    END_TRY;

    return err;
}

zxerr_t crypto_extractPublicKeySecp256k1(const uint32_t path[HDPATH_LEN_DEFAULT], uint8_t *pubKey, uint16_t pubKeyLen) {
    zemu_log("crypto_extractPublicKeySecp256k1\n");
    cx_ecfp_public_key_t cx_publicKey;
    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[SK_SECP256K1_SIZE];

    if (pubKeyLen < PK_LEN_SECP256K1_FULL) {
        return zxerr_invalid_crypto_settings;
    }

    zxerr_t error = zxerr_ok;
    BEGIN_TRY
    {
        TRY {
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                       path,
                                       HDPATH_LEN_DEFAULT,
                                       privateKeyData, NULL);

            cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, SK_SECP256K1_SIZE, &cx_privateKey);
            cx_ecfp_init_public_key(CX_CURVE_256K1, NULL, 0, &cx_publicKey);
            cx_ecfp_generate_pair(CX_CURVE_256K1, &cx_publicKey, &cx_privateKey, 1);

            memcpy(pubKey, cx_publicKey.W, PK_LEN_SECP256K1_FULL);


        }
        CATCH_OTHER(e) {
            error = zxerr_ledger_api_error;
        }
        FINALLY {
            MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
            MEMZERO(privateKeyData, SK_SECP256K1_SIZE);
        }
    }
    END_TRY;

    return error;
}

typedef struct {
    uint8_t r[32];
    uint8_t s[32];
    uint8_t v;

    // DER signature max size should be 73
    // https://bitcoin.stackexchange.com/questions/77191/what-is-the-maximum-size-of-a-der-encoded-ecdsa-signature#77192
    uint8_t der_signature[73];

} __attribute__((packed)) signature_t;


zxerr_t crypto_signSecp256k1(uint8_t *signature,
                    uint16_t signatureMaxlen,
                    const uint8_t *message,
                    uint16_t messageLen,
                    uint16_t *sigSize) {
    UNUSED(messageLen);

    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[32];
    unsigned int info = 0;

    signature_t *const signature_object = (signature_t *) signature;
    zxerr_t err = zxerr_ok;
    BEGIN_TRY
    {
        TRY
        {
            // Generate keys
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                                      hdPath,
                                                      HDPATH_LEN_DEFAULT,
                                                      privateKeyData, NULL);

            cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, 32, &cx_privateKey);

            // Sign
            cx_ecdsa_sign(&cx_privateKey,
                                            CX_RND_RFC6979 | CX_LAST,
                                            CX_SHA256,
                                            message,
                                            CX_SHA256_SIZE,
                                            signature_object->der_signature,
                                            sizeof_field(signature_t, der_signature),
                                            &info);

            err_convert_e err_c = convertDERtoRSV(signature_object->der_signature, info,  signature_object->r, signature_object->s, &signature_object->v);
            if (err_c != no_error) {
                // Error while converting so return length 0
                MEMZERO(signature, signatureMaxlen);
                err = zxerr_unknown;
            }else{
                *sigSize = sizeof_field(signature_t, r) +
                    sizeof_field(signature_t, s) +
                    sizeof_field(signature_t, v);
            }
        }
        CATCH_ALL {
            MEMZERO(signature, signatureMaxlen);
            err = zxerr_unknown;
        };
        FINALLY {
            MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
            MEMZERO(privateKeyData, 32);
        }
    }
    END_TRY;

    return err;
}

zxerr_t crypto_signEd25519(uint8_t *signature,
                     uint16_t signatureMaxlen,
                     const uint8_t *message,
                     uint16_t messageLen,
                    uint16_t *sigSize) {
    UNUSED(messageLen);

    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[32];
    int signatureLength;
    unsigned int info = 0;

    zxerr_t err = zxerr_ok;

    BEGIN_TRY
    {
        TRY
        {

            int mode = HDW_NORMAL;
            if(hdPathLen == HDPATH_LEN_ADR0008){
                mode = HDW_ED25519_SLIP10;
            }
            // Generate keys
            os_perso_derive_node_bip32_seed_key(
                    mode,
                    CX_CURVE_Ed25519,
                    hdPath,
                    hdPathLen,
                    privateKeyData,
                    NULL,
                    NULL,
                    0);
            cx_ecfp_init_private_key(CX_CURVE_Ed25519, privateKeyData, 32, &cx_privateKey);

            // Sign
            signatureLength = cx_eddsa_sign(&cx_privateKey,
                                            CX_LAST,
                                            CX_SHA512,
                                            message,
                                            CX_SHA256_SIZE,
                                            NULL,
                                            0,
                                            signature,
                                            signatureMaxlen,
                                            &info);
            *sigSize = signatureLength;
        }
        CATCH_ALL {
            err = zxerr_ledger_api_error;
        }
        FINALLY {
            MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
            MEMZERO(privateKeyData, 32);
        }
    }
    END_TRY;

    return err;
}

static uint8_t sr25519_signature[SIG_LEN];

void zeroize_sr25519_signdata(void) {
    explicit_bzero(sr25519_signature, sizeof(sr25519_signature));
}

void copy_sr25519_signdata(uint8_t *buffer) {
    memcpy(buffer, sr25519_signature, SIG_LEN);
}

zxerr_t crypto_sign_sr25519(const uint8_t *data, size_t len, const uint8_t *ctx, size_t ctx_len) {
    uint8_t sk[SK_LEN_25519];
    uint8_t pk[PK_LEN_SR25519];

    zxerr_t err = zxerr_ok;
    int ret = 0;

    BEGIN_TRY
    {
        int mode = HDW_NORMAL;
        if(hdPathLen == HDPATH_LEN_ADR0008){
            mode = HDW_ED25519_SLIP10;
        }
        TRY
        {
            os_perso_derive_node_bip32_seed_key(
                    mode,
                    CX_CURVE_Ed25519,
                    hdPath,
                    hdPathLen,
                    sk,
                    NULL,
                    NULL,
                    0);
            get_sr25519_sk(sk);
            ret = crypto_scalarmult_ristretto255_base_sdk(pk, sk);
            if (ret == 0) {
                sign_sr25519_phase1((const uint8_t *)&sk, (const uint8_t *)&pk, ctx, ctx_len,
                                    data, len, sr25519_signature);

                ret = crypto_scalarmult_ristretto255_base_sdk(sr25519_signature, sr25519_signature + PK_LEN_SR25519);
            }
        }
        CATCH_ALL
        {
            err = zxerr_unknown;
        }
        FINALLY
        {
        }
    }
    END_TRY;

    if (ret != 0 || err != zxerr_ok) {
        err = zxerr_unknown;
        explicit_bzero(sr25519_signature, sizeof(sr25519_signature));
    } else {
        sign_sr25519_phase2((const uint8_t *)sk, (const uint8_t *)pk, ctx, ctx_len,
                            data, len, sr25519_signature);
    }

    MEMZERO(pk, sizeof(pk));
    MEMZERO(sk, sizeof(sk));

    return err;
}

#define CX_SHA512_SIZE 64

typedef union {
    //    1 byte <context-version> + first 20 bytes of SHA512-256(<context-identifier> || <pubkey>)
    uint8_t address[21];
    struct {
        uint8_t version;
        uint8_t address_truncated_hash[20];
    };
    struct {
        uint8_t padding;
        uint8_t pkHash[CX_SHA512_SIZE];
    };
} tmp_address_t;

uint16_t crypto_encodeAddress(char *addr_out, uint16_t addr_out_max, uint8_t *pubkey) {
    tmp_address_t tmp;
    tmp.version = COIN_ADDRESS_VERSION;

    SHA512_256_with_context_version (
            (uint8_t *) COIN_ADDRESS_CONTEXT, strlen(COIN_ADDRESS_CONTEXT),
            COIN_ADDRESS_VERSION,
            pubkey, PK_LEN_ED25519,
            tmp.pkHash
    );

    //  and encode as bech32
    const zxerr_t err = bech32EncodeFromBytes(
            addr_out, addr_out_max,
            COIN_HRP,
            tmp.address, sizeof_field(tmp_address_t, address), 1, BECH32_ENCODING_BECH32);

    if (err != zxerr_ok) {
        return 0;
    }

    return strlen(addr_out);
}

static uint16_t crypto_encodeEthereumAddress(char *addr_out, uint16_t addr_out_max, uint8_t *pubkey) {
    zemu_log("crypto_encodeEthereumAddress\n");
    uint8_t hash[KECCAK256_HASH_LEN]={0};
    keccak (
            hash, KECCAK256_HASH_LEN,
            pubkey+1, HASH_SIZE
    );
    uint8_t ethereum_address[ETH_ADDR_LEN]={0};
    memcpy(ethereum_address, &hash[KECCAK256_HASH_LEN - ETH_ADDR_LEN],ETH_ADDR_LEN);
    array_to_hexstr(addr_out, addr_out_max, ethereum_address, ETH_ADDR_LEN);
    zemu_log(addr_out);
    zemu_log("\n");
    return strlen(addr_out);
}

zxerr_t crypto_fillAddressEd25519(uint8_t *buffer, uint16_t buffer_len, uint16_t *addrLen) {
    if (buffer_len < PK_LEN_ED25519 + 50) {
        return 0;
    }
    MEMZERO(buffer, buffer_len);

    CHECK_ZXERR(crypto_extractPublicKeyEd25519(hdPath, buffer, buffer_len))

    // format pubkey as oasis bech32 address
    char *addr_out = (char *) (buffer + PK_LEN_ED25519);
    const uint16_t addr_out_max =  buffer_len - PK_LEN_ED25519;
    const uint16_t addr_out_len = crypto_encodeAddress(addr_out, addr_out_max, buffer);

    *addrLen = PK_LEN_ED25519 + addr_out_len;
    return zxerr_ok;
}

zxerr_t crypto_fillAddressSr25519(uint8_t *buffer, uint16_t buffer_len, uint16_t *addrLen) {
    if (buffer_len < PK_LEN_SR25519 + 50) {
        return 0;
    }
    MEMZERO(buffer, buffer_len);

    CHECK_ZXERR(crypto_extractPublicKeySr25519(hdPath, buffer, buffer_len))

    // format pubkey as oasis bech32 address
    char *addr_out = (char *) (buffer + PK_LEN_SR25519);
    const uint16_t addr_out_max =  buffer_len - PK_LEN_SR25519;
    const uint16_t addr_out_len = crypto_encodeAddress(addr_out, addr_out_max, buffer);

    *addrLen = PK_LEN_SR25519 + addr_out_len;
    return zxerr_ok;
}

typedef struct {
    uint8_t compressedPublicKey[PK_LEN_SECP256K1];
    uint8_t address[50];
} __attribute__((packed)) answer_secp256k1;

zxerr_t crypto_fillAddressSecp256k1(uint8_t *buffer, uint16_t buffer_len, uint16_t *addrLen) {
    zemu_log("crypto_fillAddressSecp256k1\n");

    if (buffer_len < sizeof(answer_secp256k1)) {
        *addrLen =  0;
        return zxerr_unknown;
    }
    MEMZERO(buffer, buffer_len);

    //to compute Ethereum addresses we need the full public key (not the compressed one)
    uint8_t publicKeyFull[PK_LEN_SECP256K1_FULL] = {0};

    CHECK_ZXERR(crypto_extractPublicKeySecp256k1(hdPath, publicKeyFull, PK_LEN_SECP256K1_FULL))

    // format public key as Ethereum hex address
    char *addr_out = (char *) (buffer + PK_LEN_SECP256K1);
    const uint16_t addr_out_max =  buffer_len - PK_LEN_SECP256K1;
    const uint16_t addr_out_len = crypto_encodeEthereumAddress(addr_out, addr_out_max, publicKeyFull);

    if (addr_out_len == 0) {
        return zxerr_unknown;
    }

    // now compress the public key to send via apdu buffer
    char *pubKey = (char *) buffer;
    // Format pubkey
    for (int i = 0; i < PUB_KEY_SIZE; i++) {
        pubKey[i] = publicKeyFull[64 - i];
    }

    publicKeyFull[0] = publicKeyFull[64] & 1 ? 0x03 : 0x02; // "Compress" public key in place
    if ((publicKeyFull[PUB_KEY_SIZE] & 1) != 0) {
        pubKey[PUB_KEY_SIZE - 1] |= 0x80;
    }
    zemu_log("copy over compressed pk\n");
    memcpy(pubKey, publicKeyFull, PK_LEN_SECP256K1);

    *addrLen = addr_out_len + PK_LEN_SECP256K1;
    return zxerr_ok;
}

zxerr_t crypto_fillAddress(uint8_t *buffer, uint16_t buffer_len, uint16_t *addrLen, address_kind_e kind) {
    zemu_log("crypto_fillAddress\n");
    switch (kind) {
        case addr_ed25519:
            zemu_log("identified ed25519 address\n");
            return crypto_fillAddressEd25519(buffer, buffer_len, addrLen);
        case addr_secp256k1:
            zemu_log("identified secp256k1 address\n");
            return crypto_fillAddressSecp256k1(buffer, buffer_len, addrLen);
        case addr_sr25519:
            zemu_log("identified sr25519 address\n");
            return crypto_fillAddressSr25519(buffer, buffer_len, addrLen);
    }
    zemu_log("No match for address kind!\n");
    return zxerr_unknown;
}
