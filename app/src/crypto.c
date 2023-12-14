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
#include "tx.h"

#include <bech32.h>

uint32_t hdPath[MAX_BIP32_PATH];
uint8_t hdPathLen;
uint8_t chain_code;

#include "cx.h"

__Z_INLINE zxerr_t keccak_hash(const unsigned char *in, unsigned int inLen,
                          unsigned char *out, unsigned int outLen) {
    if (in == NULL || out == NULL || outLen < PUB_KEY_SIZE) {
        return zxerr_invalid_crypto_settings;
    }

    cx_sha3_t ctx;
    zxerr_t error = zxerr_unknown;

    CATCH_CXERROR(cx_keccak_init_no_throw(&ctx, outLen * 8));
    CATCH_CXERROR(cx_hash_no_throw((cx_hash_t *)&ctx, CX_LAST, in, inLen, out, outLen));
    error = zxerr_ok;

catch_cx_error:
    return error;
}

zxerr_t keccak_digest(const unsigned char *in, unsigned int inLen,
                          unsigned char *out, unsigned int outLen) {
    if (in == NULL || out == NULL || outLen < PUB_KEY_SIZE) {
        return zxerr_invalid_crypto_settings;
    }
    return keccak_hash(in, inLen, out, outLen);
}

static zxerr_t keccak(uint8_t *out, size_t out_len, uint8_t *in, size_t in_len){
    if (in == NULL || out == NULL || out_len < PUB_KEY_SIZE) {
        return zxerr_invalid_crypto_settings;
    }

    return keccak_hash(in, in_len, out, out_len);
}

zxerr_t  crypto_extractPublicKeySr25519(uint8_t *pubKey, uint16_t pubKeyLen) {
    if (pubKey == NULL || pubKeyLen < PK_LEN_SR25519) {
        return zxerr_invalid_crypto_settings;
    }

    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[SK_LEN_25519] = {0};

    zxerr_t error = zxerr_unknown;
    const int mode = (hdPathLen == HDPATH_LEN_ADR0008) ? HDW_ED25519_SLIP10 : HDW_NORMAL;

    // Generate keys
    CATCH_CXERROR(os_derive_bip32_with_seed_no_throw(mode,
                                                     CX_CURVE_Ed25519,
                                                     hdPath,
                                                     hdPathLen,
                                                     privateKeyData,
                                                     NULL,
                                                     NULL,
                                                     0));

    if (mode == HDW_ED25519_SLIP10) {
        uint8_t privateKeyData_expanded[SK_LEN_25519] = {0};
        expanded_sr25519_sk(privateKeyData, privateKeyData_expanded);
        MEMCPY(privateKeyData, privateKeyData_expanded, SK_LEN_25519);
        MEMZERO(privateKeyData_expanded, sizeof(privateKeyData_expanded));
    } else {
        get_sr25519_sk(privateKeyData);
    }

    CATCH_CXERROR(crypto_scalarmult_ristretto255_base_sdk(pubKey, privateKeyData));
    error = zxerr_ok;

catch_cx_error:
    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, sizeof(privateKeyData));

    if (error != zxerr_ok) {
        MEMZERO(pubKey, pubKeyLen);
    }
    return error;
}

zxerr_t  crypto_extractPublicKeyEd25519(uint8_t *pubKey, uint16_t pubKeyLen) {
    if (pubKey == NULL || pubKeyLen < PK_LEN_ED25519) {
        return zxerr_invalid_crypto_settings;
    }
    cx_ecfp_public_key_t cx_publicKey;
    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[SK_LEN_25519] = {0};

    zxerr_t error = zxerr_unknown;
    const int mode = (hdPathLen == HDPATH_LEN_ADR0008) ? HDW_ED25519_SLIP10 : HDW_NORMAL;

    // Generate keys
    CATCH_CXERROR(os_derive_bip32_with_seed_no_throw(mode,
                                                     CX_CURVE_Ed25519,
                                                     hdPath,
                                                     hdPathLen,
                                                     privateKeyData,
                                                     NULL,
                                                     NULL,
                                                     0));

    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_Ed25519, privateKeyData, 32, &cx_privateKey));
    CATCH_CXERROR(cx_ecfp_init_public_key_no_throw(CX_CURVE_Ed25519, NULL, 0, &cx_publicKey));
    CATCH_CXERROR(cx_ecfp_generate_pair_no_throw(CX_CURVE_Ed25519, &cx_publicKey, &cx_privateKey, 1));
    // Format pubkey
    for (int i = 0; i < 32; i++) {
        pubKey[i] = cx_publicKey.W[64 - i];
    }

    if ((cx_publicKey.W[32] & 1) != 0) {
        pubKey[31] |= 0x80;
    }
    error = zxerr_ok;

catch_cx_error:
    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, sizeof(privateKeyData));

    if (error != zxerr_ok) {
        MEMZERO(pubKey, pubKeyLen);
    }
    return error;
}

zxerr_t crypto_extractPublicKeySecp256k1(uint8_t *pubKey, uint16_t pubKeyLen, uint8_t *chainCode) {
    if (pubKey == NULL || pubKeyLen < PK_LEN_SECP256K1_FULL) {
        return zxerr_invalid_crypto_settings;
    }
    zemu_log("crypto_extractPublicKeySecp256k1\n");
    cx_ecfp_public_key_t cx_publicKey;
    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[64] = {0};

    zxerr_t error = zxerr_unknown;
    // Generate keys
    CATCH_CXERROR(os_derive_bip32_with_seed_no_throw(HDW_NORMAL,
                                                     CX_CURVE_256K1,
                                                     hdPath,
                                                     HDPATH_LEN_DEFAULT,
                                                     privateKeyData,
                                                     chainCode,
                                                     NULL,
                                                     0));

    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_256K1, privateKeyData, SK_SECP256K1_SIZE, &cx_privateKey));
    CATCH_CXERROR(cx_ecfp_init_public_key_no_throw(CX_CURVE_256K1, NULL, 0, &cx_publicKey));
    CATCH_CXERROR(cx_ecfp_generate_pair_no_throw(CX_CURVE_256K1, &cx_publicKey, &cx_privateKey, 1));
    memcpy(pubKey, cx_publicKey.W, PK_LEN_SECP256K1_FULL);
    error = zxerr_ok;

catch_cx_error:
    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, sizeof(privateKeyData));

    if (error != zxerr_ok) {
        MEMZERO(pubKey, pubKeyLen);
    }

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


zxerr_t crypto_signSecp256k1(uint8_t *output, uint16_t outputLen, const uint8_t *message, uint16_t messageLen, uint16_t *sigSize) {
    if (output == NULL || message == NULL || sigSize == NULL ||
        outputLen < sizeof(signature_t) || messageLen != CX_SHA256_SIZE) {
            return zxerr_invalid_crypto_settings;
    }

    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[64] = {0};
    size_t maxSignatureLen = sizeof_field(signature_t, der_signature);
    uint32_t info = 0;
    *sigSize = 0;

    signature_t *const signature_object = (signature_t *) output;
    zxerr_t error = zxerr_unknown;

    CATCH_CXERROR(os_derive_bip32_with_seed_no_throw(HDW_NORMAL,
                                                     CX_CURVE_256K1,
                                                     hdPath,
                                                     HDPATH_LEN_DEFAULT,
                                                     privateKeyData,
                                                     NULL,
                                                     NULL,
                                                     0));

    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_256K1, privateKeyData, SK_SECP256K1_SIZE, &cx_privateKey));
    CATCH_CXERROR(cx_ecdsa_sign_no_throw(&cx_privateKey,
                                         CX_RND_RFC6979 | CX_LAST,
                                         CX_SHA256,
                                         message,
                                         messageLen,
                                         signature_object->der_signature,
                                         &maxSignatureLen, &info));

    const err_convert_e err_c = convertDERtoRSV(signature_object->der_signature, info,  signature_object->r, signature_object->s, &signature_object->v);
    if (err_c == no_error) {
        *sigSize =  sizeof_field(signature_t, r) +
                    sizeof_field(signature_t, s) +
                    sizeof_field(signature_t, v);
        error = zxerr_ok;
    }

catch_cx_error:
    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, sizeof(privateKeyData));

    if (error != zxerr_ok) {
        MEMZERO(output, outputLen);
    }

    return error;
}

zxerr_t crypto_signEd25519(uint8_t *output, uint16_t outputLen, const uint8_t *message, uint16_t messageLen, uint16_t *sigSize) {
    if (output == NULL || message == NULL || sigSize == NULL ||
        outputLen < ED25519_SIGNATURE_SIZE || messageLen != CX_SHA256_SIZE) {
        return zxerr_unknown;
    }

    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[64] = {0};
    *sigSize = 0;

    zxerr_t error = zxerr_unknown;
    const int mode = (hdPathLen == HDPATH_LEN_ADR0008) ? HDW_ED25519_SLIP10 : HDW_NORMAL;

    CATCH_CXERROR(os_derive_bip32_with_seed_no_throw(mode,
                                                     CX_CURVE_Ed25519,
                                                     hdPath,
                                                     hdPathLen,
                                                     privateKeyData,
                                                     NULL,
                                                     NULL,
                                                     0));

    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_Ed25519, privateKeyData, 32, &cx_privateKey));
    CATCH_CXERROR(cx_eddsa_sign_no_throw(&cx_privateKey,
                                         CX_SHA512,
                                         message,
                                         messageLen,
                                         output,
                                         outputLen));

    *sigSize = ED25519_SIGNATURE_SIZE;
    error = zxerr_ok;

catch_cx_error:
    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, sizeof(privateKeyData));

    if (error != zxerr_ok) {
        MEMZERO(output, outputLen);
    }

    return error;
}

zxerr_t crypto_sign_sr25519(uint8_t *output, uint16_t outputLen, const uint8_t *data, size_t len, const uint8_t *ctx, size_t ctx_len, uint16_t *sigSize) {
    if (output == NULL || data == NULL || sigSize == NULL ||
        ctx == NULL ||outputLen < SIG_LEN ) {
        return zxerr_unknown;
    }
    uint8_t sk[SK_LEN_25519] = {0};
    uint8_t pk[PK_LEN_SR25519] = {0};
    *sigSize = 0;

    zxerr_t error = zxerr_unknown;
    const int mode = (hdPathLen == HDPATH_LEN_ADR0008) ? HDW_ED25519_SLIP10 : HDW_NORMAL;
    CATCH_CXERROR(os_derive_bip32_with_seed_no_throw(mode,
                                                     CX_CURVE_Ed25519,
                                                     hdPath,
                                                     hdPathLen,
                                                     sk,
                                                     NULL,
                                                     NULL,
                                                     0));
    
    if (mode == HDW_ED25519_SLIP10) {
        uint8_t privateKeyData_expanded[SK_LEN_25519] = {0};
        expanded_sr25519_sk(sk, privateKeyData_expanded);
        MEMCPY(sk, privateKeyData_expanded, SK_LEN_25519);
        MEMZERO(privateKeyData_expanded, sizeof(privateKeyData_expanded));
    } else {
        get_sr25519_sk(sk);
    }

    CATCH_CXERROR(crypto_scalarmult_ristretto255_base_sdk(pk, sk));
    sign_sr25519_phase1(sk, pk, ctx, ctx_len, data, len, output);
    CATCH_CXERROR(crypto_scalarmult_ristretto255_base_sdk(output, output + PK_LEN_SR25519));
    *sigSize = SIG_LEN;
    error = zxerr_ok;

catch_cx_error:
    if (error == zxerr_ok) {
        sign_sr25519_phase2(sk, pk, ctx, ctx_len, data, len, output);
    } else {
         MEMZERO(output, outputLen);
    }

    MEMZERO(pk, sizeof(pk));
    MEMZERO(sk, sizeof(sk));
    return error;
}

zxerr_t _sign(uint8_t *output, uint16_t outputLen, const uint8_t *message, uint16_t messageLen, uint16_t *sigSize, unsigned int *info) {
    if (output == NULL || message == NULL || sigSize == NULL ||
        outputLen < sizeof(signature_t) || messageLen != KECCAK256_HASH_LEN) {
        return zxerr_unknown;
    }

    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[64] = {0};
    signature_t *const signature = (signature_t *) output;
    size_t signatureLength = sizeof_field(signature_t, der_signature);
    uint32_t tmpInfo = 0;
    *sigSize = 0;

    zxerr_t error = zxerr_unknown;
    CATCH_CXERROR(os_derive_bip32_with_seed_no_throw(HDW_NORMAL,
                                                     CX_CURVE_256K1,
                                                     hdPath,
                                                     hdPathLen,
                                                     privateKeyData,
                                                     NULL,
                                                     NULL,
                                                     0));
    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_256K1, privateKeyData, 32, &cx_privateKey));
    CATCH_CXERROR(cx_ecdsa_sign_no_throw(&cx_privateKey,
                                         CX_RND_RFC6979 | CX_LAST,
                                         CX_SHA256,
                                         message,
                                         messageLen,
                                         signature->der_signature,
                                         &signatureLength, &tmpInfo));

    const err_convert_e err_c = convertDERtoRSV(signature->der_signature, tmpInfo,  signature->r, signature->s, &signature->v);
    if (err_c == no_error) {
        *sigSize =  sizeof_field(signature_t, r) +
                    sizeof_field(signature_t, s) +
                    sizeof_field(signature_t, v) +
                    signatureLength;
        if (info != NULL) *info = tmpInfo;
        error = zxerr_ok;
    }

catch_cx_error:
    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, sizeof(privateKeyData));

    if (error != zxerr_ok) {
        MEMZERO(output, outputLen);
    }

    return error;
}

// Sign an ethereum related transaction
zxerr_t crypto_sign_eth(uint8_t *buffer, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen, uint16_t *sigSize) {

    if (signatureMaxlen < sizeof(signature_t) ) {
        return zxerr_invalid_crypto_settings;
    }

    uint8_t message_digest[KECCAK256_HASH_LEN] = {0};
    keccak_digest(message, messageLen, message_digest, KECCAK256_HASH_LEN);

    unsigned int info = 0;
    zxerr_t error = _sign(buffer, signatureMaxlen, message_digest, KECCAK256_HASH_LEN, sigSize, &info);
    if (error != zxerr_ok){
        return zxerr_invalid_crypto_settings;
    }

    // we need to fix V
    uint8_t v = 0;
    zxerr_t err = tx_compute_eth_v(info, &v);

    if (err != zxerr_ok)
        return zxerr_invalid_crypto_settings;

    // need to reorder signature as hw-eth-app expects v at the beginning.
    // so rsv -> vrs
    uint8_t rs_size = sizeof_field(signature_t, r) + sizeof_field(signature_t, s);
    memmove(buffer + 1, buffer, rs_size);
    buffer[0] = v;

    return zxerr_ok;
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

uint16_t crypto_encodeAddress(char *addr_out, uint16_t addr_out_max, uint8_t *pubkey, address_kind_e kind) {
    tmp_address_t tmp = {0};
    tmp.version = COIN_ADDRESS_VERSION;

    const char *context = (kind == addr_ed25519) ? COIN_ADDRESS_ED25519_CONTEXT : COIN_ADDRESS_SR25519_CONTEXT;

    SHA512_256_with_context_version (
            (uint8_t *)context, strnlen(context, MAX_CONTEXT_SIZE),
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

    return strnlen(addr_out, addr_out_max);
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

    CHECK_ZXERR(crypto_extractPublicKeyEd25519(buffer, buffer_len))

    // format pubkey as oasis bech32 address
    char *addr_out = (char *) (buffer + PK_LEN_ED25519);
    const uint16_t addr_out_max =  buffer_len - PK_LEN_ED25519;
    const uint16_t addr_out_len = crypto_encodeAddress(addr_out, addr_out_max, buffer, addr_ed25519);

    *addrLen = PK_LEN_ED25519 + addr_out_len;
    return zxerr_ok;
}

zxerr_t crypto_fillAddressSr25519(uint8_t *buffer, uint16_t buffer_len, uint16_t *addrLen) {
    if (buffer_len < PK_LEN_SR25519 + 50) {
        return 0;
    }
    MEMZERO(buffer, buffer_len);

    CHECK_ZXERR(crypto_extractPublicKeySr25519(buffer, buffer_len))

    // format pubkey as oasis bech32 address
    char *addr_out = (char *) (buffer + PK_LEN_SR25519);
    const uint16_t addr_out_max =  buffer_len - PK_LEN_SR25519;
    const uint16_t addr_out_len = crypto_encodeAddress(addr_out, addr_out_max, buffer, addr_sr25519);

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

    CHECK_ZXERR(crypto_extractPublicKeySecp256k1(publicKeyFull, PK_LEN_SECP256K1_FULL, NULL))

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

typedef struct {
    // plus 1-bytes to write pubkey len
    uint8_t publicKey[PK_LEN_SECP256K1_FULL + 1];
    // hex of the ethereum address plus 1-bytes
    // to write the address len
    uint8_t address[(ETH_ADDR_LEN * 2) + 1];  // 41 = because (20+1+4)*8/5 (32 base encoded size)
    // place holder for further dev
    uint8_t chainCode[32];

} __attribute__((packed)) answer_eth_t;

zxerr_t crypto_fillEthAddress(uint8_t *buffer, uint16_t buffer_len, uint16_t *addrLen) {

    if (buffer_len < sizeof(answer_eth_t)) {
        return 0;
    }
    MEMZERO(buffer, buffer_len);
    answer_eth_t *const answer = (answer_eth_t *) buffer;

    CHECK_ZXERR(crypto_extractPublicKeySecp256k1(&answer->publicKey[1], sizeof_field(answer_eth_t, publicKey) - 1, &chain_code))

    answer->publicKey[0] = PK_LEN_SECP256K1_FULL;

    uint8_t hash[KECCAK256_HASH_LEN] = {0};

    keccak_digest(&answer->publicKey[2], PK_LEN_SECP256K1_FULL - 1, hash, KECCAK256_HASH_LEN);

    answer->address[0] = ETH_ADDR_LEN * 2;

    // get hex of the eth address(last 20 bytes of pubkey hash)
    char str[ETH_ADDR_HEX_LEN] = {0};

    // take the last 20-bytes of the hash, they are the ethereum address
    array_to_hexstr(str, ETH_ADDR_HEX_LEN, hash + ETH_ADDR_OFFSET , ETH_ADDR_LEN);
    MEMCPY(answer->address+1, str, ETH_ADDR_HEX_LEN - 1);

    *addrLen = sizeof_field(answer_eth_t, publicKey) + sizeof_field(answer_eth_t, address);

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
        case addr_eth:
            zemu_log("identified sr25519 address\n");
            return crypto_fillEthAddress(buffer, buffer_len, addrLen);
    }
    zemu_log("No match for address kind!\n");
    return zxerr_unknown;
}

