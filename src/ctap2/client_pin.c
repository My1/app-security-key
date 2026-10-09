/*
*******************************************************************************
*   Ledger App Security Key
*   (c) 2022 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*   Unless required by applicable law or agreed to in writing, software
*   distributed under the License is distributed on an "AS IS" BASIS,
*   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*   limitations under the License.
********************************************************************************/

#include <string.h>
#include <os.h>
#include <cx.h>
#include <ledger_assert.h>

#include "ctap2.h"
#include "ctap2_utils.h"
#include "config.h"
#include "cbip_helper.h"
#include "cose_keys.h"
#include "crypto.h"
#include "globals.h"

/*
 * authenticatorClientPIN, reduced to what a PIN-less, built-in-UV authenticator needs.
 *
 * The device unlock PIN is this authenticator's user verification, so there is no FIDO client PIN
 * (no setPIN / changePIN / getPinToken / getPinRetries / getPinUvAuthTokenUsingPin...). What
 * remains is the PIN/UV auth protocol machinery (shared by hmac-secret) and the issuance of
 * pinUvAuthTokens through built-in UV.
 */

#define TAG_PIN_PROTOCOL  0x01
#define TAG_SUBCOMMAND    0x02
#define TAG_KEY_AGREEMENT 0x03
#define TAG_PERMISSIONS   0x09
#define TAG_RP_ID         0x0A

#define TAG_RESP_KEY_AGREEMENT 0x01
#define TAG_RESP_PIN_TOKEN     0x02
#define TAG_RESP_UV_RETRIES    0x05

#define SUBCOMMAND_GET_KEY_AGREEMENT 0x02
// getPinUvAuthTokenUsingUvWithPermissions
#define SUBCOMMAND_GET_UV_TOKEN      0x06
#define SUBCOMMAND_GET_UV_RETRIES    0x07

// Built-in UV is the device unlock PIN: it is managed (and rate limited) by the OS, never fails
// here, and has no retry counter of its own. Report a constant, non-zero value so platforms
// never consider UV blocked.
#define UV_RETRIES_NOMINAL 5

#define HKDF_INFO_HMAC_KEY "CTAP2 HMAC key"
#define HKDF_INFO_AES_KEY  "CTAP2 AES key"

typedef struct {
    bool inUse;
    uint8_t protocol;
    uint8_t length;
    uint8_t value[AUTH_TOKEN_MAX_SIZE];
    uint8_t permissions;
    bool hasRpId;
    uint8_t rpIdHash[RP_ID_HASH_SIZE];
} pin_uv_auth_token_t;

static pin_uv_auth_token_t authToken;

static cx_ecfp_private_key_t ctap2KeyAgreement;

// Scratch buffers kept out of the stack on purpose: this app has little stack headroom, and
// static functions called once get inlined, which would put all of these in the frame of
// ctap2_client_pin_handle() for every subcommand. Only one CTAP2 command is processed at a
// time and every user wipes them with explicit_bzero() after use.
static uint8_t cryptScratch[PIN_UV_CRYPT_MAX_SIZE];
static cx_aes_key_t cryptAesKey;
static uint8_t uvSharedSecret[SHARED_SECRET_MAX_SIZE];
static uint8_t uvTokenEnc[AUTH_TOKEN_MAX_ENC_SIZE];

/******************************************/
/*     PIN/UV Auth Protocol functions     */
/******************************************/

bool ctap2_client_pin_protocol_supported(int protocol) {
    return (protocol == PIN_PROTOCOL_VERSION_V1) || (protocol == PIN_PROTOCOL_VERSION_V2);
}

// Correspond to FIDO2.1 spec PIN/UV Auth Protocol regenerate() operation
int ctap2_client_pin_regenerate(void) {
    cx_ecfp_public_key_t publicKey;
    if (cx_ecfp_generate_pair_no_throw(CX_CURVE_SECP256R1, &publicKey, &ctap2KeyAgreement, 0) !=
        CX_OK) {
        PRINTF("regenerate key agreement failed\n");
        return -1;
    }
    return 0;
}

// Single block HKDF-SHA-256 (RFC 5869) with a 32 bytes zero salt and a 32 bytes output, as
// required by PIN/UV auth protocol 2: HKDF(salt = 0^32, IKM = z, L = 32, info).
static void hkdf_sha256_32(const uint8_t *ikm,
                           uint32_t ikmLen,
                           const char *info,
                           uint8_t out[CX_SHA256_SIZE]) {
    uint8_t salt[CX_SHA256_SIZE] = {0};
    uint8_t prk[CX_SHA256_SIZE];
    uint8_t expandIn[sizeof(HKDF_INFO_HMAC_KEY) + 1];  // longest info string + counter byte
    size_t infoLen = strlen(info);

    LEDGER_ASSERT(infoLen + 1 <= sizeof(expandIn), "HKDF info too long");

    // Extract
    cx_hmac_sha256(salt, sizeof(salt), ikm, ikmLen, prk, sizeof(prk));
    // Expand, T(1) = HMAC(PRK, info || 0x01)
    memcpy(expandIn, info, infoLen);
    expandIn[infoLen] = 0x01;
    cx_hmac_sha256(prk, sizeof(prk), expandIn, infoLen + 1, out, CX_SHA256_SIZE);

    explicit_bzero(prk, sizeof(prk));
}

// Correspond to FIDO2.1 spec PIN/UV Auth Protocol decapsulate() operation
int ctap2_client_pin_decapsulate(int protocol,
                                 cbipDecoder_t *decoder,
                                 cbipItem_t *mapItem,
                                 int key,
                                 uint8_t *sharedSecret) {
    int status;
    cbipItem_t keyMapItem;
    cx_ecfp_public_key_t publicKey;
    uint8_t z[32];

    if (!ctap2_client_pin_protocol_supported(protocol)) {
        return ERROR_INVALID_PAR;
    }

    GET_MAP_KEY_ITEM(decoder, mapItem, key, keyMapItem, cbipMap);

    status = decode_cose_key(decoder, &keyMapItem, &publicKey, false);
    if (status < 0) {
        return ERROR_INVALID_CBOR;
    }

    status = cx_ecdh_no_throw(&ctap2KeyAgreement,
                              CX_ECDH_X,
                              publicKey.W,
                              sizeof(publicKey.W),
                              z,
                              sizeof(z));
    if (status != CX_OK) {
        PRINTF("ECDH failed\n");
        return ERROR_OTHER;
    }

    if (protocol == PIN_PROTOCOL_VERSION_V1) {
        cx_hash_sha256(z, sizeof(z), sharedSecret, SHARED_SECRET_V1_SIZE);
    } else {
        hkdf_sha256_32(z, sizeof(z), HKDF_INFO_HMAC_KEY, sharedSecret);
        hkdf_sha256_32(z, sizeof(z), HKDF_INFO_AES_KEY, sharedSecret + SECRET_HMAC_KEY_SIZE);
    }
    explicit_bzero(z, sizeof(z));

    return ERROR_NONE;
}

// Correspond to FIDO2.1 spec PIN/UV Auth Protocol verify() operation
bool ctap2_client_pin_verify(int protocol,
                             const uint8_t *key,
                             uint32_t keyLen,
                             const uint8_t *msg,
                             uint32_t msgLength,
                             const uint8_t *msg2,
                             uint32_t msg2Len,
                             const uint8_t *signature,
                             uint32_t signatureLength) {
    uint8_t hmacValue[CX_SHA256_SIZE];

    if (protocol == PIN_PROTOCOL_VERSION_V1) {
        if (signatureLength != AUTH_PROT_V1_SIZE) {
            return false;
        }
    } else if (protocol == PIN_PROTOCOL_VERSION_V2) {
        if (signatureLength != AUTH_PROT_V2_SIZE) {
            return false;
        }
    } else {
        return false;
    }

    if (keyLen > CX_SHA256_SIZE) {
        // If key is longer than CX_SHA256_SIZE bytes, discard the excess.
        // This selects the HMAC-key portion of the shared secret.
        keyLen = CX_SHA256_SIZE;
    }

    if (msg2 == NULL) {
        cx_hmac_sha256(key, keyLen, msg, msgLength, hmacValue, CX_SHA256_SIZE);
    } else {
        cx_hmac_sha256_t hmac;
        cx_err_t cx_err;

        cx_err = cx_hmac_sha256_init_no_throw(&hmac, key, keyLen);
        LEDGER_ASSERT(cx_err == CX_OK, "cx_hmac_sha256_init_no_throw fail");
        cx_err = cx_hmac_no_throw((cx_hmac_t *) &hmac, 0, msg, msgLength, NULL, 0);
        LEDGER_ASSERT(cx_err == CX_OK, "cx_hmac_no_throw fail");
        cx_err = cx_hmac_no_throw((cx_hmac_t *) &hmac,
                                  CX_LAST,
                                  msg2,
                                  msg2Len,
                                  hmacValue,
                                  CX_SHA256_SIZE);
        LEDGER_ASSERT(cx_err == CX_OK, "cx_hmac_no_throw fail");
    }

    if (!crypto_compare(signature, hmacValue, signatureLength)) {
        explicit_bzero(hmacValue, sizeof(hmacValue));
        return false;
    }

    explicit_bzero(hmacValue, sizeof(hmacValue));
    return true;
}

// Correspond to FIDO2.1 spec PIN/UV Auth Protocol decrypt() operation
//
// Protocol 1: AES-256-CBC, zero IV.
// Protocol 2: AES-256-CBC, the IV is the first 16 bytes of the input.
// `dataIn` and `dataOut` may be the same buffer.
int ctap2_client_pin_decrypt(int protocol,
                             const uint8_t *sharedSecret,
                             const uint8_t *dataIn,
                             uint32_t dataInLength,
                             uint8_t *dataOut,
                             uint32_t *dataOutLength) {
    uint8_t iv[AES_IV_SIZE] = {0};
    uint8_t *tmp = cryptScratch;
    const uint8_t *aesKey;
    const uint8_t *data;
    uint32_t dataLength;
    uint32_t outLength;
    cx_aes_key_t *key = &cryptAesKey;
    int ret = -1;

    if (protocol == PIN_PROTOCOL_VERSION_V1) {
        aesKey = sharedSecret;
        data = dataIn;
        dataLength = dataInLength;
    } else if (protocol == PIN_PROTOCOL_VERSION_V2) {
        if (dataInLength < 2 * AES_IV_SIZE) {
            return -1;
        }
        aesKey = sharedSecret + SECRET_HMAC_KEY_SIZE;
        memcpy(iv, dataIn, AES_IV_SIZE);
        data = dataIn + AES_IV_SIZE;
        dataLength = dataInLength - AES_IV_SIZE;
    } else {
        return -1;
    }

    if ((dataLength % CX_AES_BLOCK_SIZE) != 0 || dataLength > sizeof(cryptScratch)) {
        return -1;
    }

    // Decrypt out of place, so that the IV prefix of protocol 2 can't overlap the output
    outLength = sizeof(cryptScratch);
    if (cx_aes_init_key_no_throw(aesKey, SECRET_AES_KEY_SIZE, key) != CX_OK) {
        goto end;
    }
    if (cx_aes_iv_no_throw(key,
                           CX_LAST | CX_DECRYPT | CX_PAD_NONE | CX_CHAIN_CBC,
                           iv,
                           sizeof(iv),
                           data,
                           dataLength,
                           tmp,
                           &outLength) != CX_OK) {
        goto end;
    }

    memcpy(dataOut, tmp, outLength);
    *dataOutLength = outLength;
    ret = 0;

end:
    explicit_bzero(cryptScratch, sizeof(cryptScratch));
    explicit_bzero(&cryptAesKey, sizeof(cryptAesKey));
    return ret;
}

// Correspond to FIDO2.1 spec PIN/UV Auth Protocol encrypt() operation
//
// Protocol 1: AES-256-CBC, zero IV.
// Protocol 2: AES-256-CBC, random IV which is prepended to the output (dataOut is 16 bytes longer
//             than dataIn).
// `dataIn` and `dataOut` may be the same buffer.
int ctap2_client_pin_encrypt(int protocol,
                             const uint8_t *sharedSecret,
                             const uint8_t *dataIn,
                             uint32_t dataInLength,
                             uint8_t *dataOut,
                             uint32_t *dataOutLength) {
    uint8_t iv[AES_IV_SIZE] = {0};
    uint8_t *tmp = cryptScratch;
    const uint8_t *aesKey;
    uint32_t outLength;
    cx_aes_key_t *key = &cryptAesKey;
    int ret = -1;

    if ((dataInLength % CX_AES_BLOCK_SIZE) != 0 || dataInLength > sizeof(cryptScratch)) {
        return -1;
    }

    if (protocol == PIN_PROTOCOL_VERSION_V1) {
        aesKey = sharedSecret;
    } else if (protocol == PIN_PROTOCOL_VERSION_V2) {
        aesKey = sharedSecret + SECRET_HMAC_KEY_SIZE;
        cx_rng_no_throw(iv, sizeof(iv));
    } else {
        return -1;
    }

    outLength = sizeof(cryptScratch);
    if (cx_aes_init_key_no_throw(aesKey, SECRET_AES_KEY_SIZE, key) != CX_OK) {
        goto end;
    }
    if (cx_aes_iv_no_throw(key,
                           CX_LAST | CX_ENCRYPT | CX_PAD_NONE | CX_CHAIN_CBC,
                           iv,
                           sizeof(iv),
                           dataIn,
                           dataInLength,
                           tmp,
                           &outLength) != CX_OK) {
        goto end;
    }

    if (protocol == PIN_PROTOCOL_VERSION_V2) {
        memcpy(dataOut, iv, AES_IV_SIZE);
        memcpy(dataOut + AES_IV_SIZE, tmp, outLength);
        *dataOutLength = AES_IV_SIZE + outLength;
    } else {
        memcpy(dataOut, tmp, outLength);
        *dataOutLength = outLength;
    }
    ret = 0;

end:
    explicit_bzero(cryptScratch, sizeof(cryptScratch));
    explicit_bzero(&cryptAesKey, sizeof(cryptAesKey));
    return ret;
}

/******************************************/
/*          pinUvAuthToken state          */
/******************************************/

static void invalidate_token(void) {
    explicit_bzero(&authToken, sizeof(authToken));
}

void ctap2_client_pin_clear_permission(uint8_t permission) {
    authToken.permissions &= ~permission;
}

int ctap2_client_pin_verify_auth_token(int protocol,
                                       uint8_t permission,
                                       const uint8_t *rpIdHash,
                                       const uint8_t *msg,
                                       uint32_t msgLength,
                                       const uint8_t *signature,
                                       uint32_t signatureLength) {
    if (!authToken.inUse || (protocol != authToken.protocol)) {
        return ERROR_PIN_AUTH_INVALID;
    }

    if (!ctap2_client_pin_verify(protocol,
                                 authToken.value,
                                 authToken.length,
                                 msg,
                                 msgLength,
                                 NULL,
                                 0,
                                 signature,
                                 signatureLength)) {
        return ERROR_PIN_AUTH_INVALID;
    }

    // The token is genuine, now check what it was issued for
    if ((authToken.permissions & permission) == 0) {
        PRINTF("pinUvAuthToken lacks permission %d\n", permission);
        return ERROR_PIN_AUTH_INVALID;
    }
    if (authToken.hasRpId) {
        if (memcmp(authToken.rpIdHash, rpIdHash, RP_ID_HASH_SIZE) != 0) {
            PRINTF("pinUvAuthToken bound to another RP ID\n");
            return ERROR_PIN_AUTH_INVALID;
        }
    } else {
        // Associate the RP ID with the token on first use
        memcpy(authToken.rpIdHash, rpIdHash, RP_ID_HASH_SIZE);
        authToken.hasRpId = true;
    }

    // mc is single use: the platform must request a new token (implying a new built-in UV) for
    // each makeCredential.
    // ga is not consumed here: platforms send several getAssertion requests with the same token
    // (silent allowList probes with up=false, in batches, then the real request). It is spent by
    // the request that asks for user presence, see ctap2_client_pin_clear_permission() called
    // from getAssertion. The token also stays bound to its RP ID, is replaced by the next token
    // and is cleared on reset / power cycle.
    if (permission == PUAT_PERM_MC) {
        authToken.permissions &= ~permission;
    }
    return ERROR_NONE;
}

/******************************************/
/*         Subcommands Handlers           */
/******************************************/
__attribute__((noinline)) static void ctap2_handle_get_key_agreement(u2f_service_t *service) {
    int status;
    cbipEncoder_t encoder;
    cx_ecfp_public_key_t publicKey;

    PRINTF("client_pin_get_key_agreement\n");
    if (cx_ecfp_generate_pair_no_throw(CX_CURVE_SECP256R1, &publicKey, &ctap2KeyAgreement, 1) !=
        CX_OK) {
        send_cbor_error(service, ERROR_OTHER);
        return;
    }

    cbip_encoder_init(&encoder, responseBuffer + 1, CUSTOM_IO_APDU_BUFFER_SIZE - 1);
    cbip_add_map_header(&encoder, 1);
    cbip_add_int(&encoder, TAG_RESP_KEY_AGREEMENT);
    status = encode_cose_key(&encoder, &publicKey, true);
    if ((status < 0) || encoder.fault) {
        send_cbor_error(service, ERROR_OTHER);
        return;
    }

    responseBuffer[0] = ERROR_NONE;
    send_cbor_response(&G_io_u2f, 1 + encoder.offset, NULL);
}

__attribute__((noinline)) static void ctap2_handle_get_uv_retries(u2f_service_t *service) {
    cbipEncoder_t encoder;

    PRINTF("client_pin_get_uv_retries\n");

    cbip_encoder_init(&encoder, responseBuffer + 1, CUSTOM_IO_APDU_BUFFER_SIZE - 1);
    cbip_add_map_header(&encoder, 1);
    cbip_add_int(&encoder, TAG_RESP_UV_RETRIES);
    cbip_add_int(&encoder, UV_RETRIES_NOMINAL);

    responseBuffer[0] = ERROR_NONE;
    send_cbor_response(service, 1 + encoder.offset, NULL);
}

__attribute__((noinline)) static void ctap2_handle_get_uv_token(u2f_service_t *service,
                                      cbipDecoder_t *decoder,
                                      cbipItem_t *mapItem,
                                      int protocol) {
    int status;
    int permissions;
    char *rpId = NULL;
    uint32_t rpIdLen = 0;
    uint8_t *sharedSecret = uvSharedSecret;
    uint8_t *tokenEnc = uvTokenEnc;
    uint32_t tokenEncLen;
    cbipEncoder_t encoder;

    PRINTF("client_pin_get_uv_token\n");

    memset(uvSharedSecret, 0, sizeof(uvSharedSecret));
    status =
        ctap2_client_pin_decapsulate(protocol, decoder, mapItem, TAG_KEY_AGREEMENT, sharedSecret);
    if (status != ERROR_NONE) {
        send_cbor_error(service, status);
        goto end;
    }

    // permissions
    status = cbiph_get_map_key_int(decoder, mapItem, TAG_PERMISSIONS, &permissions);
    if (status != CBIPH_STATUS_FOUND) {
        send_cbor_error(service, ERROR_MISSING_PARAMETER);
        goto end;
    }
    if (permissions <= 0) {
        send_cbor_error(service, ERROR_INVALID_PAR);
        goto end;
    }
    if ((permissions & ~PUAT_PERM_SUPPORTED) != 0) {
        PRINTF("Unsupported permissions 0x%x\n", permissions);
        send_cbor_error(service, ERROR_UNAUTHORIZED_PERMISSION);
        goto end;
    }

    // rpId, mandatory for mc / ga
    status = cbiph_get_map_key_text(decoder, mapItem, TAG_RP_ID, &rpId, &rpIdLen);
    if (status == CBIPH_STATUS_NOT_FOUND) {
        send_cbor_error(service, ERROR_MISSING_PARAMETER);
        goto end;
    }
    if (status != CBIPH_STATUS_FOUND) {
        send_cbor_error(service, cbiph_map_cbor_error(status));
        goto end;
    }

    // A new token replaces the previous one
    invalidate_token();

    // The user is verified by the unlocked device itself, no further action is needed here. User
    // presence is still collected on the device when the token is used.
    performBuiltInUv();

    authToken.protocol = protocol;
    authToken.length =
        (protocol == PIN_PROTOCOL_VERSION_V1) ? AUTH_TOKEN_V1_SIZE : AUTH_TOKEN_V2_SIZE;
    cx_rng_no_throw(authToken.value, authToken.length);
    authToken.permissions = (uint8_t) permissions;
    cx_hash_sha256((const uint8_t *) rpId, rpIdLen, authToken.rpIdHash, RP_ID_HASH_SIZE);
    authToken.hasRpId = true;
    authToken.inUse = true;

    if (ctap2_client_pin_encrypt(protocol,
                                 sharedSecret,
                                 authToken.value,
                                 authToken.length,
                                 tokenEnc,
                                 &tokenEncLen) != 0) {
        invalidate_token();
        send_cbor_error(service, ERROR_OTHER);
        goto end;
    }

    cbip_encoder_init(&encoder, responseBuffer + 1, CUSTOM_IO_APDU_BUFFER_SIZE - 1);
    cbip_add_map_header(&encoder, 1);
    cbip_add_int(&encoder, TAG_RESP_PIN_TOKEN);
    cbip_add_byte_string(&encoder, tokenEnc, tokenEncLen);

    responseBuffer[0] = ERROR_NONE;
    send_cbor_response(&G_io_u2f, 1 + encoder.offset, NULL);

end:
    explicit_bzero(uvSharedSecret, sizeof(uvSharedSecret));
    explicit_bzero(uvTokenEnc, sizeof(uvTokenEnc));
}

/******************************************/
/*           Command Handler              */
/******************************************/
void ctap2_client_pin_handle(u2f_service_t *service, uint8_t *buffer, uint16_t length) {
    cbipDecoder_t decoder;
    cbipItem_t mapItem;
    int status;
    int protocol = 0;
    int subcommand;

    PRINTF("ctap2_client_pin_handle\n");

    cbip_decoder_init(&decoder, buffer, length);
    cbip_first(&decoder, &mapItem);
    if (mapItem.type != cbipMap) {
        PRINTF("Invalid top item\n");
        send_cbor_error(service, ERROR_INVALID_CBOR);
        return;
    }

    // Check subcommand
    status = cbiph_get_map_key_int(&decoder, &mapItem, TAG_SUBCOMMAND, &subcommand);
    if (status != CBIPH_STATUS_FOUND) {
        PRINTF("Error fetching subcommand\n");
        send_cbor_error(service, cbiph_map_cbor_error(status));
        return;
    }

    // getUVRetries needs no PIN/UV auth protocol, the other ones do
    if (subcommand == SUBCOMMAND_GET_UV_RETRIES) {
        ctap2_handle_get_uv_retries(service);
        return;
    }

    switch (subcommand) {
        case SUBCOMMAND_GET_KEY_AGREEMENT:
        case SUBCOMMAND_GET_UV_TOKEN:
            break;
        default:
            // Includes all the PIN related subcommands: there is no client PIN.
            PRINTF("Unsupported subcommand %d\n", subcommand);
            send_cbor_error(service, ERROR_UNSUPPORTED_OPTION);
            return;
    }

    status = cbiph_get_map_key_int(&decoder, &mapItem, TAG_PIN_PROTOCOL, &protocol);
    if (status != CBIPH_STATUS_FOUND) {
        PRINTF("Error fetching pin protocol\n");
        send_cbor_error(service, cbiph_map_cbor_error(status));
        return;
    }
    if (!ctap2_client_pin_protocol_supported(protocol)) {
        PRINTF("Unsupported pin protocol version\n");
        send_cbor_error(service, ERROR_INVALID_PAR);
        return;
    }

    if (subcommand == SUBCOMMAND_GET_KEY_AGREEMENT) {
        ctap2_handle_get_key_agreement(service);
    } else {
        ctap2_handle_get_uv_token(service, &decoder, &mapItem, protocol);
    }
}

void ctap2_client_pin_reset_ctx(void) {
    ctap2_client_pin_regenerate();
    invalidate_token();
}
