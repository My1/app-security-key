/*******************************************************************************
 *   Ledger App - Bitcoin Wallet
 *   (c) 2016-2019 Ledger
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

#include <string.h>
#include <os.h>
#include <cx.h>

#include "ctap2.h"
#include "ctap2_utils.h"
#include "cbip_helper.h"
#include "config.h"
#include "cose_keys.h"
#include "credential.h"
#include "crypto.h"
#include "globals.h"
#include "rk_storage.h"
#include "cred_mgmt_ui.h"

/*
 * authenticatorCredentialManagement (CTAP 2.1, command 0x0A):
 *  - getCredsMetadata
 *  - enumerateRPsBegin / enumerateRPsGetNextRP
 *  - enumerateCredentialsBegin / enumerateCredentialsGetNextCredential
 *  - deleteCredential, confirmed by the user on the device (not possible over NFC)
 *
 * Authenticated with a pinUvAuthToken carrying the cm permission, see client_pin.c. A token with
 * the cm permission is only granted while resident keys are enabled in the settings.
 *
 * Vendor command CBOR_VENDOR_RK (0x50, see processing.c, advertised by the "ledgerMy1RkRestore"
 * getInfo option), shaped like authenticatorCredentialManagement and handled here with the same
 * authentication (cm token, pinUvAuthParam over subCommand || subCommandParams):
 *
 * Subcommand getBackupId (0x02): the backup ID of the device (see config.h), stored with a
 * backup to match it with its device.
 *
 * Subcommand restoreCredential (0x01), with the same authentication
 * and the same cm token: it stores a resident credential back from what a standard enumeration
 * reported (credential id, user, RP ID) and its algorithm. The credential id is authenticated by
 * the device, so only credentials this device created (for this RP ID hash) are restored. A backup
 * holds no secret: private keys are derived from the device seed and the credential nonce.
 *
 * Only the resident credentials stored in the rk storage are managed. The RP ID is only known for
 * credentials created since it is stored with them: for older ones only the RP ID hash is
 * reported.
 */

// Request keys
#define TAG_SUBCOMMAND        0x01
#define TAG_SUBCOMMAND_PARAMS 0x02
#define TAG_PIN_PROTOCOL      0x03
#define TAG_PIN_AUTH          0x04

// subCommandParams keys
#define PARAM_RP_ID_HASH    0x01
#define PARAM_CREDENTIAL_ID 0x02
// restoreCredential
#define PARAM_VENDOR_CRED_ID   0x42
#define PARAM_VENDOR_USER_ID   0x44
#define PARAM_VENDOR_USER_NAME 0x45
#define PARAM_VENDOR_RP_ID     0x46
#define PARAM_VENDOR_ALG       0x47
#define PARAM_VENDOR_CHECK     0x48  // 1: only check, store nothing

// Subcommands
#define SUBCMD_GET_CREDS_METADATA 0x01
#define SUBCMD_ENUM_RPS_BEGIN     0x02
#define SUBCMD_ENUM_RPS_NEXT      0x03
#define SUBCMD_ENUM_CREDS_BEGIN   0x04
#define SUBCMD_ENUM_CREDS_NEXT    0x05
#define SUBCMD_DELETE_CREDENTIAL  0x06
// Subcommands of the vendor command CBOR_VENDOR_RK (processing.c), only accepted there
#define VENDOR_SUBCMD_RESTORE   0x01
#define VENDOR_SUBCMD_BACKUP_ID 0x02
// ... and the codes they are handled under here (outside of the standard range)
#define SUBCMD_VENDOR_RESTORE   0x41
#define SUBCMD_VENDOR_BACKUP_ID 0x42

// Response keys
#define TAG_RESP_EXISTING_RK_COUNT  0x01
#define TAG_RESP_REMAINING_RK_COUNT 0x02
#define TAG_RESP_RP                 0x03
#define TAG_RESP_RP_ID_HASH         0x04
#define TAG_RESP_TOTAL_RPS          0x05
#define TAG_RESP_USER               0x06
#define TAG_RESP_CREDENTIAL_ID      0x07
#define TAG_RESP_PUBLIC_KEY         0x08
#define TAG_RESP_TOTAL_CREDENTIALS  0x09
// restoreCredential, getBackupId
#define TAG_RESP_VENDOR_BACKUP_ID 0x46
#define TAG_RESP_VENDOR_RESULT     0x45

// Results of restoreCredential
#define RESTORE_STORED         0
#define RESTORE_ALREADY_THERE  1
#define RESTORE_USER_EXISTS    2
#define RESTORE_WOULD_STORE    3  // check only: this device created it, it is missing

#define CM_MAX_SLOTS (RK_SIZE / RK_SLOT_SIZE)

// Wide enough for the "light" credential id of a resident credential
#define CM_CREDENTIAL_ID_MAX_SIZE 96

// Enumeration state, valid until the next "Begin", a reset or a restart.
typedef struct {
    uint8_t slots[CM_MAX_SLOTS];
    uint8_t total;
    uint8_t next;
} cm_enum_t;

static cm_enum_t rpEnum;
static cm_enum_t credEnum;
static uint8_t credEnumRpIdHash[RP_ID_HASH_SIZE];

// Credential id buffer shared by the subcommands that need one (the id to delete, the id reported
// by an enumeration). It lives in the scratch RAM lent by client_pin.c, as RAM and stack are scarce
// on the Nano S; only one CTAP2 command is processed at a time.
// The RP ID hash of the request and the public key of an enumerated credential live there too:
// the stack is the scarcest RAM on the Nano S and an enumeration is the deepest path of the app.
//   [0, 96)    credential id
//   [96, 128)  RP ID hash of the request
//   [128, ...) public key reported by enumerateCredentials
#define CM_SCRATCH_RP_ID_HASH_OFFSET   CM_CREDENTIAL_ID_MAX_SIZE
#define CM_SCRATCH_PUBLIC_KEY_OFFSET   (CM_SCRATCH_RP_ID_HASH_OFFSET + RP_ID_HASH_SIZE)
#define cmCredentialId                 ctap2_shared_scratch()
#define cmRpIdHash                     (ctap2_shared_scratch() + CM_SCRATCH_RP_ID_HASH_OFFSET)
#define cmPublicKey \
    ((cx_ecfp_public_key_t *) (ctap2_shared_scratch() + CM_SCRATCH_PUBLIC_KEY_OFFSET))
_Static_assert(CM_SCRATCH_PUBLIC_KEY_OFFSET % 4 == 0, "public key alignment");
_Static_assert(RK_CREDENTIAL_MAX_SIZE <= CTAP2_SHARED_SCRATCH_SIZE, "restore builds a slot there");
_Static_assert(CM_SCRATCH_PUBLIC_KEY_OFFSET + sizeof(cx_ecfp_public_key_t) <=
                   CTAP2_SHARED_SCRATCH_SIZE,
               "credential management scratch");

// The credential a pending deleteCredential waits for the user to confirm
static struct {
    bool pending;
    uint8_t rpIdHash[RP_ID_HASH_SIZE];
    uint8_t nonce[CREDENTIAL_NONCE_SIZE];
} pendingDelete;

void ctap2_cred_mgmt_reset_ctx(void) {
    memset(&rpEnum, 0, sizeof(rpEnum));
    memset(&credEnum, 0, sizeof(credEnum));
    memset(credEnumRpIdHash, 0, sizeof(credEnumRpIdHash));
    memset(&pendingDelete, 0, sizeof(pendingDelete));
}

static uint8_t count_used_slots(void) {
    uint8_t count = 0;

    for (uint8_t i = 0; i < rk_storage_capacity(); i++) {
        if (rk_storage_get_slot(i, NULL, NULL, NULL, NULL)) {
            count++;
        }
    }
    return count;
}

// List the first slot of every distinct RP ID hash
static void build_rp_list(void) {
    uint8_t *hashI;
    uint8_t *hashJ;

    memset(&rpEnum, 0, sizeof(rpEnum));
    for (uint8_t i = 0; i < rk_storage_capacity(); i++) {
        bool seen = false;

        if (!rk_storage_get_slot(i, &hashI, NULL, NULL, NULL)) {
            continue;
        }
        for (uint8_t j = 0; j < i; j++) {
            if (rk_storage_get_slot(j, &hashJ, NULL, NULL, NULL) &&
                (memcmp(hashI, hashJ, RP_ID_HASH_SIZE) == 0)) {
                seen = true;
                break;
            }
        }
        if (!seen && (rpEnum.total < CM_MAX_SLOTS)) {
            rpEnum.slots[rpEnum.total++] = i;
        }
    }
}

// List every slot of an RP ID hash
__attribute__((noinline)) static void build_credential_list(const uint8_t *rpIdHash) {
    uint8_t *hash;

    memset(&credEnum, 0, sizeof(credEnum));
    memcpy(credEnumRpIdHash, rpIdHash, RP_ID_HASH_SIZE);
    for (uint8_t i = 0; i < rk_storage_capacity(); i++) {
        if (rk_storage_get_slot(i, &hash, NULL, NULL, NULL) &&
            (memcmp(hash, rpIdHash, RP_ID_HASH_SIZE) == 0) && (credEnum.total < CM_MAX_SLOTS)) {
            credEnum.slots[credEnum.total++] = i;
        }
    }
}

// Looks in all the credentials of an RP for its RP ID, which only credentials created after it was
// stored with them have. The returned pointer is into NVM.
static bool find_rp_id(const uint8_t *rpIdHash, char **rpId, uint32_t *rpIdLen) {
    uint8_t *hash;
    uint8_t *credential;
    uint32_t credentialLen;
    credential_data_t credData;

    for (uint8_t i = 0; i < rk_storage_capacity(); i++) {
        if (!rk_storage_get_slot(i, &hash, NULL, &credential, &credentialLen) ||
            (memcmp(hash, rpIdHash, RP_ID_HASH_SIZE) != 0)) {
            continue;
        }
        if (credential_decode(&credData, credential, credentialLen, true) != 0) {
            continue;
        }
        if ((credData.rpId != NULL) && (credData.rpIdLen > 0)) {
            *rpId = credData.rpId;
            *rpIdLen = credData.rpIdLen;
            return true;
        }
    }
    return false;
}

// Length in bytes of the CBOR item, including its children, as it was received.
__attribute__((noinline)) static int item_raw_length(uint8_t *buffer,
                           uint32_t length,
                           const cbipItem_t *item,
                           uint32_t *rawLength) {
    cbipDecoder_t decoder;
    cbipItem_t next;
    uint32_t end;

    cbip_decoder_init(&decoder, buffer, length);
    decoder.offset = item->offset;
    if (cbip_first(&decoder, &next) < 0) {
        return -1;
    }
    // Moves to the item following this one
    if (cbiph_next_deep(&decoder, &next) < 0) {
        return -1;
    }
    end = (next.type == cbipNone) ? length : next.offset;
    if (end < item->offset) {
        return -1;
    }
    *rawLength = end - item->offset;
    return 0;
}

__attribute__((noinline)) static int generate_public_key(const uint8_t *nonce,
                               int coseAlgorithm,
                               cx_ecfp_public_key_t *pubkey) {
    cx_ecfp_private_key_t privateKey;
    cx_curve_t bolosCurve = cose_alg_to_cx(coseAlgorithm);

    if (crypto_generate_private_key(nonce, &privateKey, bolosCurve) != 0) {
        return -1;
    }
    if (cx_ecfp_generate_pair_no_throw(bolosCurve, pubkey, &privateKey, 1) != CX_OK) {
        explicit_bzero(&privateKey, sizeof(privateKey));
        return -1;
    }
    explicit_bzero(&privateKey, sizeof(privateKey));
    return 0;
}

__attribute__((noinline)) static void send_metadata_response(u2f_service_t *service) {
    cbipEncoder_t encoder;
    uint8_t existing = count_used_slots();

    cbip_encoder_init(&encoder, responseBuffer + 1, CUSTOM_IO_APDU_BUFFER_SIZE - 1);
    cbip_add_map_header(&encoder, 2);
    cbip_add_int(&encoder, TAG_RESP_EXISTING_RK_COUNT);
    cbip_add_int(&encoder, existing);
    cbip_add_int(&encoder, TAG_RESP_REMAINING_RK_COUNT);
    cbip_add_int(&encoder, rk_storage_capacity() - existing);

    responseBuffer[0] = ERROR_NONE;
    send_cbor_response(service, 1 + encoder.offset, NULL);
}

__attribute__((noinline)) static void send_rp_response(u2f_service_t *service,
                                                       uint8_t slotIdx,
                                                       bool withTotal) {
    cbipEncoder_t encoder;
    uint8_t *hash;
    uint8_t rpIdHash[RP_ID_HASH_SIZE];
    char *rpId = NULL;
    uint32_t rpIdLen = 0;
    bool knownRpId;

    if (!rk_storage_get_slot(slotIdx, &hash, NULL, NULL, NULL)) {
        send_cbor_error(service, ERROR_NO_CREDENTIALS);
        return;
    }
    memcpy(rpIdHash, hash, sizeof(rpIdHash));
    knownRpId = find_rp_id(rpIdHash, &rpId, &rpIdLen);

    cbip_encoder_init(&encoder, responseBuffer + 1, CUSTOM_IO_APDU_BUFFER_SIZE - 1);
    cbip_add_map_header(&encoder, 1 + (knownRpId ? 1 : 0) + (withTotal ? 1 : 0));
    if (knownRpId) {
        cbip_add_int(&encoder, TAG_RESP_RP);
        cbip_add_map_header(&encoder, 1);
        cbip_add_string(&encoder, KEY_RP_ID, sizeof(KEY_RP_ID) - 1);
        cbip_add_string(&encoder, rpId, rpIdLen);
    }
    cbip_add_int(&encoder, TAG_RESP_RP_ID_HASH);
    cbip_add_byte_string(&encoder, rpIdHash, sizeof(rpIdHash));
    if (withTotal) {
        cbip_add_int(&encoder, TAG_RESP_TOTAL_RPS);
        cbip_add_int(&encoder, rpEnum.total);
    }
    if (encoder.fault) {
        send_cbor_error(service, ERROR_OTHER);
        return;
    }

    responseBuffer[0] = ERROR_NONE;
    send_cbor_response(service, 1 + encoder.offset, NULL);
}

__attribute__((noinline)) static void send_credential_response(u2f_service_t *service,
                                                               uint8_t slotIdx,
                                                               bool withTotal) {
    cbipEncoder_t encoder;
    credential_data_t credData;
    cx_ecfp_public_key_t *publicKey = cmPublicKey;
    uint8_t *rpIdHash;
    uint8_t *nonce;
    uint8_t *credential;
    uint32_t credentialLen;
    int credentialIdLen;

    if (!rk_storage_get_slot(slotIdx, &rpIdHash, &nonce, &credential, &credentialLen)) {
        send_cbor_error(service, ERROR_NO_CREDENTIALS);
        return;
    }
    if (credential_decode(&credData, credential, credentialLen, true) != 0) {
        send_cbor_error(service, ERROR_OTHER);
        return;
    }

    // The credential id is the one the platform gets from a getAssertion
    credentialIdLen = credential_wrap(rpIdHash,
                                      nonce,
                                      &credData,
                                      cmCredentialId,
                                      CM_CREDENTIAL_ID_MAX_SIZE,
                                      true,
                                      true);
    if (credentialIdLen < 0) {
        send_cbor_error(service, ERROR_OTHER);
        return;
    }
    if (generate_public_key(nonce, credData.coseAlgorithm, publicKey) != 0) {
        send_cbor_error(service, ERROR_OTHER);
        return;
    }

    cbip_encoder_init(&encoder, responseBuffer + 1, CUSTOM_IO_APDU_BUFFER_SIZE - 1);
    cbip_add_map_header(&encoder, 3 + (withTotal ? 1 : 0));

    cbip_add_int(&encoder, TAG_RESP_USER);
    cbip_add_map_header(&encoder, (credData.userStr != NULL) ? 2 : 1);
    cbip_add_string(&encoder, KEY_USER_ID, sizeof(KEY_USER_ID) - 1);
    cbip_add_byte_string(&encoder, credData.userId, credData.userIdLen);
    if (credData.userStr != NULL) {
        cbip_add_string(&encoder, KEY_USER_NAME, sizeof(KEY_USER_NAME) - 1);
        cbip_add_string(&encoder, credData.userStr, credData.userStrLen);
    }

    cbip_add_int(&encoder, TAG_RESP_CREDENTIAL_ID);
    cbip_add_map_header(&encoder, 2);
    cbip_add_string(&encoder, CREDENTIAL_DESCRIPTOR_ID, sizeof(CREDENTIAL_DESCRIPTOR_ID) - 1);
    cbip_add_byte_string(&encoder, cmCredentialId, credentialIdLen);
    cbip_add_string(&encoder, CREDENTIAL_DESCRIPTOR_TYPE, sizeof(CREDENTIAL_DESCRIPTOR_TYPE) - 1);
    cbip_add_string(&encoder, CREDENTIAL_TYPE_PUBLIC_KEY, CREDENTIAL_TYPE_PUBLIC_KEY_LENGTH);

    cbip_add_int(&encoder, TAG_RESP_PUBLIC_KEY);
    if (encode_cose_key(&encoder, publicKey, false) < 0) {
        send_cbor_error(service, ERROR_OTHER);
        return;
    }

    if (withTotal) {
        cbip_add_int(&encoder, TAG_RESP_TOTAL_CREDENTIALS);
        cbip_add_int(&encoder, credEnum.total);
    }
    if (encoder.fault) {
        send_cbor_error(service, ERROR_OTHER);
        return;
    }

    responseBuffer[0] = ERROR_NONE;
    send_cbor_response(service, 1 + encoder.offset, NULL);
}

// True if the RP already has a resident credential for this user
__attribute__((noinline)) static bool user_exists(const uint8_t *rpIdHash,
                                                 const uint8_t *userId,
                                                 uint32_t userIdLen) {
    uint8_t *hash;
    uint8_t *credential;
    uint32_t credentialLen;
    credential_data_t credData;

    for (uint8_t i = 0; i < rk_storage_capacity(); i++) {
        if (!rk_storage_get_slot(i, &hash, NULL, &credential, &credentialLen) ||
            (memcmp(hash, rpIdHash, RP_ID_HASH_SIZE) != 0)) {
            continue;
        }
        if ((credential_decode(&credData, credential, credentialLen, true) == 0) &&
            (credData.userIdLen == userIdLen) &&
            (memcmp(credData.userId, userId, userIdLen) == 0)) {
            return true;
        }
    }
    return false;
}

// restoreCredential runs in three steps, each in its own function, so that the deepest part (the
// AES-SIV check of the credential id) runs under a small frame: the Nano S has very little stack.
// What the steps share is kept in the scratch RAM, after the credential id (decrypted in place)
// and the RP ID hash, in the area of the public key (only used by enumerations). The items of the
// request are used in place: the request is not modified before the answer.
typedef struct {
    uint8_t *userId;
    uint32_t userIdLen;
    char *userName;
    uint32_t userNameLen;
    char *rpId;
    uint32_t rpIdLen;
    int alg;
    int checkOnly;
    uint8_t nonce[CREDENTIAL_NONCE_SIZE];
    uint8_t noCounter;
} restore_request_t;

#define cmRestoreRequest \
    ((restore_request_t *) (ctap2_shared_scratch() + CM_SCRATCH_PUBLIC_KEY_OFFSET))
_Static_assert(CM_SCRATCH_PUBLIC_KEY_OFFSET + sizeof(restore_request_t) <=
                   CTAP2_SHARED_SCRATCH_SIZE,
               "restore request scratch");

__attribute__((noinline)) static void send_restore_result(u2f_service_t *service, int result) {
    cbipEncoder_t encoder;

    cbip_encoder_init(&encoder, responseBuffer + 1, CUSTOM_IO_APDU_BUFFER_SIZE - 1);
    cbip_add_map_header(&encoder, 1);
    cbip_add_int(&encoder, TAG_RESP_VENDOR_RESULT);
    cbip_add_int(&encoder, result);
    responseBuffer[0] = ERROR_NONE;
    send_cbor_response(service, 1 + encoder.offset, NULL);
}

// Step 1: parameters and their checks. Returns 0 to go on, else the error was sent.
__attribute__((noinline)) static int restore_parse(u2f_service_t *service,
                                                   cbipDecoder_t *decoder,
                                                   cbipItem_t *paramsItem,
                                                   const uint8_t *rpIdHash,
                                                   uint32_t credentialIdLen,
                                                   restore_request_t *request) {
    int status;

    memset(request, 0, sizeof(*request));
    status = cbiph_get_map_key_bytes(decoder,
                                     paramsItem,
                                     PARAM_VENDOR_USER_ID,
                                     &request->userId,
                                     &request->userIdLen);
    if (status != CBIPH_STATUS_FOUND) {
        send_cbor_error(service,
                        (status < CBIPH_STATUS_NOT_FOUND) ? cbiph_map_cbor_error(status)
                                                          : ERROR_MISSING_PARAMETER);
        return -1;
    }
    status = cbiph_get_map_key_int(decoder, paramsItem, PARAM_VENDOR_ALG, &request->alg);
    if (status != CBIPH_STATUS_FOUND) {
        send_cbor_error(service,
                        (status < CBIPH_STATUS_NOT_FOUND) ? cbiph_map_cbor_error(status)
                                                          : ERROR_MISSING_PARAMETER);
        return -1;
    }
    status = cbiph_get_map_key_text(decoder,
                                    paramsItem,
                                    PARAM_VENDOR_USER_NAME,
                                    &request->userName,
                                    &request->userNameLen);
    if (status < CBIPH_STATUS_NOT_FOUND) {
        send_cbor_error(service, cbiph_map_cbor_error(status));
        return -1;
    }
    status = cbiph_get_map_key_text(decoder,
                                    paramsItem,
                                    PARAM_VENDOR_RP_ID,
                                    &request->rpId,
                                    &request->rpIdLen);
    if (status < CBIPH_STATUS_NOT_FOUND) {
        send_cbor_error(service, cbiph_map_cbor_error(status));
        return -1;
    }
    status = cbiph_get_map_key_int(decoder, paramsItem, PARAM_VENDOR_CHECK, &request->checkOnly);
    if (status < CBIPH_STATUS_NOT_FOUND) {
        send_cbor_error(service, cbiph_map_cbor_error(status));
        return -1;
    }

    if ((ctap2UxState != CTAP2_UX_STATE_NONE) || u2fUxPending) {
        // A restore ends any enumeration and any pending delete: not while the user is asked
        send_cbor_error(service, ERROR_OPERATION_PENDING);
        return -1;
    }
    if ((credentialIdLen < CREDENTIAL_MINIMAL_SIZE) || (request->userIdLen == 0) ||
        (request->userIdLen > 64) || (request->userNameLen > 64)) {
        send_cbor_error(service, ERROR_INVALID_PAR);
        return -1;
    }
    if (request->rpId != NULL) {
        // Only trusted if it is the one of the RP ID hash
        uint8_t hash[RP_ID_HASH_SIZE];

        cx_hash_sha256((const uint8_t *) request->rpId, request->rpIdLen, hash, sizeof(hash));
        if (memcmp(hash, rpIdHash, RP_ID_HASH_SIZE) != 0) {
            send_cbor_error(service, ERROR_INVALID_PAR);
            return -1;
        }
    }
    return 0;
}

// Step 2, the deep one (AES-SIV): the device checks that it created this credential for this RP,
// the credential id is authenticated with a key of the device. Not finding it in the storage is
// expected here. Returns RESTORE_STORED to go on, RESTORE_ALREADY_THERE, or -1 with *error set.
__attribute__((noinline)) static int restore_verify(const uint8_t *rpIdHash,
                                                    uint8_t *credentialId,
                                                    uint32_t credentialIdLen,
                                                    restore_request_t *request,
                                                    uint8_t *error) {
    uint8_t *unused;
    uint32_t unusedLen;
    uint8_t *nonceInId;

    *error = ERROR_INVALID_CREDENTIAL;
    if (credentialId[0] != CREDENTIAL_VERSION_CTAP2) {
        return -1;
    }
    if (credential_unwrap(rpIdHash,
                          credentialId,
                          credentialIdLen,
                          &nonceInId,
                          &unused,
                          &unusedLen) == STATUS_RK_CREDENTIAL) {
        return RESTORE_ALREADY_THERE;
    }
    if (credentialId[0] != (CREDENTIAL_VERSION_CTAP2 | CREDENTIAL_UNWRAPPED_BIT)) {
        // Not authenticated: another device, another RP, or damaged
        return -1;
    }
    memcpy(request->nonce,
           credentialId + CREDENTIAL_VERSION_SIZE + CREDENTIAL_TAG_SIZE,
           CREDENTIAL_NONCE_SIZE);
    return RESTORE_STORED;
}

// Step 3: what is stored, and the answer.
__attribute__((noinline)) static void restore_finish(u2f_service_t *service,
                                                     const uint8_t *rpIdHash,
                                                     uint8_t *credentialId,
                                                     uint32_t credentialIdLen,
                                                     restore_request_t *request) {
    credential_data_t credData;
    restore_request_t copy;
    int status;
    const uint32_t lightOffset =
        CREDENTIAL_VERSION_SIZE + CREDENTIAL_TAG_SIZE + CREDENTIAL_NONCE_SIZE;

    // It has to be a resident credential; its flags (zero counter) are kept
    if ((credential_decode(&credData,
                           credentialId + lightOffset,
                           credentialIdLen - lightOffset,
                           false) != 0) ||
        !credData.residentKey) {
        send_cbor_error(service, ERROR_INVALID_CREDENTIAL);
        return;
    }
    request->noCounter = credData.noCounter;

    if (user_exists(rpIdHash, request->userId, request->userIdLen)) {
        // Like a new registration for the same user would, but never replace what is there
        send_restore_result(service, RESTORE_USER_EXISTS);
        return;
    }
    if (request->checkOnly) {
        send_restore_result(service, RESTORE_WOULD_STORE);
        return;
    }

    // The stored form is built in the whole scratch: keep what is still needed elsewhere, the
    // request on the stack, the RP ID hash in the enumeration state (a restore ends it anyway)
    memcpy(&copy, request, sizeof(copy));
    memcpy(credEnumRpIdHash, rpIdHash, RP_ID_HASH_SIZE);
    rpIdHash = credEnumRpIdHash;

    memset(&credData, 0, sizeof(credData));
    credData.coseAlgorithm = copy.alg;
    credData.userId = copy.userId;
    credData.userIdLen = copy.userIdLen;
    credData.userStr = copy.userName;
    credData.userStrLen = copy.userNameLen;
    credData.residentKey = 1;
    credData.noCounter = copy.noCounter;
    credData.rpId = copy.rpId;
    credData.rpIdLen = copy.rpIdLen;

    status = credential_encode_resident(&credData, ctap2_shared_scratch(), RK_CREDENTIAL_MAX_SIZE);
    if ((status <= 0) || (status > RK_CREDENTIAL_MAX_SIZE)) {
        ctap2_cred_mgmt_reset_ctx();
        send_cbor_error(service, ERROR_INVALID_PAR);
        return;
    }
    status = rk_storage_store(rpIdHash, copy.nonce, ctap2_shared_scratch(), status);
    // The slots changed (or the enumeration state was used): any enumeration in progress is not
    // valid anymore
    ctap2_cred_mgmt_reset_ctx();
    if (status != 0) {
        send_cbor_error(service,
                        (status == RK_STORAGE_FULL) ? ERROR_KEY_STORE_FULL : ERROR_OTHER);
        return;
    }
    send_restore_result(service, RESTORE_STORED);
}

// Kept small: the AES-SIV of step 2 runs under this frame (and the handler's)
__attribute__((noinline)) static void restore_credential(u2f_service_t *service,
                                                         cbipDecoder_t *decoder,
                                                         cbipItem_t *paramsItem,
                                                         const uint8_t *rpIdHash,
                                                         uint8_t *credentialId,
                                                         uint32_t credentialIdLen) {
    restore_request_t *request = cmRestoreRequest;
    uint8_t error;
    int result;

    if (restore_parse(service, decoder, paramsItem, rpIdHash, credentialIdLen, request) != 0) {
        return;
    }
    result = restore_verify(rpIdHash, credentialId, credentialIdLen, request, &error);
    if (result < 0) {
        send_cbor_error(service, error);
        return;
    }
    if (result == RESTORE_ALREADY_THERE) {
        send_restore_result(service, RESTORE_ALREADY_THERE);
        return;
    }
    restore_finish(service, rpIdHash, credentialId, credentialIdLen, request);
}

__attribute__((noinline)) static void send_backup_id_response(u2f_service_t *service) {
    cbipEncoder_t encoder;
    char backupId[BACKUP_ID_SIZE];

    config_get_backup_id(backupId);

    cbip_encoder_init(&encoder, responseBuffer + 1, CUSTOM_IO_APDU_BUFFER_SIZE - 1);
    cbip_add_map_header(&encoder, 1);
    cbip_add_int(&encoder, TAG_RESP_VENDOR_BACKUP_ID);
    cbip_add_string(&encoder, backupId, BACKUP_ID_SIZE - 1);
    responseBuffer[0] = ERROR_NONE;
    send_cbor_response(service, 1 + encoder.offset, NULL);
}

// Finds the resident credential a credential id designates: the id is encrypted for an RP ID, so
// try each RP ID hash of the storage. Returns 0 and the RP ID hash and nonce of the credential.
__attribute__((noinline)) static int locate_credential(const uint8_t *credentialId,
                             uint32_t credentialIdLen,
                             uint8_t *rpIdHash,
                             uint8_t *nonce) {
    // The copy is in the scratch, after the credential id and the RP ID hash (the public key area,
    // unused by a delete): a delete is as deep on the stack as an enumeration. The credential id of
    // a resident key is short (its light encoding only holds the version and the flags), longer
    // ones can't designate one.
    uint8_t *copy = ctap2_shared_scratch() + CM_SCRATCH_PUBLIC_KEY_OFFSET;
    const uint32_t copySize = CTAP2_SHARED_SCRATCH_SIZE - CM_SCRATCH_PUBLIC_KEY_OFFSET;
    uint8_t *hash;
    uint8_t *credNonce;
    uint8_t *encodedCredential;
    uint32_t encodedCredentialLen;
    int ret = -1;

    if ((credentialIdLen == 0) || (credentialIdLen > copySize)) {
        return -1;
    }

    build_rp_list();
    for (uint8_t i = 0; (i < rpEnum.total) && (ret != 0); i++) {
        if (!rk_storage_get_slot(rpEnum.slots[i], &hash, NULL, NULL, NULL)) {
            continue;
        }
        // The credential id is decrypted in place
        memcpy(copy, credentialId, credentialIdLen);
        if (credential_unwrap(hash,
                              copy,
                              credentialIdLen,
                              &credNonce,
                              &encodedCredential,
                              &encodedCredentialLen) == STATUS_RK_CREDENTIAL) {
            memcpy(rpIdHash, hash, RP_ID_HASH_SIZE);
            memcpy(nonce, credNonce, CREDENTIAL_NONCE_SIZE);
            ret = 0;
        }
    }
    explicit_bzero(copy, copySize);
    return ret;
}

// Puts what the user is asked to confirm in the display buffers
__attribute__((noinline)) static void prepare_delete_display(const uint8_t *rpIdHash,
                                                             const uint8_t *nonce) {
    static const char hexDigits[] = "0123456789abcdef";
    char unknownRp[] = "unknown (xxxxxxxx)";
    credential_data_t credData;
    uint8_t *credential;
    uint32_t credentialLen;
    char *rpId = NULL;
    uint32_t rpIdLen = 0;

    if (find_rp_id(rpIdHash, &rpId, &rpIdLen)) {
        globals_display_set_rp(rpId, rpIdLen);
    } else {
        // Only the hash is known
        for (uint8_t i = 0; i < 4; i++) {
            unknownRp[9 + 2 * i] = hexDigits[rpIdHash[i] >> 4];
            unknownRp[10 + 2 * i] = hexDigits[rpIdHash[i] & 0x0F];
        }
        globals_display_set_rp(unknownRp, strlen(unknownRp));
    }

    globals_display_clear_username();
    if ((rk_storage_find_account(rpIdHash, nonce, &credential, &credentialLen) > 0) &&
        (credential_decode(&credData, credential, credentialLen, true) == 0) &&
        (credData.userStr != NULL)) {
        globals_display_set_username(credData.userStr, credData.userStrLen);
    } else {
        globals_display_set_username("(no name)", 9);
    }
}

void ctap2_cred_mgmt_delete_confirm(void) {
    int erased;

    if (!pendingDelete.pending) {
        send_cbor_error(&G_io_u2f, ERROR_OPERATION_DENIED);
        return;
    }
    pendingDelete.pending = false;

    erased = rk_storage_erase_by_nonce(pendingDelete.rpIdHash, pendingDelete.nonce);
    // The slots changed: any enumeration in progress is not valid anymore
    ctap2_cred_mgmt_reset_ctx();

    if (!erased) {
        send_cbor_error(&G_io_u2f, ERROR_NO_CREDENTIALS);
        return;
    }
    responseBuffer[0] = ERROR_NONE;
    send_cbor_response(&G_io_u2f, 1, NULL);
}

void ctap2_cred_mgmt_delete_discard(void) {
    pendingDelete.pending = false;
}

void ctap2_cred_mgmt_delete_cancel(void) {
    pendingDelete.pending = false;
    send_cbor_error(&G_io_u2f, ERROR_OPERATION_DENIED);
}

// The pinUvAuthParam is HMAC(token, subCommand || subCommandParams), the params being the CBOR
// map exactly as the platform sent it.
static int authenticate(int subCommand,
                        bool hasParams,
                        const uint8_t *rawParams,
                        uint32_t rawParamsLen,
                        int protocol,
                        const uint8_t *pinUvAuthParam,
                        uint32_t pinUvAuthParamLen,
                        const uint8_t *rpIdHash) {
    uint8_t subCommandByte = (uint8_t) subCommand;

    if (pinUvAuthParam == NULL) {
        return ERROR_PUAT_REQUIRED;
    }
    if (protocol == 0) {
        return ERROR_MISSING_PARAMETER;
    }
    if (!ctap2_client_pin_protocol_supported(protocol)) {
        return ERROR_INVALID_PAR;
    }
    return ctap2_client_pin_verify_cm(protocol,
                                      &subCommandByte,
                                      1,
                                      hasParams ? rawParams : NULL,
                                      hasParams ? rawParamsLen : 0,
                                      pinUvAuthParam,
                                      pinUvAuthParamLen,
                                      rpIdHash);
}

// Stack: on the Nano S the whole stack is ~1.4 KB and an enumeration (this handler, then
// send_credential_response, credential_wrap and the AES-SIV / CMAC code) is the deepest path of the
// app. The helpers above are kept out of line (noinline) so that their locals (the 96 bytes copy of
// locate_credential, the display strings, the private key) are not part of this frame on every
// path, only while they run.
void ctap2_cred_mgmt_handle(u2f_service_t *service,
                            uint8_t *buffer,
                            uint16_t length,
                            bool vendorCommand) {
    cbipDecoder_t decoder;
    cbipItem_t mapItem;
    cbipItem_t paramsItem;
    int status;
    int subCommand;
    // As received, it is the one the pinUvAuthParam covers
    int wireSubCommand;
    int protocol = 0;
    uint8_t *pinUvAuthParam = NULL;
    uint32_t pinUvAuthParamLen = 0;
    bool hasParams = false;
    uint8_t *rawParams = NULL;
    uint32_t rawParamsLen = 0;
    // The response is built in a buffer that can alias the request: nothing is read from the
    // request once it starts, so copy what is needed
    uint8_t *rpIdHash = cmRpIdHash;
    bool hasRpIdHash = false;
    uint8_t *credentialId = cmCredentialId;
    uint32_t credentialIdLen = 0;
    bool hasCredentialId = false;
    cbipItem_t descriptorItem;
    uint8_t *tmp;
    uint32_t tmpLen;

    PRINTF("ctap2_cred_mgmt_handle\n");

    if (!CTAP2_RK_ENABLED()) {
        send_cbor_error(service, ERROR_UNSUPPORTED_OPTION);
        return;
    }

    cbip_decoder_init(&decoder, buffer, length);
    cbip_first(&decoder, &mapItem);
    if (mapItem.type != cbipMap) {
        send_cbor_error(service, ERROR_INVALID_CBOR);
        return;
    }

    status = cbiph_get_map_key_int(&decoder, &mapItem, TAG_SUBCOMMAND, &subCommand);
    if (status != CBIPH_STATUS_FOUND) {
        send_cbor_error(service, cbiph_map_cbor_error(status));
        return;
    }

    // The standard command only has the standard subcommands, the vendor command only its own
    wireSubCommand = subCommand;
    if (vendorCommand) {
        if (subCommand == VENDOR_SUBCMD_RESTORE) {
            subCommand = SUBCMD_VENDOR_RESTORE;
        } else if (subCommand == VENDOR_SUBCMD_BACKUP_ID) {
            subCommand = SUBCMD_VENDOR_BACKUP_ID;
        } else {
            send_cbor_error(service, ERROR_INVALID_SUBCOMMAND);
            return;
        }
    } else if ((subCommand == SUBCMD_VENDOR_RESTORE) || (subCommand == SUBCMD_VENDOR_BACKUP_ID)) {
        send_cbor_error(service, ERROR_INVALID_SUBCOMMAND);
        return;
    }

    // subCommandParams
    status =
        cbiph_get_map_item(&decoder, &mapItem, TAG_SUBCOMMAND_PARAMS, NULL, &paramsItem, cbipMap);
    if (status == CBIPH_STATUS_FOUND) {
        hasParams = true;
        if (item_raw_length(buffer, length, &paramsItem, &rawParamsLen) < 0) {
            send_cbor_error(service, ERROR_INVALID_CBOR);
            return;
        }
        rawParams = buffer + paramsItem.offset;

        status = cbiph_get_map_key_bytes(&decoder, &paramsItem, PARAM_RP_ID_HASH, &tmp, &tmpLen);
        if (status == CBIPH_STATUS_FOUND) {
            if (tmpLen != RP_ID_HASH_SIZE) {
                send_cbor_error(service, ERROR_INVALID_PAR);
                return;
            }
            memcpy(rpIdHash, tmp, RP_ID_HASH_SIZE);
            hasRpIdHash = true;
        } else if (status < CBIPH_STATUS_NOT_FOUND) {
            send_cbor_error(service, cbiph_map_cbor_error(status));
            return;
        }

        // credentialId: {"id": bytes, "type": "public-key"}
        status = cbiph_get_map_item(&decoder,
                                    &paramsItem,
                                    PARAM_CREDENTIAL_ID,
                                    NULL,
                                    &descriptorItem,
                                    cbipMap);
        if (status == CBIPH_STATUS_FOUND) {
            status = cbiph_get_map_key_str_bytes(&decoder,
                                                 &descriptorItem,
                                                 CREDENTIAL_DESCRIPTOR_ID,
                                                 &tmp,
                                                 &tmpLen);
            if (status == CBIPH_STATUS_FOUND) {
                hasCredentialId = true;
                // Longer than any credential id of a resident key: can't designate one
                credentialIdLen = (tmpLen <= CM_CREDENTIAL_ID_MAX_SIZE) ? tmpLen : 0;
                memcpy(credentialId, tmp, credentialIdLen);
            } else {
                send_cbor_error(service, (status < CBIPH_STATUS_NOT_FOUND)
                                             ? cbiph_map_cbor_error(status)
                                             : ERROR_MISSING_PARAMETER);
                return;
            }
        } else if (status < CBIPH_STATUS_NOT_FOUND) {
            send_cbor_error(service, cbiph_map_cbor_error(status));
            return;
        }

        if (subCommand == SUBCMD_VENDOR_RESTORE) {
            // credential id (plain bytes), a copy as it is decrypted in place
            status = cbiph_get_map_key_bytes(&decoder,
                                             &paramsItem,
                                             PARAM_VENDOR_CRED_ID,
                                             &tmp,
                                             &tmpLen);
            if (status == CBIPH_STATUS_FOUND) {
                if (tmpLen > CM_CREDENTIAL_ID_MAX_SIZE) {
                    send_cbor_error(service, ERROR_INVALID_PAR);
                    return;
                }
                hasCredentialId = true;
                credentialIdLen = tmpLen;
                memcpy(credentialId, tmp, tmpLen);
            } else if (status < CBIPH_STATUS_NOT_FOUND) {
                send_cbor_error(service, cbiph_map_cbor_error(status));
                return;
            }
        }
    } else if (status < CBIPH_STATUS_NOT_FOUND) {
        send_cbor_error(service, cbiph_map_cbor_error(status));
        return;
    }

    // pinUvAuthProtocol and pinUvAuthParam, mandatory but the subcommands that continue an
    // enumeration
    status = cbiph_get_map_key_int(&decoder, &mapItem, TAG_PIN_PROTOCOL, &protocol);
    if (status < CBIPH_STATUS_NOT_FOUND) {
        send_cbor_error(service, cbiph_map_cbor_error(status));
        return;
    }
    status = cbiph_get_map_key_bytes(&decoder,
                                     &mapItem,
                                     TAG_PIN_AUTH,
                                     &pinUvAuthParam,
                                     &pinUvAuthParamLen);
    if (status < CBIPH_STATUS_NOT_FOUND) {
        send_cbor_error(service, cbiph_map_cbor_error(status));
        return;
    }
    if (status == CBIPH_STATUS_NOT_FOUND) {
        pinUvAuthParam = NULL;
    }

    switch (subCommand) {
        case SUBCMD_GET_CREDS_METADATA:
        case SUBCMD_ENUM_RPS_BEGIN:
        case SUBCMD_ENUM_CREDS_BEGIN:
        case SUBCMD_DELETE_CREDENTIAL:
        case SUBCMD_VENDOR_BACKUP_ID:
            if ((subCommand == SUBCMD_ENUM_CREDS_BEGIN) && !hasRpIdHash) {
                send_cbor_error(service, ERROR_MISSING_PARAMETER);
                return;
            }
            if ((subCommand == SUBCMD_DELETE_CREDENTIAL) && !hasCredentialId) {
                send_cbor_error(service, ERROR_MISSING_PARAMETER);
                return;
            }
            status = authenticate(wireSubCommand,
                                  hasParams,
                                  rawParams,
                                  rawParamsLen,
                                  protocol,
                                  pinUvAuthParam,
                                  pinUvAuthParamLen,
                                  (subCommand == SUBCMD_ENUM_CREDS_BEGIN) ? rpIdHash : NULL);
            if (status != ERROR_NONE) {
                send_cbor_error(service, status);
                return;
            }
            break;
        case SUBCMD_VENDOR_RESTORE:
            if (!hasParams || !hasRpIdHash || !hasCredentialId) {
                send_cbor_error(service, ERROR_MISSING_PARAMETER);
                return;
            }
            status = authenticate(wireSubCommand,
                                  hasParams,
                                  rawParams,
                                  rawParamsLen,
                                  protocol,
                                  pinUvAuthParam,
                                  pinUvAuthParamLen,
                                  rpIdHash);
            if (status != ERROR_NONE) {
                send_cbor_error(service, status);
                return;
            }
            break;
        case SUBCMD_ENUM_RPS_NEXT:
        case SUBCMD_ENUM_CREDS_NEXT:
            // Continue an enumeration authenticated by its "Begin"
            break;
        default:
            // Includes updateUserInformation, not supported yet
            PRINTF("Unsupported subcommand %d\n", subCommand);
            send_cbor_error(service, ERROR_INVALID_SUBCOMMAND);
            return;
    }

    switch (subCommand) {
        case SUBCMD_GET_CREDS_METADATA:
            send_metadata_response(service);
            break;
        case SUBCMD_VENDOR_BACKUP_ID:
            send_backup_id_response(service);
            break;
        case SUBCMD_ENUM_RPS_BEGIN:
            build_rp_list();
            if (rpEnum.total == 0) {
                send_cbor_error(service, ERROR_NO_CREDENTIALS);
                break;
            }
            rpEnum.next = 1;
            send_rp_response(service, rpEnum.slots[0], true);
            break;
        case SUBCMD_ENUM_RPS_NEXT:
            if (rpEnum.next >= rpEnum.total) {
                send_cbor_error(service, ERROR_NO_CREDENTIALS);
                break;
            }
            send_rp_response(service, rpEnum.slots[rpEnum.next++], false);
            break;
        case SUBCMD_ENUM_CREDS_BEGIN:
            build_credential_list(rpIdHash);
            if (credEnum.total == 0) {
                send_cbor_error(service, ERROR_NO_CREDENTIALS);
                break;
            }
            credEnum.next = 1;
            send_credential_response(service, credEnum.slots[0], true);
            break;
        case SUBCMD_ENUM_CREDS_NEXT:
            if (credEnum.next >= credEnum.total) {
                send_cbor_error(service, ERROR_NO_CREDENTIALS);
                break;
            }
            send_credential_response(service, credEnum.slots[credEnum.next++], false);
            break;
        case SUBCMD_VENDOR_RESTORE:
            restore_credential(service, &decoder, &paramsItem, rpIdHash, credentialId,
                               credentialIdLen);
            break;
        case SUBCMD_DELETE_CREDENTIAL: {
            uint8_t nonce[CREDENTIAL_NONCE_SIZE];

            if (CMD_IS_OVER_U2F_NFC) {
                // The user can't answer over NFC
                send_cbor_error(service, ERROR_OPERATION_DENIED);
                break;
            }
            if ((ctap2UxState != CTAP2_UX_STATE_NONE) || u2fUxPending) {
                send_cbor_error(service, ERROR_OPERATION_PENDING);
                break;
            }
            if (locate_credential(credentialId, credentialIdLen, rpIdHash, nonce) != 0) {
                send_cbor_error(service, ERROR_NO_CREDENTIALS);
                break;
            }
            // A token bound to an RP can only delete the credentials of this RP
            if (!ctap2_client_pin_token_allows_rp(rpIdHash)) {
                send_cbor_error(service, ERROR_PIN_AUTH_INVALID);
                break;
            }
            pendingDelete.pending = true;
            memcpy(pendingDelete.rpIdHash, rpIdHash, RP_ID_HASH_SIZE);
            memcpy(pendingDelete.nonce, nonce, CREDENTIAL_NONCE_SIZE);
            prepare_delete_display(rpIdHash, nonce);
            // The response is sent when the user has answered
            ctap2_cred_mgmt_delete_ux();
            break;
        }
        default:
            break;
    }
}
