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

#include "os.h"
#include "os_io_seproxyhal.h"
#include "u2f_processing.h"
#include "io.h"

#include "cbip_helper.h"
#include "globals.h"
#include "fido_known_apps.h"
#include "ui_shared.h"
#include "sw_code.h"
#include "nfc_io.h"
#include "ctap2_utils.h"
#include "ctap2.h"

#define CBOR_MAKE_CREDENTIAL    0x01
#define CBOR_GET_ASSERTION      0x02
#define CBOR_GET_NEXT_ASSERTION 0x08
#define CBOR_CRED_MGMT          0x0A
// Vendor (0x40 - 0xBF, avoiding 0x40 / 0x41 of CTAP 2.1 PRE): resident credential backup ID and
// restore, see cred_mgmt.c
#define CBOR_VENDOR_RK 0x50
#define CBOR_GET_INFO           0x04
#define CBOR_CLIENT_PIN         0x06
#define CBOR_RESET              0x07

void ctap2_handle_cmd_cbor(u2f_service_t *service, uint8_t *buffer, uint16_t length) {
    int status;
    // PRINTF("cmd_cbor %d %.*H\n", length, length, buffer);

    if (length < 1) {
        send_cbor_error(service, ERROR_INVALID_CBOR);
        return;
    }

    // While the user approves a credential management token, the token waits in RAM shared with
    // the other PIN/UV commands: only getInfo (which does not touch it) can be answered
    if ((ctap2UxState == CTAP2_UX_STATE_CM_AUTH) && (buffer[0] != CBOR_GET_INFO)) {
        PRINTF("CBOR command refused: credential management approval pending\n");
        send_cbor_error(service, ERROR_OPERATION_PENDING);
        return;
    }

    // Only these commands keep pointers into their request across the user review,
    // so only they are gated and only they are copied. Every other command, known
    // or not, is parsed in place and completes before returning: copying it would
    // overwrite the request a pending review still points into.
    switch (buffer[0]) {
        case CBOR_MAKE_CREDENTIAL:
        case CBOR_GET_ASSERTION:
        case CBOR_GET_NEXT_ASSERTION:
        case CBOR_RESET:
            if ((ctap2UxState != CTAP2_UX_STATE_NONE) || u2fUxPending) {
                PRINTF("CBOR command refused: user confirmation pending\n");
                send_cbor_error(service, ERROR_OPERATION_PENDING);
                return;
            }
            if (length > IO_APDU_BUFFER_SIZE) {
                PRINTF("CBOR command too long\n");
                send_cbor_error(service, ERROR_REQUEST_TOO_LARGE);
                return;
            }
#ifndef TARGET_NANOS
            // G_io_apdu_buffer does not survive the user review.
            memcpy(ctap2RequestBuffer, buffer, length);
            buffer = ctap2RequestBuffer;
#endif
            break;
        default:
            break;
    }

#ifdef HAVE_CBOR_DEBUG
    PRINTF("CBOR %.*H\n", length, buffer);
    cbiph_dump(buffer + 1, length - 1);
#endif

    status = cbiph_validate(buffer + 1, length - 1);
    if (status < 0) {
        PRINTF("Failed to validate cbor\n");
        send_cbor_error(service, ERROR_INVALID_CBOR);
        return;
    }

    switch (buffer[0]) {
        case CBOR_MAKE_CREDENTIAL:
            ctap2_make_credential_handle(service, buffer + 1, length - 1);
            break;
        case CBOR_GET_ASSERTION:
            ctap2_get_assertion_handle(service, buffer + 1, length - 1);
            break;
        case CBOR_GET_NEXT_ASSERTION:
            ctap2_get_next_assertion_handle(service, buffer + 1, length - 1);
            break;
        case CBOR_GET_INFO:
            ctap2_get_info_handle(service, buffer + 1, length - 1);
            break;
        case CBOR_CLIENT_PIN:
            ctap2_client_pin_handle(service, buffer + 1, length - 1);
            break;
        case CBOR_RESET:
            ctap2_reset_handle(service, buffer + 1, length - 1);
            break;
        case CBOR_CRED_MGMT:
            ctap2_cred_mgmt_handle(service, buffer + 1, length - 1, false);
            break;
        case CBOR_VENDOR_RK:
            ctap2_cred_mgmt_handle(service, buffer + 1, length - 1, true);
            break;
        default:
            send_cbor_error(service, ERROR_INVALID_CBOR);
            break;
    }
}

void ctap2_handle_cmd_cancel(u2f_service_t *service, uint8_t *buffer, uint16_t length) {
    UNUSED(buffer);
    UNUSED(length);

    PRINTF("ctap2_cmd_cancel %d\n", ctap2UxState);
    if (ctap2UxState != CTAP2_UX_STATE_NONE) {
        PRINTF("Cancel pending UI\n");

        if (ctap2UxState == CTAP2_UX_STATE_CM_AUTH) {
            // Forget the token that was waiting for the approval (it also answers, see below)
            ctap2_client_pin_cm_auth_discard();
        } else if (ctap2UxState == CTAP2_UX_STATE_DELETE_CRED) {
            ctap2_cred_mgmt_delete_discard();
        }
        ctap2UxState = CTAP2_UX_STATE_NONE;

        // Answer as fast as possible as Chrome expect a fast answer and in case
        // it didn't comes fast enough, it won't be sent back if the user
        // eventually choose again this authenticator.
        send_cbor_error(service, ERROR_KEEPALIVE_CANCEL);

#ifdef HAVE_BAGL
        ux_stack_pop();
        ux_stack_push();
#endif
        ui_idle();
    }
}
