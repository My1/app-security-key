/*
*******************************************************************************
*   Ledger App Security Key
*   (c) 2024 Ledger
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
#include "ux.h"

#include "ctap2.h"
#include "ctap2_utils.h"
#include "globals.h"
#include "ui_shared.h"

#include "cred_mgmt_ui.h"

static void ctap_ux_on_user_choice(bool confirm) {
    if (confirm) {
        ctap2_cred_mgmt_delete_confirm();
    } else {
        ctap2_cred_mgmt_delete_cancel();
    }
    // The request is fully handled: nothing is read from it after the user answered
    ctap2UxState = CTAP2_UX_STATE_NONE;
    ui_idle();
}

static void ctap_ux_on_auth_choice(bool confirm) {
    if (confirm) {
        ctap2_client_pin_cm_auth_confirm();
    } else {
        ctap2_client_pin_cm_auth_cancel();
    }
    ctap2UxState = CTAP2_UX_STATE_NONE;
    ui_idle();
}

#if defined(HAVE_BAGL)

UX_STEP_NOCB(ux_ctap2_cm_auth_flow_first_step,
             pnn,
             {
                 &C_icon_warning,
                 "Manage saved",
                 "accounts?",
             });

UX_STEP_NOCB(ux_ctap2_cm_auth_flow_info_step,
             bnnn_paging,
             {
                 .title = "Allow",
                 .text = "Listing and deleting your saved accounts",
             });

UX_STEP_CB(ux_ctap2_cm_auth_flow_accept_step,
           pb,
           ctap_ux_on_auth_choice(true),
           {
               &C_icon_validate_14,
               "Yes, allow",
           });

UX_STEP_CB(ux_ctap2_cm_auth_flow_refuse_step,
           pb,
           ctap_ux_on_auth_choice(false),
           {
               &C_icon_crossmark,
               "No, deny",
           });

UX_FLOW(ux_ctap2_cm_auth_flow,
        &ux_ctap2_cm_auth_flow_first_step,
        &ux_ctap2_cm_auth_flow_info_step,
        &ux_ctap2_cm_auth_flow_accept_step,
        &ux_ctap2_cm_auth_flow_refuse_step);

UX_STEP_NOCB(ux_ctap2_delete_cred_flow_first_step,
             pnn,
             {
                 &C_icon_warning,
                 "Delete",
                 "saved account?",
             });

UX_STEP_NOCB(ux_ctap2_delete_cred_flow_domain_step,
             bnnn_paging,
             {
                 .title = "Website",
                 .text = g.rp_buffer,
             });

UX_STEP_NOCB(ux_ctap2_delete_cred_flow_user_step,
             bnnn_paging,
             {
                 .title = "User ID",
                 .text = g.username_buffer,
             });

UX_STEP_CB(ux_ctap2_delete_cred_flow_accept_step,
           pb,
           ctap_ux_on_user_choice(true),
           {
               &C_icon_validate_14,
               "Yes, delete",
           });

UX_STEP_CB(ux_ctap2_delete_cred_flow_refuse_step,
           pb,
           ctap_ux_on_user_choice(false),
           {
               &C_icon_crossmark,
               "No, don't delete",
           });

UX_FLOW(ux_ctap2_delete_cred_flow,
        &ux_ctap2_delete_cred_flow_first_step,
        &ux_ctap2_delete_cred_flow_domain_step,
        &ux_ctap2_delete_cred_flow_user_step,
        &ux_ctap2_delete_cred_flow_accept_step,
        &ux_ctap2_delete_cred_flow_refuse_step);

#elif defined(HAVE_NBGL)

#include "nbgl_use_case.h"
#include "nbgl_layout.h"

#define NB_OF_AUTH_PAIRS 1
static const nbgl_layoutTagValue_t authPairs[NB_OF_AUTH_PAIRS] = {{
    .item = "Allow",
    .value = "Listing and deleting your saved accounts",
}};

#define NB_OF_PAIRS 2
static const nbgl_layoutTagValue_t pairs[NB_OF_PAIRS] = {{
                                                             .item = "Website",
                                                             .value = g.rp_buffer,
                                                         },
                                                         {
                                                             .item = "User ID",
                                                             .value = g.username_buffer,
                                                         }};

#endif

void ctap2_cred_mgmt_delete_ux(void) {
    ctap2UxState = CTAP2_UX_STATE_DELETE_CRED;

    UX_WAKE_UP();

#if defined(HAVE_BAGL)
    ux_flow_init(0, ux_ctap2_delete_cred_flow, NULL);
#elif defined(HAVE_NBGL)
    io_seproxyhal_play_tune(TUNE_LOOK_AT_ME);

    app_nbgl_start_review(NB_OF_PAIRS, pairs, "Delete saved account", ctap_ux_on_user_choice, NULL);
#endif
}

void ctap2_cred_mgmt_auth_ux(void) {
    ctap2UxState = CTAP2_UX_STATE_CM_AUTH;

    UX_WAKE_UP();

#if defined(HAVE_BAGL)
    ux_flow_init(0, ux_ctap2_cm_auth_flow, NULL);
#elif defined(HAVE_NBGL)
    io_seproxyhal_play_tune(TUNE_LOOK_AT_ME);

    app_nbgl_start_review(NB_OF_AUTH_PAIRS,
                          authPairs,
                          "Allow account management",
                          ctap_ux_on_auth_choice,
                          NULL);
#endif
}

// The SDK ticker fires about every 100 ms
#define CM_UX_TIMEOUT_TICKS 600  // ~60 s

static uint16_t cmUxTicks;

void ctap2_cred_mgmt_ux_tick(void) {
    if ((ctap2UxState != CTAP2_UX_STATE_CM_AUTH) && (ctap2UxState != CTAP2_UX_STATE_DELETE_CRED)) {
        cmUxTicks = 0;
        return;
    }
    if (++cmUxTicks < CM_UX_TIMEOUT_TICKS) {
        return;
    }
    cmUxTicks = 0;

    PRINTF("Credential management screen timed out\n");
    if (ctap2UxState == CTAP2_UX_STATE_CM_AUTH) {
        ctap2_client_pin_cm_auth_discard();
    } else {
        ctap2_cred_mgmt_delete_discard();
    }
    ctap2UxState = CTAP2_UX_STATE_NONE;
    send_cbor_error(&G_io_u2f, ERROR_USER_ACTION_TIMEOUT);

#ifdef HAVE_BAGL
    ux_stack_pop();
    ux_stack_push();
#endif
    ui_idle();
}
