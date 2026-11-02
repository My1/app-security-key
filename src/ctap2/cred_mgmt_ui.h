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

#pragma once

// Asks the user to confirm the deletion of the credential prepared by a deleteCredential request,
// shown on the device (g.rp_buffer and g.username_buffer already hold what to display).
void ctap2_cred_mgmt_delete_ux(void);

// Asks the user to approve a credential management token (listing and deleting the accounts).
void ctap2_cred_mgmt_auth_ux(void);

// Called on every ticker event: a credential management screen (approval, delete) that stays
// unanswered for about 60 seconds is closed and answered with USER_ACTION_TIMEOUT, as the host
// may be gone without cancelling (closed tool, unplugged hub, ...).
void ctap2_cred_mgmt_ux_tick(void);
