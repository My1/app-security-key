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

#include "os.h"

// c45922b4-256a-4ce6-80a5-37bce7ab79f5 (random UUIDv4)
//
// This build is not Ledger's: it must not claim Ledger's per-device AAGUIDs, which identify
// Ledger's certified authenticators. Registrations use self attestation (no certificate), so
// relying parties cannot verify this value, they can only treat it as a label.
uint8_t const AAGUID[16] = {0xc4,
                            0x59,
                            0x22,
                            0xb4,
                            0x25,
                            0x6a,
                            0x4c,
                            0xe6,
                            0x80,
                            0xa5,
                            0x37,
                            0xbc,
                            0xe7,
                            0xab,
                            0x79,
                            0xf5};
