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
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "coin.h"
#include "zxerror.h"

extern uint16_t action_addrResponseLen;

// Reject every incoming APDU while a user review is on screen. The flag is
// raised after a handler enters an async review (view_review_show +
// IO_ASYNCH_REPLY) and cleared by each terminal callback below. Without this
// gate the BLE transport accepts a new APDU during the review window and
// rewrites tx_get_buffer() / hdPath under the approval callback.
extern volatile bool g_review_pending;

static inline bool review_is_pending(void) { return g_review_pending; }
static inline void review_mark_pending(void) { g_review_pending = true; }
static inline void review_clear_pending(void) { g_review_pending = false; }

void app_sign_ed25519();
void app_sign_secp256k1();
void app_sign_sr25519();
void app_sign_eth();
zxerr_t app_fill_address(address_kind_e kind);

void app_reject();

void app_reply_address();

void app_reply_error();
