/*******************************************************************************
*  (c) 2019 ZondaX GmbH
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

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#define HDPATH_0_DEFAULT     (0x80000000u | 0x2cu)
#define HDPATH_1_DEFAULT     (0x80000000u | 0x1da)
#define HDPATH_2_DEFAULT     (0x80000000u | 0u)
#define HDPATH_3_DEFAULT     (0u)
#define HDPATH_4_DEFAULT     (0u)

#define COIN_HRP            "oasis"
#define COIN_AMOUNT_DECIMAL_PLACES 9
#define COIN_RATE_DECIMAL_PLACES 5

#define MAX_RATES           10
#define MAX_CONTEXT_SIZE    64
#define MAX_ENTITY_NODES    16

#define MENU_MAIN_APP_LINE1 "Oasis"

#ifdef TESTING_ENABLED
#define MENU_MAIN_APP_LINE2 "Network"
#else
#define MENU_MAIN_APP_LINE2 "Network"
#endif

#define VIEW_ADDRESS_BUFFER_OFFSET    (PK_LEN)

#ifdef __cplusplus
}
#endif
