/*******************************************************************************
*   (c) 2018 ZondaX GmbH
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

#if defined(APP_VALIDATOR)

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>
#include <stddef.h>

#define TYPE_PREVOTE        0x01
#define TYPE_PRECOMMIT      0x02
#define TYPE_PROPOSAL       0x20

typedef struct {
    uint8_t Type;
    int64_t Height;
    int8_t Round;
} vote_t;

typedef struct {
  int8_t isInitialized;
  vote_t vote;
} vote_state_t;

typedef struct {
    const uint8_t *votePtr;
    uint16_t voteLen;
    uint8_t type;
    uint64_t height;
    uint64_t round;
} oasis_tx_vote_t;

extern vote_state_t vote_state;
extern vote_t vote;


/// Clears the vote buffer
void vote_state_reset();

#ifdef __cplusplus
}
#endif

#else
typedef struct{} oasis_tx_vote_t;

#endif //APP_VALIDATOR