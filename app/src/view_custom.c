/*******************************************************************************
*   (c) 2018, 2019 Zondax GmbH
*   (c) 2016 Ledger
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

#include "view.h"
#include "coin.h"
#include "crypto.h"
#include "view_internal.h"
#include <os_io_seproxyhal.h>
#include <ux.h>
#include <zxformat.h>

#include <string.h>
#include <stdio.h>

#if defined(APP_VALIDATOR)
#if defined(TARGET_NANOS)

#include "bagl.h"
#include "zxmacros.h"
#include "view_templates.h"
#include "vote.h"

char view_status_line1[20];
char view_status_line2[20];
char view_status_line3[20];
char view_status_tmp[20];

static const bagl_element_t view_status[] = {
        UI_FillRectangle(0, 0, 0, UI_SCREEN_WIDTH, UI_SCREEN_HEIGHT, UI_BLACK, UI_WHITE),
        // Type
        // "Height:Round"
        // "PK"      [PK]
        UI_LabelLine(1, 0, 8, UI_SCREEN_WIDTH, UI_11PX, UI_WHITE, UI_BLACK, (const char *) view_status_line1),
        UI_LabelLine(1, 0, 19, UI_SCREEN_WIDTH, UI_11PX, UI_WHITE, UI_BLACK, (const char *) view_status_line2),
        UI_LabelLine(1, 0, 30, UI_SCREEN_WIDTH, UI_11PX, UI_WHITE, UI_BLACK, (const char *) view_status_line3),
};

static unsigned int view_status_button(
        unsigned int button_mask,
        unsigned int button_mask_counter) {
    // Ignore buttons
    return 0;
}

void view_status_show() {
    switch(vote_state.vote.Type) {
        case TYPE_PREVOTE:
            snprintf(view_status_line1, sizeof(view_status_line1), "OASIS: Prevote");
            break;
        case TYPE_PRECOMMIT:
            snprintf(view_status_line1, sizeof(view_status_line1), "OASIS: Precommit");
            break;
        case TYPE_PROPOSAL:
            snprintf(view_status_line1, sizeof(view_status_line1), "OASIS: Proposal");
            break;
        default:
            snprintf(view_status_line1, sizeof(view_status_line1), "ERROR ??");
            break;
    }

    // Format height
    int64_to_str((char *) view_status_tmp, sizeof(view_status_line2), vote_state.vote.Height);
    snprintf(view_status_line2, sizeof(view_status_line2), "H: %s", view_status_tmp);

    // Format Round
    int64_to_str((char *) view_status_tmp, sizeof(view_status_line2), vote_state.vote.Round);
    snprintf(view_status_line3, sizeof(view_status_line3), "R: %s", view_status_tmp);

    // Show
    UX_DISPLAY(view_status, NULL);
}


void view_sign_show() {}

#endif
#endif
