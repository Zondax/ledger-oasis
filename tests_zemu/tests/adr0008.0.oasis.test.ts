/** ******************************************************************************
 *  (c) 2020 Zondax GmbH
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
 ******************************************************************************* */

import Zemu, { DEFAULT_START_OPTIONS } from "@zondax/zemu";
// @ts-ignore
import { OasisApp } from "@zondax/ledger-oasis";
import { models } from "./common";

const APP_SEED =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
};

jest.setTimeout(100000);

describe("Standard-Adr0008-0-Oasis", function () {
  test.concurrent.each(models)("get address", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name });
      const app = new OasisApp(sim.getTransport());

      const path = "m/44'/474'/0'";
      const resp = await app.getAddressAndPubKey_ed25519(path);

      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const expected_bech32_address =
        "oasis1qqx0wgxjwlw3jwatuwqj6582hdm9rjs4pcnvzz66";
      const expected_pk =
        "ad55bbb7c192b8ecfeb6ad18bbd7681c0923f472d5b0c212fbde33008005ad61";

      expect(resp.bech32_address).toEqual(expected_bech32_address);
      expect(resp.pk.toString("hex")).toEqual(expected_pk);
    } finally {
      await sim.close();
    }
  });
});
