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

import Zemu, {DEFAULT_START_OPTIONS, DeviceModel} from "@zondax/zemu";
// @ts-ignore
import {OasisApp} from "@zondax/ledger-oasis";

const ed25519 = require("ed25519-supercop");
const sha512 = require("js-sha512");

const Resolve = require("path").resolve;
const APP_PATH_S = Resolve("../app/output/app_s.elf");
const APP_PATH_X = Resolve("../app/output/app_x.elf");

const APP_SEED = "equip will roof matter pink blind book anxiety banner elbow sun young"

const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`
};

jest.setTimeout(60000)

export const models: DeviceModel[] = [
  {name: 'nanos', prefix: 'S', path: APP_PATH_S},
  {name: 'nanox', prefix: 'X', path: APP_PATH_X}
]

describe('Standard-Adr0008-0', function () {
  test.each(models)('can start and stop container', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
    } finally {
      await sim.close();
    }
  });

  test.each(models)('main menu', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      await sim.compareSnapshotsAndAccept(".", `${m.prefix.toLowerCase()}-adr0008-0-mainmenu`, 3);
    } finally {
      await sim.close();
    }
  });

  test.each(models)('get app version', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new OasisApp(sim.getTransport());
      const resp = await app.getVersion();

      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");
      expect(resp).toHaveProperty("test_mode");
      expect(resp).toHaveProperty("major");
      expect(resp).toHaveProperty("minor");
      expect(resp).toHaveProperty("patch");
    } finally {
      await sim.close();
    }
  });

  test.each(models)('get address', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new OasisApp(sim.getTransport());

      const path ="m/44'/474'/0'";
      const resp = await app.getAddressAndPubKey(path);

      console.log(resp)

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const expected_bech32_address = "oasis1qqjkrr643qv7yzem6g4m8rrtceh42n46usfscpcf";
      const expected_pk = "45601f761af17dba50243529e629732f1c58d08ffddaa8491238540475729d85";

      expect(resp.bech32_address).toEqual(expected_bech32_address);
      expect(resp.pk.toString('hex')).toEqual(expected_pk);

    } finally {
      await sim.close();
    }
  });

  test.each(models)('show address', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new OasisApp(sim.getTransport());

      // Derivation path. First 3 items are automatically hardened!
      const path ="m/44'/474'/0'";
      const respRequest = app.showAddressAndPubKey(path);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);

      await sim.compareSnapshotsAndAccept(".", `${m.prefix.toLowerCase()}-adr0008-0-show_address`, m.name === "nanos" ? 2 : 2);

      const resp = await respRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const expected_bech32_address = "oasis1qqjkrr643qv7yzem6g4m8rrtceh42n46usfscpcf";
      const expected_pk = "45601f761af17dba50243529e629732f1c58d08ffddaa8491238540475729d85";

      expect(resp.bech32_address).toEqual(expected_bech32_address);
      expect(resp.pk.toString('hex')).toEqual(expected_pk);
    } finally {
      await sim.close();
    }
  });

  test.each(models)('sign basic - withdraw', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new OasisApp(sim.getTransport());

      const path ="m/44'/474'/0'";
      const context = "oasis-core/consensus: tx for chain bc1c715319132305795fa86bd32e93291aaacbfb5b5955f3ba78bdba413af9e1";
      const txBlob = Buffer.from(
        "pGNmZWWiY2dhcwBmYW1vdW50QGRib2R5omRmcm9tVQAGaeylE0pICHuqRvArp3IYjeXN22ZhbW91bnRAZW5vbmNlAGZtZXRob2Rwc3Rha2luZy5XaXRoZHJhdw==",
        "base64",
      );

      const pkResponse = await app.getAddressAndPubKey(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.sign(path, context, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);

      await sim.compareSnapshotsAndAccept(".", `${m.prefix.toLowerCase()}-adr0008-0-sign_basic_withdraw`, m.name === "nanos" ? 8 : 8);

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const hasher = sha512.sha512_256.update(context)
      hasher.update(txBlob);
      const msgHash = Buffer.from(hasher.hex(), "hex")

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk);
      expect(valid).toEqual(true);
    } finally {
      await sim.close();
    }
  });


  test.each(models)('sign basic - allow', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new OasisApp(sim.getTransport());

      const path ="m/44'/474'/0'";
      const context = "oasis-core/consensus: tx for chain bc1c715319132305795fa86bd32e93291aaacbfb5b5955f3ba78bdba413af9e1";
      const txBlob = Buffer.from(
        "pGNmZWWiY2dhcwBmYW1vdW50QGRib2R5omtiZW5lZmljaWFyeVUA8PesI5mFWUkMVHwStQ6Fieb4bsFtYW1vdW50X2NoYW5nZUBlbm9uY2UBZm1ldGhvZG1zdGFraW5nLkFsbG93",
        "base64",
      );

      const pkResponse = await app.getAddressAndPubKey(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.sign(path, context, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);

      await sim.compareSnapshotsAndAccept(".", `${m.prefix.toLowerCase()}-adr0008-0-sign_basic_allow`, 8);

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const hasher = sha512.sha512_256.update(context)
      hasher.update(txBlob);
      const msgHash = Buffer.from(hasher.hex(), "hex")

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk);
      expect(valid).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  it('hash', async function () {
    const txBlob = Buffer.from(
      "pGNmZWWiY2dhcwBmYW1vdW50QGRib2R5omd4ZmVyX3RvWCBkNhaFWEyIEubmS3EVtRLTanD3U+vDV5fke4Obyq83CWt4ZmVyX3Rva2Vuc0Blbm9uY2UAZm1ldGhvZHBzdGFraW5nLlRyYW5zZmVy",
      "base64",
    );
    const context = "oasis-core/consensus: tx for chain testing";
    const hasher = sha512.sha512_256.update(context)
    hasher.update(txBlob);
    const hash = Buffer.from(hasher.hex(), "hex")
    console.log(hash.toString("hex"))
    expect(hash.toString("hex")).toEqual("86f53ebf15a09c4cd1cf7a52b8b381d74a2142996aca20690d2e750c1d262ec0")
  });

  test.each(models)('sign basic', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});

      const app = new OasisApp(sim.getTransport());

      const path ="m/44'/474'/0'";
      const context = "oasis-core/consensus: tx for chain testing";
      const txBlob = Buffer.from(
        "pGNmZWWiY2dhcwBmYW1vdW50QGRib2R5omJ0b1UAxzzAAUY0NJFbo/OXUb63wJBbRetmYW1vdW50QGVub25jZQBmbWV0aG9kcHN0YWtpbmcuVHJhbnNmZXI=",
        "base64",
      );

      const pkResponse = await app.getAddressAndPubKey(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.sign(path, context, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);

      await sim.compareSnapshotsAndAccept(".", `${m.prefix.toLowerCase()}-adr0008-0-sign_basic`, 7);

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const hasher = sha512.sha512_256.update(context)
      hasher.update(txBlob);
      const msgHash = Buffer.from(hasher.hex(), "hex")

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk);
      expect(valid).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.each(models)('submit proposal - upgrade', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new OasisApp(sim.getTransport());

      const path ="m/44'/474'/0'";
      const context = "oasis-core/consensus: tx for chain 31baebfc917e608ab5d26d8e072d70627cdef4df342b98bb61fe3683e4e4b2ac";
      const txBlob = Buffer.from(
        "pGNmZWWiY2dhcwBmYW1vdW50QGRib2R5oWd1cGdyYWRlpGF2AWVlcG9jaBv//////////mZ0YXJnZXSjcmNvbnNlbnN1c19wcm90b2NvbKJlbWlub3IMZXBhdGNoAXVydW50aW1lX2hvc3RfcHJvdG9jb2yjZW1ham9yAWVtaW5vcgJlcGF0Y2gDeBpydW50aW1lX2NvbW1pdHRlZV9wcm90b2NvbKJlbWFqb3IYKmVwYXRjaAFnaGFuZGxlcnJkZXNjcmlwdG9yLWhhbmRsZXJlbm9uY2UAZm1ldGhvZHgZZ292ZXJuYW5jZS5TdWJtaXRQcm9wb3NhbA==",
        "base64",
      );

      const pkResponse = await app.getAddressAndPubKey(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.sign(path, context, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);

      await sim.compareSnapshotsAndAccept(".", `${m.prefix.toLowerCase()}-adr0008-0-submit_proposal_upgrade`, m.name === "nanos" ? 11 : 12);

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const hasher = sha512.sha512_256.update(context)
      hasher.update(txBlob);
      const msgHash = Buffer.from(hasher.hex(), "hex")

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk);
      expect(valid).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.each(models)('submit proposal - cancel upgrade', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new OasisApp(sim.getTransport());

      const path ="m/44'/474'/0'";
      const context = "oasis-core/consensus: tx for chain 31baebfc917e608ab5d26d8e072d70627cdef4df342b98bb61fe3683e4e4b2ac";
      const txBlob = Buffer.from(
        "pGNmZWWiY2dhcwBmYW1vdW50QGRib2R5oW5jYW5jZWxfdXBncmFkZaFrcHJvcG9zYWxfaWQb//////////9lbm9uY2UBZm1ldGhvZHgZZ292ZXJuYW5jZS5TdWJtaXRQcm9wb3NhbA==",
        "base64",
      );

      const pkResponse = await app.getAddressAndPubKey(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.sign(path, context, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);

      await sim.compareSnapshotsAndAccept(".", `${m.prefix.toLowerCase()}-adr0008-0-submit_proposal_cancel_upgrade`, m.name === "nanos" ? 7 : 8);

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const hasher = sha512.sha512_256.update(context)
      hasher.update(txBlob);
      const msgHash = Buffer.from(hasher.hex(), "hex")

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk);
      expect(valid).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.each(models)('add escrow', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});

      const app = new OasisApp(sim.getTransport());

      const path ="m/44'/474'/0'";
      const context = "oasis-core/consensus: tx for chain bc1c715319132305795fa86bd32e93291aaacbfb5b5955f3ba78bdba413af9e1";
      const txBlob = Buffer.from(
          "pGNmZWWiY2dhcwBmYW1vdW50QGRib2R5omZhbW91bnRCA+hnYWNjb3VudFUAWjuJqnaIaHy9a5gyaOTU0hR4ladlbm9uY2UAZm1ldGhvZHFzdGFraW5nLkFkZEVzY3Jvdw==",
          "base64",
      );


      const pkResponse = await app.getAddressAndPubKey(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.sign(path, context, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);

      await sim.compareSnapshotsAndAccept(".", `${m.prefix.toLowerCase()}-adr0008-0-add_escrow`, m.name === "nanos" ? 8 : 8);

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const hasher = sha512.sha512_256.update(context)
      hasher.update(txBlob);
      const msgHash = Buffer.from(hasher.hex(), "hex")

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk);
      expect(valid).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.each(models)('reclaim escrow', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});

      const app = new OasisApp(sim.getTransport());

      const path ="m/44'/474'/0'";
      const context = "oasis-core/consensus: tx for chain bc1c715319132305795fa86bd32e93291aaacbfb5b5955f3ba78bdba413af9e1";
      const txBlob = Buffer.from(
          "pGNmZWWiY2dhcxkD6GZhbW91bnRAZGJvZHmiZnNoYXJlc0BnYWNjb3VudFUAcFT2Pq0X0FM7dpOkrzN8jWLiu4Blbm9uY2UBZm1ldGhvZHVzdGFraW5nLlJlY2xhaW1Fc2Nyb3c=",
          "base64",
      );


      const pkResponse = await app.getAddressAndPubKey(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.sign(path, context, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);

      await sim.compareSnapshotsAndAccept(".", `${m.prefix.toLowerCase()}-adr0008-0-reclaim_escrow`, m.name === "nanos" ? 8 : 8);

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const hasher = sha512.sha512_256.update(context)
      hasher.update(txBlob);
      const msgHash = Buffer.from(hasher.hex(), "hex")

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk);
      expect(valid).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.each(models)('transfer', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});

      const app = new OasisApp(sim.getTransport());

      const path ="m/44'/474'/0'";
      const context = "oasis-core/consensus: tx for chain bc1c715319132305795fa86bd32e93291aaacbfb5b5955f3ba78bdba413af9e1";
      const txBlob = Buffer.from(
          "pGNmZWWiY2dhcxkD6GZhbW91bnRAZGJvZHmiYnRvVQDHPMABRjQ0kVuj85dRvrfAkFtF62ZhbW91bnRAZW5vbmNlCmZtZXRob2Rwc3Rha2luZy5UcmFuc2Zlcg==",
          "base64",
      );


      const pkResponse = await app.getAddressAndPubKey(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.sign(path, context, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);

      await sim.compareSnapshotsAndAccept(".", `${m.prefix.toLowerCase()}-adr0008-0-transfer`, m.name === "nanos" ? 8 : 8);

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const hasher = sha512.sha512_256.update(context)
      hasher.update(txBlob);
      const msgHash = Buffer.from(hasher.hex(), "hex")

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk);
      expect(valid).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.each(models)('cast vote - abstain', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});

      const app = new OasisApp(sim.getTransport());

      const path ="m/44'/474'/0'";
      const context = "oasis-core/consensus: tx for chain 31baebfc917e608ab5d26d8e072d70627cdef4df342b98bb61fe3683e4e4b2ac";
      const txBlob = Buffer.from(
        "pGNmZWWiY2dhcwBmYW1vdW50QGRib2R5omJpZABkdm90ZQNlbm9uY2UBZm1ldGhvZHNnb3Zlcm5hbmNlLkNhc3RWb3Rl",
        "base64",
      );

      const pkResponse = await app.getAddressAndPubKey(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.sign(path, context, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);

      await sim.compareSnapshotsAndAccept(".", `${m.prefix.toLowerCase()}-adr0008-0-cast_vote_abstain`, m.name === "nanos" ? 7 : 8);

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const hasher = sha512.sha512_256.update(context)
      hasher.update(txBlob);
      const msgHash = Buffer.from(hasher.hex(), "hex")

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk);
      expect(valid).toEqual(true);
    } finally {
      await sim.close();
    }
  });


  test.each(models)('cast vote - yes', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new OasisApp(sim.getTransport());

      const path ="m/44'/474'/0'";
      const context = "oasis-core/consensus: tx for chain 31baebfc917e608ab5d26d8e072d70627cdef4df342b98bb61fe3683e4e4b2ac";
      const txBlob = Buffer.from(
        "pGNmZWWiY2dhcwBmYW1vdW50QGRib2R5omJpZBoAmJaAZHZvdGUBZW5vbmNlAWZtZXRob2RzZ292ZXJuYW5jZS5DYXN0Vm90ZQ==",
        "base64",
      );

      const pkResponse = await app.getAddressAndPubKey(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.sign(path, context, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);

      await sim.compareSnapshotsAndAccept(".", `${m.prefix.toLowerCase()}-adr0008-0-cast_vote_yes`, m.name === "nanos" ? 7 : 8);

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const hasher = sha512.sha512_256.update(context)
      hasher.update(txBlob);
      const msgHash = Buffer.from(hasher.hex(), "hex")

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk);
      expect(valid).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.each(models)('cast vote - no', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new OasisApp(sim.getTransport());

      const path ="m/44'/474'/0'";
      const context = "oasis-core/consensus: tx for chain 31baebfc917e608ab5d26d8e072d70627cdef4df342b98bb61fe3683e4e4b2ac";
      const txBlob = Buffer.from(
        "pGNmZWWiY2dhcwBmYW1vdW50QGRib2R5omJpZBv//////////2R2b3RlAmVub25jZQFmbWV0aG9kc2dvdmVybmFuY2UuQ2FzdFZvdGU=",
        "base64",
      );

      const pkResponse = await app.getAddressAndPubKey(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.sign(path, context, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);

      await sim.compareSnapshotsAndAccept(".", `${m.prefix.toLowerCase()}-adr0008-0-cast_vote_no`, m.name === "nanos" ? 7 : 8);

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const hasher = sha512.sha512_256.update(context)
      hasher.update(txBlob);
      const msgHash = Buffer.from(hasher.hex(), "hex")

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk);
      expect(valid).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.each(models)('sign basic - invalid', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new OasisApp(sim.getTransport());

      const path ="m/44'/474'/0'";
      const context = "oasis-core/consensus: tx for chain testing";
      let invalidMessage = Buffer.from(
        "pGNmZWWiY2dhcwBmYW1vdW50QGRib2R5omd4ZmVyX3RvWCBkNhaFWEyIEubmS3EVtRLTanD3U+vDV5fke4Obyq83CWt4ZmVyX3Rva2Vuc0Blbm9uY2UAZm1ldGhvZHBzdGFraW5nLlRyYW5zZmVy",
        "base64",
      );
      invalidMessage = Buffer.concat([invalidMessage, Buffer.from("1")]);

      const pkResponse = await app.getAddressAndPubKey(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const responseSign = await app.sign(path, context, invalidMessage);
      console.log(responseSign);

      expect(responseSign.return_code).toEqual(0x6984);
      expect(responseSign.error_message).toEqual("Data is invalid : Unexpected field");
    } finally {
      await sim.close();
    }
  });

  test.each(models)('sign amend schedule', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new OasisApp(sim.getTransport());

      const path ="m/44'/474'/0'";
      const context = "oasis-core/consensus: tx for chain testing amend";
      const txBlob = Buffer.from(
        "pGNmZWWiY2dhcxkD6GZhbW91bnRAZGJvZHmhaWFtZW5kbWVudKJlcmF0ZXOFomRyYXRlQicQZXN0YXJ0GQPoomRyYXRlQicQZXN0YXJ0GQPoomRyYXRlQicQZXN0YXJ0GQPoomRyYXRlQicQZXN0YXJ0GQPoomRyYXRlQicQZXN0YXJ0GQPoZmJvdW5kc4WjZXN0YXJ0GQPoaHJhdGVfbWF4QicQaHJhdGVfbWluQicQo2VzdGFydBkD6GhyYXRlX21heEInEGhyYXRlX21pbkInEKNlc3RhcnQZA+hocmF0ZV9tYXhCJxBocmF0ZV9taW5CJxCjZXN0YXJ0GQPoaHJhdGVfbWF4QicQaHJhdGVfbWluQicQo2VzdGFydBkD6GhyYXRlX21heEInEGhyYXRlX21pbkInEGVub25jZRkD6GZtZXRob2R4H3N0YWtpbmcuQW1lbmRDb21taXNzaW9uU2NoZWR1bGU=",
        "base64",
      );

      const pkResponse = await app.getAddressAndPubKey(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.sign(path, context, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);

      await sim.compareSnapshotsAndAccept(".", `${m.prefix.toLowerCase()}-adr0008-0-sign_amend`, m.name === "nanos" ? 29 : 30);

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const hasher = sha512.sha512_256.update(context)
      hasher.update(txBlob);
      const msgHash = Buffer.from(hasher.hex(), "hex")

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk);
      expect(valid).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.each(models)('sign entity metadata', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new OasisApp(sim.getTransport());

      const path ="m/44'/474'/0'";
      const context = "oasis-metadata-registry: entity";

      const txBlob = Buffer.from(
        "a76176016375726c7568747470733a2f2f6d792e656e746974792f75726c646e616d656e4d7920656e74697479206e616d6565656d61696c6d6d7940656e746974792e6f72676673657269616c01676b657962617365716d795f6b6579626173655f68616e646c656774776974746572716d795f747769747465725f68616e646c65",
        "hex",
      );

      const pkResponse = await app.getAddressAndPubKey(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.sign(path, context, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);

      await sim.compareSnapshotsAndAccept(".", `${m.prefix.toLowerCase()}-adr0008-0-sign_entity_metadata`, m.name === "nanos" ? 7 : 8);

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const hasher = sha512.sha512_256.update(context)
      hasher.update(txBlob);
      const msgHash = Buffer.from(hasher.hex(), "hex")

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk);
      expect(valid).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.each(models)('sign entity register', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new OasisApp(sim.getTransport());

      const path ="m/44'/474'/0'";
      const context = "oasis-core/consensus: tx for chain 265bbfc4e631486af2d846e8dfb3aa67ab379e18eb911a056e7ab38e3934a9a5";

      const txBlob = Buffer.from(
          "pGNmZWWiY2dhcxkD6GZhbW91bnRCEJJkYm9keaJpc2lnbmF0dXJlomlzaWduYXR1cmVYQOMUbqcZ88wjPfkp9/poVJJKrxD/UN7qvEQQi5O5D7IFD7ujuBsfaCkbuXtFUMIrlAbsC9RuvLPcsPQqm5jIWApqcHVibGljX2tleVgg3wNS/vFr/qqy6oAqgBzesWUMhZB7C8DnCED4T/NKy6NzdW50cnVzdGVkX3Jhd192YWx1ZVjao2F2AmJpZFgg3wNS/vFr/qqy6oAqgBzesWUMhZB7C8DnCED4T/NKy6Nlbm9kZXOFWCB45nhPM7JsZvqGq/ODtQGz93xlsv51iRbAQP+5dCy/ZVggnc1QiTMP4HFSTpiEiEtnFDRtYxKRc85PTTR8SlH1g8JYIKx4PngeJJhJb+tTC7IR/BWh5mTB+uJOLY04HFA3DwGcWCCZkWVMaW1btF+krrmppVsALHVwxbj5pu0nj6HgADbN91ggobWw+PHovNp7UxCZ0yw8lbbs5jTvV5vY3zu7yrVxVD9lbm9uY2Ub//////////9mbWV0aG9kd3JlZ2lzdHJ5LlJlZ2lzdGVyRW50aXR5",
          "base64",
      );

      const pkResponse = await app.getAddressAndPubKey(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.sign(path, context, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);

      await sim.compareSnapshotsAndAccept(".", `${m.prefix.toLowerCase()}-adr0008-0-sign_entity_register`, m.name === "nanos" ? 24 : 24);

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const hasher = sha512.sha512_256.update(context)
      hasher.update(txBlob);
      const msgHash = Buffer.from(hasher.hex(), "hex")

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk);
      expect(valid).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.each(models)('sign entity register without nodes', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new OasisApp(sim.getTransport());

      const path ="m/44'/474'/0'";
      const context = "oasis-core/consensus: tx for chain 265bbfc4e631486af2d846e8dfb3aa67ab379e18eb911a056e7ab38e3934a9a5";

      const txBlob = Buffer.from(
          "pGNmZWWiY2dhcwBmYW1vdW50QGRib2R5omlzaWduYXR1cmWiaXNpZ25hdHVyZVhACXa0AUpgRcGA0PHYSaX7p+tMiVqo6NkQH5TY9WuGz84SuZCYpzoNsijTTzCQYp5Xc6T9b2Ew9TIoz9E7JvvSBmpwdWJsaWNfa2V5WCDfA1L+8Wv+qrLqgCqAHN6xZQyFkHsLwOcIQPhP80rLo3N1bnRydXN0ZWRfcmF3X3ZhbHVlWCmiYXYCYmlkWCDfA1L+8Wv+qrLqgCqAHN6xZQyFkHsLwOcIQPhP80rLo2Vub25jZQBmbWV0aG9kd3JlZ2lzdHJ5LlJlZ2lzdGVyRW50aXR5",
          "base64",
      );

      const pkResponse = await app.getAddressAndPubKey(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.sign(path, context, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);

      await sim.compareSnapshotsAndAccept(".", `${m.prefix.toLowerCase()}-adr0008-0-sign_entity_register_no_nodes`, m.name === "nanos" ? 14 : 14);

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const hasher = sha512.sha512_256.update(context)
      hasher.update(txBlob);
      const msgHash = Buffer.from(hasher.hex(), "hex")

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk);
      expect(valid).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.each(models)('sign entity metadata - utf8', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new OasisApp(sim.getTransport());

      const path = "m/44'/474'/0'";
      const context = "oasis-metadata-registry: entity";

      const txBlob = Buffer.from(
          "A76176016375726C7568747470733A2F2F6D792E656E746974792F75726C646E616D656868C3A96CC3A86E6565656D61696C6D6D7940656E746974792E6F72676673657269616C01676B657962617365716D795F6B6579626173655F68616E646C656774776974746572716D795F747769747465725F68616E646C65",
          "hex",
      );

      const pkResponse = await app.getAddressAndPubKey(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.sign(path, context, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);

      await sim.compareSnapshotsAndAccept(".", `${m.prefix.toLowerCase()}-adr0008-0-sign_entity_metadata_utf8`, m.name === "nanos" ? 7 : 8);

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const hasher = sha512.sha512_256.update(context)
      hasher.update(txBlob);
      const msgHash = Buffer.from(hasher.hex(), "hex")

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk);
      expect(valid).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.each(models)('sign entity metadata - long url', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new OasisApp(sim.getTransport());

      const path ="m/44'/474'/0'";
      const context = "oasis-metadata-registry: entity";

      const txBlob = Buffer.from(
        "a76176016375726c783f68747470733a2f2f6d792e656e746974792f75726c2f746869732f69732f736f6d652f766572792f6c6f6e672f76616c69642f75726c2f75702f746f2f3634646e616d6578315468697320697320736f6d652076657279206c6f6e6720656e74697479206e616d65206275742076616c6964202835302965656d61696c6d6d7940656e746974792e6f72676673657269616c01676b657962617365716d795f6b6579626173655f68616e646c656774776974746572716d795f747769747465725f68616e646c65",
        "hex",
      );

      const pkResponse = await app.getAddressAndPubKey(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.sign(path, context, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);

      await sim.compareSnapshotsAndAccept(".", `${m.prefix.toLowerCase()}-adr0008-0-sign_entity_metadata_long`, m.name === "nanos" ? 9 : 8);

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const hasher = sha512.sha512_256.update(context)
      hasher.update(txBlob);
      const msgHash = Buffer.from(hasher.hex(), "hex")

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk);
      expect(valid).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.each(models)('sign entity metadata - long name', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});

      const app = new OasisApp(sim.getTransport());

      const path ="m/44'/474'/0'";
      const context = "oasis-metadata-registry: entity";

      const txBlob = Buffer.from(
        "a76176016375726c7568747470733a2f2f6d792e656e746974792f75726c646e616d6578335468697320697320736f6d6520746f6f6f6f6f6f6f6f6f6f6f6f6f6f6f206c6f6e6720656e74697479206e616d65202835312965656d61696c6d6d7940656e746974792e6f72676673657269616c01676b657962617365716d795f6b6579626173655f68616e646c656774776974746572716d795f747769747465725f68616e646c65",
        "hex",
      );

      const pkResponse = await app.getAddressAndPubKey(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.sign(path, context, txBlob);

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x6984);
      expect(resp.error_message).toEqual("Data is invalid : Invalid name length (max 50 characters)");
    } finally {
      await sim.close();
    }
  });

});

describe('Issue #68', function () {
  test.each(models)('should sign a transaction two time in a row (issue #68)', async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({...defaultOptions, model: m.name,});
      const app = new OasisApp(sim.getTransport());

      const path ="m/44'/474'/0'";
      const context = "oasis-core/consensus: tx for chain testing";
      const txBlob = Buffer.from(
        "pGNmZWWiY2dhcwBmYW1vdW50QGRib2R5omJ0b1UAxzzAAUY0NJFbo/OXUb63wJBbRetmYW1vdW50QGVub25jZQBmbWV0aG9kcHN0YWtpbmcuVHJhbnNmZXI=",
        "base64",
      );

      const pkResponse = await app.getAddressAndPubKey(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.sign(path, context, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);

      await sim.compareSnapshotsAndAccept(".", `${m.prefix.toLowerCase()}-adr0008-0-sign_basic`, 7);

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      // Need to wait a bit before signing again.
      await Zemu.delay(200);

      // Here we go again
      const signatureRequestBis = app.sign(path, context, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);

      await sim.compareSnapshotsAndAccept(".", `${m.prefix.toLowerCase()}-adr0008-0-sign_basic`, 7);

      let respBis = await signatureRequestBis;
      console.log(respBis);

      expect(respBis.return_code).toEqual(0x9000);
      expect(respBis.error_message).toEqual("No errors");

    } finally {
      await sim.close();
    }
  });
})
