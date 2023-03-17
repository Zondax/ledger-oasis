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
import { blake2bFinal, blake2bInit, blake2bUpdate } from "blakejs";
import crypto from 'crypto'

const ed25519 = require("ed25519-supercop");
const sha512 = require("js-sha512");
const secp256k1 = require("secp256k1/elliptic");
const addon = require("../../tests_tools/neon/native");


const APP_SEED =
  "equip will roof matter pink blind book anxiety banner elbow sun young";

const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
};

// Derivation path. First 3 items are automatically hardened!
const path = "m/44'/474'/0'";
const secp256k1_path = "m/44'/60'/0'";

jest.setTimeout(60000);

describe("Standard-Adr0014", function () {
  test.concurrent.each(models)("get Secp256k1 address", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name });
      const app = new OasisApp(sim.getTransport());

      const resp = await app.getAddressAndPubKey_secp256k1(secp256k1_path);

      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const expected_hex_address = "95e5e3c1bdd92cd4a0c14c62480db5867946281d";
      const expected_pk =
        "021853d93524119eeb31ab0b06f1dcb068f84943bb230dfa10b1292f47af643575";

      expect(resp.hex_address).toEqual(expected_hex_address);
      expect(resp.pk.toString("hex")).toEqual(expected_pk);
    } finally {
      await sim.close();
    }
  });

  test.concurrent.each(models)("show Secp256k1 address", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name });
      const app = new OasisApp(sim.getTransport());

      const respRequest = app.showAddressAndPubKey_secp256k1(secp256k1_path);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);
      await sim.compareSnapshotsAndApprove(
        ".",
        `${m.prefix.toLowerCase()}-adr0014_show_address_secp256k1`
      );

      const resp = await respRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const expected_hex_address = "95e5e3c1bdd92cd4a0c14c62480db5867946281d";
      const expected_pk =
        "021853d93524119eeb31ab0b06f1dcb068f84943bb230dfa10b1292f47af643575";

      expect(resp.hex_address).toEqual(expected_hex_address);
      expect(resp.pk.toString("hex")).toEqual(expected_pk);
    } finally {
      await sim.close();
    }
  });

  test.concurrent.each(models)("sign ed25519 consensus - deposit", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name });
      const app = new OasisApp(sim.getTransport());

      const meta = Buffer.from(
        "ompydW50aW1lX2lkeEAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBlMmVhYTk5ZmMwMDhmODdmbWNoYWluX2NvbnRleHR4QGIxMWIzNjllMGRhNWJiMjMwYjIyMDEyN2Y1ZTdiMjQyZDM4NWVmOGM2ZjU0OTA2MjQzZjMwYWY2M2M4MTU1MzU=",
        "base64"
      );

      const txBlob = Buffer.from(
        "o2F2AWJhaaJic2mBomVub25jZQBsYWRkcmVzc19zcGVjoWlzaWduYXR1cmWhZ2VkMjU1MTlYIDXD8zVt2FNk/roDVLVFraEJ0b2zi/XWEmgX24xyz9aRY2ZlZaJmYW1vdW50gkBAcmNvbnNlbnN1c19tZXNzYWdlcwFkY2FsbKJkYm9keaJidG9VAMjQ9FnbOOXMMcp35m0sRFbcvrUCZmFtb3VudIJAQGZtZXRob2RxY29uc2Vuc3VzLkRlcG9zaXQ=",
        "base64"
      );

      const sigCtx = Buffer.from(
        "oasis-runtime-sdk/tx: v0 for chain 03e5935652dc03c4a97e07ab2383bfbcc806a6760f872c1782a7ea560f4f7738"
      );

      const pkResponse = await app.getAddressAndPubKey_ed25519(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.signRtEd25519(path, meta, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);
      await sim.compareSnapshotsAndApprove(
        ".",
        `${m.prefix.toLowerCase()}-adr0014-sign_ed25519_consensus_deposit`
      );

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const hasher = sha512.sha512_256.update(sigCtx);
      hasher.update(txBlob);
      const msgHash = Buffer.from(hasher.hex(), "hex");

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk);
      expect(valid).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.concurrent.each(models)("sign ed25519 accounts - transfer", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name });
      const app = new OasisApp(sim.getTransport());

      const meta = Buffer.from(
        "o2dvcmlnX3RveCowWERDRTA3NUUxQzM5QjFBRTBCNzVENTU0NTU4QjY0NTFBMjI2RkZFMDBqcnVudGltZV9pZHhAMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwNzJjODIxNWU2MGQ1YmNhN21jaGFpbl9jb250ZXh0eEA1MDMwNGY5OGRkYjY1NjYyMGVhODE3Y2MxNDQ2YzQwMTc1MmEwNWEyNDliMzZjOWI5MGRiYTQ2MTY4Mjk5Nzdh",
        "base64"
      );

      const txBlob = Buffer.from(
        "o2F2AWJhaaJic2mBomVub25jZQBsYWRkcmVzc19zcGVjoWlzaWduYXR1cmWhZ2VkMjU1MTlYIDXD8zVt2FNk/roDVLVFraEJ0b2zi/XWEmgX24xyz9aRY2ZlZaJjZ2FzGQ+gZmFtb3VudIJEB1vNFUNGT09kY2FsbKJkYm9keaJidG9VAO1D91JQJv1Tegv1JEiLfFSfA5glZmFtb3VudIJARFdCVENmbWV0aG9kcWFjY291bnRzLlRyYW5zZmVy",
        "base64"
      );

      const sigCtx = Buffer.from(
        "oasis-runtime-sdk/tx: v0 for chain 7f1eb9fa832a02ccda132d330f342dbef92c0817bf73eeea12020552f1d62f86"
      );

      const pkResponse = await app.getAddressAndPubKey_ed25519(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.signRtEd25519(path, meta, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);
      await sim.compareSnapshotsAndApprove(
        ".",
        `${m.prefix.toLowerCase()}-adr0014-sign_ed25519_accounts_transfer`
      );

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const hasher = sha512.sha512_256.update(sigCtx);
      hasher.update(txBlob);
      const msgHash = Buffer.from(hasher.hex(), "hex");

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk);
      expect(valid).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.concurrent.each(models)("sign ed25519 consensus - withdraw", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name });
      const app = new OasisApp(sim.getTransport());

      const meta = Buffer.from(
        "ompydW50aW1lX2lkeEAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBlMmVhYTk5ZmMwMDhmODdmbWNoYWluX2NvbnRleHR4QGIxMWIzNjllMGRhNWJiMjMwYjIyMDEyN2Y1ZTdiMjQyZDM4NWVmOGM2ZjU0OTA2MjQzZjMwYWY2M2M4MTU1MzU=",
        "base64"
      );

      const txBlob = Buffer.from(
        "o2F2AWJhaaJic2mBomVub25jZQBsYWRkcmVzc19zcGVjoWlzaWduYXR1cmWhZ2VkMjU1MTlYIDXD8zVt2FNk/roDVLVFraEJ0b2zi/XWEmgX24xyz9aRY2ZlZaJmYW1vdW50gkBAcmNvbnNlbnN1c19tZXNzYWdlcwFkY2FsbKJkYm9keaFmYW1vdW50gkID6ERXQlRDZm1ldGhvZHJjb25zZW5zdXMuV2l0aGRyYXc=",
        "base64"
      );

      const sigCtx = Buffer.from(
        "oasis-runtime-sdk/tx: v0 for chain 03e5935652dc03c4a97e07ab2383bfbcc806a6760f872c1782a7ea560f4f7738"
      );

      const pkResponse = await app.getAddressAndPubKey_ed25519(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.signRtEd25519(path, meta, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);
      await sim.compareSnapshotsAndApprove(
        ".",
        `${m.prefix.toLowerCase()}-adr0014-sign_ed25519_consensus_withdraw`
      );

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const hasher = sha512.sha512_256.update(sigCtx);
      hasher.update(txBlob);
      const msgHash = Buffer.from(hasher.hex(), "hex");

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk);
      expect(valid).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.concurrent.each(models)("sign secp256k1 accounts - transfer", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name });
      const app = new OasisApp(sim.getTransport());

      const meta = Buffer.from(
        "o2dvcmlnX3RveCg3MDlFRWJkOTc5MzI4QTJCMzYwNUExNjA5MTVERUIyNkUxODZhYkY4anJ1bnRpbWVfaWR4QDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDcyYzgyMTVlNjBkNWJjYTdtY2hhaW5fY29udGV4dHhANTAzMDRmOThkZGI2NTY2MjBlYTgxN2NjMTQ0NmM0MDE3NTJhMDVhMjQ5YjM2YzliOTBkYmE0NjE2ODI5OTc3YQ==",
        "base64"
      );

      const txBlob = Buffer.from(
        "o2F2AWJhaaJic2mBomVub25jZQFsYWRkcmVzc19zcGVjoWlzaWduYXR1cmWhbHNlY3AyNTZrMWV0aFghAwF6GNjbybMzhi3XRj5R1oTiMMkO1nAwB7NZAlH1X4BEY2ZlZaJjZ2FzGQ+gZmFtb3VudIJEB1vNFUNGT09kY2FsbKJkYm9keaJidG9VADDXgI3ukLc0acA65kYHwNVuBE4rZmFtb3VudIJARFdCVENmbWV0aG9kcWFjY291bnRzLlRyYW5zZmVy",
        "base64"
      );

      const sigCtx = Buffer.from(
        "oasis-runtime-sdk/tx: v0 for chain 7f1eb9fa832a02ccda132d330f342dbef92c0817bf73eeea12020552f1d62f86"
      );

      const pkResponse = await app.getAddressAndPubKey_secp256k1(
        secp256k1_path
      );
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.signRtSecp256k1(
        secp256k1_path,
        meta,
        txBlob
      );

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);
      await sim.compareSnapshotsAndApprove(
        ".",
        `${m.prefix.toLowerCase()}-adr0014-sign_secp256k1_accounts_transfer`
      );

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const hasher = sha512.sha512_256.update(sigCtx);
      hasher.update(txBlob);
      const msgHash = Buffer.from(hasher.hex(), "hex");

      const signatureRS = Uint8Array.from(resp.signature).slice(0, -1);

      const signatureOk = secp256k1.ecdsaVerify(
        signatureRS,
        msgHash,
        pkResponse.pk
      );
      expect(signatureOk).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.concurrent.each(models)("sign secp256k1 consensus - withdraw", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name });
      const app = new OasisApp(sim.getTransport());

      const meta = Buffer.from(
        "ompydW50aW1lX2lkeEAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBhNmQxZTNlYmY2MGRmZjZjbWNoYWluX2NvbnRleHR4QDUwMzA0Zjk4ZGRiNjU2NjIwZWE4MTdjYzE0NDZjNDAxNzUyYTA1YTI0OWIzNmM5YjkwZGJhNDYxNjgyOTk3N2E=",
        "base64"
      );

      const txBlob = Buffer.from(
        "o2F2AWJhaaJic2mBomVub25jZRv//////////2xhZGRyZXNzX3NwZWOhaXNpZ25hdHVyZaFsc2VjcDI1NmsxZXRoWCEDAXoY2NvJszOGLddGPlHWhOIwyQ7WcDAHs1kCUfVfgERjZmVlomZhbW91bnSCQEByY29uc2Vuc3VzX21lc3NhZ2VzAWRjYWxsomRib2R5omJ0b1UA84957B5s/pe0/gbHiYtSqPrbR4NmYW1vdW50gkgBY0V4XYoAAERXQlRDZm1ldGhvZHJjb25zZW5zdXMuV2l0aGRyYXc=",
        "base64"
      );

      const sigCtx = Buffer.from(
        "oasis-runtime-sdk/tx: v0 for chain 899658d606b299101f96238fac38a575a7024415b94e0d97ad0fe63f36d362bc"
      );

      const pkResponse = await app.getAddressAndPubKey_secp256k1(
        secp256k1_path
      );
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.signRtSecp256k1(
        secp256k1_path,
        meta,
        txBlob
      );

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);
      await sim.compareSnapshotsAndApprove(
        ".",
        `${m.prefix.toLowerCase()}-adr0014-sign_secp256k1_consensus_withdraw`
      );

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const hasher = sha512.sha512_256.update(sigCtx);
      hasher.update(txBlob);
      const msgHash = Buffer.from(hasher.hex(), "hex");

      const signatureRS = Uint8Array.from(resp.signature).slice(0, -1);

      const signatureOk = secp256k1.ecdsaVerify(
        signatureRS,
        msgHash,
        pkResponse.pk
      );
      expect(signatureOk).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.concurrent.each(models)("sign ed25519 contracts - call", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name });
      const app = new OasisApp(sim.getTransport());
      // Change to expert mode so we can skip fields
      await sim.clickRight();
      await sim.clickBoth();
      await sim.clickLeft();

      const meta = Buffer.from(
        "ompydW50aW1lX2lkeEAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBlMmVhYTk5ZmMwMDhmODdmbWNoYWluX2NvbnRleHR4QGIxMWIzNjllMGRhNWJiMjMwYjIyMDEyN2Y1ZTdiMjQyZDM4NWVmOGM2ZjU0OTA2MjQzZjMwYWY2M2M4MTU1MzU=",
        "base64"
      );

      const txBlob = Buffer.from(
        "o2F2AWJhaaJic2mBomVub25jZQBsYWRkcmVzc19zcGVjoWlzaWduYXR1cmWhZ2VkMjU1MTlYIDXD8zVt2FNk/roDVLVFraEJ0b2zi/XWEmgX24xyz9aRY2ZlZaFmYW1vdW50gkBAZGNhbGyiZGJvZHmjYmlkAGRkYXRhQaBmdG9rZW5zg4JEO5rKAECCQgfQRFdCVEOCQy3GwERXRVRIZm1ldGhvZG5jb250cmFjdHMuQ2FsbA==",
        "base64"
      );

      const sigCtx = Buffer.from(
        "oasis-runtime-sdk/tx: v0 for chain 03e5935652dc03c4a97e07ab2383bfbcc806a6760f872c1782a7ea560f4f7738"
      );

      const pkResponse = await app.getAddressAndPubKey_ed25519(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.signRtEd25519(path, meta, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);
      await sim.compareSnapshotsAndApprove(
        ".",
        `${m.prefix.toLowerCase()}-adr0014-sign_ed25519_contracts_call`
      );

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const hasher = sha512.sha512_256.update(sigCtx);
      hasher.update(txBlob);
      const msgHash = Buffer.from(hasher.hex(), "hex");

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk);
      expect(valid).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.concurrent.each(models)("sign ed25519 contracts - upgrade", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name });
      const app = new OasisApp(sim.getTransport());

      // Change to expert mode so we can skip fields
      await sim.clickRight();
      await sim.clickBoth();
      await sim.clickLeft();

      const meta = Buffer.from(
        "ompydW50aW1lX2lkeEAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBlMmVhYTk5ZmMwMDhmODdmbWNoYWluX2NvbnRleHR4QGIxMWIzNjllMGRhNWJiMjMwYjIyMDEyN2Y1ZTdiMjQyZDM4NWVmOGM2ZjU0OTA2MjQzZjMwYWY2M2M4MTU1MzU=",
        "base64"
      );

      const txBlob = Buffer.from(
        "o2F2AWJhaaJic2mBomVub25jZQBsYWRkcmVzc19zcGVjoWlzaWduYXR1cmWhZ2VkMjU1MTlYIDXD8zVt2FNk/roDVLVFraEJ0b2zi/XWEmgX24xyz9aRY2ZlZaFmYW1vdW50gkBAZGNhbGyiZGJvZHmkYmlkAGRkYXRhWCCha2luc3RhbnRpYXRloW9pbml0aWFsX2NvdW50ZXIYKmZ0b2tlbnODgkQ7msoAQIJCB9BEV0JUQ4JDLcbARFdFVEhnY29kZV9pZABmbWV0aG9kcWNvbnRyYWN0cy5VcGdyYWRl",
        "base64"
      );

      const sigCtx = Buffer.from(
        "oasis-runtime-sdk/tx: v0 for chain 03e5935652dc03c4a97e07ab2383bfbcc806a6760f872c1782a7ea560f4f7738"
      );

      const pkResponse = await app.getAddressAndPubKey_ed25519(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.signRtEd25519(path, meta, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);
      await sim.compareSnapshotsAndApprove(
        ".",
        `${m.prefix.toLowerCase()}-adr0014-sign_ed25519_contracts_upgrade`
      );

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const hasher = sha512.sha512_256.update(sigCtx);
      hasher.update(txBlob);
      const msgHash = Buffer.from(hasher.hex(), "hex");

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk);
      expect(valid).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.concurrent.each(models)("sign ed25519 contracts - instantiate", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name });
      const app = new OasisApp(sim.getTransport());
      // Change to expert mode so we can skip fields
      await sim.clickRight();
      await sim.clickBoth();
      await sim.clickLeft();

      const meta = Buffer.from(
        "ompydW50aW1lX2lkeEAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBlMmVhYTk5ZmMwMDhmODdmbWNoYWluX2NvbnRleHR4QGIxMWIzNjllMGRhNWJiMjMwYjIyMDEyN2Y1ZTdiMjQyZDM4NWVmOGM2ZjU0OTA2MjQzZjMwYWY2M2M4MTU1MzU=",
        "base64"
      );

      const txBlob = Buffer.from(
        "o2F2AWJhaaJic2mBomVub25jZQBsYWRkcmVzc19zcGVjoWlzaWduYXR1cmWhZ2VkMjU1MTlYIDXD8zVt2FNk/roDVLVFraEJ0b2zi/XWEmgX24xyz9aRY2ZlZaFmYW1vdW50gkBAZGNhbGyiZGJvZHmkZGRhdGFToWlzYXlfaGVsbG+hY3dob2JtZWZ0b2tlbnODgkQ7msoAQIJCB9BEV0JUQ4JDLcbARFdFVEhnY29kZV9pZABvdXBncmFkZXNfcG9saWN5oWhldmVyeW9uZaBmbWV0aG9kdWNvbnRyYWN0cy5JbnN0YW50aWF0ZQ==",
        "base64"
      );

      const sigCtx = Buffer.from(
        "oasis-runtime-sdk/tx: v0 for chain 03e5935652dc03c4a97e07ab2383bfbcc806a6760f872c1782a7ea560f4f7738"
      );

      const pkResponse = await app.getAddressAndPubKey_ed25519(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.signRtEd25519(path, meta, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);
      await sim.compareSnapshotsAndApprove(
        ".",
        `${m.prefix.toLowerCase()}-adr0014-sign_ed25519_contracts_instantiate`
      );

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const hasher = sha512.sha512_256.update(sigCtx);
      hasher.update(txBlob);
      const msgHash = Buffer.from(hasher.hex(), "hex");

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk);
      expect(valid).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.concurrent.each(models)("sign ed25519 runtime - encrypted", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name });
      const app = new OasisApp(sim.getTransport());

      // Change to expert mode so we can skip fields
      await sim.clickRight();
      await sim.clickBoth();
      await sim.clickLeft();

      const meta = Buffer.from(
        "ompydW50aW1lX2lkeEAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBlMmVhYTk5ZmMwMDhmODdmbWNoYWluX2NvbnRleHR4QGIxMWIzNjllMGRhNWJiMjMwYjIyMDEyN2Y1ZTdiMjQyZDM4NWVmOGM2ZjU0OTA2MjQzZjMwYWY2M2M4MTU1MzU=",
        "base64"
      );

      const txBlob = Buffer.from(
        "o2F2AWJhaaJic2mBomVub25jZQBsYWRkcmVzc19zcGVjoWlzaWduYXR1cmWhZ2VkMjU1MTlYIDXD8zVt2FNk/roDVLVFraEJ0b2zi/XWEmgX24xyz9aRY2ZlZaFmYW1vdW50gkBAZGNhbGyiZGJvZHmjYnBrWCBzb21lcHVibGlja2V5MTIzc29tZXB1YmxpY2tleTEyM2RkYXRhWGyiZGJvZHmjYnBrWCDmZ1CN4J/Y25fyLn3uNAMB7Irbh4kLWjEgVBPy6+R9FGRkYXRhWBu//CmsZl8IPaB9fHJmTdJHpoeEL2k5YPM+SCRlbm9uY2VP2vmpbD1OFFuXYCigkTchZmZvcm1hdAFlbm9uY2VPc29tZXJhbmRvbW5vbmNlZmZvcm1hdAE=",
        "base64"
      );

      const sigCtx = Buffer.from(
        "oasis-runtime-sdk/tx: v0 for chain 03e5935652dc03c4a97e07ab2383bfbcc806a6760f872c1782a7ea560f4f7738"
      );

      const pkResponse = await app.getAddressAndPubKey_ed25519(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.signRtEd25519(path, meta, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);
      await sim.compareSnapshotsAndApprove(
        ".",
        `${m.prefix.toLowerCase()}-adr0014-sign_ed25519_runtime_encrypted`
      );

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const hasher = sha512.sha512_256.update(sigCtx);
      hasher.update(txBlob);
      const msgHash = Buffer.from(hasher.hex(), "hex");

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk);
      expect(valid).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.concurrent.each(models)("sign ed25519 runtime - evm", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name });
      const app = new OasisApp(sim.getTransport());

      // Change to expert mode so we can skip fields
      await sim.clickRight();
      await sim.clickBoth();
      await sim.clickLeft();

      const meta = Buffer.from(
        "ompydW50aW1lX2lkeEAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBhNmQxZTNlYmY2MGRmZjZjbWNoYWluX2NvbnRleHR4QDUwMzA0Zjk4ZGRiNjU2NjIwZWE4MTdjYzE0NDZjNDAxNzUyYTA1YTI0OWIzNmM5YjkwZGJhNDYxNjgyOTk3N2E=",
        "base64"
      );

      const txBlob = Buffer.from(
        "o2F2AWJhaaJic2mBomVub25jZRv//////////2xhZGRyZXNzX3NwZWOhaXNpZ25hdHVyZaFnc3IyNTUxOVggljm9ZwdAldhlyWM2B4C+3gQZis+ceaxnt6QA4rOcP0ljZmVlomNnYXMZD6BmYW1vdW50gkQHW80VQ0ZPT2RjYWxsomRib2R5o2RkYXRhWESpBZy7AAAAAAAAAAAAAAAAkK3jtwZfpxXHoVAxOHffHTPnd9UAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2V2YWx1ZVggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABnYWRkcmVzc1QhxxjCLVLQ86eJt1LUwv1ZCKinM2ZtZXRob2RoZXZtLkNhbGw=",
        "base64"
      );

      const sigCtx = Buffer.from(
        "oasis-runtime-sdk/tx: v0 for chain 899658d606b299101f96238fac38a575a7024415b94e0d97ad0fe63f36d362bc"
      );

      const pkResponse = await app.getAddressAndPubKey_ed25519(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.signRtEd25519(path, meta, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);
      await sim.compareSnapshotsAndApprove(
        ".",
        `${m.prefix.toLowerCase()}-adr0014-sign_ed25519_runtime_evm`
      );

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const hasher = sha512.sha512_256.update(sigCtx);
      hasher.update(txBlob);
      const msgHash = Buffer.from(hasher.hex(), "hex");

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk);
      expect(valid).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.concurrent.each(models)("get Sr25519 address", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name });
      const app = new OasisApp(sim.getTransport());

      const resp = await app.getAddressAndPubKey_sr25519(path);

      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const expected_bech32_address =
        "oasis1qqajq8zd0srsqufm5x2qayurm45uxvuaxcc32zvt";
      const expected_pk =
        "d424ac290ba31640775fef1c87ffae982efeb8d2ffe2c4b33d625f6c01f1946d";

      expect(resp.bech32_address).toEqual(expected_bech32_address);
      expect(resp.pk.toString("hex")).toEqual(expected_pk);
    } finally {
      await sim.close();
    }
  });

  test.concurrent.each(models)("show Sr25519 address", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name });
      const app = new OasisApp(sim.getTransport());

      const respRequest = app.showAddressAndPubKey_sr25519(path);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);
      await sim.compareSnapshotsAndApprove(
        ".",
        `${m.prefix.toLowerCase()}-adr0014_show_address_sr25519`
      );

      const resp = await respRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

      const expected_bech32_address =
        "oasis1qqajq8zd0srsqufm5x2qayurm45uxvuaxcc32zvt";
      const expected_pk =
        "d424ac290ba31640775fef1c87ffae982efeb8d2ffe2c4b33d625f6c01f1946d";

      expect(resp.bech32_address).toEqual(expected_bech32_address);
      expect(resp.pk.toString("hex")).toEqual(expected_pk);
    } finally {
      await sim.close();
    }
  });

  test.concurrent.each(models)("sign sr25519 consensus - withdraw", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name });
      const app = new OasisApp(sim.getTransport());

      // Change to expert mode so we can skip fields
      await sim.clickRight();
      await sim.clickBoth();
      await sim.clickLeft();

      const meta = Buffer.from(
        "ompydW50aW1lX2lkeEAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBhNmQxZTNlYmY2MGRmZjZjbWNoYWluX2NvbnRleHR4QDUwMzA0Zjk4ZGRiNjU2NjIwZWE4MTdjYzE0NDZjNDAxNzUyYTA1YTI0OWIzNmM5YjkwZGJhNDYxNjgyOTk3N2E=",
        "base64"
      );

      const txBlob = Buffer.from(
        "o2F2AWJhaaJic2mBomVub25jZQBsYWRkcmVzc19zcGVjoWlzaWduYXR1cmWhZ3NyMjU1MTlYIJY5vWcHQJXYZcljNgeAvt4EGYrPnHmsZ7ekAOKznD9JY2ZlZaNjZ2FzGQfQZmFtb3VudIJAQHJjb25zZW5zdXNfbWVzc2FnZXMBZGNhbGyiZGJvZHmiYnRvVQDzj3nsHmz+l7T+BseJi1Ko+ttHg2ZhbW91bnSCQgPoQGZtZXRob2RyY29uc2Vuc3VzLldpdGhkcmF3",
        "base64"
      );

      const sigCtx = Buffer.from(
        "oasis-runtime-sdk/tx: v0 for chain 899658d606b299101f96238fac38a575a7024415b94e0d97ad0fe63f36d362bc"
      );

      const pkResponse = await app.getAddressAndPubKey_sr25519(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.signRtSr25519(path, meta, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);
      await sim.compareSnapshotsAndApprove(
        ".",
        `${m.prefix.toLowerCase()}-adr0014-sign_sr25519_consensus_withdraw`
      );

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

    const hash = crypto.createHash('sha256')
    const prehash = hash.update(txBlob).digest()

      // Now verify the signature
      const valid = addon.schnorrkel_verify(
        pkResponse.pk,
        sigCtx,
        prehash,
        resp.signature
      );
      expect(valid).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.concurrent.each(models)("sign sr25519 runtime - evm", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name });
      const app = new OasisApp(sim.getTransport());

      // Change to expert mode so we can skip fields
      await sim.clickRight();
      await sim.clickBoth();
      await sim.clickLeft();

      const meta = Buffer.from(
        "ompydW50aW1lX2lkeEAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBhNmQxZTNlYmY2MGRmZjZjbWNoYWluX2NvbnRleHR4QDUwMzA0Zjk4ZGRiNjU2NjIwZWE4MTdjYzE0NDZjNDAxNzUyYTA1YTI0OWIzNmM5YjkwZGJhNDYxNjgyOTk3N2E=",
        "base64"
      );

      const txBlob = Buffer.from(
        "o2F2AWJhaaJic2mBomVub25jZRv//////////2xhZGRyZXNzX3NwZWOhaXNpZ25hdHVyZaFnc3IyNTUxOVggljm9ZwdAldhlyWM2B4C+3gQZis+ceaxnt6QA4rOcP0ljZmVlomNnYXMZD6BmYW1vdW50gkQHW80VQ0ZPT2RjYWxsomRib2R5o2RkYXRhWESpBZy7AAAAAAAAAAAAAAAAkK3jtwZfpxXHoVAxOHffHTPnd9UAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2V2YWx1ZVggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABnYWRkcmVzc1QhxxjCLVLQ86eJt1LUwv1ZCKinM2ZtZXRob2RoZXZtLkNhbGw=",
        "base64"
      );

      const sigCtx = Buffer.from(
        "oasis-runtime-sdk/tx: v0 for chain 899658d606b299101f96238fac38a575a7024415b94e0d97ad0fe63f36d362bc"
      );

      const pkResponse = await app.getAddressAndPubKey_sr25519(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.signRtSr25519(path, meta, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);
      await sim.compareSnapshotsAndApprove(
        ".",
        `${m.prefix.toLowerCase()}-adr0014-sign_sr25519_runtime_evm`
      );

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");

    const hash = crypto.createHash('sha256')
    const prehash = hash.update(txBlob).digest()

      // Now verify the signature
      const valid = addon.schnorrkel_verify(
        pkResponse.pk,
        sigCtx,
        prehash,
        resp.signature
      );
      expect(valid).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.concurrent.each(models)("sign sr25519 runtime - encrypted", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name });
      const app = new OasisApp(sim.getTransport());

      // Change to expert mode so we can skip fields
      await sim.clickRight();
      await sim.clickBoth();
      await sim.clickLeft();

      const meta = Buffer.from(
        "ompydW50aW1lX2lkeEAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBlMmVhYTk5ZmMwMDhmODdmbWNoYWluX2NvbnRleHR4QGIxMWIzNjllMGRhNWJiMjMwYjIyMDEyN2Y1ZTdiMjQyZDM4NWVmOGM2ZjU0OTA2MjQzZjMwYWY2M2M4MTU1MzU=",
        "base64"
      );

      const txBlob = Buffer.from(
        "o2F2AWJhaaJic2mBomVub25jZQBsYWRkcmVzc19zcGVjoWlzaWduYXR1cmWhZ2VkMjU1MTlYIDXD8zVt2FNk/roDVLVFraEJ0b2zi/XWEmgX24xyz9aRY2ZlZaFmYW1vdW50gkBAZGNhbGyiZGJvZHmjYnBrWCBzb21lcHVibGlja2V5MTIzc29tZXB1YmxpY2tleTEyM2RkYXRhWGyiZGJvZHmjYnBrWCDmZ1CN4J/Y25fyLn3uNAMB7Irbh4kLWjEgVBPy6+R9FGRkYXRhWBu//CmsZl8IPaB9fHJmTdJHpoeEL2k5YPM+SCRlbm9uY2VP2vmpbD1OFFuXYCigkTchZmZvcm1hdAFlbm9uY2VPc29tZXJhbmRvbW5vbmNlZmZvcm1hdAE=",
        "base64"
      );

      const sigCtx = Buffer.from(
        "oasis-runtime-sdk/tx: v0 for chain 03e5935652dc03c4a97e07ab2383bfbcc806a6760f872c1782a7ea560f4f7738"
      );

      const pkResponse = await app.getAddressAndPubKey_sr25519(path);
      console.log(pkResponse);
      expect(pkResponse.return_code).toEqual(0x9000);
      expect(pkResponse.error_message).toEqual("No errors");

      // do not wait here..
      const signatureRequest = app.signRtSr25519(path, meta, txBlob);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);
      await sim.compareSnapshotsAndApprove(
        ".",
        `${m.prefix.toLowerCase()}-adr0014-sign_sr25519_runtime_encrypted`
      );

      let resp = await signatureRequest;
      console.log(resp);

      expect(resp.return_code).toEqual(0x9000);
      expect(resp.error_message).toEqual("No errors");
      
      const hash = crypto.createHash('sha256')
      const prehash = hash.update(txBlob).digest()

      // Now verify the signature
      const valid = addon.schnorrkel_verify(
        pkResponse.pk,
        sigCtx,
        prehash,
        resp.signature
      );
      expect(valid).toEqual(true);
    } finally {
      await sim.close();
    }
  });
});
