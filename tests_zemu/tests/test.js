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

import jest, {expect} from "jest";
import Zemu from "@zondax/zemu";
import {OasisApp} from "@zondax/ledger-oasis";

const ed25519 = require("ed25519-supercop");
const sha512 = require("js-sha512");

const Resolve = require("path").resolve;
const APP_PATH = Resolve("../app/bin/app.elf");

const APP_SEED = "equip will roof matter pink blind book anxiety banner elbow sun young"
const sim_options = {
    press_delay: 300,
    logging: true,
    start_delay: 1000,
    custom: `-s "${APP_SEED}"`
    //, X11: true
};

jest.setTimeout(80000)

describe('Standard', function () {
    it('can start and stop container', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
        } finally {
            await sim.close();
        }
    });

    it('sign basic - withdraw', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new OasisApp(sim.getTransport());

            const path = [44, 474, 5, 0x80000000, 0x80000003];
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

            await sim.compareSnapshotsAndAccept(".", "sign_basic_withdraw", 9);

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


    it('sign basic - allow', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new OasisApp(sim.getTransport());

            const path = [44, 474, 5, 0x80000000, 0x80000003];
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

            await sim.compareSnapshotsAndAccept(".", "sign_basic_allow", 9);

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

    it('app version', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
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

    it('get address', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new OasisApp(sim.getTransport());

            const path = [44, 474, 5, 0x80000000, 0x80000003];
            const resp = await app.getAddressAndPubKey(path);

            console.log(resp)

            expect(resp.return_code).toEqual(0x9000);
            expect(resp.error_message).toEqual("No errors");

            const expected_bech32_address = "oasis1qphdkldpttpsj2j3l9sde9h26cwpfwqwwuhvruyu";
            const expected_pk = "aba52c0dcb80c2fe96ed4c3741af40c573a0500c0d73acda22795c37cb0f1739";

            expect(resp.bech32_address).toEqual(expected_bech32_address);
            expect(resp.pk.toString('hex')).toEqual(expected_pk);

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

    it('show address', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new OasisApp(sim.getTransport());

            // Derivation path. First 3 items are automatically hardened!
            const path = [44, 474, 5, 0x80000000, 0x80000003];
            const respRequest = app.showAddressAndPubKey(path);

            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);

            await sim.compareSnapshotsAndAccept(".", "show_address", 3);

            const resp = await respRequest;
            console.log(resp);

            expect(resp.return_code).toEqual(0x9000);
            expect(resp.error_message).toEqual("No errors");

            const expected_bech32_address = "oasis1qphdkldpttpsj2j3l9sde9h26cwpfwqwwuhvruyu";
            const expected_pk = "aba52c0dcb80c2fe96ed4c3741af40c573a0500c0d73acda22795c37cb0f1739";

            expect(resp.bech32_address).toEqual(expected_bech32_address);
            expect(resp.pk.toString('hex')).toEqual(expected_pk);
        } finally {
            await sim.close();
        }
    });

    it('sign basic', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new OasisApp(sim.getTransport());

            const path = [44, 474, 5, 0x80000000, 0x80000003];
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

            await sim.compareSnapshotsAndAccept(".", "sign_basic", 7);

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

    it('submit proposal - upgrade', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new OasisApp(sim.getTransport());

            const path = [44, 474, 5, 0x80000000, 0x80000003];
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

            await sim.compareSnapshotsAndAccept(".", "submit_proposal_upgrade", 12);

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

    it('submit proposal - cancel upgrade', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new OasisApp(sim.getTransport());

            const path = [44, 474, 5, 0x80000000, 0x80000003];
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

            await sim.compareSnapshotsAndAccept(".", "submit_proposal_cancel_upgrade", 8);

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

    it('cast vote - abstain', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new OasisApp(sim.getTransport());

            const path = [44, 474, 5, 0x80000000, 0x80000003];
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

            await sim.compareSnapshotsAndAccept(".", "cast_vote_abstain", 8);

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

    it('cast vote - yes', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new OasisApp(sim.getTransport());

            const path = [44, 474, 5, 0x80000000, 0x80000003];
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

            await sim.compareSnapshotsAndAccept(".", "cast_vote_yes", 8);

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

    it('cast vote - no', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new OasisApp(sim.getTransport());

            const path = [44, 474, 5, 0x80000000, 0x80000003];
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

            await sim.compareSnapshotsAndAccept(".", "cast_vote_no", 8);

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

    it('sign basic - invalid', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new OasisApp(sim.getTransport());

            const path = [44, 474, 5, 0x80000000, 0x80000003];
            const context = "oasis-core/consensus: tx for chain testing";
            let invalidMessage = Buffer.from(
                "pGNmZWWiY2dhcwBmYW1vdW50QGRib2R5omd4ZmVyX3RvWCBkNhaFWEyIEubmS3EVtRLTanD3U+vDV5fke4Obyq83CWt4ZmVyX3Rva2Vuc0Blbm9uY2UAZm1ldGhvZHBzdGFraW5nLlRyYW5zZmVy",
                "base64",
            );
            invalidMessage += "1";

            const pkResponse = await app.getAddressAndPubKey(path);
            console.log(pkResponse);
            expect(pkResponse.return_code).toEqual(0x9000);
            expect(pkResponse.error_message).toEqual("No errors");

            // do not wait here..
            const responseSign = await app.sign(path, context, invalidMessage);
            console.log(responseSign);

            expect(responseSign.return_code).toEqual(0x6984);
            expect(responseSign.error_message).toEqual("Data is invalid : Root item should be a map");
        } finally {
            await sim.close();
        }
    });

    it('sign amend schedule', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new OasisApp(sim.getTransport());

            const path = [44, 474, 5, 0x80000000, 0x80000003];
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

            await sim.compareSnapshotsAndAccept(".", "sign_amend", 29);

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

    it('sign entity metadata', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new OasisApp(sim.getTransport());

            const path = [44, 474, 5, 0x80000000, 0x80000003];
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

            await sim.compareSnapshotsAndAccept(".", "sign_entity_metadata", 7);

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

    it('sign entity metadata - long url', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new OasisApp(sim.getTransport());

            const path = [44, 474, 5, 0x80000000, 0x80000003];
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

            await sim.compareSnapshotsAndAccept(".", "sign_entity_metadata_long", 9);

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

    it('sign entity metadata - too long name', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new OasisApp(sim.getTransport());

            const path = [44, 474, 5, 0x80000000, 0x80000003];
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
  it('should sign a transaction two time in a row (issue #68)', async function () {
    const sim = new Zemu(APP_PATH);
    try {
        await sim.start(sim_options);
        const app = new OasisApp(sim.getTransport());

        const path = [44, 474, 5, 0x80000000, 0x80000003];
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

        await sim.compareSnapshotsAndAccept(".", "sign_basic", 7);

        let resp = await signatureRequest;
        console.log(resp);

        expect(resp.return_code).toEqual(0x9000);
        expect(resp.error_message).toEqual("No errors");

        // Need to wait a bit before signing again.
        await Zemu.delay(200);

        // Here we go again
        const signatureRequestBis = app.sign(path, context, txBlob);

        await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);

        await sim.compareSnapshotsAndAccept(".", "sign_basic", 7);

        let respBis = await signatureRequestBis;
        console.log(respBis);

        expect(respBis.return_code).toEqual(0x9000);
        expect(respBis.error_message).toEqual("No errors");

    } finally {
        await sim.close();
    }
  });
})
