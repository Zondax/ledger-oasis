import jest, {expect} from "jest";
import Zemu from "@zondax/zemu";
import {OasisApp} from "@zondax/ledger-oasis";

const ed25519 = require("ed25519-supercop");
const sha512 = require("js-sha512");

const Resolve = require("path").resolve;
const APP_PATH = Resolve("../app/bin/app.elf");

const APP_SEED = "equip will roof matter pink blind book anxiety banner elbow sun young"
const sim_options = {
    press_delay: 500,
    logging: true,
    start_delay: 3000,
    custom: `-s "${APP_SEED}"`
    ,X11: true
};

jest.setTimeout(20000)

function compareSnapshots(snapshotPrefixTmp, snapshotPrefixGolden, snapshotCount) {
    for (let i = 0; i < snapshotCount; i++) {
        const img1 = Zemu.LoadPng2RGB(`${snapshotPrefixTmp}${i}.png`);
        const img2 = Zemu.LoadPng2RGB(`${snapshotPrefixGolden}${i}.png`);
        expect(img1).toEqual(img2);
    }
}

describe('Basic checks', function () {
    it('can start and stop container', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
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

            const expected_bech32_address = "oasis1qp0cnmkjl22gky6p6qeghjytt4v7dkxsrsmueweh";
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
        const snapshotPrefixGolden = "snapshots/show-address/";
        const snapshotPrefixTmp = "snapshots-tmp/show-address/";
        let snapshotCount = 0;

        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new OasisApp(sim.getTransport());

            // Derivation path. First 3 items are automatically hardened!
            const path = [44, 474, 5, 0x80000000, 0x80000003];
            const respRequest = app.showAddressAndPubKey(path);

            // We need to wait until the app responds to the APDU
            await Zemu.sleep(4000);

            // Now navigate the address / path
            await sim.snapshot(`${snapshotPrefixTmp}${snapshotCount++}.png`);
            await sim.clickRight(`${snapshotPrefixTmp}${snapshotCount++}.png`);
            await sim.clickRight(`${snapshotPrefixTmp}${snapshotCount++}.png`);
            await sim.clickRight(`${snapshotPrefixTmp}${snapshotCount++}.png`);
            await sim.clickBoth(`${snapshotPrefixTmp}${snapshotCount++}.png`);

            const resp = await respRequest;
            console.log(resp);

            compareSnapshots(snapshotPrefixTmp, snapshotPrefixGolden, snapshotCount);

            expect(resp.return_code).toEqual(0x9000);
            expect(resp.error_message).toEqual("No errors");

            const expected_bech32_address = "oasis1qp0cnmkjl22gky6p6qeghjytt4v7dkxsrsmueweh";
            const expected_pk = "aba52c0dcb80c2fe96ed4c3741af40c573a0500c0d73acda22795c37cb0f1739";

            expect(resp.bech32_address).toEqual(expected_bech32_address);
            expect(resp.pk.toString('hex')).toEqual(expected_pk);
        } finally {
            await sim.close();
        }
    });

    it('sign basic', async function () {
        const snapshotPrefixGolden = "snapshots/sign-basic/";
        const snapshotPrefixTmp = "snapshots-tmp/sign-basic/";
        let snapshotCount = 0;

        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new OasisApp(sim.getTransport());

            const path = [44, 474, 5, 0x80000000, 0x80000003];
            const context = "oasis-core/consensus: tx for chain testing";
            const txBlob = Buffer.from(
                "pGNmZWWiY2dhcwBmYW1vdW50QGRib2R5omd4ZmVyX3RvVQDHPMABRjQ0kVuj85dRvrfAkFtF62t4ZmVyX3Rva2Vuc0Blbm9uY2UAZm1ldGhvZHBzdGFraW5nLlRyYW5zZmVy",
                "base64",
            );

            const pkResponse = await app.getAddressAndPubKey(path);
            console.log(pkResponse);
            expect(pkResponse.return_code).toEqual(0x9000);
            expect(pkResponse.error_message).toEqual("No errors");

            // do not wait here..
            const signatureRequest = app.sign(path, context, txBlob);

            await Zemu.sleep(2000);

            // Reference window
            await sim.snapshot(`${snapshotPrefixTmp}${snapshotCount++}.png`);
            for (let i = 0; i < 7; i++) {
                await sim.clickRight(Resolve(`${snapshotPrefixTmp}${snapshotCount++}.png`));
            }
            await sim.clickBoth();

            let resp = await signatureRequest;
            console.log(resp);

            compareSnapshots(snapshotPrefixTmp, snapshotPrefixGolden, snapshotCount);

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
            expect(responseSign.error_message).toEqual("Data is invalid : Unexpected data type");
        } finally {
            await sim.close();
        }
    });
});
