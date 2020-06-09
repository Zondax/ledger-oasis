import jest, {expect} from "jest";
import Zemu from "@zondax/zemu";
import {OasisValidatorApp} from "@zondax/ledger-oasis";

const tweetnacl = require("tweetnacl");

const Resolve = require("path").resolve;
const APP_PATH = Resolve("../app/bin/app_val.elf");

const APP_SEED = "equip will roof matter pink blind book anxiety banner elbow sun young"
const sim_options = {
    press_delay: 500,
    logging: true,
    start_delay: 3000,
    custom: `-s "${APP_SEED}"`
    //,X11: true
};
const VOTE_SLEEP = 500;

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
            const app = new OasisValidatorApp(sim.getTransport());
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

    it('validator sign basic', async function () {
        const snapshotPrefixGolden = "snapshots/sign-basic/";
        const snapshotPrefixTmp = "snapshots-tmp/sign-basic/";
        let snapshotCount = 0;

        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new OasisValidatorApp(sim.getTransport());

            const path = [474, 474, 5, 0x80000000, 0x80000003];
            const context = "oasis-core/consensus: tx for chain testing";

            const txBlob0 = Buffer.from("210801110500000000000000190000000000000000220b088092b8c398feffffff01", "hex",);
            const txBlob1 = Buffer.from("210801110500000000000000190100000000000000220b088092b8c398feffffff01", "hex",);
            const txBlob2 = Buffer.from("210801110500000000000000190200000000000000220b088092b8c398feffffff01", "hex",);
            const txBlob3 = Buffer.from("210801110500000000000000190300000000000000220b088092b8c398feffffff01", "hex",);
            const txBlob4 = Buffer.from("210801110500000000000000190400000000000000220b088092b8c398feffffff01", "hex",);
            const txBlob5 = Buffer.from("210801110500000000000000190500000000000000220b088092b8c398feffffff01", "hex",);

            let signatureRequest = app.sign(path, context, txBlob0);
            await Zemu.sleep(VOTE_SLEEP);

            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickBoth();

            let signatureResponse = await signatureRequest;
            console.log(signatureResponse);

            expect(signatureResponse.return_code).toEqual(0x6985);
            expect(signatureResponse.error_message).toEqual("Conditions not satisfied");

            for (let i = 1; i <= 5; i++) {
                let blob = eval("txBlob" + i)
                signatureResponse = await app.sign(path, context, blob);
                await Zemu.sleep(VOTE_SLEEP);
                console.log(signatureResponse);
                expect(signatureResponse.return_code).toEqual(0x9000);
                expect(signatureResponse.error_message).toEqual("No errors");
            }

        } finally {
            await sim.close();
        }
    });
});
