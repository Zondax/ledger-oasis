import jest, {expect} from "jest";
import Zemu from "@zondax/zemu";
import Oasis from "@zondax/ledger-oasis";

const tweetnacl = require("tweetnacl");

const Resolve = require("path").resolve;
const APP_PATH = Resolve("../app/bin/app_val.elf");

const APP_SEED = "equip will roof matter pink blind book anxiety banner elbow sun young"
const sim_options = {
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
            const app = new Oasis.OasisValidatorApp(sim.getTransport());
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

    it('sign basic', async function () {
        const snapshotPrefixGolden = "snapshots/sign-basic/";
        const snapshotPrefixTmp = "snapshots-tmp/sign-basic/";
        let snapshotCount = 0;

        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new Oasis.OasisValidatorApp(sim.getTransport());

            const path = [474, 474, 5, 0x80000000, 0x80000003];
            const context = "oasis-core/consensus: tx for chain testing";

            const txBlob1 = Buffer.from("210801110500000000000000190000000000000000220b088092b8c398feffffff01", "hex",);
            const txBlob2 = Buffer.from("210801110500000000000000190100000000000000220b088092b8c398feffffff01", "hex",);
            const txBlob3 = Buffer.from("210801110500000000000000190200000000000000220b088092b8c398feffffff01", "hex",);
            const txBlob4 = Buffer.from("210801110500000000000000190300000000000000220b088092b8c398feffffff01", "hex",);
            const txBlob5 = Buffer.from("210801110500000000000000190400000000000000220b088092b8c398feffffff01", "hex",);
            const txBlob6 = Buffer.from("210801110500000000000000190500000000000000220b088092b8c398feffffff01", "hex",);

            let signatureResponse = await app.sign(path, context, txBlob1);
            console.log(signatureResponse);
            await Zemu.sleep(VOTE_SLEEP);


        } finally {
            await sim.close();
        }
    });
});
