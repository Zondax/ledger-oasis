import Zemu, {DEFAULT_START_OPTIONS} from "@zondax/zemu";

// @ts-ignore
import {OasisValidatorApp} from "@zondax/ledger-oasis";
import { models } from "./common";

const Resolve = require("path").resolve;
const APP_PATH = Resolve("../app/bin/app_val.elf");

const APP_SEED = "equip will roof matter pink blind book anxiety banner elbow sun young"
const sim_options = {
    ...DEFAULT_START_OPTIONS,
    logging: true,
    startDelay: 3000,
    custom: `-s "${APP_SEED}"`,
    model: models[0].name,
    startText: 'Validator'
};
const VOTE_SLEEP = 500;

jest.setTimeout(30000)

describe('Validator', function () {
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

    it('Validator vote sign - basic', async function () {

        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new OasisValidatorApp(sim.getTransport());

            const path = [43, 474, 5, 0x80000000, 0x80000003];
            const context = "oasis-core/tendermint";

            const txBlob0 = Buffer.from("96010802114aa701000000000022480a20843c851b4795252c91b61b7f76615a8bce05b0c0c2d3a3da4af2bf7cef34ba3712240a20155d404d4864d503967e2176cb8fbc030c6c4051402870bfebbd82f8084907c910012a0b089b8fd5f70510e3c9fa2232326136333464323232346435343962383536303338616364396264616434373638346431333236326438376531633062386361", "hex",);
            const txBlob1 = Buffer.from("96010802114ba701000000000022480a20843c851b4795252c91b61b7f76615a8bce05b0c0c2d3a3da4af2bf7cef34ba3712240a20155d404d4864d503967e2176cb8fbc030c6c4051402870bfebbd82f8084907c910012a0b089b8fd5f70510e3c9fa2232326136333464323232346435343962383536303338616364396264616434373638346431333236326438376531633062386361", "hex",);

            let signatureRequest = app.sign(path, context, txBlob0);
            await Zemu.sleep(VOTE_SLEEP);

            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickBoth();

            let signatureResponse = await signatureRequest;
            console.log(signatureResponse);

            expect(signatureResponse.return_code).toEqual(0x6985);
            expect(signatureResponse.error_message).toEqual("Conditions not satisfied");

            signatureResponse = await app.sign(path, context, txBlob1);
            await Zemu.sleep(VOTE_SLEEP);
            console.log(signatureResponse);
            expect(signatureResponse.return_code).toEqual(0x9000);
            expect(signatureResponse.error_message).toEqual("No errors");

            signatureResponse = await app.sign(path, context, txBlob1);
            await Zemu.sleep(VOTE_SLEEP);
            console.log(signatureResponse);
            expect(signatureResponse.return_code).toEqual(0x6986);
            expect(signatureResponse.error_message).toEqual("Transaction rejected");

        } finally {
            await sim.close();
        }
    });
});
