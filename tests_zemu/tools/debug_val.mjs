import Zemu from "@zondax/zemu";
import Oasis from "@zondax/ledger-oasis";
import path from "path";

const APP_PATH = path.resolve(`./../../app/bin/app.elf`);

const seed = "equip will roof matter pink blind book anxiety banner elbow sun young"
const SIM_OPTIONS = {
    logging: true,
    start_delay: 4000,
    X11: true,
    custom: `-s "${seed}" --color LAGOON_BLUE`
};

async function beforeStart() {
    process.on("SIGINT", () => {
        Zemu.default.stopAllEmuContainers(function () {
            process.exit();
        });
    });
    await Zemu.default.checkAndPullImage();
}

async function beforeEnd() {
    await Zemu.default.stopAllEmuContainers();
}

async function debugScenario(sim, app) {
    // Here you can customize what you want to do :)

    const path = [44, 474, 5, 0x80000000, 0x80000003];
    const context = "oasis-core/consensus: tx for chain testing";

    const txBlob1 = Buffer.from("210801110500000000000000190000000000000000220b088092b8c398feffffff01", "hex",);
    const txBlob2 = Buffer.from("210801110500000000000000190100000000000000220b088092b8c398feffffff01", "hex",);
    const txBlob3 = Buffer.from("210801110500000000000000190200000000000000220b088092b8c398feffffff01", "hex",);
    const txBlob4 = Buffer.from("210801110500000000000000190300000000000000220b088092b8c398feffffff01", "hex",);
    const txBlob5 = Buffer.from("210801110500000000000000190400000000000000220b088092b8c398feffffff01", "hex",);
    const txBlob6 = Buffer.from("210801110500000000000000190500000000000000220b088092b8c398feffffff01", "hex",);

    let signatureResponse = await app.sign(path, context, txBlob1);
    console.log(signatureResponse)
    signatureResponse = await app.sign(path, context, txBlob2);
    console.log(signatureResponse)
    signatureResponse = await app.sign(path, context, txBlob3);
    console.log(signatureResponse)
    signatureResponse = await app.sign(path, context, txBlob4);
    console.log(signatureResponse)
    signatureResponse = await app.sign(path, context, txBlob5);
    console.log(signatureResponse)
    signatureResponse = await app.sign(path, context, txBlob6);
    console.log(signatureResponse)
}

async function main() {
    await beforeStart();

    if (process.argv.length > 2 && process.argv[2] === "debug") {
        SIM_OPTIONS["custom"] = SIM_OPTIONS["custom"] + " --debug";
    }

    const sim = new Zemu.default(APP_PATH);

    try {
        await sim.start(SIM_OPTIONS);
        const app = new Oasis.OasisValidatorApp(sim.getTransport());

        ////////////
        /// TIP you can use zemu commands here to take the app to the point where you trigger a breakpoint

        await debugScenario(sim, app);

        /// TIP

    } finally {
        await sim.close();
        await beforeEnd();
    }
}

(async () => {
    await main();
})();
