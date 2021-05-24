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

    const path = "m/44'/474'/5'/0'/3'";
    const context = "oasis-core/consensus: tx for chain testing";
    const txBlob = Buffer.from(
        "pGNmZWWiY2dhcxkD6GZhbW91bnRCB9BkYm9keaJneGZlcl90b1UA4ywoibwEEhHt7fqvlNL9hmmLsH9reGZlcl90b2tlbnNFJ5TKJABlbm9uY2UHZm1ldGhvZHBzdGFraW5nLlRyYW5zZmVy",
        "base64",
    );

    const signatureRequest = await app.sign(path, context, txBlob);
    const signatureResponse = await signatureRequest;
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
        const app = new Oasis.OasisApp(sim.getTransport());

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
