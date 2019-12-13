# Instructions

- install dependencies
    ```bash
    yarn install
    ```

- in order to create/update manual tests, add a new item to `incomplete_testvectors.js` and run:

    ```bash
    node updateManualTestcase.js
    ```

    This will encode (cbor/base64) and update `../manual_testvectors.json'`
