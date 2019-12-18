const fs = require('fs');
const cbor = require('cbor');

function bigintToArray(v) {
    tmp = BigInt(v).toString(16);
    // not sure why it is not padding and buffer does not like it
    if (tmp.length % 2 === 1) tmp = "0" + tmp;
    return Buffer.from(tmp, "hex");
}

function fixFieldsForCBOR(obj) {
    // We need to convert types here otherwise the encoder will output CborTextStringType and not CborByteStringType
    out = JSON.parse(JSON.stringify(obj));

    try {
        out.id = Buffer.from(out.id, 'hex');
    } catch (e) {
    }

    try {
        for (let i = 0; i < out.nodes.length; i++) {
            out.nodes[i] = Buffer.from(out.nodes[i], 'hex');
        }
    } catch (e) {
    }

    try {
        out.fee.amount = bigintToArray(out.fee.amount)
    } catch (e) {
    }

    try {
        out.body.burn_tokens = bigintToArray(out.body.burn_tokens);
    } catch (e) {
    }

    try {
        out.body.signature.signature = Buffer.from(out.body.signature.signature, 'hex');
    } catch (e) {
    }
    try {
        // In test the public keys are given in base 64 encoding!
        out.body.signature.public_key = Buffer.from(out.body.signature.public_key, 'hex');
    } catch (e) {
    }

    try {
        out.body.untrusted_raw_value = toCBOR(out.body.untrusted_raw_value);
    } catch (e) {
    }

    return out;
}

function fixFieldsForJSON(obj) {
    // We need to convert types here otherwise the encoder will output CborTextStringType and not CborByteStringType
    out = JSON.parse(JSON.stringify(obj));

    try {
        out.entity.id = Buffer.from(out.entity.id, 'hex').toString('base64')
    } catch (e) {
    }

    try {
        for (let i = 0; i < out.entity.nodes.length; i++) {
            out.entity.nodes[i] = Buffer.from(out.entity.nodes[i], 'hex').toString('base64');
        }
    } catch (e) {
    }

    try {
        out.tx.body.untrusted_raw_value.entity.id = Buffer.from(out.tx.body.untrusted_raw_value.entity.id, 'hex').toString('base64')
    } catch (e) {
    }

    try {
        for (let i = 0; i < out.tx.body.untrusted_raw_value.entity.nodes.length; i++) {
            out.tx.body.untrusted_raw_value.entity.nodes[i] = Buffer.from(out.tx.body.untrusted_raw_value.entity.nodes[i], 'hex').toString('base64');
        }
    } catch (e) {
    }

    try {
        out.tx.body.signature.signature = Buffer.from(out.tx.body.signature.signature, 'hex').toString('base64');
    } catch (e) {
    }
    try {
        out.tx.body.signature.public_key = Buffer.from(out.tx.body.signature.public_key, 'hex').toString('base64');
    } catch (e) {
    }

    return out;
}

function toCBOR(root) {
    root = JSON.parse(JSON.stringify(root));

// Now process the data and generate the correct cbor output
    if ('entity' in root) {
        tmp = fixFieldsForCBOR(root.entity);
    } else {
        // Fix types
        tmp = fixFieldsForCBOR(root.tx);
    }
    return cbor.encode(tmp).toString('base64');
}

let rawData = fs.readFileSync('template_testvectors.json');

let jsonData = JSON.parse(rawData);

newJsonData = [];
jsonData.forEach(tc => {
    tc['encoded_tx'] = toCBOR(tc);
    tc['encoded_tx_hex'] = Buffer.from(toCBOR(tc), 'base64').toString('hex');
    newJsonData.push(fixFieldsForJSON(tc));
});

let rawdata = JSON.stringify(newJsonData, null, 4);

fs.writeFileSync('../manual_testvectors.json', rawdata);
