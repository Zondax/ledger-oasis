const fs = require('fs');
//const base64 = require('base64-js');
const cbor = require('cbor');

let rawData = fs.readFileSync('template_testvectors.json');
let jsonData = JSON.parse(rawData);

function bigintToArray(v) {
    tmp = BigInt(v).toString(16);
    // not sure why it is not padding and buffer does not like it
    if (tmp.length % 2 === 1) tmp = "0" + tmp;
    return Buffer.from(tmp, "hex");
}

function hexstringToArray(v) {
    return Buffer.from(v, "hex");
}

function fixFields(obj) {
    // We need to convert types here otherwise the encoder will
    // output CborTextStringType and not CborByteStringType

    out = JSON.parse(JSON.stringify(obj));

    try {
        out.id = Buffer.from(out.id, 'hex');
        obj.id = out.id.toString('base64')
    } catch (e) {
    }

    try {
        for (let i = 0; i < out.nodes.length; i++) {
            out.nodes[i] = Buffer.from(out.nodes[i], 'hex');
            obj.nodes[i] = out.nodes[i].toString('base64');
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
        out.body.signature.signature = hexstringToArray(out.body.signature.signature);
        obj.body.signature.signature = out.body.signature.signature.toString('base64');
    } catch (e) {
    }
    try {
        // In test the public keys are given in base 64 encoding!
        out.body.signature.public_key = Buffer.from(out.body.signature.public_key, 'hex');
        obj.body.signature.public_key = out.body.signature.public_key.toString('base64');
    } catch (e) {
    }

    return out;
}

// Now process the data and generate the correct cbor output
jsonData.forEach(tc => {

    if ('entity' in tc) {
        tmp = fixFields(tc.entity);
        console.log(tc.entity);
    } else {
        // Fix types
        tmp = fixFields(tc.tx);
        console.log(tc.tx);
    }

    cbortx = cbor.encode(tmp);

    tc['encoded_tx'] = cbortx.toString('base64');
    tc['cborhex'] = cbortx.toString('hex');
});

let rawdata = JSON.stringify(jsonData, null, 4);
fs.writeFileSync('../manual_testvectors.json', rawdata);
