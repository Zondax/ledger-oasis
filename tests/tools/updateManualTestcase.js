const fs = require('fs');
const base64 = require('base64-js');
const cbor = require('cbor');

let rawData = fs.readFileSync('incomplete_testvectors.json');
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

function fixQuantityTypes(tx) {
    // We need to convert types here otherwise the encoder will
    // output CborTextStringType and not CborByteStringType

    out = JSON.parse(JSON.stringify(tx));

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
    } catch (e) {
    }
    try {
        out.body.signature.public_key = hexstringToArray(out.body.signature.public_key);
    } catch (e) {
    }

    return out;
}

function fixPublicKeysTypes(entity) {

    out = JSON.parse(JSON.stringify(entity));

    out.id = hexstringToArray(out.id);

    for (let i =0; i < out.nodes.length; i++) {
        out.nodes[i] = hexstringToArray(out.nodes[i])
    }

    return out;

}


// Now process the data and generate the correct cbor output
jsonData.forEach(tc => {

    if ('entity' in tc) {
        console.log(tc.entity);
        tmp = fixPublicKeysTypes(tc.entity);
    } else {
        // Fix types
        console.log(tc.tx);
        tmp = fixQuantityTypes(tc.tx);
    }



    cbortx = cbor.encode(tmp);
    base64Tx = base64.fromByteArray(cbortx);

    tc['encoded_tx'] = base64Tx;
    tc['cborhex'] = cbortx.toString('hex');
});

let rawdata = JSON.stringify(jsonData, null, 4);
fs.writeFileSync('../manual_testvectors.json', rawdata);
