import bech32 from "bech32";
import {
  CHUNK_SIZE,
  DEFAULT_HRP,
  errorCodeToString,
  INS,
  P1_VALUES, PAYLOAD_TYPE,
  processErrorResponse,
  publicKeyv1,
} from "./common";

const HARDENED = 0x80000000;

function processGetAddrEd25519Response(response) {
  const errorCodeData = response.slice(-2);
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

  const pk = Buffer.from(response.slice(0, 32));
  const bech32Address = Buffer.from(response.slice(32, -2)).toString();

  return {
    bech32_address: bech32Address,
    pk,
    return_code: returnCode,
    error_message: errorCodeToString(returnCode),
  };
}

export class OasisAppBase {
  // eslint-disable-next-line class-methods-use-this
  CLA() {
    return 0x00;
  }

  // eslint-disable-next-line class-methods-use-this
  APP_KEY() {
    return "OAS";
  }

  constructor(transport) {
    if (!transport) {
      throw new Error("Transport has not been defined");
    }

    this.transport = transport;
    transport.decorateAppAPIMethods(
      this,
      ["getVersion", "sign", "getAddressAndPubKey", "appInfo", "deviceInfo", "getBech32FromPK"],
      this.APP_KEY(),
    );
  }

  static getBech32FromPK(pk) {
    if (pk.length !== 32) {
      throw new Error("expected public key [32 bytes]");
    }
    return bech32.encode(DEFAULT_HRP, bech32.toWords(pk));
  }

  async serializePath(path) {
    if(path instanceof Array){

      if (!path || ( path.length !== 5 && path.length !== 3 ))
        throw new Error("Invalid path.");

      let buf = Buffer.alloc(path.length === 3 ? 12 : 20);
      buf.writeUInt32LE(0x80000000 + path[0], 0);
      buf.writeUInt32LE(0x80000000 + path[1], 4);
      buf.writeUInt32LE(0x80000000 + path[2], 8);

      if(path.length === 5){
        buf.writeUInt32LE(path[3], 12);
        buf.writeUInt32LE(path[4], 16);
      }

      return buf;
    }

    if( typeof path === "string") {
      if (!path.startsWith("m"))
        throw new Error('Path should start with "m" (e.g "m/44\'/461\'/5\'/0/3")');

      const pathArray = path.split("/");

      if (pathArray.length !== 6 && pathArray.length !== 4)
        throw new Error("Invalid path. (e.g \"m/44'/461'/5'/0/3\" or \"m/44'/461'/5'\")");

      const buf = Buffer.alloc(pathArray.length === 4 ? 12 : 20);

      for (let i = 1; i < pathArray.length; i += 1) {
        let value = 0;
        let child = pathArray[i];
        if (child.endsWith("'")) {
          value += HARDENED;
          child = child.slice(0, -1);
        }

        const childNumber = Number(child);

        if (Number.isNaN(childNumber)) {
          throw new Error(`Invalid path : ${child} is not a number. (e.g "m/44'/461'/5'/0/3")`);
        }

        if (childNumber >= HARDENED) {
          throw new Error("Incorrect child value (bigger or equal to 0x80000000)");
        }

        value += childNumber;

        buf.writeUInt32LE(value, 4 * (i - 1));
      }

      return buf;
    }

    throw new Error("Path should be a string (e.g \"m/44'/461'/5'/0/3\") or an Array (e.g \"m/44'/474'/5'/0'/3'\")");
  }

  static prepareChunks(serializedPathBuffer, context, message) {
    const chunks = [];

    // First chunk (only path)
    chunks.push(serializedPathBuffer);

    const contextSizeBuffer = Buffer.from([context.length]);
    const contextBuffer = Buffer.from(context);
    const messageBuffer = Buffer.from(message);

    if (context.length > 255) {
      throw new Error("Maximum supported context size is 255 bytes");
    }

    if (contextSizeBuffer.length > 1) {
      throw new Error("Context size buffer should be exactly 1 byte");
    }

    // Now split context length + context + message into more chunks
    const buffer = Buffer.concat([contextSizeBuffer, contextBuffer, messageBuffer]);
    for (let i = 0; i < buffer.length; i += CHUNK_SIZE) {
      let end = i + CHUNK_SIZE;
      if (i > buffer.length) {
        end = buffer.length;
      }
      chunks.push(buffer.slice(i, end));
    }

    return chunks;
  }

  async signGetChunks(path, context, message) {
    const serializedPath = await this.serializePath(path);

    return OasisAppBase.prepareChunks(serializedPath, context, message);
  }

  async getVersion() {
    return this.transport.send(this.CLA(), INS.GET_VERSION, 0, 0).then((response) => {
      const errorCodeData = response.slice(-2);
      const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

      let targetId = 0;
      if (response.length >= 9) {
        /* eslint-disable no-bitwise */
        targetId = (response[5] << 24) + (response[6] << 16) + (response[7] << 8) + (response[8] << 0);
        /* eslint-enable no-bitwise */
      }

      return {
        return_code: returnCode,
        error_message: errorCodeToString(returnCode),
        // ///
        test_mode: response[0] !== 0,
        major: response[1],
        minor: response[2],
        patch: response[3],
        device_locked: response[4] === 1,
        target_id: targetId.toString(16),
      };
    }, processErrorResponse);
  }

  async appInfo() {
    return this.transport.send(0xb0, 0x01, 0, 0).then((response) => {
      const errorCodeData = response.slice(-2);
      const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

      const result = {};

      let appName = "err";
      let appVersion = "err";
      let flagLen = 0;
      let flagsValue = 0;

      if (response[0] !== 1) {
        // Ledger responds with format ID 1. There is no spec for any format != 1
        result.error_message = "response format ID not recognized";
        result.return_code = 0x9001;
      } else {
        const appNameLen = response[1];
        appName = response.slice(2, 2 + appNameLen).toString("ascii");
        let idx = 2 + appNameLen;
        const appVersionLen = response[idx];
        idx += 1;
        appVersion = response.slice(idx, idx + appVersionLen).toString("ascii");
        idx += appVersionLen;
        const appFlagsLen = response[idx];
        idx += 1;
        flagLen = appFlagsLen;
        flagsValue = response[idx];
      }

      return {
        return_code: returnCode,
        error_message: errorCodeToString(returnCode),
        // //
        appName,
        appVersion,
        flagLen,
        flagsValue,
        // eslint-disable-next-line no-bitwise
        flag_recovery: (flagsValue & 1) !== 0,
        // eslint-disable-next-line no-bitwise
        flag_signed_mcu_code: (flagsValue & 2) !== 0,
        // eslint-disable-next-line no-bitwise
        flag_onboarded: (flagsValue & 4) !== 0,
        // eslint-disable-next-line no-bitwise
        flag_pin_validated: (flagsValue & 128) !== 0,
      };
    }, processErrorResponse);
  }

  async deviceInfo() {
    return this.transport.send(0xe0, 0x01, 0, 0, Buffer.from([]), [0x9000, 0x6e00]).then((response) => {
      const errorCodeData = response.slice(-2);
      const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

      if (returnCode === 0x6e00) {
        return {
          return_code: returnCode,
          error_message: "This command is only available in the Dashboard",
        };
      }

      const targetId = response.slice(0, 4).toString("hex");

      let pos = 4;
      const secureElementVersionLen = response[pos];
      pos += 1;
      const seVersion = response.slice(pos, pos + secureElementVersionLen).toString();
      pos += secureElementVersionLen;

      const flagsLen = response[pos];
      pos += 1;
      const flag = response.slice(pos, pos + flagsLen).toString("hex");
      pos += flagsLen;

      const mcuVersionLen = response[pos];
      pos += 1;
      // Patch issue in mcu version
      let tmp = response.slice(pos, pos + mcuVersionLen);
      if (tmp[mcuVersionLen - 1] === 0) {
        tmp = response.slice(pos, pos + mcuVersionLen - 1);
      }
      const mcuVersion = tmp.toString();

      return {
        return_code: returnCode,
        error_message: errorCodeToString(returnCode),
        // //
        targetId,
        seVersion,
        flag,
        mcuVersion,
      };
    }, processErrorResponse);
  }

  async publicKey(path) {
    const serializedPath = await this.serializePath(path);
    return publicKeyv1(this, serializedPath);
  }

  async getAddressAndPubKey(path) {
    const data = await this.serializePath(path);
    return this.transport
      .send(this.CLA(), INS.GET_ADDR_ED25519, P1_VALUES.ONLY_RETRIEVE, 0, data, [0x9000])
      .then(processGetAddrEd25519Response, processErrorResponse);
  }

  async showAddressAndPubKey(path) {
    const data = await this.serializePath(path);
    return this.transport
      .send(this.CLA(), INS.GET_ADDR_ED25519, P1_VALUES.SHOW_ADDRESS_IN_DEVICE, 0, data, [0x9000])
      .then(processGetAddrEd25519Response, processErrorResponse);
  }

  async signSendChunk(chunkIdx, chunkNum, chunk) {
    let payloadType = PAYLOAD_TYPE.ADD;
    if (chunkIdx === 1) {
      payloadType = PAYLOAD_TYPE.INIT;
    }
    if (chunkIdx === chunkNum) {
      payloadType = PAYLOAD_TYPE.LAST;
    }

    return this.transport
      .send(this.CLA(), INS.SIGN_ED25519, payloadType, 0, chunk, [0x9000, 0x6984, 0x6a80])
      .then((response) => {
        const errorCodeData = response.slice(-2);
        const returnCode = errorCodeData[0] * 256 + errorCodeData[1];
        let errorMessage = errorCodeToString(returnCode);

        if (returnCode === 0x6a80 || returnCode === 0x6984) {
          errorMessage = `${errorMessage} : ${response.slice(0, response.length - 2).toString("ascii")}`;
        }

        let signature = null;
        if (response.length > 2) {
          signature = response.slice(0, response.length - 2);
        }

        return {
          signature,
          return_code: returnCode,
          error_message: errorMessage,
        };
      }, processErrorResponse);
  }

  async sign(path, context, message) {
    const chunks = await this.signGetChunks(path, context, message);

    return this.signSendChunk(1, chunks.length, chunks[0], [0x9000]).then(async (response) => {
      let result = {
        return_code: response.return_code,
        error_message: response.error_message,
        signature: null,
      };

      for (let i = 1; i < chunks.length; i += 1) {
        // eslint-disable-next-line no-await-in-loop
        result = await this.signSendChunk(1 + i, chunks.length, chunks[i]);
        if (result.return_code !== 0x9000) {
          break;
        }
      }

      return {
        return_code: result.return_code,
        error_message: result.error_message,
        // ///
        signature: result.signature,
      };
    }, processErrorResponse);
  }
}
