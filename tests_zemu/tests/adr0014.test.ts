/** ******************************************************************************
 *  (c) 2020 Zondax GmbH
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ******************************************************************************* */

import Zemu, { ButtonKind, DEFAULT_START_OPTIONS, isTouchDevice } from '@zondax/zemu'
// @ts-ignore
import { OasisApp } from '@zondax/ledger-oasis'
import { models } from './common'

const ed25519 = require('ed25519-supercop')
const sha512 = require('js-sha512')
const secp256k1 = require('secp256k1/elliptic')
const addon = require('../../tests_tools/neon/native')

const APP_SEED = 'equip will roof matter pink blind book anxiety banner elbow sun young'

const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
}

// Derivation path. First 3 items are automatically hardened!
const path = "m/44'/474'/0'"
const secp256k1_path = "m/44'/60'/0'/0/0"
const polkadot_path = "m/44'/354'/0'/0/0"

jest.setTimeout(100000)

describe('Standard-Adr0014', function () {
  test.concurrent.each(models)('get Secp256k1 address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new OasisApp(sim.getTransport())

      const resp = await app.getAddressAndPubKey_secp256k1(secp256k1_path)

      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')

      const expected_hex_address = '95e5e3c1bdd92cd4a0c14c62480db5867946281d'
      const expected_pk = '021853d93524119eeb31ab0b06f1dcb068f84943bb230dfa10b1292f47af643575'

      expect(resp.hex_address).toEqual(expected_hex_address)
      expect(resp.pk.toString('hex')).toEqual(expected_pk)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('show Secp256k1 address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({
        ...defaultOptions,
        model: m.name,
        approveKeyword: isTouchDevice(m.name) ? 'Confirm' : '',
        approveAction: ButtonKind.ApproveTapButton,
      })
      const app = new OasisApp(sim.getTransport())

      const respRequest = app.showAddressAndPubKey_secp256k1(secp256k1_path)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-adr0014_show_address_secp256k1`)

      const resp = await respRequest
      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')

      const expected_hex_address = '95e5e3c1bdd92cd4a0c14c62480db5867946281d'
      const expected_pk = '021853d93524119eeb31ab0b06f1dcb068f84943bb230dfa10b1292f47af643575'

      expect(resp.hex_address).toEqual(expected_hex_address)
      expect(resp.pk.toString('hex')).toEqual(expected_pk)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('get polkadot path', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({
        ...defaultOptions,
        model: m.name,
        approveKeyword: isTouchDevice(m.name) ? 'Path' : '',
        approveAction: ButtonKind.ApproveTapButton,
      })
      const app = new OasisApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.toggleExpertMode()

      const respRequest = app.showAddressAndPubKey_secp256k1(polkadot_path)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-adr0014_get_polkadot_path`)

      const resp = await respRequest
      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')

      const expected_hex_address = 'c90e1fff32d75635f76c3a80aa57ec2d887d0056'
      const expected_pk = '0304f96fe439a685648cb216639fd3b2a6fbb668169b764b478fa4c342bf7aae8b'

      expect(resp.hex_address).toEqual(expected_hex_address)
      expect(resp.pk.toString('hex')).toEqual(expected_pk)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign ed25519 consensus - deposit', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new OasisApp(sim.getTransport())

      const meta = Buffer.from(
        'ompydW50aW1lX2lkeEAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBlMmVhYTk5ZmMwMDhmODdmbWNoYWluX2NvbnRleHR4QGJiM2Q3NDhkZWY1NWJkZmI3OTdhMmFjNTNlZTZlZTE0MWU1NGNkMmFiMmRjMjM3NWY0YTA3MDNhMTc4ZTZlNTU=',
        'base64',
      )

      const txBlob = Buffer.from(
        'o2F2AWJhaaJic2mBomVub25jZQBsYWRkcmVzc19zcGVjoWlzaWduYXR1cmWhZ2VkMjU1MTlYIDXD8zVt2FNk/roDVLVFraEJ0b2zi/XWEmgX24xyz9aRY2ZlZaJmYW1vdW50gkBAcmNvbnNlbnN1c19tZXNzYWdlcwFkY2FsbKJkYm9keaJidG9VAMjQ9FnbOOXMMcp35m0sRFbcvrUCZmFtb3VudIJAQGZtZXRob2RxY29uc2Vuc3VzLkRlcG9zaXQ=',
        'base64',
      )

      const sigCtx = Buffer.from('oasis-runtime-sdk/tx: v0 for chain 70869cb5e35133c69c82c91ccae4cbc0d6c53cfaf5e64fee098b74e7588eba03')

      const pkResponse = await app.getAddressAndPubKey_ed25519(path)
      console.log(pkResponse)
      expect(pkResponse.return_code).toEqual(0x9000)
      expect(pkResponse.error_message).toEqual('No errors')

      // do not wait here..
      const signatureRequest = app.signRtEd25519(path, meta, txBlob)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-adr0014-sign_ed25519_consensus_deposit`)

      let resp = await signatureRequest
      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')

      const hasher = sha512.sha512_256.update(sigCtx)
      hasher.update(txBlob)
      const msgHash = Buffer.from(hasher.hex(), 'hex')

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk)
      expect(valid).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign ed25519 accounts - transfer', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new OasisApp(sim.getTransport())

      const meta = Buffer.from(
        'ompydW50aW1lX2lkeEAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBlMmVhYTk5ZmMwMDhmODdmbWNoYWluX2NvbnRleHR4QGJiM2Q3NDhkZWY1NWJkZmI3OTdhMmFjNTNlZTZlZTE0MWU1NGNkMmFiMmRjMjM3NWY0YTA3MDNhMTc4ZTZlNTU=',
        'base64',
      )

      const txBlob = Buffer.from(
        'o2F2AWJhaaJic2mBomVub25jZQBsYWRkcmVzc19zcGVjoWlzaWduYXR1cmWhZ2VkMjU1MTlYIDXD8zVt2FNk/roDVLVFraEJ0b2zi/XWEmgX24xyz9aRY2ZlZaFmYW1vdW50gkBAZGNhbGyiZGJvZHmiYnRvVQDI0PRZ2zjlzDHKd+ZtLERW3L61AmZhbW91bnSCSAFjRXhdigAAQGZtZXRob2RxYWNjb3VudHMuVHJhbnNmZXI=',
        'base64',
      )

      const sigCtx = Buffer.from('oasis-runtime-sdk/tx: v0 for chain 70869cb5e35133c69c82c91ccae4cbc0d6c53cfaf5e64fee098b74e7588eba03')

      const pkResponse = await app.getAddressAndPubKey_ed25519(path)
      console.log(pkResponse)
      expect(pkResponse.return_code).toEqual(0x9000)
      expect(pkResponse.error_message).toEqual('No errors')

      // do not wait here..
      const signatureRequest = app.signRtEd25519(path, meta, txBlob)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-adr0014-sign_ed25519_accounts_transfer`)

      let resp = await signatureRequest
      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')

      const hasher = sha512.sha512_256.update(sigCtx)
      hasher.update(txBlob)
      const msgHash = Buffer.from(hasher.hex(), 'hex')

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk)
      expect(valid).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign ed25519 consensus - withdraw', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new OasisApp(sim.getTransport())

      const meta = Buffer.from(
        'ompydW50aW1lX2lkeEAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBlMmVhYTk5ZmMwMDhmODdmbWNoYWluX2NvbnRleHR4QGJiM2Q3NDhkZWY1NWJkZmI3OTdhMmFjNTNlZTZlZTE0MWU1NGNkMmFiMmRjMjM3NWY0YTA3MDNhMTc4ZTZlNTU=',
        'base64',
      )

      const txBlob = Buffer.from(
        'o2F2AWJhaaJic2mBomVub25jZQBsYWRkcmVzc19zcGVjoWlzaWduYXR1cmWhZ2VkMjU1MTlYIDXD8zVt2FNk/roDVLVFraEJ0b2zi/XWEmgX24xyz9aRY2ZlZaJmYW1vdW50gkBAcmNvbnNlbnN1c19tZXNzYWdlcwFkY2FsbKJkYm9keaFmYW1vdW50gkBAZm1ldGhvZHJjb25zZW5zdXMuV2l0aGRyYXc=',
        'base64',
      )

      const sigCtx = Buffer.from('oasis-runtime-sdk/tx: v0 for chain 70869cb5e35133c69c82c91ccae4cbc0d6c53cfaf5e64fee098b74e7588eba03')

      const pkResponse = await app.getAddressAndPubKey_ed25519(path)
      console.log(pkResponse)
      expect(pkResponse.return_code).toEqual(0x9000)
      expect(pkResponse.error_message).toEqual('No errors')

      // do not wait here..
      const signatureRequest = app.signRtEd25519(path, meta, txBlob)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-adr0014-sign_ed25519_consensus_withdraw`)

      let resp = await signatureRequest
      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')

      const hasher = sha512.sha512_256.update(sigCtx)
      hasher.update(txBlob)
      const msgHash = Buffer.from(hasher.hex(), 'hex')

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk)
      expect(valid).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign secp256k1 accounts - transfer', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new OasisApp(sim.getTransport())

      const meta = Buffer.from(
        'ompydW50aW1lX2lkeEAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBlMmVhYTk5ZmMwMDhmODdmbWNoYWluX2NvbnRleHR4QGJiM2Q3NDhkZWY1NWJkZmI3OTdhMmFjNTNlZTZlZTE0MWU1NGNkMmFiMmRjMjM3NWY0YTA3MDNhMTc4ZTZlNTU=',
        'base64',
      )

      const txBlob = Buffer.from(
        'o2F2AWJhaaJic2mBomVub25jZQBsYWRkcmVzc19zcGVjoWlzaWduYXR1cmWhZ2VkMjU1MTlYIDXD8zVt2FNk/roDVLVFraEJ0b2zi/XWEmgX24xyz9aRY2ZlZaFmYW1vdW50gkBAZGNhbGyiZGJvZHmiYnRvVQDI0PRZ2zjlzDHKd+ZtLERW3L61AmZhbW91bnSCSAFjRXhdigAAQGZtZXRob2RxYWNjb3VudHMuVHJhbnNmZXI=',
        'base64',
      )

      const sigCtx = Buffer.from('oasis-runtime-sdk/tx: v0 for chain 70869cb5e35133c69c82c91ccae4cbc0d6c53cfaf5e64fee098b74e7588eba03')

      const pkResponse = await app.getAddressAndPubKey_secp256k1(secp256k1_path)
      console.log(pkResponse)
      expect(pkResponse.return_code).toEqual(0x9000)
      expect(pkResponse.error_message).toEqual('No errors')

      // do not wait here..
      const signatureRequest = app.signRtSecp256k1(secp256k1_path, meta, txBlob)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-adr0014-sign_secp256k1_accounts_transfer`)

      let resp = await signatureRequest
      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')

      const hasher = sha512.sha512_256.update(sigCtx)
      hasher.update(txBlob)
      const msgHash = Buffer.from(hasher.hex(), 'hex')

      const signatureRS = Uint8Array.from(resp.signature).slice(0, -1)

      const signatureOk = secp256k1.ecdsaVerify(signatureRS, msgHash, pkResponse.pk)
      expect(signatureOk).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign secp256k1 consensus - withdraw', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new OasisApp(sim.getTransport())

      const meta = Buffer.from(
        'ompydW50aW1lX2lkeEAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBlMmVhYTk5ZmMwMDhmODdmbWNoYWluX2NvbnRleHR4QGJiM2Q3NDhkZWY1NWJkZmI3OTdhMmFjNTNlZTZlZTE0MWU1NGNkMmFiMmRjMjM3NWY0YTA3MDNhMTc4ZTZlNTU=',
        'base64',
      )

      const txBlob = Buffer.from(
        'o2F2AWJhaaJic2mBomVub25jZQBsYWRkcmVzc19zcGVjoWlzaWduYXR1cmWhZ2VkMjU1MTlYIDXD8zVt2FNk/roDVLVFraEJ0b2zi/XWEmgX24xyz9aRY2ZlZaJmYW1vdW50gkBAcmNvbnNlbnN1c19tZXNzYWdlcwFkY2FsbKJkYm9keaFmYW1vdW50gkBAZm1ldGhvZHJjb25zZW5zdXMuV2l0aGRyYXc=',
        'base64',
      )

      const sigCtx = Buffer.from('oasis-runtime-sdk/tx: v0 for chain 70869cb5e35133c69c82c91ccae4cbc0d6c53cfaf5e64fee098b74e7588eba03')

      const pkResponse = await app.getAddressAndPubKey_secp256k1(secp256k1_path)
      console.log(pkResponse)
      expect(pkResponse.return_code).toEqual(0x9000)
      expect(pkResponse.error_message).toEqual('No errors')

      // do not wait here..
      const signatureRequest = app.signRtSecp256k1(secp256k1_path, meta, txBlob)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-adr0014-sign_secp256k1_consensus_withdraw`)

      let resp = await signatureRequest
      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')

      const hasher = sha512.sha512_256.update(sigCtx)
      hasher.update(txBlob)
      const msgHash = Buffer.from(hasher.hex(), 'hex')

      const signatureRS = Uint8Array.from(resp.signature).slice(0, -1)

      const signatureOk = secp256k1.ecdsaVerify(signatureRS, msgHash, pkResponse.pk)
      expect(signatureOk).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign ed25519 runtime - encrypted', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new OasisApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.toggleExpertMode()

      const meta = Buffer.from(
        'ompydW50aW1lX2lkeEAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBlMmVhYTk5ZmMwMDhmODdmbWNoYWluX2NvbnRleHR4QGJiM2Q3NDhkZWY1NWJkZmI3OTdhMmFjNTNlZTZlZTE0MWU1NGNkMmFiMmRjMjM3NWY0YTA3MDNhMTc4ZTZlNTU=',
        'base64',
      )

      const txBlob = Buffer.from(
        'o2F2AWJhaaJic2mBomVub25jZQBsYWRkcmVzc19zcGVjoWlzaWduYXR1cmWhZ2VkMjU1MTlYIDXD8zVt2FNk/roDVLVFraEJ0b2zi/XWEmgX24xyz9aRY2ZlZaFmYW1vdW50gkBAZGNhbGyiZGJvZHmjYnBrWCBzb21lcHVibGlja2V5MTIzc29tZXB1YmxpY2tleTEyM2RkYXRhWGyiZGJvZHmjYnBrWCDmZ1CN4J/Y25fyLn3uNAMB7Irbh4kLWjEgVBPy6+R9FGRkYXRhWBu//CmsZl8IPaB9fHJmTdJHpoeEL2k5YPM+SCRlbm9uY2VP2vmpbD1OFFuXYCigkTchZmZvcm1hdAFlbm9uY2VPc29tZXJhbmRvbW5vbmNlZmZvcm1hdAE=',
        'base64',
      )

      const sigCtx = Buffer.from('oasis-runtime-sdk/tx: v0 for chain 70869cb5e35133c69c82c91ccae4cbc0d6c53cfaf5e64fee098b74e7588eba03')

      const pkResponse = await app.getAddressAndPubKey_ed25519(path)
      console.log(pkResponse)
      expect(pkResponse.return_code).toEqual(0x9000)
      expect(pkResponse.error_message).toEqual('No errors')

      // do not wait here..
      const signatureRequest = app.signRtEd25519(path, meta, txBlob)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-adr0014-sign_ed25519_runtime_encrypted`)

      let resp = await signatureRequest
      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')

      const hasher = sha512.sha512_256.update(sigCtx)
      hasher.update(txBlob)
      const msgHash = Buffer.from(hasher.hex(), 'hex')

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk)
      expect(valid).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign ed25519 runtime - evm', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new OasisApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.toggleExpertMode()

      const meta = Buffer.from(
        'ompydW50aW1lX2lkeEAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBlMmVhYTk5ZmMwMDhmODdmbWNoYWluX2NvbnRleHR4QGJiM2Q3NDhkZWY1NWJkZmI3OTdhMmFjNTNlZTZlZTE0MWU1NGNkMmFiMmRjMjM3NWY0YTA3MDNhMTc4ZTZlNTU=',
        'base64',
      )

      const txBlob = Buffer.from(
        'o2F2AWJhaaJic2mBomVub25jZRv//////////2xhZGRyZXNzX3NwZWOhaXNpZ25hdHVyZaFnZWQyNTUxOVggNcPzNW3YU2T+ugNUtUWtoQnRvbOL9dYSaBfbjHLP1pFjZmVlomNnYXMZB9BmYW1vdW50gkBAZGNhbGyiZGJvZHmjZGRhdGFYRKkFnLsAAAAAAAAAAAAAAACQreO3Bl+nFcehUDE4d98dM+d31QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPZXZhbHVlWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGdhZGRyZXNzVCHHGMItUtDzp4m3UtTC/VkIqKczZm1ldGhvZGhldm0uQ2FsbA==',
        'base64',
      )

      const sigCtx = Buffer.from('oasis-runtime-sdk/tx: v0 for chain 70869cb5e35133c69c82c91ccae4cbc0d6c53cfaf5e64fee098b74e7588eba03')

      const pkResponse = await app.getAddressAndPubKey_ed25519(path)
      console.log(pkResponse)
      expect(pkResponse.return_code).toEqual(0x9000)
      expect(pkResponse.error_message).toEqual('No errors')

      // do not wait here..
      const signatureRequest = app.signRtEd25519(path, meta, txBlob)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-adr0014-sign_ed25519_runtime_evm`)

      let resp = await signatureRequest
      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')

      const hasher = sha512.sha512_256.update(sigCtx)
      hasher.update(txBlob)
      const msgHash = Buffer.from(hasher.hex(), 'hex')

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk)
      expect(valid).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('get Sr25519 address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new OasisApp(sim.getTransport())

      const resp = await app.getAddressAndPubKey_sr25519(path)

      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')

      const expected_bech32_address = 'oasis1qr9af6sfg3gmv5nefxkq7k7cxpz48r0wlu2j9frf'
      const expected_pk = 'bcfd51e4c33347fafdae2732998a4f6c103d26f9a58b1773944616129c791316'

      expect(resp.bech32_address).toEqual(expected_bech32_address)
      expect(resp.pk.toString('hex')).toEqual(expected_pk)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('show Sr25519 address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({
        ...defaultOptions,
        model: m.name,
        approveKeyword: isTouchDevice(m.name) ? 'Confirm' : '',
        approveAction: ButtonKind.ApproveTapButton,
      })
      const app = new OasisApp(sim.getTransport())

      const respRequest = app.showAddressAndPubKey_sr25519(path)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-adr0014_show_address_sr25519`)

      const resp = await respRequest
      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')

      const expected_bech32_address = 'oasis1qr9af6sfg3gmv5nefxkq7k7cxpz48r0wlu2j9frf'
      const expected_pk = 'bcfd51e4c33347fafdae2732998a4f6c103d26f9a58b1773944616129c791316'

      expect(resp.bech32_address).toEqual(expected_bech32_address)
      expect(resp.pk.toString('hex')).toEqual(expected_pk)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign sr25519 consensus - withdraw', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new OasisApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.toggleExpertMode()

      const meta = Buffer.from(
        'ompydW50aW1lX2lkeEAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBlMmVhYTk5ZmMwMDhmODdmbWNoYWluX2NvbnRleHR4QGJiM2Q3NDhkZWY1NWJkZmI3OTdhMmFjNTNlZTZlZTE0MWU1NGNkMmFiMmRjMjM3NWY0YTA3MDNhMTc4ZTZlNTU=',
        'base64',
      )

      const txBlob = Buffer.from(
        'o2F2AWJhaaJic2mBomVub25jZQBsYWRkcmVzc19zcGVjoWlzaWduYXR1cmWhZ2VkMjU1MTlYIDXD8zVt2FNk/roDVLVFraEJ0b2zi/XWEmgX24xyz9aRY2ZlZaJmYW1vdW50gkBAcmNvbnNlbnN1c19tZXNzYWdlcwFkY2FsbKJkYm9keaFmYW1vdW50gkBAZm1ldGhvZHJjb25zZW5zdXMuV2l0aGRyYXc=',
        'base64',
      )

      const sigCtx = Buffer.from('oasis-runtime-sdk/tx: v0 for chain 70869cb5e35133c69c82c91ccae4cbc0d6c53cfaf5e64fee098b74e7588eba03')

      const pkResponse = await app.getAddressAndPubKey_sr25519(path)
      console.log(pkResponse)
      expect(pkResponse.return_code).toEqual(0x9000)
      expect(pkResponse.error_message).toEqual('No errors')

      // do not wait here..
      const signatureRequest = app.signRtSr25519(path, meta, txBlob)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-adr0014-sign_sr25519_consensus_withdraw`)

      let resp = await signatureRequest
      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')

      // Now verify the signature
      const valid = addon.schnorrkel_verify(pkResponse.pk, sigCtx, txBlob, resp.signature)
      expect(valid).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign sr25519 runtime - evm', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new OasisApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.toggleExpertMode()

      const meta = Buffer.from(
        'ompydW50aW1lX2lkeEAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBlMmVhYTk5ZmMwMDhmODdmbWNoYWluX2NvbnRleHR4QGJiM2Q3NDhkZWY1NWJkZmI3OTdhMmFjNTNlZTZlZTE0MWU1NGNkMmFiMmRjMjM3NWY0YTA3MDNhMTc4ZTZlNTU=',
        'base64',
      )

      const txBlob = Buffer.from(
        'o2F2AWJhaaJic2mBomVub25jZRv//////////2xhZGRyZXNzX3NwZWOhaXNpZ25hdHVyZaFnZWQyNTUxOVggNcPzNW3YU2T+ugNUtUWtoQnRvbOL9dYSaBfbjHLP1pFjZmVlomNnYXMZB9BmYW1vdW50gkBAZGNhbGyiZGJvZHmjZGRhdGFYRKkFnLsAAAAAAAAAAAAAAACQreO3Bl+nFcehUDE4d98dM+d31QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPZXZhbHVlWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGdhZGRyZXNzVCHHGMItUtDzp4m3UtTC/VkIqKczZm1ldGhvZGhldm0uQ2FsbA==',
        'base64',
      )

      const sigCtx = Buffer.from('oasis-runtime-sdk/tx: v0 for chain 70869cb5e35133c69c82c91ccae4cbc0d6c53cfaf5e64fee098b74e7588eba03')

      const pkResponse = await app.getAddressAndPubKey_sr25519(path)
      console.log(pkResponse)
      expect(pkResponse.return_code).toEqual(0x9000)
      expect(pkResponse.error_message).toEqual('No errors')

      // do not wait here..
      const signatureRequest = app.signRtSr25519(path, meta, txBlob)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-adr0014-sign_sr25519_runtime_evm`)

      let resp = await signatureRequest
      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')

      // Now verify the signature
      const valid = addon.schnorrkel_verify(pkResponse.pk, sigCtx, txBlob, resp.signature)
      expect(valid).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign sr25519 runtime - encrypted', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new OasisApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.toggleExpertMode()

      const meta = Buffer.from(
        'ompydW50aW1lX2lkeEAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBlMmVhYTk5ZmMwMDhmODdmbWNoYWluX2NvbnRleHR4QGJiM2Q3NDhkZWY1NWJkZmI3OTdhMmFjNTNlZTZlZTE0MWU1NGNkMmFiMmRjMjM3NWY0YTA3MDNhMTc4ZTZlNTU=',
        'base64',
      )

      const txBlob = Buffer.from(
        'o2F2AWJhaaJic2mBomVub25jZQBsYWRkcmVzc19zcGVjoWlzaWduYXR1cmWhZ2VkMjU1MTlYIDXD8zVt2FNk/roDVLVFraEJ0b2zi/XWEmgX24xyz9aRY2ZlZaFmYW1vdW50gkBAZGNhbGyiZGJvZHmjYnBrWCBzb21lcHVibGlja2V5MTIzc29tZXB1YmxpY2tleTEyM2RkYXRhWGyiZGJvZHmjYnBrWCDmZ1CN4J/Y25fyLn3uNAMB7Irbh4kLWjEgVBPy6+R9FGRkYXRhWBu//CmsZl8IPaB9fHJmTdJHpoeEL2k5YPM+SCRlbm9uY2VP2vmpbD1OFFuXYCigkTchZmZvcm1hdAFlbm9uY2VPc29tZXJhbmRvbW5vbmNlZmZvcm1hdAE=',
        'base64',
      )

      const sigCtx = Buffer.from('oasis-runtime-sdk/tx: v0 for chain 70869cb5e35133c69c82c91ccae4cbc0d6c53cfaf5e64fee098b74e7588eba03')

      const pkResponse = await app.getAddressAndPubKey_sr25519(path)
      console.log(pkResponse)
      expect(pkResponse.return_code).toEqual(0x9000)
      expect(pkResponse.error_message).toEqual('No errors')

      // do not wait here..
      const signatureRequest = app.signRtSr25519(path, meta, txBlob)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-adr0014-sign_sr25519_runtime_encrypted`)

      let resp = await signatureRequest
      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')

      // Now verify the signature
      const valid = addon.schnorrkel_verify(pkResponse.pk, sigCtx, txBlob, resp.signature)
      expect(valid).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('contracts-empty-data', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new OasisApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.toggleExpertMode()

      const meta = Buffer.from(
        'ompydW50aW1lX2lkeEAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBlMmVhYTk5ZmMwMDhmODdmbWNoYWluX2NvbnRleHR4QGJiM2Q3NDhkZWY1NWJkZmI3OTdhMmFjNTNlZTZlZTE0MWU1NGNkMmFiMmRjMjM3NWY0YTA3MDNhMTc4ZTZlNTU=',
        'base64',
      )

      const txBlob = Buffer.from(
        'o2F2AWJhaaJic2mBomVub25jZQBsYWRkcmVzc19zcGVjoWlzaWduYXR1cmWhZ2VkMjU1MTlYIDXD8zVt2FNk/roDVLVFraEJ0b2zi/XWEmgX24xyz9aRY2ZlZaFmYW1vdW50gkBAZGNhbGyiZGJvZHmkZGRhdGFBoGZ0b2tlbnODgkQ7msoAQIJCB9BEV0JUQ4JDLcbARFdFVEhnY29kZV9pZABvdXBncmFkZXNfcG9saWN5oWhldmVyeW9uZaBmbWV0aG9kdWNvbnRyYWN0cy5JbnN0YW50aWF0ZQ==',
        'base64',
      )

      const sigCtx = Buffer.from('oasis-runtime-sdk/tx: v0 for chain 70869cb5e35133c69c82c91ccae4cbc0d6c53cfaf5e64fee098b74e7588eba03')

      const pkResponse = await app.getAddressAndPubKey_ed25519(path)
      console.log(pkResponse)
      expect(pkResponse.return_code).toEqual(0x9000)
      expect(pkResponse.error_message).toEqual('No errors')

      const signatureRequest = app.signRtEd25519(path, meta, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-adr0014-sign_ed15519_contracts-empty-data`)

      let resp = await signatureRequest
      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')

      const hasher = sha512.sha512_256.update(sigCtx)
      hasher.update(txBlob)
      const msgHash = Buffer.from(hasher.hex(), 'hex')

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk)
      expect(valid).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('contracts-array-map', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new OasisApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.toggleExpertMode()

      const meta = Buffer.from(
        'ompydW50aW1lX2lkeEAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBlMmVhYTk5ZmMwMDhmODdmbWNoYWluX2NvbnRleHR4QGJiM2Q3NDhkZWY1NWJkZmI3OTdhMmFjNTNlZTZlZTE0MWU1NGNkMmFiMmRjMjM3NWY0YTA3MDNhMTc4ZTZlNTU=',
        'base64',
      )

      const txBlob = Buffer.from(
        'o2F2AWJhaaJic2mBomVub25jZQBsYWRkcmVzc19zcGVjoWlzaWduYXR1cmWhZ2VkMjU1MTlYIDXD8zVt2FNk/roDVLVFraEJ0b2zi/XWEmgX24xyz9aRY2ZlZaFmYW1vdW50gkBAZGNhbGyiZGJvZHmkZGRhdGFYQKJlb3RoZXKDAaJhYQFhYgICZmJpZ21hcKFnYmlnbWFwMqJrbmV3X2NvdW50ZXICb2luaXRpYWxfY291bnRlcgFmdG9rZW5zg4JEO5rKAECCQgfQRFdCVEOCQy3GwERXRVRIZ2NvZGVfaWQAb3VwZ3JhZGVzX3BvbGljeaFoZXZlcnlvbmWgZm1ldGhvZHVjb250cmFjdHMuSW5zdGFudGlhdGU=',
        'base64',
      )

      const sigCtx = Buffer.from('oasis-runtime-sdk/tx: v0 for chain 70869cb5e35133c69c82c91ccae4cbc0d6c53cfaf5e64fee098b74e7588eba03')

      const pkResponse = await app.getAddressAndPubKey_ed25519(path)
      console.log(pkResponse)
      expect(pkResponse.return_code).toEqual(0x9000)
      expect(pkResponse.error_message).toEqual('No errors')

      const signatureRequest = app.signRtEd25519(path, meta, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      if (m.name == 'nanos') {
        await sim.navigateAndCompareSnapshots(
          '.',
          `${m.prefix.toLowerCase()}-adr0014-sign_ed15519_contracts-array-map`,
          [2, 0, 0, 1, 0, 2, 0, 2, 0, 8, 0],
          false,
        )
      } else if (isTouchDevice(m.name)) {
        await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-adr0014-sign_ed15519_contracts-array-map`)
      } else {
        await sim.navigateAndCompareSnapshots(
          '.',
          `${m.prefix.toLowerCase()}-adr0014-sign_ed15519_contracts--array-map`,
          [3, 0, 0, 1, 0, 2, 0, 2, 0, 8, 0],
          false,
        )
      }

      let resp = await signatureRequest
      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')

      const hasher = sha512.sha512_256.update(sigCtx)
      hasher.update(txBlob)
      const msgHash = Buffer.from(hasher.hex(), 'hex')

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk)
      expect(valid).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('contracts-types', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new OasisApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.toggleExpertMode()

      const meta = Buffer.from(
        'ompydW50aW1lX2lkeEAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBlMmVhYTk5ZmMwMDhmODdmbWNoYWluX2NvbnRleHR4QGJiM2Q3NDhkZWY1NWJkZmI3OTdhMmFjNTNlZTZlZTE0MWU1NGNkMmFiMmRjMjM3NWY0YTA3MDNhMTc4ZTZlNTU=',
        'base64',
      )

      const txBlob = Buffer.from(
        'o2F2AWJhaaJic2mBomVub25jZQBsYWRkcmVzc19zcGVjoWlzaWduYXR1cmWhZ2VkMjU1MTlYIDXD8zVt2FNk/roDVLVFraEJ0b2zi/XWEmgX24xyz9aRY2ZlZaFmYW1vdW50gkBAZGNhbGyiZGJvZHmkZGRhdGFYcqdjYWxs+kL26dVkYWxsMfVkYWxsMvZlZmlyc3RldGVzdGVlb3RoZXKDAaJhYQFhYgICZmJpZ21hcKFnYmlnbWFwMqJrbmV3X2NvdW50ZXICb2luaXRpYWxfY291bnRlcgFraW5zdGFudGlhdGWiAQICA2Z0b2tlbnODgkQ7msoAQIJCB9BEV0JUQ4JDLcbARFdFVEhnY29kZV9pZABvdXBncmFkZXNfcG9saWN5oWhldmVyeW9uZaBmbWV0aG9kdWNvbnRyYWN0cy5JbnN0YW50aWF0ZQ==',
        'base64',
      )

      const sigCtx = Buffer.from('oasis-runtime-sdk/tx: v0 for chain 70869cb5e35133c69c82c91ccae4cbc0d6c53cfaf5e64fee098b74e7588eba03')

      const pkResponse = await app.getAddressAndPubKey_ed25519(path)
      console.log(pkResponse)
      expect(pkResponse.return_code).toEqual(0x9000)
      expect(pkResponse.error_message).toEqual('No errors')
      const signatureRequest = app.signRtEd25519(path, meta, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      if (m.name == 'nanos') {
        await sim.navigateAndCompareSnapshots(
          '.',
          `${m.prefix.toLowerCase()}-adr0014-sign_ed15519_contracts-types`,
          [2, 0, 0, 5, 0, 0, -1, 0, 8, 0],
          false,
        )
      } else if (isTouchDevice(m.name)) {
        await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-adr0014-sign_ed15519_contracts-array-map`)
      } else {
        await sim.navigateAndCompareSnapshots(
          '.',
          `${m.prefix.toLowerCase()}-adr0014-sign_ed15519_contracts-types`,
          [3, 0, 0, 5, 0, 0, -1, 0, 8, 0],
          false,
        )
      }

      let resp = await signatureRequest
      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')

      const hasher = sha512.sha512_256.update(sigCtx)
      hasher.update(txBlob)
      const msgHash = Buffer.from(hasher.hex(), 'hex')

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk)
      expect(valid).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign ed25519 consensus - delegate', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new OasisApp(sim.getTransport())

      const meta = Buffer.from(
        'ompydW50aW1lX2lkeEAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBlMmVhYTk5ZmMwMDhmODdmbWNoYWluX2NvbnRleHR4QGJiM2Q3NDhkZWY1NWJkZmI3OTdhMmFjNTNlZTZlZTE0MWU1NGNkMmFiMmRjMjM3NWY0YTA3MDNhMTc4ZTZlNTU=',
        'base64',
      )

      const txBlob = Buffer.from(
        'o2F2AWJhaaJic2mBomVub25jZQFsYWRkcmVzc19zcGVjoWlzaWduYXR1cmWhZ2VkMjU1MTlYIDXD8zVt2FNk/roDVLVFraEJ0b2zi/XWEmgX24xyz9aRY2ZlZaNjZ2FzGQfQZmFtb3VudIJAQHJjb25zZW5zdXNfbWVzc2FnZXMBZGNhbGyiZGJvZHmiYnRvVQAml8ChOLxRJ4uAlvu79/O9KQ0gmGZhbW91bnSCSAFjRXhdigAAQGZtZXRob2RyY29uc2Vuc3VzLkRlbGVnYXRl',
        'base64',
      )

      const sigCtx = Buffer.from('oasis-runtime-sdk/tx: v0 for chain 70869cb5e35133c69c82c91ccae4cbc0d6c53cfaf5e64fee098b74e7588eba03')

      const pkResponse = await app.getAddressAndPubKey_ed25519(path)
      console.log(pkResponse)
      expect(pkResponse.return_code).toEqual(0x9000)
      expect(pkResponse.error_message).toEqual('No errors')

      // do not wait here..
      const signatureRequest = app.signRtEd25519(path, meta, txBlob)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-adr0014-sign_ed25519_consensus_delegate`)

      let resp = await signatureRequest
      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')

      const hasher = sha512.sha512_256.update(sigCtx)
      hasher.update(txBlob)
      const msgHash = Buffer.from(hasher.hex(), 'hex')

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk)
      expect(valid).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign ed25519 consensus - undelegate', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new OasisApp(sim.getTransport())

      const meta = Buffer.from(
        'ompydW50aW1lX2lkeEAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBlMmVhYTk5ZmMwMDhmODdmbWNoYWluX2NvbnRleHR4QGJiM2Q3NDhkZWY1NWJkZmI3OTdhMmFjNTNlZTZlZTE0MWU1NGNkMmFiMmRjMjM3NWY0YTA3MDNhMTc4ZTZlNTU=',
        'base64',
      )

      const txBlob = Buffer.from(
        'o2F2AWJhaaJic2mBomVub25jZQFsYWRkcmVzc19zcGVjoWlzaWduYXR1cmWhZ2VkMjU1MTlYIDXD8zVt2FNk/roDVLVFraEJ0b2zi/XWEmgX24xyz9aRY2ZlZaJmYW1vdW50gkBAcmNvbnNlbnN1c19tZXNzYWdlcwFkY2FsbKJkYm9keaJkZnJvbVUA7UP3UlAm/VN6C/UkSIt8VJ8DmCVmc2hhcmVzSAFjRXhdigAAZm1ldGhvZHRjb25zZW5zdXMuVW5kZWxlZ2F0ZQ==',
        'base64',
      )

      const sigCtx = Buffer.from('oasis-runtime-sdk/tx: v0 for chain 70869cb5e35133c69c82c91ccae4cbc0d6c53cfaf5e64fee098b74e7588eba03')

      const pkResponse = await app.getAddressAndPubKey_ed25519(path)
      console.log(pkResponse)
      expect(pkResponse.return_code).toEqual(0x9000)
      expect(pkResponse.error_message).toEqual('No errors')

      // do not wait here..
      const signatureRequest = app.signRtEd25519(path, meta, txBlob)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-adr0014-sign_ed25519_consensus_undelegate`)

      let resp = await signatureRequest
      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')

      const hasher = sha512.sha512_256.update(sigCtx)
      hasher.update(txBlob)
      const msgHash = Buffer.from(hasher.hex(), 'hex')

      // Now verify the signature
      const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk)
      expect(valid).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})
