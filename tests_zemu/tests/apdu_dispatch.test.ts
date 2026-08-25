/** ******************************************************************************
 *  (c) 2018 - 2026 Zondax AG
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

import Zemu, { DEFAULT_START_OPTIONS } from '@zondax/zemu'
import { models } from './common'

jest.setTimeout(180000)

const APP_SEED = 'equip will roof matter pink blind book anxiety banner elbow sun young'

const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
}

const CLA = 0x05
const CLA_ETH = 0xe0

// 0x02 is INS_GET_ADDR_ETH under CLA_ETH and INS_SIGN_ED25519 under CLA.
const INS_02 = 0x02

const SW_OK = 0x9000
const SW_COMMAND_NOT_ALLOWED = 0x6986
const SW_INS_NOT_SUPPORTED = 0x6d00
const SW_CLA_NOT_SUPPORTED = 0x6e00

// m/44'/60'/0'/0/<account> as BE uint32 words, prefixed with the component count.
function ethPath(account: number): Buffer {
  const words = [0x8000002c, 0x8000003c, 0x80000000, 0x00000000, account]
  const buf = Buffer.alloc(1 + 4 * words.length)
  buf[0] = words.length
  words.forEach((w, i) => buf.writeUInt32BE(w >>> 0, 1 + 4 * i))
  return buf
}

function apdu(cla: number, ins: number, p1: number, p2: number, data: Buffer): string {
  return Buffer.concat([Buffer.from([cla, ins, p1, p2, data.length]), data]).toString('hex')
}

// The transport serialises exchanges, so it cannot put a second APDU on the
// wire while the first is still awaiting a user review. Speak to the emulator's
// APDU endpoint directly, which is what a second host process would do.
async function raw(port: number, hex: string, timeoutMs = 45000): Promise<string> {
  const res = await fetch(`http://127.0.0.1:${port}/apdu`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ data: hex }),
    signal: AbortSignal.timeout(timeoutMs),
  })
  return (await res.json()).data ?? ''
}

const statusOf = (r: string) => parseInt(r.slice(-4), 16)

// Named to match the `jest -t 'Standard'` filter the CI job runs; a describe
// block outside that pattern is silently skipped there.
describe('Standard-APDU-Dispatch', function () {
  test.concurrent.each(models)('INS 0x02 resolves by class', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const port = (sim as any).speculosApiPort

      // CLA_ETH + 0x02 is get-address. Without confirmation it answers directly.
      const noConfirm = await raw(port, apdu(CLA_ETH, INS_02, 0x00, 0x00, ethPath(0)))
      expect(statusOf(noConfirm)).toEqual(SW_OK)
      expect(noConfirm.length).toBeGreaterThan(4)

      // CLA + 0x02 is ed25519 signing. It must reach that handler rather than
      // the address one, i.e. it must not be reported as an unknown INS/CLA.
      const signInit = await raw(port, apdu(CLA, INS_02, 0x00, 0x00, ethPath(0)))
      expect(statusOf(signInit)).not.toEqual(SW_INS_NOT_SUPPORTED)
      expect(statusOf(signInit)).not.toEqual(SW_CLA_NOT_SUPPORTED)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('a pending review is not served', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const port = (sim as any).speculosApiPort

      const account0 = await raw(port, apdu(CLA_ETH, INS_02, 0x00, 0x00, ethPath(0)))
      expect(statusOf(account0)).toEqual(SW_OK)

      // Ask for the same address with confirmation and leave it on screen.
      const pending = raw(port, apdu(CLA_ETH, INS_02, 0x01, 0x00, ethPath(0)), 90000).catch(() => '')
      await Zemu.sleep(2500)

      // A second request for a *different* account must not be served while
      // that review is up, otherwise it would move the reply out from under it.
      const raced = await raw(port, apdu(CLA_ETH, INS_02, 0x00, 0x00, ethPath(9)))
      expect(statusOf(raced)).toEqual(SW_COMMAND_NOT_ALLOWED)

      await pending
    } finally {
      await sim.close()
    }
  })

  // Button navigation only: the touch models need snapshot baselines to drive a
  // review reliably, and this case asserts status words rather than pixels.
  const buttonModels = models.filter(m => m.name.startsWith('nano'))

  test.concurrent.each(buttonModels)('an approved review answers, and releases', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const port = (sim as any).speculosApiPort

      const reference = await raw(port, apdu(CLA_ETH, INS_02, 0x00, 0x00, ethPath(0)))
      expect(statusOf(reference)).toEqual(SW_OK)

      const pending = raw(port, apdu(CLA_ETH, INS_02, 0x01, 0x00, ethPath(0)), 90000)
      await Zemu.sleep(2500)

      for (let i = 0; i < 12; i += 1) {
        const events = await sim.getEvents()
        const text = events.slice(-4).map((e: any) => e.text).filter(Boolean).join(' | ')
        if (/APPROVE/i.test(text)) {
          await sim.clickBoth()
          break
        }
        await sim.clickRight()
      }

      // The confirmed request is answered, with the address that was displayed.
      const answered = await pending
      expect(statusOf(answered)).toEqual(SW_OK)
      expect(answered).toEqual(reference)

      // ...and the device serves requests again afterwards.
      const afterwards = await raw(port, apdu(CLA_ETH, INS_02, 0x00, 0x00, ethPath(0)))
      expect(statusOf(afterwards)).toEqual(SW_OK)
    } finally {
      await sim.close()
    }
  })
})
