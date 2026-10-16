# USB protocol (host ↔ phone)

The phone and its host (the macOS companion, or the Python reference client
`tools/aoa_client.py`) talk over **Android Open Accessory (AOA)**. The desktop is the USB host;
the phone is the accessory. There is no other transport: the phone has no network, Bluetooth or
camera input.

Sources of truth, if this document and the code ever disagree:

| Side | Files |
|---|---|
| Phone (Java) | `app/src/main/java/dev/phonevault/signer/AccessoryTransport.java` (framing, size limits, strict parse), `Eip1559Request.java`, `MessageRequest.java`, `AttestationProtocol.java`, `BtcRequest.java`, `HostSimulation.java`, `EvmSigner.java`, `MessageApprovalSession.java`, request dispatch in `MainActivity.onRequest` |
| Companion (Rust) | `companion/src-tauri/src/aoa.rs` (accessory switch, framing, response caps), `verify.rs`, `message.rs`, `attest/`, `btc/verify.rs` |
| Reference client (Python) | `tools/aoa_client.py`, `tools/evm_verify.py` |

Related design documents: [message-signing.md](message-signing.md),
[device-attestation.md](device-attestation.md), [simulation.md](simulation.md), and the
"Bitcoin" sections of [threat-model.md](threat-model.md).

## Accessory handshake

The host switches the phone into accessory mode with the standard AOA control requests
(`GET_PROTOCOL` 51, `SEND_STRING` 52, `START` 53) and the identity strings
`PhoneVault` / `EVM Signer` (manufacturer / model, which the app's accessory filter matches).
It then claims the vendor interface with two bulk endpoints (class/subclass/protocol
`ff/ff/00`). Only one Android device may be attached; a host-side `adb` server holding the
interface must be stopped first.

The phone opens a transport only on a fresh `ACCESSORY_ATTACHED`. After any lock the host must
reconnect (unplug/replug, or reset the gadget).

## Framing

- One request, one response. Both are a single line of UTF-8 JSON terminated by `\n`.
- A request is at most **32 KiB**. A `btcSignPsbt` request may be up to **288 KiB**, but only if
  `"method":"btcSignPsbt"` appears within its first 32 KiB (so the host sends `psbt` last); a long
  line that then parses as any other method is refused.
- The host accepts responses up to 64 KiB (272 KiB for `btcSignPsbt`), refuses more than one
  framed response per request, and requires the response `id` to equal the request `id`.
- The phone queues at most 4 unread responses; a host that stops reading has its session ended.
- Any read, parse or write failure ends the session.

## Request rules (all methods)

The phone parses every line with a strict RFC 8259 parser (`StrictJson`) and then checks the
method's schema exactly:

- The line must be one JSON object, followed by nothing but JSON whitespace.
- Malformed UTF-8, truncated frames, duplicate keys, comments, invalid or non-ASCII `\u` escapes,
  raw control characters and unpaired surrogates are refused.
- **Every value is a string**, except the one nested object `hostSimulation` (below).
- The field set must equal the method's schema exactly: missing or unknown fields are refused.
- `id`: 1–128 characters of `[A-Za-z0-9._:-]`.
- Integer quantities are canonical `0x` hex (`0x0`, `0x1a`; no leading zeros; a bare `0x` is invalid).
- Addresses are `0x` + 40 hex characters.

## Readiness and the locked phone

The phone answers only while it is unlocked, holds an authoritative loaded wallet, has
completed the backup check, has an active account selected, and is not in a sensitive flow
(seed reveal, wallet replacement, passphrase entry). Otherwise it answers
`{"id":…,"status":"error","error":"Wallet is not ready: …"}`.

A request that arrives while the phone is **locked** is decoded for display only: the PIN screen
shows a summary ("The connected host asks for your receiving address. Unlock to continue.", or
the type/amount/recipient/network of a transaction). **Nothing is sent** until the PIN is
entered; the request then goes through the normal review path. Locking drops the held request.

Only one approval may be pending at a time ("Another approval is pending").

## Response shapes

| Outcome | Shape |
|---|---|
| Informational success | `{"id","status":"ok", …}` |
| Approved signature | `{"id","status":"approved", …}` |
| User declined | `{"id","status":"rejected"}` |
| Refused (schema, policy, not ready) | `{"id","status":"error","error":"<human-readable reason>"}` |

A created signature is reported as approved; the phone never claims it was delivered, broadcast
or settled. The host must verify every response independently (below).

## Methods

### `getAddress`

```json
{"id":"address-1","method":"getAddress"}
{"id":"address-1","status":"ok","address":"0x…","account":"1","wallet":"standard"}
```

Returns the **active** account: its address, its 1-based account number, and `wallet` =
`standard` or `passphrase`. No label, fingerprint or passphrase is ever sent.

### `signEip1559`

```json
{
  "id":"test-1",
  "method":"signEip1559",
  "chainId":"0xaa36a7",
  "nonce":"0x0",
  "maxPriorityFeePerGas":"0x3b9aca00",
  "maxFeePerGas":"0x77359400",
  "gasLimit":"0x5208",
  "to":"0x1111111111111111111111111111111111111111",
  "value":"0x0",
  "data":"0x"
}
```

Optional fields:

- `from`: the account the host expects. If it is not the active account the request is refused
  ("Switch to the right account on the phone"). Not signed.
- `hostSimulation`: the companion's **untrusted**, display-only claim of balance changes
  (`{"changes":[{"asset","delta",…}],"node","block"}`; schema in `HostSimulation.java` and
  [simulation.md](simulation.md)). It is never signed and never used to decode the transaction;
  the review shows it in a separate box and flags a claim that contradicts the phone's own
  decoding. A malformed claim refuses the whole request.

Rules:

- Only type-2 (EIP-1559) transactions are built. A request naming `authorizationList` or type 4
  (EIP-7702 set-code) is refused explicitly.
- `chainId` must have a reviewed chain profile: Ethereum (1), Sepolia (11155111), Base (8453),
  OP Mainnet (10), Arbitrum One (42161), Polygon (137). Other chains are refused.
- Quantities ≤ 256 bits, `maxPriorityFeePerGas` ≤ `maxFeePerGas`, `gasLimit` > 0, zero `to`
  refused, `data` even-length hex.
- Calldata the phone cannot fully decode is **refused**, never offered for blind signing. Decoded:
  - empty `data`: native transfer;
  - ERC-20 `transfer`, `approve`, `transferFrom`, `increaseAllowance` (no native value allowed);
    token names and decimals come from the built-in, SHA-256-pinned token list
    (`app/token-list/SOURCES.md`); other contracts are shown as unknown, in raw base units;
  - NFT `setApprovalForAll`, ERC-721 `safeTransferFrom` (with and without data), ERC-1155
    `safeTransferFrom` / `safeBatchTransferFrom` (no native value allowed);
  - calls to a pinned Uniswap router (Universal Router 2.0 / 2.1.x, SwapRouter02;
    `app/token-list/ROUTER-SOURCES.md`), decoded in full into a swap review or refused.

Approved response:

```json
{"id":"test-1","status":"approved","address":"0x…","signedTransaction":"0x02…","transactionHash":"0x…"}
```

The host must decode `signedTransaction`, compare every field with what it asked for, recompute
the hash from the signed bytes, recover the signer, and require it to equal both `address` and
the address pinned at pairing (`companion/src-tauri/src/verify.rs`, `tools/evm_verify.py`).

### `personal_sign` and `eth_signTypedData_v4`

```json
{"id":"m1","method":"personal_sign","chainId":"0x1","message":"0x48656c6c6f"}
{"id":"m2","method":"eth_signTypedData_v4","chainId":"0x1","typedData":"{\"types\":…}"}
```

- `chainId`: the network the host is working on (a reviewed chain profile). It is not signed; the
  review compares it with the chain the message names and warns on a mismatch.
- `message`: non-empty, even-length `0x` hex, at most 8192 bytes. An EIP-7702 authorization tuple
  (`0x05…`) is refused.
- `typedData`: the EIP-712 JSON as a **string** (at most 24 KiB, bounded types/fields/arrays; see
  `Eip712.java`). Typed data that encodes a delegation is refused.
- Optional `from` (as above) and `origin`: the web origin the host says asked
  (`https://<lowercase host>[:port]`, or `http://localhost` / `127.0.0.1` / `[::1]` with optional
  port; ≤ 255 characters). Display only; the phone cannot verify it.

Approved response (`signature` is `r‖s‖v`, 65 bytes, `v` = 27/28):

```json
{"id":"m1","status":"approved","address":"0x…","signature":"0x…","digest":"0x…"}
```

The host recomputes the digest from its original request with its own implementation and refuses
a signature whose digest differs or that does not recover to the pinned address. Raw `eth_sign`
does not exist. Details: [message-signing.md](message-signing.md).

### `attest`

```json
{"id":"a1","method":"attest","challenge":"<16..64 bytes, lowercase hex>"}
{"id":"a1","status":"ok","version":"1","address":"0x…","securityLevel":"StrongBox",
 "certificates":"<base64 DER leaf>,…,<base64 DER root>","signature":"0x<DER ECDSA>"}
```

A fresh StrongBox (Titan M / M2) key attests the challenge; it signs
`"PhoneVault-attest-v1" ‖ 0x00 ‖ len(challenge) ‖ challenge ‖ address (20 bytes)`. The wallet
key is never used, there is no review screen, and each challenge is answered once
("This challenge was already answered"). `securityLevel` is `StrongBox` or
`TrustedEnvironment`. The companion verifies the chain to Google's pinned roots and decides
GENUINE / DEVELOPMENT / FAIL; see [device-attestation.md](device-attestation.md).

### Bitcoin: `btcGetAccount`, `btcShowAddress`, `btcSignPsbt`

Same seed, standard wallet only (refused while a passphrase wallet is open). `network` is
`bitcoin`, `testnet` or `signet` (coin type 0 / 1 / 1); `type` is `p2wpkh` (BIP-84), `p2tr`
(BIP-86, key path), or, for coins of a restored Ledger/Trezor-era wallet, `p2sh-p2wpkh` (BIP-49
Nested SegWit, `3…` / `2…`) or `p2pkh` (BIP-44 Legacy, `1…` / `m…`, `n…`); `account` is
`"1"`…`"20"` (account `"1"` is `m/84'/coin'/0'`, `m/86'/coin'/0'`, `m/49'/coin'/0'` or
`m/44'/coin'/0'`). The account key is always an `xpub`/`tpub` (never SLIP-132 `ypub`); the
descriptor names the script: `wpkh(…)`, `tr(…)`, `sh(wpkh(…))` or `pkh(…)`.

```json
{"id":"b1","method":"btcGetAccount","network":"bitcoin","type":"p2wpkh","account":"1"}
{"id":"b1","status":"ok","fingerprint":"73c5da0a","path":"m/84'/0'/0'","xpub":"xpub6Cat…","descriptor":"wpkh([73c5da0a/84h/0h/0h]xpub6Cat…/<0;1>/*)#qf45pmyh"}

{"id":"b2","method":"btcShowAddress","network":"testnet","type":"p2tr","account":"1","change":"0","index":"0"}
{"id":"b2","status":"ok","address":"tb1p…"}

{"id":"b3","method":"btcSignPsbt","network":"bitcoin","psbt":"cHNidP8B…"}
{"id":"b3","status":"approved","psbt":"cHNidP8B…"}
```

- `btcGetAccount` asks once per (network, type, account) on the phone ("Share Bitcoin account
  with the Mac?") and is remembered until revoked under ☰ → Bitcoin sharing.
- `btcShowAddress` (`change` `"0"`/`"1"`, `index` `"0"`…`"9999"`) answers after the user compared
  the address on the phone and tapped Done.
- `btcSignPsbt` takes a canonical, padded base64 BIP-174 **v0** PSBT (≤ 200 KiB decoded,
  ≤ 100 inputs/outputs) and returns it with `PSBT_IN_PARTIAL_SIG` (P2WPKH and P2SH-P2WPKH:
  BIP-143 ECDSA; P2PKH: legacy-sighash ECDSA; all `SIGHASH_ALL`) or `PSBT_IN_TAP_KEY_SIG` (P2TR
  key path, BIP-341/340 Schnorr, 64 bytes for `SIGHASH_DEFAULT`) added; nothing is finalized. The
  host builds the scriptSig / witness (P2SH-P2WPKH: scriptSig = push of the redeem script
  `0014‖HASH160(key)`, witness = sig, key; P2PKH: scriptSig = sig, key) and broadcasts after its
  own checks (`companion/src-tauri/src/btc/verify.rs`). Every input but Taproot must carry
  `non_witness_utxo` (the previous transaction proves the amount: a legacy signature commits to
  no amount, a SegWit v0 one only to its own); SegWit inputs carry `witness_utxo`, P2SH-P2WPKH
  inputs their `redeem_script`; P2PKH inputs may omit `witness_utxo` (if present it must agree).
  Inputs may mix types; the BIP-32 path's purpose must match each script's type.

Signing rules and the review are in [threat-model.md](threat-model.md) ("Bitcoin").

## Reference client

```sh
python -m pip install --require-hashes -r tools/requirements.txt
python tools/aoa_client.py pair            # compare the address with the PHONE's screen, then pin it
python tools/aoa_client.py sign-test       # disposable Sepolia transfer; approve on the phone
python tools/aoa_client.py sign-message --text "hello"
python tools/aoa_client.py attest --save /tmp/attest
python tools/aoa_client.py btc-account --network testnet
```

`pair` is mandatory: without a pinned address the client refuses every signature, because a
self-consistent response from an unknown device proves nothing. The pairing file is written
privately (0600, atomic replace) and rejected on load if it is a symlink, group/world readable,
or owned by someone else. Rejections and device errors exit non-zero.
