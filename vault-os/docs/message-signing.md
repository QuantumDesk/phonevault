# Message and typed-data signing

Status: implemented and unit-tested (phone JVM, companion Rust, host Python); **not yet tested on
a phone** (`tools/dev-device/msgsigntest.sh`). Nothing in `path-to-release.md` is ticked by this.

The phone signs two kinds of message besides transactions: `personal_sign` (EIP-191 version 0x45)
and `eth_signTypedData_v4` (EIP-712). Raw `eth_sign` (signing an arbitrary 32-byte hash) is not
offered and is refused as an unknown method.

## Rule

The review screen and the signed digest come from **one parsed object**. The phone parses the
request once (`MessageRequest.parse`), computes the digest from that parsed object
(`PersonalMessage` bytes or the `Eip712.TypedData` value tree), builds the review from the same
object (`MessageReview`), and `MessageApprovalSession` signs the digest it stored at review time.
Nothing re-reads the host's JSON after the review is built. The companion then recomputes the
digest from the original request with an independent implementation and refuses any signature
whose digest differs or that does not recover to the pinned address.

## Wire format

Same USB framing as `signEip1559`: one newline-terminated, flat JSON object whose values are all
strings, schema-exact (missing, unknown or duplicate fields are refused), ≤ 32 KiB per line.

```
{"id":"…","method":"personal_sign","chainId":"0x1","message":"0x48656c6c6f"}
{"id":"…","method":"eth_signTypedData_v4","chainId":"0x1","typedData":"{\"types\":…}"}
```

- `id`: `[A-Za-z0-9._:-]{1,128}`, echoed back.
- `chainId`: canonical hex quantity of the network the **host** is on; must be one of the reviewed
  chain profiles (1, 10, 137, 8453, 42161, 11155111). It is not signed. The review compares it
  with the chain the message names and warns on a mismatch (the phone has no network of its own).
- `message`: the exact bytes to sign as `0x` hex (even length, 1 … 8192 bytes). Text is sent as
  its UTF-8 bytes.
- `typedData`: the `eth_signTypedData_v4` JSON **as text** inside the string (JSON-escaped). It is
  parsed by the phone's own strict parser, not by `org.json`.
- `origin` (optional, these two methods only; `signEip1559` refuses it): the site that asked, when
  the companion knows it. `^https://[a-z0-9-]+(\.[a-z0-9-]+)*(:[1-9][0-9]{0,4})?$` or
  `^http://(localhost|127\.0\.0\.1|\[::1\])(:[1-9][0-9]{0,4})?$`, port ≤ 65535, at most 255
  characters (`https://app.uniswap.org`, `http://localhost:5173`; internationalized names in
  punycode); anything else refuses the whole request, so the companion leaves out an origin it
  cannot write this way. It is the browser-reported origin (extension) or WalletConnect Verify's
  origin when Verify said VALID; it is absent for unverified WalletConnect requests and for
  messages started on the Mac. Not signed. The companion has already refused a sign-in message
  whose domain or URI host differs from it.

Responses:

```
{"id":"…","status":"approved","address":"0x…","signature":"0x<r 32><s 32><v 1>","digest":"0x<32 bytes>"}
{"id":"…","status":"rejected"}
{"id":"…","status":"error","error":"…"}
```

`signature` is 65 bytes, `v` ∈ {27, 28}, low-s (EIP-2). `digest` is what the phone signed:
`keccak256("\x19Ethereum Signed Message:\n" ‖ len ‖ bytes)` or
`keccak256(0x1901 ‖ domainSeparator ‖ hashStruct(message))`. The host must not trust it: it
recomputes it and compares.

## What is refused (typed data)

The parser (`StrictJson`) and encoder (`Eip712`) refuse rather than interpret:

- JSON: duplicate keys, `null`, unpaired surrogates, raw control characters in strings, trailing
  data, non-RFC-8259 numbers, nesting deeper than 16.
- Structure: top level must be exactly `types`, `primaryType`, `domain`, `message`; `types` must
  define `EIP712Domain`; `primaryType` must be defined and must not be `EIP712Domain`; every
  declared type must be reachable from the primary type or the domain (unused types refused,
  like ethers); type and field names are identifiers ≤ 64 characters; no duplicate field names;
  struct names cannot shadow atomic types (`address`, `uint…`, `bytes…`, …); every struct value
  must have exactly its declared fields.
- Domain: only `name` (string), `version` (string), `chainId` (uint256), `verifyingContract`
  (address), `salt` (bytes32), in that order, any subset. `EIP712Domain` cannot be a field type.
- Types: `bool`, `address`, `string`, `bytes`, `bytes1…32`, `uint8…256`, `int8…256` (multiples of 8;
  unsized `uint`/`int` refused), struct names, arrays `T[]` / `T[n]` (n 1…128, ≤ 3 dimensions).
- Values: integers as JSON integers or strings (decimal, no leading zeros, no `-0`, ≤ 80 chars;
  or `0x` hex ≤ 64 digits), range-checked for the exact width (no wrapping, negative only for
  `int`); `bool` only as `true`/`false`; addresses `0x` + 40 hex, mixed case must be a valid EIP-55
  checksum; `bytesN` exactly N bytes and `bytes` as even-length `0x` hex (text is not converted);
  fixed arrays exactly n elements.

## Limits

| Limit | Value |
| --- | --- |
| USB request line | 32 KiB (existing transport limit) |
| `typedData` JSON text | 24 KiB (UTF-8) |
| `personal_sign` message | 8192 bytes |
| JSON nesting depth | 16 |
| Struct types | 32 |
| Fields per struct | 48 |
| Array length | 128 (dynamic and fixed) |
| Array dimensions | 3 |
| Values (structs + arrays + leaves) | 1024 |
| `string` / `bytes` value | 4096 bytes |
| Type/field name | 64 characters |

## What the phone shows

Summary first, then "Show details" (folded): the complete field tree (every leaf with its path and
type), the primary type's `encodeType`, the domain separator, message hash and **signing digest**
(the same value the host receives, so it can be compared). Strings are shown with every control,
formatting, bidi and zero-width character as a visible `\u{…}` escape.

Typed data, always: who is asking (domain name, version, chain, verifying contract, salt), the
signing address, the host network. DANGER when the domain chain differs from the host's; WARNING
when the domain names no chain. Recognized shapes:

| Shape | Recognition | Shown |
| --- | --- | --- |
| EIP-2612 Permit | primary `Permit(owner,spender,value,nonce,deadline)` | spender, token contract (+ its claimed name, unverified), amount (max uint256 → **UNLIMITED**), deadline as UTC date, owner (WARNING if not this wallet), nonce; DANGER allowance banner |
| DAI-style Permit | primary `Permit(holder,spender,nonce,expiry,allowed)` | as above; `allowed=true` → UNLIMITED, `expiry=0` → no expiry |
| Permit2 | primary `PermitSingle`, `PermitBatch`, `PermitTransferFrom`, `PermitBatchTransferFrom`, `Permit(Batch)WitnessTransferFrom` with the canonical field layout | spender, every token + amount (max uint160/uint256 → UNLIMITED), allowance expiry (max uint48 → NEVER, 0 explained), signature deadline, nonces; witness field flagged; WARNING if the domain is not `Permit2` at `0x000000000022D473030F116dDEE9F6B43aC78BA3` |
| Orders | domain `Seaport`, primary `OrderComponents`/`BulkOrder`, `OfferItem`/`ConsiderationItem` types, or a primary type containing "order" | "This signs an order" DANGER, offer/consideration counts, offerer (WARNING if not this wallet), end time |
| Anything else | — | top-level fields; WARNING for address fields named spender/operator/approved/delegate(e); WARNING for max-value integers |

Dates are UTC from the value in the message; the offline phone's clock is not used to judge them.

`personal_sign`:

- **Readable text** (strict UTF-8, only printable characters plus LF, TAB, CRLF): shown verbatim.
- **Unreadable data** (invalid UTF-8, control/format/bidi/zero-width/private-use/unassigned
  characters, lone CR, whitespace only): shown as hex under a DANGER "Unreadable data" warning,
  with an extra note when it is exactly 32 bytes (hash-sized). The sign button says "Sign
  unreadable data".
- **Sign-In with Ethereum** (EIP-4361, recognized by its first line): website (as claimed), account
  (DANGER if not this wallet; WARNING if not EIP-55), statement, URI (WARNING if its host differs
  from the website), chain (WARNING if not the host's), nonce, issued/expiry/not-before, request
  ID, resources; always a WARNING that the phone cannot see which site asked. A message that
  starts like a sign-in but breaks the grammar is shown as text with a DANGER banner.

The review then uses the transaction screen's controls unchanged: acknowledgement checkbox,
Sign (enabled only after the checkbox), Reject, one pending request, obscured-touch rejection,
session/identity binding, and the lock/replug behaviour. Signing uses the credentials already
loaded by the unlock + seed-key flow, exactly like transactions.

## Verification on the host

- Companion (`companion/src-tauri/src/message.rs`, `verify.rs::validate_message_signature`): a
  separate Rust implementation of the same parser, rules and limits recomputes the digest from the
  original request; the phone's `digest` must equal it; the signature must recover to the pinned
  signer over the recomputed digest; the claimed `address` must match. Otherwise the signature is
  not returned to the UI. The companion also pre-checks requests before sending them.
- Python host client (`tools/aoa_client.py sign-message`): computes personal_sign digests itself;
  has no EIP-712 encoder, so typed-data checks need `--expect-digest` (used by the harness with the
  shared vectors).

## Tests

`app/src/test/resources/message-signing-vectors.json` is generated by
`message-signing-vectors.gen.mjs` with ethers v6 and cross-checked against
`@metamask/eth-sig-util` v7 (digests and signatures must agree in both). It holds 11 vectors
(EIP-712 Mail — whose signature equals the one published in the EIP — nested struct arrays,
every atomic type incl. negative ints and 2-D/fixed arrays, EIP-2612 Permit, Permit2
single/batch/transfer, a Seaport-shaped order, and personal_sign text/binary/SIWE) and 52
must-reject inputs. The phone's JVM tests, the companion's Rust tests and the Python client tests
all read this one file.

## Known limits

- Token identity, symbol and decimals are never verified; amounts are raw integers.
- The phone cannot see the requesting website; the domain and SIWE fields are the message's claims.
- Recognition is by type shape and names; an unrecognized permission-like message falls back to
  the generic review with the whole field tree.
- Unassigned-code-point detection follows the device's Unicode tables, which can differ from the
  JVM's; this affects only the readable/unreadable classification, never the digest.

## EIP-7702 refusal (2026-10-11)

`MessageRequest.parse` refuses, with "Account delegation (EIP-7702) is not supported: it can hand
control of this wallet to a contract", a `personal_sign` whose bytes are an EIP-7702
authorization tuple (`0x05 ‖ rlp([chain_id, address, nonce])`) and typed data whose primary type
is a 7702-style authorization (a name containing "7702", or "…Authorization" with a nonce and an
address field) or an ERC-7710 `Delegation`. The refusal is answered as an error and shown on the
phone (`Eip7702`, `Eip7702Test`). The shared vectors are unaffected.
