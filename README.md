# Phone Vault prototype

Native Android proof-of-concept that turns a spare phone into a user-confirmed EVM signer.

## Security status

This is unaudited prototype software for disposable keys and testnet assets only. It intentionally has no
network permission. The private key is encrypted at rest by a non-exportable Android Keystore AES key, but it
exists in application memory while the signer is running. Replacing the active disposable key is not represented
as guaranteed forensic erasure of prior plaintext, ciphertext, or storage history.

## USB protocol

The desktop is the Android Open Accessory (AOA) USB host. Requests and responses are newline-delimited UTF-8
JSON, limited to 32 KiB per request. A request must end with a newline before disconnect, use a short ASCII
request ID, and contain exactly the fields in its method schema. Malformed UTF-8, truncated frames, missing
fields, unknown fields, duplicate keys, non-string values, and trailing JSON data fail closed.

Address request:

```json
{"id":"address-1","method":"getAddress"}
```

EIP-1559 signing request (all integer quantities are canonical `0x` hex):

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

The prototype accepts only native transfers and canonical ABI-shaped `transfer(address,uint256)` or
`approve(address,uint256)` calls. Arbitrary contract calldata fails closed. It displays the exact signing address,
network, recipient or approved-address argument, raw `uint256` amount/allowance/token-ID argument, target contract,
exact four-byte selector, maximum fee, nonce, and decoded arguments. The approval session binds that displayed
address to an immutable credential snapshot and refuses to sign if the active identity changes after review. Key
replacement is unavailable while USB is connected, a replacement is running, or an approval is pending. A selector
and well-formed ABI arguments do not prove that the target implements ERC-20,
ERC-721, or any expected behavior, so the contract interface and execution semantics remain explicitly
unverified. A maximum-`uint256` argument is labeled as a value commonly used for unlimited ERC-20 allowance—not
asserted as one; token identity and decimals remain unverified. The user
must reach and select an operation-specific review checkbox before **Sign** becomes available. Screenshots are
blocked, and sensitive controls discard both fully and partially obscured touches to reduce overlay/tapjacking
risk.

`tools/build.sh` produces two deliberately separate development artifacts:

- `app-debug.apk` is the normal installable app and permits software-backed key wrapping on phones without
  StrongBox so development remains accessible.
- `app-appliance.apk` is non-debuggable and requires hardware-backed key wrapping. Vault OS embeds this variant,
  even for bring-up images. Production releases must instead use the separately release-signed APK workflow.

The resolved app dependency graph is pinned in `app/gradle.lockfile`, and
`gradle/verification-metadata.xml` records SHA-256 digests for build plugins,
metadata, and dependencies. Gradle refuses bytes that do not match this
inventory. Release builders should prefetch the reviewed inventory and run
`tools/build.sh --offline` so the signing build has no repository access.
The appliance APK is v2-only signed with deterministic RSA PKCS#1 (the APK
manifest still requires API 28), allowing independent clean builds using the
same development or release identity to be compared byte-for-byte.

## Desktop test client

Install the hash-locked dependency set with
`python -m pip install --require-hashes -r tools/requirements.txt`, connect an
unlocked phone, and run:

```sh
python tools/aoa_client.py address
python tools/aoa_client.py sign-test
```

The second command waits for explicit approval on the phone and prints the signed typed transaction response.
The client refuses ambiguous multi-device selection, validates the exact AOA
interface and bulk endpoints, and independently decodes the returned EIP-1559
RLP envelope. It reports success only when every encoded transaction field
matches the original request; rejection and device errors use a nonzero exit
status and never satisfy the signed-response schema.
