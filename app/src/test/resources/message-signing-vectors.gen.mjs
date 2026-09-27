import { ethers } from "ethers";
import { TypedDataUtils, SignTypedDataVersion, signTypedData, personalSign } from "@metamask/eth-sig-util";
const cow = ethers.keccak256(ethers.toUtf8Bytes("cow"));
const wallet = new ethers.Wallet(cow);
const V = [];
function typed(name, td) {
  const text = JSON.stringify(td);
  const { EIP712Domain, ...types } = td.types;
  const ethersDigest = ethers.TypedDataEncoder.hash(td.domain, types, td.message);
  const sigUtil = "0x" + Buffer.from(TypedDataUtils.eip712Hash(td, SignTypedDataVersion.V4)).toString("hex");
  if (ethersDigest !== sigUtil) throw new Error(name + " ethers " + ethersDigest + " != eth-sig-util " + sigUtil);
  const sep = "0x" + Buffer.from(TypedDataUtils.eip712DomainHash(td, SignTypedDataVersion.V4)).toString("hex");
  const mh = "0x" + Buffer.from(TypedDataUtils.hashStruct(td.primaryType, td.message, td.types, SignTypedDataVersion.V4)).toString("hex");
  const sig = signTypedData({ privateKey: Buffer.from(cow.slice(2), "hex"), data: td, version: SignTypedDataVersion.V4 });
  const sig2 = wallet.signingKey.sign(ethersDigest).serialized;
  if (sig !== sig2) throw new Error(name + " sig mismatch");
  V.push({ name, kind: "typed", typedData: text, domainSeparator: sep, messageHash: mh, digest: ethersDigest, signature: sig });
}
function personal(name, hex) {
  const digest = ethers.hashMessage(ethers.getBytes(hex));
  const sig = personalSign({ privateKey: Buffer.from(cow.slice(2), "hex"), data: hex });
  const sig2 = wallet.signingKey.sign(digest).serialized;
  if (sig !== sig2) throw new Error(name + " psig mismatch");
  V.push({ name, kind: "personal", message: hex, digest, signature: sig });
}
const domainT = [
  { name: "name", type: "string" }, { name: "version", type: "string" },
  { name: "chainId", type: "uint256" }, { name: "verifyingContract", type: "address" }];
typed("eip712-mail", {
  types: { EIP712Domain: domainT, Person: [{ name: "name", type: "string" }, { name: "wallet", type: "address" }],
    Mail: [{ name: "from", type: "Person" }, { name: "to", type: "Person" }, { name: "contents", type: "string" }] },
  primaryType: "Mail",
  domain: { name: "Ether Mail", version: "1", chainId: 1, verifyingContract: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC" },
  message: { from: { name: "Cow", wallet: "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826" },
    to: { name: "Bob", wallet: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB" }, contents: "Hello, Bob!" } });
typed("sig-util-v4-nested-arrays", {
  types: { EIP712Domain: domainT, Person: [{ name: "name", type: "string" }, { name: "wallets", type: "address[]" }],
    Mail: [{ name: "from", type: "Person" }, { name: "to", type: "Person[]" }, { name: "contents", type: "string" }] },
  primaryType: "Mail",
  domain: { name: "Ether Mail", version: "1", chainId: 1, verifyingContract: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC" },
  message: { from: { name: "Cow", wallets: ["0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826", "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"] },
    to: [{ name: "Bob", wallets: ["0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB", "0xB0BdaBea57B0BDABeA57b0bdABEA57b0BDabEa57", "0xB0B0b0b0b0b0B000000000000000000000000000"] }],
    contents: "Hello, Bob!" } });
typed("all-atomic-types", {
  types: { EIP712Domain: [...domainT, { name: "salt", type: "bytes32" }],
    Leaf: [{ name: "flag", type: "bool" }, { name: "note", type: "string" }],
    Kitchen: [
      { name: "i8", type: "int8" }, { name: "i256", type: "int256" }, { name: "u8", type: "uint8" },
      { name: "u256", type: "uint256" }, { name: "u160hex", type: "uint160" }, { name: "b1", type: "bytes1" },
      { name: "b32", type: "bytes32" }, { name: "dyn", type: "bytes" }, { name: "empty", type: "bytes" },
      { name: "yes", type: "bool" }, { name: "no", type: "bool" }, { name: "text", type: "string" },
      { name: "fixed", type: "uint256[2]" }, { name: "grid", type: "address[][]" }, { name: "leaves", type: "Leaf[2]" },
      { name: "none", type: "int16[]" }, { name: "neg", type: "int64" }] },
  primaryType: "Kitchen",
  domain: { name: "Kitchen é😀", version: "2", chainId: "0x2105", verifyingContract: "0x1111111111111111111111111111111111111111",
    salt: "0x" + "ab".repeat(32) },
  message: { i8: -128, i256: "-57896044618658097711785492504343953926634992332820282019728792003956564819968", u8: "255",
    u256: "115792089237316195423570985008687907853269984665640564039457584007913129639935", u160hex: "0xff00",
    b1: "0x7f", b32: "0x" + "01".repeat(32), dyn: "0xdeadbeef", empty: "0x", yes: true, no: false,
    text: "line1\nline2 ünicode 👋", fixed: [1, "2"], grid: [["0x0000000000000000000000000000000000000000"], [], ["0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF", "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"]],
    leaves: [{ flag: true, note: "" }, { flag: false, note: "x" }], none: [], neg: "-1" } });
typed("eip2612-permit-unlimited", {
  types: { EIP712Domain: domainT, Permit: [{ name: "owner", type: "address" }, { name: "spender", type: "address" },
    { name: "value", type: "uint256" }, { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint256" }] },
  primaryType: "Permit",
  domain: { name: "USD Coin", version: "2", chainId: 1, verifyingContract: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" },
  message: { owner: "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826", spender: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
    value: "115792089237316195423570985008687907853269984665640564039457584007913129639935", nonce: 0, deadline: 1767225600 } });
const permitDetails = [{ name: "token", type: "address" }, { name: "amount", type: "uint160" }, { name: "expiration", type: "uint48" }, { name: "nonce", type: "uint48" }];
const p2domain = { name: "Permit2", chainId: 1, verifyingContract: "0x000000000022D473030F116dDEE9F6B43aC78BA3" };
const p2domainT = [{ name: "name", type: "string" }, { name: "chainId", type: "uint256" }, { name: "verifyingContract", type: "address" }];
typed("permit2-single", {
  types: { EIP712Domain: p2domainT, PermitDetails: permitDetails,
    PermitSingle: [{ name: "details", type: "PermitDetails" }, { name: "spender", type: "address" }, { name: "sigDeadline", type: "uint256" }] },
  primaryType: "PermitSingle", domain: p2domain,
  message: { details: { token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", amount: "1461501637330902918203684832716283019655932542975", expiration: "281474976710655", nonce: 0 },
    spender: "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD", sigDeadline: 1767225600 } });
typed("permit2-batch", {
  types: { EIP712Domain: p2domainT, PermitDetails: permitDetails,
    PermitBatch: [{ name: "details", type: "PermitDetails[]" }, { name: "spender", type: "address" }, { name: "sigDeadline", type: "uint256" }] },
  primaryType: "PermitBatch", domain: p2domain,
  message: { details: [
      { token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", amount: "1000000", expiration: 1767225600, nonce: 3 },
      { token: "0xdAC17F958D2ee523a2206206994597C13D831ec7", amount: "1461501637330902918203684832716283019655932542975", expiration: 0, nonce: 1 }],
    spender: "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD", sigDeadline: 1767225600 } });
typed("permit2-transfer-from", {
  types: { EIP712Domain: p2domainT, TokenPermissions: [{ name: "token", type: "address" }, { name: "amount", type: "uint256" }],
    PermitTransferFrom: [{ name: "permitted", type: "TokenPermissions" }, { name: "spender", type: "address" }, { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint256" }] },
  primaryType: "PermitTransferFrom", domain: p2domain,
  message: { permitted: { token: "0x6B175474E89094C44Da98b954EedeAC495271d0F", amount: "250000000000000000000" },
    spender: "0x00000000000000000000000000000000000000aa", nonce: "0x1", deadline: 1767225600 } });
typed("seaport-like-order", {
  types: { EIP712Domain: domainT,
    OrderComponents: [{ name: "offerer", type: "address" }, { name: "offer", type: "OfferItem[]" }, { name: "consideration", type: "ConsiderationItem[]" }, { name: "endTime", type: "uint256" }, { name: "salt", type: "uint256" }],
    OfferItem: [{ name: "itemType", type: "uint8" }, { name: "token", type: "address" }, { name: "identifierOrCriteria", type: "uint256" }, { name: "startAmount", type: "uint256" }, { name: "endAmount", type: "uint256" }],
    ConsiderationItem: [{ name: "itemType", type: "uint8" }, { name: "token", type: "address" }, { name: "identifierOrCriteria", type: "uint256" }, { name: "startAmount", type: "uint256" }, { name: "endAmount", type: "uint256" }, { name: "recipient", type: "address" }] },
  primaryType: "OrderComponents",
  domain: { name: "Seaport", version: "1.6", chainId: 1, verifyingContract: "0x0000000000000068F116a894984e2DB1123eB395" },
  message: { offerer: "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
    offer: [{ itemType: 2, token: "0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D", identifierOrCriteria: "1234", startAmount: 1, endAmount: 1 }],
    consideration: [{ itemType: 0, token: "0x0000000000000000000000000000000000000000", identifierOrCriteria: 0, startAmount: "975000000000000000", endAmount: "975000000000000000", recipient: "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826" }],
    endTime: 1767225600, salt: "0x" + "12".repeat(32) } });
personal("personal-hello", ethers.hexlify(ethers.toUtf8Bytes("Hello, Phone Vault!")));
personal("personal-binary-32", "0x" + "ff00".repeat(16));
const siwe = "example.com wants you to sign in with your Ethereum account:\n0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826\n\nSign in to the example app.\n\nURI: https://example.com/login\nVersion: 1\nChain ID: 1\nNonce: 32891756\nIssued At: 2026-09-27T12:00:00Z\nExpiration Time: 2026-09-28T12:00:00Z\nResources:\n- ipfs://bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/\n- https://example.com/my-web2-claim.json";
personal("personal-siwe", ethers.hexlify(ethers.toUtf8Bytes(siwe)));
// ---- inputs BOTH implementations must refuse (policy is stricter than ethers / eth-sig-util)
const R = [];
const mail = JSON.parse(V[0].typedData);
const clone = () => JSON.parse(JSON.stringify(mail));
const rej = (name, mutate) => { const t = clone(); const out = mutate(t); R.push({ name, typedData: typeof out === "string" ? out : JSON.stringify(t) }); };
const txt = JSON.stringify(mail);
rej("duplicate-key", () => txt.replace('"contents":"Hello, Bob!"', '"contents":"Hello, Bob!","contents":"Pay Eve"'));
rej("missing-field", (t) => { delete t.message.contents; });
rej("extra-field", (t) => { t.message.amount = "1"; });
rej("extra-field-nested", (t) => { t.message.from.age = "1"; });
rej("unknown-type", (t) => { t.types.Mail[0].type = "Persn"; });
rej("unused-type", (t) => { t.types.Group = [{ name: "name", type: "string" }]; });
rej("primary-is-domain", (t) => { t.primaryType = "EIP712Domain"; });
rej("primary-undefined", (t) => { t.primaryType = "Letter"; });
rej("no-domain-type", (t) => { delete t.types.EIP712Domain; });
rej("domain-unknown-field", (t) => { t.types.EIP712Domain.push({ name: "foo", type: "string" }); t.domain.foo = "x"; });
rej("domain-out-of-order", (t) => { const d = t.types.EIP712Domain; [d[0], d[1]] = [d[1], d[0]]; });
rej("domain-wrong-type", (t) => { t.types.EIP712Domain[2].type = "uint64"; });
rej("domain-value-extra", (t) => { t.domain.salt = "0x" + "00".repeat(32); });
rej("domain-type-as-field", (t) => { t.types.Mail.push({ name: "d", type: "EIP712Domain" }); t.message.d = t.domain; });
rej("top-level-extra", (t) => { t.extra = 1; });
rej("null-value", (t) => { t.message.contents = null; });
rej("fraction", (t) => { t.domain.chainId = 1.5; });
rej("exponent", (t) => { t.domain.chainId = "1e3"; });
rej("exponent-number", () => txt.replace('"chainId":1', '"chainId":1e0'));
rej("negative-uint", (t) => { t.domain.chainId = -1; });
rej("minus-zero", (t) => { t.domain.chainId = "-0"; });
rej("leading-zero", (t) => { t.domain.chainId = "01"; });
rej("uint-too-big", (t) => { t.domain.chainId = "0x1" + "0".repeat(64); });
rej("bool-as-string", (t) => { t.types.Person.push({ name: "ok", type: "bool" }); t.message.from.ok = "true"; t.message.to.ok = true; });
rej("number-as-string-type", (t) => { t.message.contents = 5; });
rej("address-bad-checksum", (t) => { t.message.from.wallet = "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD827".replace("CD2a", "Cd2a"); });
rej("address-short", (t) => { t.message.from.wallet = "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD8"; });
rej("address-no-prefix", (t) => { t.message.from.wallet = "CD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"; });
rej("uint8-overflow", (t) => { t.types.Person.push({ name: "n", type: "uint8" }); t.message.from.n = 256; t.message.to.n = 0; });
rej("int8-overflow", (t) => { t.types.Person.push({ name: "n", type: "int8" }); t.message.from.n = 128; t.message.to.n = 0; });
rej("int8-underflow", (t) => { t.types.Person.push({ name: "n", type: "int8" }); t.message.from.n = -129; t.message.to.n = 0; });
rej("bytes32-short", (t) => { t.types.Person.push({ name: "h", type: "bytes32" }); t.message.from.h = "0x1234"; t.message.to.h = "0x" + "00".repeat(32); });
rej("bytes-odd", (t) => { t.types.Person.push({ name: "h", type: "bytes" }); t.message.from.h = "0x123"; t.message.to.h = "0x"; });
rej("bytes-utf8-text", (t) => { t.types.Person.push({ name: "h", type: "bytes" }); t.message.from.h = "hello"; t.message.to.h = "0x"; });
rej("fixed-array-length", (t) => { t.types.Person.push({ name: "a", type: "uint8[2]" }); t.message.from.a = [1]; t.message.to.a = [1, 2]; });
rej("fixed-array-zero", (t) => { t.types.Person.push({ name: "a", type: "uint8[0]" }); t.message.from.a = []; t.message.to.a = []; });
rej("unsized-uint", (t) => { t.types.Person.push({ name: "n", type: "uint" }); t.message.from.n = 1; t.message.to.n = 1; });
rej("bad-size-uint7", (t) => { t.types.Person.push({ name: "n", type: "uint7" }); t.message.from.n = 1; t.message.to.n = 1; });
rej("bad-size-bytes33", (t) => { t.types.Person.push({ name: "n", type: "bytes33" }); t.message.from.n = "0x00"; t.message.to.n = "0x00"; });
rej("reserved-type-name", (t) => { t.types.address = [{ name: "x", type: "string" }]; t.types.Mail[2].type = "address"; });
rej("duplicate-field-name", (t) => { t.types.Person.push({ name: "name", type: "string" }); });
rej("field-extra-key", (t) => { t.types.Person[0].extra = "x"; });
rej("array-too-long", (t) => { t.types.Person.push({ name: "a", type: "uint8[]" }); t.message.from.a = Array(129).fill(1); t.message.to.a = []; });
rej("string-too-long", (t) => { t.message.contents = "x".repeat(4097); });
rej("payload-too-large", (t) => { t.message.contents = "x".repeat(4000); t.types.Mail.push(...[1,2,3,4,5,6].map(i => ({ name: "c" + i, type: "string" }))); for (let i = 1; i <= 6; i++) t.message["c" + i] = "y".repeat(4000); });
rej("unpaired-surrogate", () => txt.replace('Hello, Bob!', 'Hello, Bob!\\ud800'.replace('\\\\', '\\')));
rej("raw-control-char", () => txt.replace('Hello, Bob!', 'Hello,\tBob!'.replace('\\t', '\t')));
rej("trailing-data", () => txt + " {}");
rej("not-an-object", () => "[]");
rej("wrong-array-depth", (t) => { t.types.Person.push({ name: "g", type: "uint8[][][]" }); t.message.from.g = [[[1]]]; t.message.to.g = [[[[1]]]]; });
rej("json-too-deep", () => txt.replace('"contents":"Hello, Bob!"', '"contents":"Hello, Bob!","x":' + "[".repeat(20) + "]".repeat(20)));
rej("too-many-dimensions", (t) => { t.types.Person.push({ name: "g", type: "uint8[][][][]" }); t.message.from.g = []; t.message.to.g = []; });
console.log(JSON.stringify({
  comment: "Generated by ethers v6 (TypedDataEncoder / hashMessage) and cross-checked against @metamask/eth-sig-util v7: every digest and signature below agreed in both. Signing key: keccak256('cow'), the EIP-712 example TEST key. Shared by the phone JVM tests and the companion Rust tests.",
  signer: wallet.address.toLowerCase(), vectors: V, rejections: R }, null, 1));
