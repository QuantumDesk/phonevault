// EIP-55 mixed-case checksum, for DISPLAY only (addresses the UI shows in lower case: WalletConnect
// requests, speed-up/cancel quotes, typed-data fields). Nothing signed or compared depends on it;
// Rust checks every address that matters. Keccak-256 is implemented here (32-bit lanes) so the UI
// needs no extra dependency; results are cached.

const RC = [
  [0x00000001, 0x00000000], [0x00008082, 0x00000000], [0x0000808a, 0x80000000], [0x80008000, 0x80000000],
  [0x0000808b, 0x00000000], [0x80000001, 0x00000000], [0x80008081, 0x80000000], [0x00008009, 0x80000000],
  [0x0000008a, 0x00000000], [0x00000088, 0x00000000], [0x80008009, 0x00000000], [0x8000000a, 0x00000000],
  [0x8000808b, 0x00000000], [0x0000008b, 0x80000000], [0x00008089, 0x80000000], [0x00008003, 0x80000000],
  [0x00008002, 0x80000000], [0x00000080, 0x80000000], [0x0000800a, 0x00000000], [0x8000000a, 0x80000000],
  [0x80008081, 0x80000000], [0x00008080, 0x80000000], [0x80000001, 0x00000000], [0x80008008, 0x80000000],
];
// rotation offsets and pi-step destinations, lane index x + 5y
const ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];

/** Keccak-f[1600] on 25 lanes stored as [lo, hi] 32-bit pairs in a flat array of 50. */
function keccakF(s: Uint32Array) {
  const c = new Uint32Array(10), b = new Uint32Array(50);
  for (let round = 0; round < 24; round++) {
    for (let x = 0; x < 5; x++) {
      c[2 * x] = s[2 * x] ^ s[2 * x + 10] ^ s[2 * x + 20] ^ s[2 * x + 30] ^ s[2 * x + 40];
      c[2 * x + 1] = s[2 * x + 1] ^ s[2 * x + 11] ^ s[2 * x + 21] ^ s[2 * x + 31] ^ s[2 * x + 41];
    }
    for (let x = 0; x < 5; x++) {
      const p = (x + 4) % 5, q = (x + 1) % 5;
      const lo = c[2 * p] ^ ((c[2 * q] << 1) | (c[2 * q + 1] >>> 31));
      const hi = c[2 * p + 1] ^ ((c[2 * q + 1] << 1) | (c[2 * q] >>> 31));
      for (let y = 0; y < 25; y += 5) { s[2 * (x + y)] ^= lo; s[2 * (x + y) + 1] ^= hi; }
    }
    // rho + pi: lane (x, y) rotated goes to (y, 2x + 3y)
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) {
      const i = x + 5 * y, j = y + 5 * ((2 * x + 3 * y) % 5);
      const r = ROT[i], lo = s[2 * i], hi = s[2 * i + 1];
      let nlo: number, nhi: number;
      if (r === 0) { nlo = lo; nhi = hi; }
      else if (r < 32) { nlo = (lo << r) | (hi >>> (32 - r)); nhi = (hi << r) | (lo >>> (32 - r)); }
      else if (r === 32) { nlo = hi; nhi = lo; }
      else { const k = r - 32; nlo = (hi << k) | (lo >>> (32 - k)); nhi = (lo << k) | (hi >>> (32 - k)); }
      b[2 * j] = nlo; b[2 * j + 1] = nhi;
    }
    // chi
    for (let y = 0; y < 25; y += 5) for (let x = 0; x < 5; x++) {
      const i = x + y, i1 = ((x + 1) % 5) + y, i2 = ((x + 2) % 5) + y;
      s[2 * i] = b[2 * i] ^ (~b[2 * i1] & b[2 * i2]);
      s[2 * i + 1] = b[2 * i + 1] ^ (~b[2 * i1 + 1] & b[2 * i2 + 1]);
    }
    // iota
    s[0] ^= RC[round][0]; s[1] ^= RC[round][1];
  }
}

/** Keccak-256 (the original padding Ethereum uses, not SHA3-256) of bytes, as lower-case hex. */
export function keccak256Hex(data: Uint8Array): string {
  const rate = 136;
  const padded = new Uint8Array(Math.ceil((data.length + 1) / rate) * rate);
  padded.set(data);
  padded[data.length] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;
  const s = new Uint32Array(50);
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 4; i++) {
      const k = off + 4 * i;
      s[i] ^= padded[k] | (padded[k + 1] << 8) | (padded[k + 2] << 16) | (padded[k + 3] << 24);
    }
    keccakF(s);
  }
  let out = "";
  for (let i = 0; i < 8; i++) for (let k = 0; k < 4; k++) out += ((s[i] >>> (8 * k)) & 0xff).toString(16).padStart(2, "0");
  return out;
}

const cache = new Map<string, string>();

/** `addr` in EIP-55 mixed case; anything that isn't 0x + 40 hex characters comes back unchanged. */
export function checksumAddress(addr: string): string {
  if (!/^0x[0-9a-fA-F]{40}$/.test(addr)) return addr;
  const lower = addr.slice(2).toLowerCase();
  const hit = cache.get(lower);
  if (hit) return hit;
  const hash = keccak256Hex(new TextEncoder().encode(lower));
  let out = "0x";
  for (let i = 0; i < 40; i++) out += parseInt(hash[i], 16) >= 8 ? lower[i].toUpperCase() : lower[i];
  if (cache.size > 512) cache.clear();
  cache.set(lower, out);
  return out;
}
