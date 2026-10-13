package dev.phonevault.signer;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * A BIP-174 version-0 Partially Signed Bitcoin Transaction, parsed STRUCTURALLY: magic, maps,
 * canonical sizes, no duplicate keys, the exact key/value shapes BIP-174 and BIP-371 define for
 * the fields they name, the unsigned transaction (legacy serialization, empty scriptSigs, one map
 * per input and output), and a non-witness UTXO whose txid matches its outpoint. Unknown fields
 * are kept so the PSBT round-trips. Whether the phone will SIGN it is a separate, much stricter
 * decision ({@link BtcPsbtReview}).
 */
final class Psbt {
    static final int MAX_BYTES = 200 * 1024;
    private static final byte[] MAGIC = {0x70, 0x73, 0x62, 0x74, (byte) 0xff};

    // global
    static final int GLOBAL_UNSIGNED_TX = 0x00, GLOBAL_XPUB = 0x01, GLOBAL_VERSION = 0xFB, PROPRIETARY = 0xFC;
    // input
    static final int IN_NON_WITNESS_UTXO = 0x00, IN_WITNESS_UTXO = 0x01, IN_PARTIAL_SIG = 0x02, IN_SIGHASH_TYPE = 0x03,
            IN_REDEEM_SCRIPT = 0x04, IN_WITNESS_SCRIPT = 0x05, IN_BIP32_DERIVATION = 0x06, IN_FINAL_SCRIPTSIG = 0x07,
            IN_FINAL_SCRIPTWITNESS = 0x08, IN_POR_COMMITMENT = 0x09, IN_RIPEMD160 = 0x0a, IN_SHA256 = 0x0b,
            IN_HASH160 = 0x0c, IN_HASH256 = 0x0d, IN_TAP_KEY_SIG = 0x13, IN_TAP_SCRIPT_SIG = 0x14,
            IN_TAP_LEAF_SCRIPT = 0x15, IN_TAP_BIP32_DERIVATION = 0x16, IN_TAP_INTERNAL_KEY = 0x17, IN_TAP_MERKLE_ROOT = 0x18;
    // output
    static final int OUT_REDEEM_SCRIPT = 0x00, OUT_WITNESS_SCRIPT = 0x01, OUT_BIP32_DERIVATION = 0x02,
            OUT_TAP_INTERNAL_KEY = 0x05, OUT_TAP_TREE = 0x06, OUT_TAP_BIP32_DERIVATION = 0x07;

    static final class InvalidPsbt extends IllegalArgumentException {
        InvalidPsbt(String message) { super(message); }
    }

    /** One key-value pair; {@code key} is the whole key (type prefix included). */
    static final class Entry {
        final long type;
        final byte[] key;
        final byte[] keyData; // key minus the type prefix
        final byte[] value;

        Entry(long type, byte[] key, byte[] keyData, byte[] value) {
            this.type = type;
            this.key = key;
            this.keyData = keyData;
            this.value = value;
        }
    }

    /** A key origin: master fingerprint + derivation path. */
    static final class Origin {
        final byte[] fingerprint;
        final int[] path;
        Origin(byte[] fingerprint, int[] path) { this.fingerprint = fingerprint; this.path = path; }
    }

    static final class Derivation {
        /** 33-byte compressed pubkey (ECDSA), or 32-byte x-only key (Taproot). */
        final byte[] key;
        final Origin origin;
        /** Taproot only: leaf hashes the key is used in (empty for the key path). */
        final int leafHashes;
        Derivation(byte[] key, Origin origin, int leafHashes) { this.key = key; this.origin = origin; this.leafHashes = leafHashes; }
    }

    final List<Entry> global;
    final BtcTx tx;
    final List<List<Entry>> inputs;
    final List<List<Entry>> outputs;

    private Psbt(List<Entry> global, BtcTx tx, List<List<Entry>> inputs, List<List<Entry>> outputs) {
        this.global = global;
        this.tx = tx;
        this.inputs = inputs;
        this.outputs = outputs;
    }

    // ------------------------------------------------------------------ parsing

    static Psbt parse(byte[] data) {
        if (data == null) throw new InvalidPsbt("PSBT is missing");
        if (data.length > MAX_BYTES) throw new InvalidPsbt("PSBT is larger than " + (MAX_BYTES / 1024) + " KiB");
        if (data.length < MAGIC.length || !Arrays.equals(Arrays.copyOf(data, MAGIC.length), MAGIC)) {
            throw new InvalidPsbt("Not a PSBT (bad magic)");
        }
        try {
            BtcTx.Reader r = new BtcTx.Reader(data);
            r.at = MAGIC.length;
            List<Entry> global = readMap(r);
            BtcTx tx = null;
            for (Entry e : global) {
                if (e.type == GLOBAL_UNSIGNED_TX) {
                    keyLength(e, 0, "global unsigned transaction");
                    BtcTx.Reader tr = new BtcTx.Reader(e.value);
                    tx = readLegacyTx(tr);
                    if (!tr.done()) throw new InvalidPsbt("Unsigned transaction has trailing bytes (witness serialization is not allowed)");
                    for (BtcTx.Input in : tx.inputs) {
                        if (in.scriptSig.length != 0) throw new InvalidPsbt("Unsigned transaction has a non-empty scriptSig");
                    }
                } else if (e.type == GLOBAL_XPUB) {
                    keyLength(e, 78, "global xpub");
                    origin(e.value, "global xpub");
                } else if (e.type == GLOBAL_VERSION) {
                    keyLength(e, 0, "PSBT version");
                    if (e.value.length != 4) throw new InvalidPsbt("PSBT version must be 4 bytes");
                    long v = new BtcTx.Reader(e.value).u32();
                    if (v != 0) throw new InvalidPsbt("PSBT version " + v + " is not supported (only version 0)");
                } else if (e.type >= 0x02 && e.type <= 0x06) {
                    throw new InvalidPsbt("PSBT version 2 fields are not supported (only version 0)");
                }
            }
            if (tx == null) throw new InvalidPsbt("PSBT has no unsigned transaction");
            List<List<Entry>> ins = new ArrayList<>(), outs = new ArrayList<>();
            for (int i = 0; i < tx.inputs.size(); i++) {
                if (r.done()) throw new InvalidPsbt("PSBT is missing input " + i);
                List<Entry> m = readMap(r);
                checkInput(m, tx.inputs.get(i), i);
                ins.add(m);
            }
            for (int i = 0; i < tx.outputs.size(); i++) {
                if (r.done()) throw new InvalidPsbt("PSBT is missing output " + i);
                List<Entry> m = readMap(r);
                checkOutput(m, i);
                outs.add(m);
            }
            if (!r.done()) throw new InvalidPsbt("Trailing data after the PSBT");
            return new Psbt(global, tx, ins, outs);
        } catch (InvalidPsbt e) {
            throw e;
        } catch (IllegalArgumentException e) {
            throw new InvalidPsbt("Malformed PSBT: " + e.getMessage());
        }
    }

    private static BtcTx readLegacyTx(BtcTx.Reader r) {
        // PSBT stores the unsigned transaction WITHOUT witness serialization, so a zero input count
        // is just that (BIP-174 test vector "0 inputs and 0 outputs"), never a SegWit marker.
        long version = r.u32();
        long nIn = r.compact();
        if (nIn > BtcTx.MAX_IO) throw new InvalidPsbt("Too many inputs (" + nIn + "); the phone signs at most " + BtcTx.MAX_IO);
        List<BtcTx.Input> ins = new ArrayList<>();
        for (int i = 0; i < nIn; i++) {
            byte[] txid = r.bytes(32);
            long vout = r.u32();
            byte[] script = r.varBytes();
            ins.add(new BtcTx.Input(txid, vout, script, r.u32()));
        }
        long nOut = r.compact();
        if (nOut > BtcTx.MAX_IO) throw new InvalidPsbt("Too many outputs (" + nOut + "); the phone signs at most " + BtcTx.MAX_IO);
        List<BtcTx.Output> outs = new ArrayList<>();
        for (int i = 0; i < nOut; i++) {
            long value = r.u64();
            if (value < 0 || value > 21_000_000L * 100_000_000L) throw new InvalidPsbt("Output amount out of range");
            outs.add(new BtcTx.Output(value, r.varBytes()));
        }
        return new BtcTx(version, ins, outs, r.u32(), false);
    }

    private static List<Entry> readMap(BtcTx.Reader r) {
        List<Entry> map = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        while (true) {
            long keyLen = r.compact();
            if (keyLen == 0) return map;
            byte[] key = r.bytes(keyLen);
            BtcTx.Reader kr = new BtcTx.Reader(key);
            long type = kr.compact();
            byte[] keyData = kr.bytes(kr.remaining());
            byte[] value = r.varBytes();
            if (!seen.add(BtcCrypto.hex(key))) throw new InvalidPsbt("Duplicate key in PSBT map");
            map.add(new Entry(type, key, keyData, value));
        }
    }

    private static void keyLength(Entry e, int keyDataLength, String what) {
        if (e.keyData.length != keyDataLength) throw new InvalidPsbt("Invalid key length for " + what);
    }

    private static void pubkeyKey(Entry e, String what) {
        boolean ok = e.keyData.length == 33 ? BtcCrypto.validCompressed(e.keyData)
                : e.keyData.length == 65 && e.keyData[0] == 4 && validPoint(e.keyData);
        if (!ok) throw new InvalidPsbt("Invalid public key in " + what);
    }

    private static boolean validPoint(byte[] p) {
        try { BtcCrypto.decodePoint(p); return true; } catch (RuntimeException e) { return false; }
    }

    static Origin origin(byte[] v, String what) {
        if (v.length < 4 || v.length % 4 != 0 || v.length > 4 + 4 * 255) throw new InvalidPsbt("Invalid key origin in " + what);
        int[] path = new int[(v.length - 4) / 4];
        for (int i = 0; i < path.length; i++) {
            int o = 4 + 4 * i;
            path[i] = (v[o] & 0xff) | ((v[o + 1] & 0xff) << 8) | ((v[o + 2] & 0xff) << 16) | ((v[o + 3] & 0xff) << 24);
        }
        return new Origin(Arrays.copyOf(v, 4), path);
    }

    /** Taproot derivation value: compact count, 32-byte leaf hashes, then the origin. */
    static Derivation tapDerivation(Entry e, String what) {
        BtcTx.Reader r = new BtcTx.Reader(e.value);
        long n = r.compact();
        if (n > 1000) throw new InvalidPsbt("Too many leaf hashes in " + what);
        r.bytes(32 * n);
        return new Derivation(e.keyData, origin(r.bytes(r.remaining()), what), (int) n);
    }

    private static void checkInput(List<Entry> m, BtcTx.Input txIn, int index) {
        String where = "input " + index;
        for (Entry e : m) {
            int t = (int) Math.min(e.type, Integer.MAX_VALUE);
            switch (t) {
                case IN_NON_WITNESS_UTXO: {
                    keyLength(e, 0, "non-witness UTXO of " + where);
                    BtcTx prev = BtcTx.parse(e.value, BtcTx.MAX_PREV_IO);
                    if (!Arrays.equals(prev.txid(), txIn.prevTxid)) throw new InvalidPsbt("Non-witness UTXO of " + where + " does not match its outpoint");
                    if (txIn.vout >= prev.outputs.size()) throw new InvalidPsbt("Non-witness UTXO of " + where + " has no output " + txIn.vout);
                    break;
                }
                case IN_WITNESS_UTXO: keyLength(e, 0, "witness UTXO of " + where); witnessUtxo(e.value); break;
                case IN_PARTIAL_SIG: pubkeyKey(e, "partial signature of " + where); if (e.value.length < 9 || e.value.length > 73) throw new InvalidPsbt("Invalid partial signature in " + where); break;
                case IN_SIGHASH_TYPE: keyLength(e, 0, "sighash type of " + where); if (e.value.length != 4) throw new InvalidPsbt("Invalid sighash type in " + where); break;
                case IN_REDEEM_SCRIPT: keyLength(e, 0, "redeem script of " + where); break;
                case IN_WITNESS_SCRIPT: keyLength(e, 0, "witness script of " + where); break;
                case IN_BIP32_DERIVATION: pubkeyKey(e, "BIP-32 derivation of " + where); origin(e.value, where); break;
                case IN_FINAL_SCRIPTSIG: keyLength(e, 0, "final scriptSig of " + where); break;
                case IN_FINAL_SCRIPTWITNESS: {
                    keyLength(e, 0, "final script witness of " + where);
                    BtcTx.Reader r = new BtcTx.Reader(e.value);
                    long items = r.compact();
                    for (long j = 0; j < items; j++) r.varBytes();
                    if (!r.done()) throw new InvalidPsbt("Invalid final script witness in " + where);
                    break;
                }
                case IN_POR_COMMITMENT: keyLength(e, 0, "proof-of-reserves commitment of " + where); break;
                case IN_RIPEMD160: case IN_HASH160: preimage(e, 20, where); break;
                case IN_SHA256: case IN_HASH256: preimage(e, 32, where); break;
                case 0x0e: case 0x0f: case 0x10: case 0x11: case 0x12:
                    throw new InvalidPsbt("PSBT version 2 input fields are not allowed in version 0");
                case IN_TAP_KEY_SIG:
                    keyLength(e, 0, "Taproot key signature of " + where);
                    if (e.value.length != 64 && e.value.length != 65) throw new InvalidPsbt("Invalid Taproot key signature length in " + where);
                    break;
                case IN_TAP_SCRIPT_SIG:
                    keyLength(e, 64, "Taproot script signature of " + where);
                    if (e.value.length != 64 && e.value.length != 65) throw new InvalidPsbt("Invalid Taproot script signature length in " + where);
                    break;
                case IN_TAP_LEAF_SCRIPT:
                    if (e.keyData.length < 33 || (e.keyData.length - 33) % 32 != 0 || e.keyData.length > 33 + 32 * 128) {
                        throw new InvalidPsbt("Invalid Taproot control block in " + where);
                    }
                    if (e.value.length < 1) throw new InvalidPsbt("Invalid Taproot leaf script in " + where);
                    break;
                case IN_TAP_BIP32_DERIVATION: keyLength(e, 32, "Taproot BIP-32 derivation of " + where); tapDerivation(e, where); break;
                case IN_TAP_INTERNAL_KEY: keyLength(e, 0, "Taproot internal key of " + where); if (e.value.length != 32) throw new InvalidPsbt("Invalid Taproot internal key in " + where); break;
                case IN_TAP_MERKLE_ROOT: keyLength(e, 0, "Taproot merkle root of " + where); if (e.value.length != 32) throw new InvalidPsbt("Invalid Taproot merkle root in " + where); break;
                default: break; // unknown / proprietary: kept (the signing policy decides)
            }
        }
    }

    private static void preimage(Entry e, int hashLength, String where) {
        if (e.keyData.length != hashLength) throw new InvalidPsbt("Invalid hash preimage key in " + where);
    }

    private static void checkOutput(List<Entry> m, int index) {
        String where = "output " + index;
        for (Entry e : m) {
            int t = (int) Math.min(e.type, Integer.MAX_VALUE);
            switch (t) {
                case OUT_REDEEM_SCRIPT: keyLength(e, 0, "redeem script of " + where); break;
                case OUT_WITNESS_SCRIPT: keyLength(e, 0, "witness script of " + where); break;
                case OUT_BIP32_DERIVATION: pubkeyKey(e, "BIP-32 derivation of " + where); origin(e.value, where); break;
                case 0x03: case 0x04: throw new InvalidPsbt("PSBT version 2 output fields are not allowed in version 0");
                case OUT_TAP_INTERNAL_KEY: keyLength(e, 0, "Taproot internal key of " + where); if (e.value.length != 32) throw new InvalidPsbt("Invalid Taproot internal key in " + where); break;
                case OUT_TAP_TREE: keyLength(e, 0, "Taproot tree of " + where); if (e.value.length < 3) throw new InvalidPsbt("Invalid Taproot tree in " + where); break;
                case OUT_TAP_BIP32_DERIVATION: keyLength(e, 32, "Taproot BIP-32 derivation of " + where); tapDerivation(e, where); break;
                default: break;
            }
        }
    }

    static BtcTx.Output witnessUtxo(byte[] v) {
        BtcTx.Reader r = new BtcTx.Reader(v);
        long amount = r.u64();
        if (amount < 0 || amount > 21_000_000L * 100_000_000L) throw new InvalidPsbt("Witness UTXO amount out of range");
        byte[] script = r.varBytes();
        if (!r.done()) throw new InvalidPsbt("Witness UTXO has trailing bytes");
        return new BtcTx.Output(amount, script);
    }

    // ------------------------------------------------------------------ typed views

    static Entry find(List<Entry> map, int type) {
        for (Entry e : map) if (e.type == type) return e;
        return null;
    }

    static List<Entry> all(List<Entry> map, int type) {
        List<Entry> out = new ArrayList<>();
        for (Entry e : map) if (e.type == type) out.add(e);
        return out;
    }

    // ------------------------------------------------------------------ writing

    /**
     * A copy of this PSBT with {@code additions[i]} put into input map i (an existing entry with
     * the same key is replaced). Everything else is preserved byte-for-byte, in order.
     */
    byte[] serializeWith(List<List<Entry>> additions) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(MAGIC, 0, MAGIC.length);
        writeMap(o, global, Collections.<Entry>emptyList());
        for (int i = 0; i < inputs.size(); i++) {
            writeMap(o, inputs.get(i), additions == null || additions.size() <= i || additions.get(i) == null
                    ? Collections.<Entry>emptyList() : additions.get(i));
        }
        for (List<Entry> m : outputs) writeMap(o, m, Collections.<Entry>emptyList());
        return o.toByteArray();
    }

    byte[] serialize() { return serializeWith(null); }

    private static void writeMap(ByteArrayOutputStream o, List<Entry> map, List<Entry> add) {
        Set<String> replaced = new HashSet<>();
        for (Entry a : add) replaced.add(BtcCrypto.hex(a.key));
        for (Entry e : map) if (!replaced.contains(BtcCrypto.hex(e.key))) writeEntry(o, e);
        for (Entry a : add) writeEntry(o, a);
        o.write(0x00);
    }

    private static void writeEntry(ByteArrayOutputStream o, Entry e) {
        BtcTx.varBytes(o, e.key);
        BtcTx.varBytes(o, e.value);
    }

    static Entry entry(int type, byte[] keyData, byte[] value) {
        byte[] key = new byte[1 + keyData.length];
        key[0] = (byte) type;
        System.arraycopy(keyData, 0, key, 1, keyData.length);
        return new Entry(type, key, keyData, value);
    }
}
