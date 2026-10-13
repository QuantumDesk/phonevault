package dev.phonevault.signer;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A Bitcoin transaction: strict parsing (canonical compact sizes, bounded counts, no trailing
 * bytes), the legacy serialization used for txids, and the two signature hashes the phone signs:
 * BIP-143 (SegWit v0) and BIP-341 (Taproot key path).
 */
final class BtcTx {
    static final int MAX_IO = 100;          // the phone's own cap for a transaction it signs
    static final int MAX_PREV_IO = 10_000;  // cap for a previous transaction (non_witness_utxo)

    static final int SIGHASH_DEFAULT = 0x00, SIGHASH_ALL = 0x01, SIGHASH_NONE = 0x02, SIGHASH_SINGLE = 0x03,
            SIGHASH_ANYONECANPAY = 0x80;

    static final class Input {
        final byte[] prevTxid;  // internal byte order (as serialized)
        final long vout;        // uint32
        final byte[] scriptSig;
        final long sequence;    // uint32

        Input(byte[] prevTxid, long vout, byte[] scriptSig, long sequence) {
            this.prevTxid = prevTxid;
            this.vout = vout;
            this.scriptSig = scriptSig;
            this.sequence = sequence;
        }

        /** "txid:vout" with the txid in the usual (reversed) display order. */
        String outpoint() { return BtcCrypto.hex(BtcCrypto.reversed(prevTxid)) + ":" + vout; }
    }

    static final class Output {
        final long value; // satoshis
        final byte[] script;
        Output(long value, byte[] script) { this.value = value; this.script = script; }
    }

    final long version; // uint32 on the wire (signed int32 in consensus; serialized identically)
    final List<Input> inputs;
    final List<Output> outputs;
    final long locktime;
    /** True when the parsed bytes carried witness data (never allowed for the unsigned transaction). */
    final boolean hadWitness;

    BtcTx(long version, List<Input> inputs, List<Output> outputs, long locktime, boolean hadWitness) {
        this.version = version;
        this.inputs = Collections.unmodifiableList(inputs);
        this.outputs = Collections.unmodifiableList(outputs);
        this.locktime = locktime;
        this.hadWitness = hadWitness;
    }

    // ------------------------------------------------------------------ reading

    static final class Reader {
        final byte[] b;
        int at;
        Reader(byte[] b) { this.b = b; }

        int remaining() { return b.length - at; }
        boolean done() { return at == b.length; }

        int u8() {
            if (at >= b.length) throw new IllegalArgumentException("unexpected end of data");
            return b[at++] & 0xff;
        }

        long u32() {
            need(4);
            long v = (b[at] & 0xffL) | ((b[at + 1] & 0xffL) << 8) | ((b[at + 2] & 0xffL) << 16) | ((b[at + 3] & 0xffL) << 24);
            at += 4;
            return v;
        }

        long u64() {
            need(8);
            long v = 0;
            for (int i = 7; i >= 0; i--) v = (v << 8) | (b[at + i] & 0xffL);
            at += 8;
            return v;
        }

        /** Canonical (minimally encoded) CompactSize. */
        long compact() {
            int first = u8();
            if (first < 0xfd) return first;
            long v;
            if (first == 0xfd) { need(2); v = (b[at] & 0xffL) | ((b[at + 1] & 0xffL) << 8); at += 2; if (v < 0xfd) throw new IllegalArgumentException("non-canonical compact size"); }
            else if (first == 0xfe) { v = u32(); if (v <= 0xffff) throw new IllegalArgumentException("non-canonical compact size"); }
            else { v = u64(); if (v >= 0 && v <= 0xffffffffL) throw new IllegalArgumentException("non-canonical compact size"); }
            if (v < 0 || v > Integer.MAX_VALUE) throw new IllegalArgumentException("compact size too large");
            return v;
        }

        byte[] bytes(long n) {
            if (n < 0 || n > remaining()) throw new IllegalArgumentException("length exceeds data");
            byte[] out = new byte[(int) n];
            System.arraycopy(b, at, out, 0, (int) n);
            at += (int) n;
            return out;
        }

        byte[] varBytes() { return bytes(compact()); }

        private void need(int n) { if (remaining() < n) throw new IllegalArgumentException("unexpected end of data"); }
    }

    /** Parse a whole transaction; {@code maxIo} bounds input and output counts. */
    static BtcTx parse(byte[] raw, int maxIo) {
        Reader r = new Reader(raw);
        BtcTx tx = read(r, maxIo);
        if (!r.done()) throw new IllegalArgumentException("trailing bytes after transaction");
        return tx;
    }

    static BtcTx read(Reader r, int maxIo) {
        long version = r.u32();
        boolean witness = false;
        long nIn = r.compact();
        if (nIn == 0) {
            int flag = r.u8();
            if (flag != 1) throw new IllegalArgumentException("invalid segwit flag");
            witness = true;
            nIn = r.compact();
            if (nIn == 0) throw new IllegalArgumentException("transaction has no inputs");
        }
        if (nIn > maxIo) throw new IllegalArgumentException("too many inputs (" + nIn + ")");
        List<Input> ins = new ArrayList<>();
        for (int i = 0; i < nIn; i++) {
            byte[] txid = r.bytes(32);
            long vout = r.u32();
            byte[] script = r.varBytes();
            ins.add(new Input(txid, vout, script, r.u32()));
        }
        long nOut = r.compact();
        if (nOut > maxIo) throw new IllegalArgumentException("too many outputs (" + nOut + ")");
        List<Output> outs = new ArrayList<>();
        for (int i = 0; i < nOut; i++) {
            long value = r.u64();
            if (value < 0 || value > 21_000_000L * 100_000_000L) throw new IllegalArgumentException("output amount out of range");
            outs.add(new Output(value, r.varBytes()));
        }
        if (witness) {
            boolean any = false;
            for (int i = 0; i < nIn; i++) {
                long items = r.compact();
                for (long j = 0; j < items; j++) r.varBytes();
                if (items > 0) any = true;
            }
            if (!any) throw new IllegalArgumentException("segwit flag without witness data");
        }
        long locktime = r.u32();
        return new BtcTx(version, ins, outs, locktime, witness);
    }

    // ------------------------------------------------------------------ writing

    static void u32(ByteArrayOutputStream o, long v) { for (int i = 0; i < 4; i++) o.write((int) (v >>> (8 * i)) & 0xff); }

    static void u64(ByteArrayOutputStream o, long v) { for (int i = 0; i < 8; i++) o.write((int) (v >>> (8 * i)) & 0xff); }

    static void compact(ByteArrayOutputStream o, long n) {
        if (n < 0xfd) o.write((int) n);
        else if (n <= 0xffff) { o.write(0xfd); o.write((int) n & 0xff); o.write((int) (n >>> 8) & 0xff); }
        else if (n <= 0xffffffffL) { o.write(0xfe); u32(o, n); }
        else { o.write(0xff); u64(o, n); }
    }

    static void varBytes(ByteArrayOutputStream o, byte[] b) {
        compact(o, b.length);
        o.write(b, 0, b.length);
    }

    static void output(ByteArrayOutputStream o, Output out) {
        u64(o, out.value);
        varBytes(o, out.script);
    }

    /** Serialization without witness (the txid preimage; also how PSBT stores the unsigned tx). */
    byte[] serializeLegacy() {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        u32(o, version);
        compact(o, inputs.size());
        for (Input in : inputs) {
            o.write(in.prevTxid, 0, 32);
            u32(o, in.vout);
            varBytes(o, in.scriptSig);
            u32(o, in.sequence);
        }
        compact(o, outputs.size());
        for (Output out : outputs) output(o, out);
        u32(o, locktime);
        return o.toByteArray();
    }

    /** txid in internal byte order. */
    byte[] txid() { return BtcCrypto.sha256d(serializeLegacy()); }

    // ------------------------------------------------------------------ BIP-143 (SegWit v0)

    /**
     * BIP-143 signature hash of input {@code index} spending {@code amount} with {@code scriptCode}
     * (for P2WPKH: OP_DUP OP_HASH160 &lt;hash&gt; OP_EQUALVERIFY OP_CHECKSIG).
     */
    byte[] sighashSegwitV0(int index, byte[] scriptCode, long amount, int hashType) {
        int base = hashType & 0x1f;
        boolean anyone = (hashType & SIGHASH_ANYONECANPAY) != 0;
        byte[] zero = new byte[32];
        byte[] hashPrevouts = zero, hashSequence = zero, hashOutputs = zero;
        if (!anyone) {
            ByteArrayOutputStream p = new ByteArrayOutputStream();
            for (Input in : inputs) { p.write(in.prevTxid, 0, 32); u32(p, in.vout); }
            hashPrevouts = BtcCrypto.sha256d(p.toByteArray());
        }
        if (!anyone && base != SIGHASH_SINGLE && base != SIGHASH_NONE) {
            ByteArrayOutputStream s = new ByteArrayOutputStream();
            for (Input in : inputs) u32(s, in.sequence);
            hashSequence = BtcCrypto.sha256d(s.toByteArray());
        }
        if (base != SIGHASH_SINGLE && base != SIGHASH_NONE) {
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            for (Output out : outputs) output(os, out);
            hashOutputs = BtcCrypto.sha256d(os.toByteArray());
        } else if (base == SIGHASH_SINGLE && index < outputs.size()) {
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            output(os, outputs.get(index));
            hashOutputs = BtcCrypto.sha256d(os.toByteArray());
        }
        Input in = inputs.get(index);
        ByteArrayOutputStream m = new ByteArrayOutputStream();
        u32(m, version);
        m.write(hashPrevouts, 0, 32);
        m.write(hashSequence, 0, 32);
        m.write(in.prevTxid, 0, 32);
        u32(m, in.vout);
        varBytes(m, scriptCode);
        u64(m, amount);
        u32(m, in.sequence);
        m.write(hashOutputs, 0, 32);
        u32(m, locktime);
        u32(m, hashType & 0xffffffffL);
        return BtcCrypto.sha256d(m.toByteArray());
    }

    // ------------------------------------------------------------------ BIP-341 (Taproot)

    /**
     * BIP-341 SigMsg for a key-path spend (ext_flag 0) of input {@code index}. {@code amounts} and
     * {@code scripts} are those of EVERY input being spent, which the hash commits to. All hash
     * types are implemented (the BIP's test vectors use them); the phone signs only DEFAULT/ALL.
     */
    byte[] sigMsgTaproot(int index, long[] amounts, byte[][] scripts, int hashType, byte[] annex) {
        if (amounts.length != inputs.size() || scripts.length != inputs.size()) throw new IllegalArgumentException("every spent output is needed");
        int out = hashType & 0x03;
        boolean anyone = (hashType & SIGHASH_ANYONECANPAY) != 0;
        if (!(hashType == 0 || (hashType >= 1 && hashType <= 3) || (hashType >= 0x81 && hashType <= 0x83))) {
            throw new IllegalArgumentException("invalid taproot hash type");
        }
        if (out == SIGHASH_SINGLE && index >= outputs.size()) throw new IllegalArgumentException("SIGHASH_SINGLE without a matching output");
        ByteArrayOutputStream m = new ByteArrayOutputStream();
        m.write(0x00); // epoch
        m.write(hashType);
        u32(m, version);
        u32(m, locktime);
        if (!anyone) {
            ByteArrayOutputStream p = new ByteArrayOutputStream(), a = new ByteArrayOutputStream(),
                    s = new ByteArrayOutputStream(), q = new ByteArrayOutputStream();
            for (int i = 0; i < inputs.size(); i++) {
                Input in = inputs.get(i);
                p.write(in.prevTxid, 0, 32);
                u32(p, in.vout);
                u64(a, amounts[i]);
                varBytes(s, scripts[i]);
                u32(q, in.sequence);
            }
            m.write(BtcCrypto.sha256(p.toByteArray()), 0, 32);
            m.write(BtcCrypto.sha256(a.toByteArray()), 0, 32);
            m.write(BtcCrypto.sha256(s.toByteArray()), 0, 32);
            m.write(BtcCrypto.sha256(q.toByteArray()), 0, 32);
        }
        if (out != SIGHASH_NONE && out != SIGHASH_SINGLE) {
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            for (Output o : outputs) output(os, o);
            m.write(BtcCrypto.sha256(os.toByteArray()), 0, 32);
        }
        m.write(annex != null ? 1 : 0); // spend_type = ext_flag*2 + annex_present
        if (anyone) {
            Input in = inputs.get(index);
            m.write(in.prevTxid, 0, 32);
            u32(m, in.vout);
            u64(m, amounts[index]);
            varBytes(m, scripts[index]);
            u32(m, in.sequence);
        } else {
            u32(m, index);
        }
        if (annex != null) {
            ByteArrayOutputStream an = new ByteArrayOutputStream();
            varBytes(an, annex);
            m.write(BtcCrypto.sha256(an.toByteArray()), 0, 32);
        }
        if (out == SIGHASH_SINGLE) {
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            output(os, outputs.get(index));
            m.write(BtcCrypto.sha256(os.toByteArray()), 0, 32);
        }
        return m.toByteArray();
    }

    byte[] sighashTaproot(int index, long[] amounts, byte[][] scripts, int hashType) {
        return BtcCrypto.taggedHash("TapSighash", sigMsgTaproot(index, amounts, scripts, hashType, null));
    }

    // ------------------------------------------------------------------ size

    /** Unsigned (legacy) size in bytes. */
    int baseSize() { return serializeLegacy().length; }

    /**
     * Virtual size once signed, given the witness bytes each input will carry (count prefix
     * included). The SegWit marker and flag count as witness data.
     */
    long vsize(int[] witnessBytes) {
        long weight = 4L * baseSize() + 2;
        for (int w : witnessBytes) weight += w;
        return (weight + 3) / 4;
    }
}
