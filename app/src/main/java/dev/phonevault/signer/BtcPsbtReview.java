package dev.phonevault.signer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * The signing policy and plain-language review for one PSBT (btcSignPsbt). Built once from the
 * parsed {@link Psbt} and this phone's own {@link BtcWallet}; {@link BtcPsbtSigner} signs exactly
 * the inputs listed here, so what the user approves and what is signed cannot diverge.
 *
 * <p>Refused (with a reason shown on the phone), before any review exists:
 * <ul>
 *   <li>any input that is not this wallet's own Native SegWit (m/84'/coin'/a'/c/i) or Taproot
 *       key-path (m/86'/coin'/a'/c/i, BIP-86, no script tree) coin, proven by deriving the key from
 *       the account xpub and matching the UTXO's script (coinjoin / payjoin / multisig are not supported);</li>
 *   <li>an input without a witness UTXO, or whose non-witness UTXO disagrees with it;</li>
 *   <li>sighash types other than ALL (SegWit v0) or DEFAULT/ALL (Taproot);</li>
 *   <li>input fields the phone does not understand (scripts, finalized data, script-path Taproot,
 *       MuSig2, hash preimages, proprietary or unknown types): they could change what a signature means;</li>
 *   <li>an output script that is not a standard address type or OP_RETURN data;</li>
 *   <li>an output that claims to be this wallet's but does not match the derived key;</li>
 *   <li>outputs worth more than the inputs; a coin the phone already signed for with a different amount.</li>
 * </ul>
 */
final class BtcPsbtReview {
    static final String DANGER = MessageReview.DANGER;
    static final String WARNING = MessageReview.WARNING;
    /** Row label rendered in amber by the approval screen. */
    static final String TEST_NETWORK = "TEST NETWORK";
    static final String REFUSED_TITLE = "Bitcoin transaction refused";

    static final long COIN = 100_000_000L;
    static final long MAX_MONEY = 21_000_000L * COIN;
    /** DANGER above this absolute fee (0.01 BTC). */
    static final long DANGER_FEE_SATS = 1_000_000L;
    /** WARNING above this fee rate. */
    static final double WARNING_FEE_RATE = 500.0;
    /** Witness bytes once signed (count prefix included): P2WPKH 1 + (1+72) + (1+33); P2TR key path 1 + (1+64[+1]). */
    static final int P2WPKH_WITNESS = 108, P2TR_WITNESS = 66;

    static final class SignInput {
        final int index;
        final BtcWallet.Type type;
        final int account, change, addressIndex;
        /** Compressed public key the phone derived for this input. */
        final byte[] pubkey;
        final long amount;
        final byte[] script;
        final int hashType;
        final String address;
        final String path;

        SignInput(int index, BtcWallet.Type type, int account, int change, int addressIndex, byte[] pubkey,
                  long amount, byte[] script, int hashType, String address, String path) {
            this.index = index;
            this.type = type;
            this.account = account;
            this.change = change;
            this.addressIndex = addressIndex;
            this.pubkey = pubkey;
            this.amount = amount;
            this.script = script;
            this.hashType = hashType;
            this.address = address;
            this.path = path;
        }
    }

    static final class Out {
        final int index;
        final long value;
        final BtcScript.Kind kind;
        final String address;  // null for OP_RETURN
        /** This wallet's own change (…/1/i), verified by derivation. */
        final boolean change;
        /** This wallet's own receive address (…/0/i), verified by derivation. */
        final boolean ownReceive;
        final String path;     // for own outputs

        Out(int index, long value, BtcScript.Kind kind, String address, boolean change, boolean ownReceive, String path) {
            this.index = index;
            this.value = value;
            this.kind = kind;
            this.address = address;
            this.change = change;
            this.ownReceive = ownReceive;
            this.path = path;
        }
    }

    final BtcNetwork network;
    final Psbt psbt;
    final List<SignInput> inputs;
    final List<Out> outputs;
    final long totalIn, totalOut, fee, sent, changeTotal;
    final long vsize;
    final String feeRate; // "12.3"
    final String title, kicker, subtitle;
    final List<MessageReview.Row> summary, details;
    final String reviewPrompt, signLabel;
    /** Counterparties recorded in {@link RecipientHistory} after signing (BTC address keys). */
    final List<TransactionReview.Party> parties;
    /** History wallet key: btc-wallet:&lt;network&gt;:&lt;fingerprint&gt;. */
    final String walletKey;

    private BtcPsbtReview(BtcNetwork network, Psbt psbt, List<SignInput> inputs, List<Out> outputs, long totalIn,
                          long totalOut, long sent, long changeTotal, long vsize, String walletKey) {
        this.network = network;
        this.psbt = psbt;
        this.inputs = Collections.unmodifiableList(inputs);
        this.outputs = Collections.unmodifiableList(outputs);
        this.totalIn = totalIn;
        this.totalOut = totalOut;
        this.fee = totalIn - totalOut;
        this.sent = sent;
        this.changeTotal = changeTotal;
        this.vsize = vsize;
        this.feeRate = rate(fee, vsize);
        this.walletKey = walletKey;
        this.kicker = network.test() ? network.label.toUpperCase(Locale.ROOT) + " · TEST COINS" : "BITCOIN TRANSACTION REVIEW";
        this.subtitle = "Compare every output with what you intend. Only this phone's screen is trusted; the Mac prepared this transaction.";
        this.title = sent > 0 ? "Send " + btc(sent, network) : "Move " + btc(totalOut, network) + " within your wallet";
        this.reviewPrompt = "I checked the network, every recipient address and amount, the change, and the fee shown above.";
        this.signLabel = "Approve & sign";
        this.summary = new ArrayList<>();
        this.details = new ArrayList<>();
        this.parties = new ArrayList<>();
    }

    // ------------------------------------------------------------------ building

    /**
     * @param safety the phone's address book and recipient history (display only), or null
     * @param amounts amounts the phone already signed per outpoint this process (fee-attack guard), or null
     */
    static BtcPsbtReview build(Psbt psbt, BtcNetwork network, BtcWallet wallet, AddressSafety safety, BtcAmountMemory amounts)
            throws RequestRefusal {
        if (wallet == null || wallet.network != network) throw new IllegalStateException("wallet for another network");
        BtcTx tx = psbt.tx;
        if (tx.version < 1 || tx.version > 3) throw refuse("Unusual transaction version " + tx.version + ".");
        if (tx.inputs.isEmpty()) throw refuse("The transaction spends no coins.");
        if (tx.outputs.isEmpty()) throw refuse("The transaction has no outputs.");
        byte[] fp = wallet.fingerprint();
        String fpHex = wallet.fingerprintHex();

        // ---- inputs: every one must be this wallet's own coin, proven by derivation
        List<SignInput> ins = new ArrayList<>();
        Set<String> outpoints = new HashSet<>();
        long totalIn = 0;
        for (int i = 0; i < tx.inputs.size(); i++) {
            BtcTx.Input txIn = tx.inputs.get(i);
            if (!outpoints.add(txIn.outpoint())) throw refuse("Input " + (i + 1) + " spends the same coin twice.");
            List<Psbt.Entry> map = psbt.inputs.get(i);
            for (Psbt.Entry e : map) {
                String why = inputFieldProblem(e.type);
                if (why != null) throw refuse("Input " + (i + 1) + " carries " + why + ", which this phone does not sign.");
            }
            Psbt.Entry wu = Psbt.find(map, Psbt.IN_WITNESS_UTXO);
            if (wu == null) throw refuse("Input " + (i + 1) + " has no witness UTXO (amount and script of the coin), so the phone can't check it.");
            BtcTx.Output utxo = Psbt.witnessUtxo(wu.value);
            Psbt.Entry nwu = Psbt.find(map, Psbt.IN_NON_WITNESS_UTXO);
            if (nwu != null) {
                BtcTx prev = BtcTx.parse(nwu.value, BtcTx.MAX_PREV_IO);
                BtcTx.Output o = prev.outputs.get((int) txIn.vout);
                if (o.value != utxo.value || !Arrays.equals(o.script, utxo.script)) {
                    throw refuse("Input " + (i + 1) + ": the previous transaction and the witness UTXO disagree about the coin.");
                }
            }
            BtcScript.Kind kind = BtcScript.kind(utxo.script);
            BtcWallet.Type type = kind == BtcScript.Kind.P2WPKH ? BtcWallet.Type.P2WPKH : kind == BtcScript.Kind.P2TR ? BtcWallet.Type.P2TR : null;
            if (type == null) {
                throw refuse("Input " + (i + 1) + " spends a " + BtcScript.kindLabel(kind) + " coin. The phone signs only its own Native SegWit (BIP-84) and Taproot (BIP-86) coins.");
            }
            Owned own = ownedBy(map, type, true, fp, network, wallet, utxo.script, "Input " + (i + 1));
            if (own == null) {
                throw refuse("Input " + (i + 1) + " is not a coin of this wallet (no key derivation for fingerprint " + fpHex
                        + "). Transactions that mix in other people's coins (coinjoin, payjoin, multisig) are not supported.");
            }
            Psbt.Entry sh = Psbt.find(map, Psbt.IN_SIGHASH_TYPE);
            int hashType = type == BtcWallet.Type.P2WPKH ? BtcTx.SIGHASH_ALL : BtcTx.SIGHASH_DEFAULT;
            if (sh != null) {
                long v = new BtcTx.Reader(sh.value).u32();
                boolean ok = type == BtcWallet.Type.P2WPKH ? v == BtcTx.SIGHASH_ALL : v == BtcTx.SIGHASH_DEFAULT || v == BtcTx.SIGHASH_ALL;
                if (!ok) throw refuse("Input " + (i + 1) + " asks for signature hash type 0x" + Long.toHexString(v)
                        + ". Only SIGHASH_ALL (and DEFAULT for Taproot) is signed: other types let the transaction be changed after you sign.");
                hashType = (int) v;
            }
            totalIn = addMoney(totalIn, utxo.value);
            ins.add(new SignInput(i, type, own.account, own.change, own.index, own.pubkey, utxo.value, utxo.script, hashType,
                    BtcScript.address(utxo.script, network), wallet.addressPathString(type, own.account, own.change, own.index)));
        }
        if (amounts != null) {
            for (SignInput in : ins) {
                String conflict = amounts.conflict(tx.inputs.get(in.index).outpoint(), in.amount, in.script);
                if (conflict != null) throw refuse("Input " + (in.index + 1) + " (" + conflict + "). A host that lies about coin "
                        + "amounts can trick a wallet into paying a huge fee. Nothing was signed.");
            }
        }

        // ---- outputs
        List<Out> outs = new ArrayList<>();
        long totalOut = 0, sent = 0, change = 0;
        for (int i = 0; i < tx.outputs.size(); i++) {
            BtcTx.Output o = tx.outputs.get(i);
            List<Psbt.Entry> map = psbt.outputs.get(i);
            BtcScript.Kind kind = BtcScript.kind(o.script);
            if (kind == BtcScript.Kind.UNKNOWN) {
                throw refuse("Output " + (i + 1) + " pays to a script the phone can't show as an address ("
                        + (o.script.length > 40 ? BtcCrypto.hex(Arrays.copyOf(o.script, 40)) + "…" : BtcCrypto.hex(o.script)) + ").");
            }
            totalOut = addMoney(totalOut, o.value);
            if (kind == BtcScript.Kind.OP_RETURN) {
                outs.add(new Out(i, o.value, kind, null, false, false, null));
                sent = addMoney(sent, o.value);
                continue;
            }
            String address = BtcScript.address(o.script, network);
            BtcWallet.Type type = kind == BtcScript.Kind.P2WPKH ? BtcWallet.Type.P2WPKH : kind == BtcScript.Kind.P2TR ? BtcWallet.Type.P2TR : null;
            Owned own = type == null ? null : ownedBy(map, type, false, fp, network, wallet, o.script, "Output " + (i + 1));
            if (type == null) noOwnClaim(map, fp, i);
            boolean isChange = own != null && own.change == 1;
            boolean isOwnReceive = own != null && own.change == 0;
            String path = own == null ? null : wallet.addressPathString(type, own.account, own.change, own.index);
            outs.add(new Out(i, o.value, kind, address, isChange, isOwnReceive, path));
            if (isChange) change = addMoney(change, o.value);
            else sent = addMoney(sent, o.value);
        }
        if (totalOut > totalIn) {
            throw refuse("The outputs (" + btc(totalOut, network) + ") are worth more than the coins spent (" + btc(totalIn, network) + ").");
        }
        int[] witness = new int[ins.size()];
        for (int k = 0; k < ins.size(); k++) {
            SignInput in = ins.get(k);
            witness[k] = in.type == BtcWallet.Type.P2WPKH ? P2WPKH_WITNESS : P2TR_WITNESS + (in.hashType == BtcTx.SIGHASH_ALL ? 1 : 0);
        }
        long vsize = tx.vsize(witness);
        BtcPsbtReview r = new BtcPsbtReview(network, psbt, ins, outs, totalIn, totalOut, sent, change, vsize,
                walletKey(network, fpHex));
        r.render(safety, wallet);
        return r;
    }

    /** The phone's verified claim on a key: which account/branch/index of this wallet it is. */
    private static final class Owned {
        final int account, change, index;
        final byte[] pubkey;
        Owned(int account, int change, int index, byte[] pubkey) { this.account = account; this.change = change; this.index = index; this.pubkey = pubkey; }
    }

    /**
     * The derivation for this wallet's fingerprint in an input/output map, verified: allowed path for
     * the network and script type, key re-derived from the account xpub, script re-computed from it.
     * Null when the map makes no claim for this fingerprint. A claim that does not verify is refused.
     */
    private static Owned ownedBy(List<Psbt.Entry> map, BtcWallet.Type type, boolean input, byte[] fp, BtcNetwork network,
                                 BtcWallet wallet, byte[] script, String what) throws RequestRefusal {
        int ecdsaType = input ? Psbt.IN_BIP32_DERIVATION : Psbt.OUT_BIP32_DERIVATION;
        int tapType = input ? Psbt.IN_TAP_BIP32_DERIVATION : Psbt.OUT_TAP_BIP32_DERIVATION;
        List<Psbt.Derivation> mine = new ArrayList<>();
        List<Psbt.Derivation> wrongKind = new ArrayList<>();
        for (Psbt.Entry e : map) {
            if (e.type == ecdsaType) {
                Psbt.Origin o = Psbt.origin(e.value, what);
                if (Arrays.equals(o.fingerprint, fp)) (type == BtcWallet.Type.P2WPKH ? mine : wrongKind).add(new Psbt.Derivation(e.keyData, o, 0));
            } else if (e.type == tapType) {
                Psbt.Derivation d = Psbt.tapDerivation(e, what);
                if (Arrays.equals(d.origin.fingerprint, fp)) (type == BtcWallet.Type.P2TR ? mine : wrongKind).add(d);
            }
        }
        if (!wrongKind.isEmpty()) throw refuse(what + " names a key of this wallet that does not fit its script type.");
        if (mine.isEmpty()) return null;
        if (mine.size() > 1) throw refuse(what + " names more than one key of this wallet.");
        Psbt.Derivation d = mine.get(0);
        if (d.leafHashes != 0) throw refuse(what + " uses a Taproot script path; only key-path spends (BIP-86) are signed.");
        int[] p = d.origin.path;
        String shown = Bip32.pathString(p);
        if (p.length != 5 || p[0] != (type.purpose | Bip32.HARDENED) || p[1] != (network.coinType | Bip32.HARDENED)
                || (p[2] & Bip32.HARDENED) == 0 || (p[2] & ~Bip32.HARDENED) >= BtcWallet.ACCOUNTS
                || (p[3] != 0 && p[3] != 1) || p[4] < 0 || p[4] > BtcWallet.MAX_PSBT_INDEX) {
            throw refuse(what + " uses key path " + shown + ", outside this wallet's " + network.label + " accounts (m/"
                    + type.purpose + "'/" + network.coinType + "'/0'…" + (BtcWallet.ACCOUNTS - 1) + "'/0|1/i).");
        }
        int account = p[2] & ~Bip32.HARDENED;
        byte[] pub = wallet.publicKey(type, account, p[3], p[4]);
        byte[] expectKey = type == BtcWallet.Type.P2WPKH ? pub : Arrays.copyOfRange(pub, 1, 33);
        if (!Arrays.equals(expectKey, d.key)) throw refuse(what + " names key path " + shown + " but a different key than this wallet's.");
        if (!Arrays.equals(BtcWallet.scriptFor(type, pub), script)) throw refuse(what + " claims key path " + shown + " but its script does not belong to that key.");
        if (type == BtcWallet.Type.P2TR) {
            Psbt.Entry internal = Psbt.find(map, input ? Psbt.IN_TAP_INTERNAL_KEY : Psbt.OUT_TAP_INTERNAL_KEY);
            if (internal != null && !Arrays.equals(internal.value, expectKey)) throw refuse(what + " names a different Taproot internal key.");
            if (!input && Psbt.find(map, Psbt.OUT_TAP_TREE) != null) throw refuse(what + " adds a Taproot script tree to this wallet's key.");
        }
        return new Owned(account, p[3], p[4], pub);
    }

    private static void noOwnClaim(List<Psbt.Entry> map, byte[] fp, int index) throws RequestRefusal {
        for (Psbt.Entry e : map) {
            byte[] origin = null;
            if (e.type == Psbt.OUT_BIP32_DERIVATION) origin = e.value;
            else if (e.type == Psbt.OUT_TAP_BIP32_DERIVATION) origin = Psbt.tapDerivation(e, "output").origin.fingerprint;
            if (origin != null && origin.length >= 4 && Arrays.equals(Arrays.copyOf(origin, 4), fp)) {
                throw refuse("Output " + (index + 1) + " claims to be this wallet's, but it is not a Native SegWit or Taproot address the phone derives.");
            }
        }
    }

    /** Why an input field stops the phone from signing, or null when it is understood. */
    static String inputFieldProblem(long type) {
        switch ((int) Math.min(type, Integer.MAX_VALUE)) {
            case Psbt.IN_NON_WITNESS_UTXO: case Psbt.IN_WITNESS_UTXO: case Psbt.IN_PARTIAL_SIG: case Psbt.IN_SIGHASH_TYPE:
            case Psbt.IN_BIP32_DERIVATION: case Psbt.IN_TAP_KEY_SIG: case Psbt.IN_TAP_BIP32_DERIVATION: case Psbt.IN_TAP_INTERNAL_KEY:
                return null;
            case Psbt.IN_REDEEM_SCRIPT: return "a redeem script (P2SH)";
            case Psbt.IN_WITNESS_SCRIPT: return "a witness script (P2WSH)";
            case Psbt.IN_FINAL_SCRIPTSIG: case Psbt.IN_FINAL_SCRIPTWITNESS: return "already finalized data";
            case Psbt.IN_POR_COMMITMENT: return "a proof-of-reserves commitment";
            case Psbt.IN_RIPEMD160: case Psbt.IN_SHA256: case Psbt.IN_HASH160: case Psbt.IN_HASH256: return "a hash preimage";
            case Psbt.IN_TAP_SCRIPT_SIG: case Psbt.IN_TAP_LEAF_SCRIPT: case Psbt.IN_TAP_MERKLE_ROOT: return "Taproot script-path data";
            case 0x19: case 0x1a: case 0x1b: return "MuSig2 data";
            case Psbt.PROPRIETARY: return "a proprietary field";
            default: return "an unknown field (type 0x" + Long.toHexString(type) + ")";
        }
    }

    private static long addMoney(long a, long b) throws RequestRefusal {
        long s = a + b;
        if (b < 0 || s < a || s > MAX_MONEY) throw refuse("Amounts add up to more than 21 million BTC.");
        return s;
    }

    static RequestRefusal refuse(String message) { return new RequestRefusal(REFUSED_TITLE, message + " Nothing was signed."); }

    static String walletKey(BtcNetwork network, String fingerprintHex) {
        return "btc-wallet:" + network.wire + ":" + fingerprintHex.toLowerCase(Locale.ROOT);
    }

    // ------------------------------------------------------------------ rendering

    private void render(AddressSafety safety, BtcWallet wallet) {
        List<MessageReview.Row> rows = summary;
        rows.add(row(network.test() ? TEST_NETWORK : "Network", network.test()
                ? network.label + " — test coins with no value. Never use this for real bitcoin." : network.label));
        // where the money comes from
        Map<String, long[]> from = new LinkedHashMap<>();
        for (SignInput in : inputs) {
            String k = BtcWallet.accountLabel(in.type, in.account) + " (" + wallet.accountPathString(in.type, in.account) + ")";
            long[] v = from.get(k);
            if (v == null) from.put(k, v = new long[2]);
            v[0]++;
            v[1] += in.amount;
        }
        for (Map.Entry<String, long[]> e : from.entrySet()) {
            rows.add(row("Spending from", e.getKey() + "\n" + e.getValue()[0] + (e.getValue()[0] == 1 ? " coin, " : " coins, ") + btc(e.getValue()[1], network)));
        }
        for (Out o : outputs) {
            if (o.change) continue;
            if (o.kind == BtcScript.Kind.OP_RETURN) {
                rows.add(row("Data output (" + BtcScript.dataLength(psbt.tx.outputs.get(o.index).script) + " bytes)",
                        "Writes data into the blockchain. It pays nobody" + (o.value > 0 ? "." : " (0 BTC).")));
                if (o.value > 0) rows.add(row(DANGER, btc(o.value, network) + " sent to the data output is destroyed forever: nobody can ever spend it."));
                continue;
            }
            rows.add(row("Send", btc(o.value, network) + " to\n" + BtcScript.grouped(o.address, 5)));
            if (o.ownReceive) {
                rows.add(row("Your own address ✓", "This wallet's receiving address " + o.path + " (checked by the phone)."));
            } else if (safety != null) {
                rows.addAll(safety.rows(walletKey, AddressKeys.btc(network, o.address), RecipientHistory.Role.SEND));
                parties.add(new TransactionReview.Party(AddressKeys.btc(network, o.address), RecipientHistory.Role.SEND));
            } else {
                parties.add(new TransactionReview.Party(AddressKeys.btc(network, o.address), RecipientHistory.Role.SEND));
            }
        }
        for (Out o : outputs) {
            if (!o.change) continue;
            rows.add(row("Change back to your wallet ✓", btc(o.value, network) + " · " + AddressKeys.shortBtc(o.address) + " · " + o.path));
        }
        rows.add(row("Network fee", btc(fee, network) + " (" + feeRate + " sat/vB)"));
        long base = sent > 0 ? sent : totalOut;
        if (fee > DANGER_FEE_SATS || (base > 0 && fee * 10 > base) || (base == 0 && fee > 0)) {
            rows.add(row(DANGER, "The network fee is " + btc(fee, network) + (base > 0 ? ", " + percent(fee, base) + " of the amount sent" : "")
                    + ". That is far more than a normal fee. Check the fee on your Mac; do not sign unless you meant to pay this."));
        }
        double r = vsize == 0 ? 0 : (double) fee / vsize;
        if (r > WARNING_FEE_RATE) {
            rows.add(row(WARNING, "The fee rate is " + feeRate + " sat/vB, above " + (int) WARNING_FEE_RATE + " sat/vB. Fees that high are rarely needed."));
        } else if (r < 1.0) {
            rows.add(row(WARNING, "The fee rate is " + feeRate + " sat/vB, below the usual 1 sat/vB minimum: the network may not relay this transaction."));
        }
        if (sent == 0) rows.add(row("Recipients", "None outside this wallet: every output comes back to you."));

        // technical details
        for (SignInput in : inputs) {
            details.add(row("Input " + (in.index + 1), psbt.tx.inputs.get(in.index).outpoint() + "\n" + btc(in.amount, network)
                    + " · " + sats(in.amount) + "\n" + in.address + "\n" + in.path + " · " + in.type.label
                    + (in.hashType == BtcTx.SIGHASH_ALL ? " · SIGHASH_ALL" : " · SIGHASH_DEFAULT")));
        }
        for (Out o : outputs) {
            String what = o.kind == BtcScript.Kind.OP_RETURN ? "OP_RETURN data " + BtcCrypto.hex(psbt.tx.outputs.get(o.index).script)
                    : o.address + "\n" + BtcScript.kindLabel(o.kind) + (o.change ? " · change " + o.path : o.ownReceive ? " · own " + o.path : "");
            details.add(row("Output " + (o.index + 1), sats(o.value) + "\n" + what));
        }
        details.add(row("Totals", "In " + sats(totalIn) + " · out " + sats(totalOut) + " · fee " + sats(fee)));
        details.add(row("Size", vsize + " vB (estimated once signed)"));
        boolean rbf = false;
        for (BtcTx.Input in : psbt.tx.inputs) if (in.sequence < 0xfffffffeL) rbf = true;
        details.add(row("Version · lock time", psbt.tx.version + " · " + psbt.tx.locktime
                + (psbt.tx.locktime == 0 ? " (none)" : psbt.tx.locktime < 500_000_000L ? " (block height)" : " (unix time)")));
        details.add(row("Replace-by-fee", rbf ? "Yes: the Mac can replace it with a higher fee before it confirms" : "No"));
        details.add(row("Wallet fingerprint", wallet.fingerprintHex()));
    }

    /** One line for the lock screen; needs no keys (nothing is classified as change yet). */
    static String lockedSummary(Psbt psbt, BtcNetwork network) {
        return "A " + network.label + " transaction (" + psbt.tx.inputs.size() + (psbt.tx.inputs.size() == 1 ? " input, " : " inputs, ")
                + psbt.tx.outputs.size() + (psbt.tx.outputs.size() == 1 ? " output" : " outputs")
                + "). Unlock to review every output before anything is signed.";
    }

    private static MessageReview.Row row(String label, String value) { return new MessageReview.Row(label, value); }

    /** "0.01234567 BTC". */
    static String btc(long sats, BtcNetwork network) {
        return String.format(Locale.ROOT, "%d.%08d %s", sats / COIN, sats % COIN, network.unit);
    }

    /** "1,234,567 sats". */
    static String sats(long sats) { return String.format(Locale.ROOT, "%,d sats", sats); }

    /** Fee rate with one decimal, rounded half up. */
    static String rate(long fee, long vsize) {
        if (vsize <= 0) return "0.0";
        long tenths = (fee * 10 * 2 + vsize) / (2 * vsize);
        return (tenths / 10) + "." + (tenths % 10);
    }

    private static String percent(long part, long whole) {
        long tenths = (part * 1000 * 2 + whole) / (2 * whole);
        return (tenths / 10) + "." + (tenths % 10) + "%";
    }
}
