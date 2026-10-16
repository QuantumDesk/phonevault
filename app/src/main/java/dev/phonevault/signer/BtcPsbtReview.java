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
 *   <li>any input that is not this wallet's own Native SegWit (m/84'/coin'/a'/c/i), Taproot
 *       key-path (m/86'/coin'/a'/c/i, BIP-86, no script tree), Nested SegWit (m/49'/coin'/a'/c/i,
 *       BIP-49, P2SH-P2WPKH) or Legacy (m/44'/coin'/a'/c/i, BIP-44, P2PKH) coin, proven by deriving the
 *       key from the account xpub and matching the UTXO's script; the derivation's purpose must be
 *       the script type's (coinjoin / payjoin / multisig are not supported);</li>
 *   <li>a SegWit input without a witness UTXO, or any input whose non-witness UTXO disagrees with
 *       it; any input but Taproot without its non-witness UTXO (the previous transaction, hashed to
 *       the outpoint's txid, proves the amount: SegWit v0 signatures commit only to their own
 *       input's amount, and legacy P2PKH signatures to no amount at all);</li>
 *   <li>a Nested SegWit input without its redeem script, or with one that is not 0x0014 ‖
 *       HASH160(the derived key); a redeem script on any other input;</li>
 *   <li>sighash types other than ALL (ECDSA: SegWit v0 and legacy) or DEFAULT/ALL (Taproot);</li>
 *   <li>input fields the phone does not understand (witness scripts, finalized data, script-path
 *       Taproot, MuSig2, hash preimages, proprietary or unknown types): they could change what a
 *       signature means;</li>
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
    /**
     * Final scriptSig bytes: Nested SegWit pushes its 22-byte redeem script (1 + 22); Legacy pushes
     * the signature and the key, (1+72) + (1+33).
     */
    static final int P2SH_P2WPKH_SCRIPTSIG = 23, P2PKH_SCRIPTSIG = 107;

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
        /**
         * True when the amount is proven by the coin's previous transaction (non-witness UTXO, checked
         * against the outpoint's txid). Only proven amounts may go into {@link BtcAmountMemory}: a
         * Taproot input without one may carry a lied amount (its signature is then merely invalid),
         * and recording that lie would block the honest PSBT later.
         */
        final boolean amountProven;

        SignInput(int index, BtcWallet.Type type, int account, int change, int addressIndex, byte[] pubkey,
                  long amount, byte[] script, int hashType, String address, String path) {
            this(index, type, account, change, addressIndex, pubkey, amount, script, hashType, address, path, false);
        }

        SignInput(int index, BtcWallet.Type type, int account, int change, int addressIndex, byte[] pubkey,
                  long amount, byte[] script, int hashType, String address, String path, boolean amountProven) {
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
            this.amountProven = amountProven;
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
        /**
         * This wallet's key (verified by derivation) but not where the wallet app looks: change for
         * another account or script type than the coins spent, or an index far past the ones in use.
         * Shown as a normal output with a WARNING and its full path.
         */
        final boolean ownElsewhere;
        /** Why an {@link #ownElsewhere} output may not show in the wallet app (the WARNING's wording), else null. */
        final String elsewhereReason;
        final String path;     // for own outputs
        /** "Account 2 · Taproot" for own outputs, else null. */
        final String ownAccount;

        Out(int index, long value, BtcScript.Kind kind, String address, boolean change, boolean ownReceive, String path) {
            this(index, value, kind, address, change, ownReceive, null, path, null);
        }

        Out(int index, long value, BtcScript.Kind kind, String address, boolean change, boolean ownReceive,
            String elsewhereReason, String path, String ownAccount) {
            this.index = index;
            this.value = value;
            this.kind = kind;
            this.address = address;
            this.change = change;
            this.ownReceive = ownReceive;
            this.ownElsewhere = elsewhereReason != null;
            this.elsewhereReason = elsewhereReason;
            this.path = path;
            this.ownAccount = ownAccount;
        }
    }

    /**
     * The standard gap limit (BIP-44; the Mac app's scanner and recovery wallets): a wallet app looks
     * at most this many unused addresses past the last one it has seen used, on each chain.
     */
    static final int GAP_LIMIT = 20;

    /**
     * Highest address index (receive or change chain) at which an output still counts as this
     * wallet's change / own receive address: {@link #GAP_LIMIT} past the highest index of the coins
     * this PSBT spends from the same account and script type (proof that index is in use), or
     * indexes 0…{@code GAP_LIMIT − 1} for an account and type it does not spend from. Beyond that a
     * wallet app scanning with the gap limit may never see the coins.
     */
    static int ownIndexLimit(List<SignInput> inputs, BtcWallet.Type type, int account) {
        int highest = -1;
        for (SignInput in : inputs) {
            if (in.type == type && in.account == account) highest = Math.max(highest, in.addressIndex);
        }
        return highest + GAP_LIMIT;
    }

    private static boolean spendsFrom(List<SignInput> inputs, BtcWallet.Type type, int account) {
        for (SignInput in : inputs) if (in.type == type && in.account == account) return true;
        return false;
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
                if (e.type == Psbt.IN_REDEEM_SCRIPT) continue; // allowed on Nested SegWit inputs only (checked below)
                String why = inputFieldProblem(e.type);
                if (why != null) throw refuse("Input " + (i + 1) + " carries " + why + ", which this phone does not sign.");
            }
            Psbt.Entry wu = Psbt.find(map, Psbt.IN_WITNESS_UTXO);
            Psbt.Entry nwu = Psbt.find(map, Psbt.IN_NON_WITNESS_UTXO);
            BtcTx.Output prevOut = null;
            if (nwu != null) {
                BtcTx prev = BtcTx.parse(nwu.value, BtcTx.MAX_PREV_IO);
                // Psbt.parse already checked these; repeated here because the fee shown depends on them.
                if (!Arrays.equals(prev.txid(), txIn.prevTxid) || txIn.vout >= prev.outputs.size()) {
                    throw refuse("Input " + (i + 1) + ": the previous transaction is not the one this input spends.");
                }
                prevOut = prev.outputs.get((int) txIn.vout);
            }
            BtcTx.Output utxo;
            if (wu != null) {
                utxo = Psbt.witnessUtxo(wu.value);
                if (prevOut != null && (prevOut.value != utxo.value || !Arrays.equals(prevOut.script, utxo.script))) {
                    throw refuse("Input " + (i + 1) + ": the previous transaction and the witness UTXO disagree about the coin.");
                }
            } else if (prevOut != null && BtcScript.kind(prevOut.script) == BtcScript.Kind.P2PKH) {
                // A legacy coin has no witness: its previous transaction alone says what it is (BIP-174).
                utxo = prevOut;
            } else {
                throw refuse("Input " + (i + 1) + " has no witness UTXO (amount and script of the coin), so the phone can't check it.");
            }
            BtcScript.Kind kind = BtcScript.kind(utxo.script);
            BtcWallet.Type type = typeOf(kind);
            if (type == null) {
                throw refuse("Input " + (i + 1) + " spends a " + BtcScript.kindLabel(kind) + " coin. The phone signs only its own Native SegWit (BIP-84), "
                        + "Taproot (BIP-86), Nested SegWit (BIP-49) and Legacy (BIP-44) coins.");
            }
            if (nwu == null && type != BtcWallet.Type.P2TR) {
                // A SegWit v0 signature commits only to ITS OWN input's amount, and a legacy (P2PKH)
                // signature to no amount at all, so the host's word for the others is all the review
                // has: two signing sessions, each lying about a different input, combine into a
                // transaction with a much larger real fee. The previous transaction (hashed to the
                // outpoint's txid) proves the amount. Taproot signatures commit to every input's
                // amount and script, so Taproot inputs may omit it.
                throw refuse("Input " + (i + 1) + " is a " + type.label + " coin without its previous transaction (non-witness UTXO), "
                        + "so the phone can't prove the coin's amount and the fee shown could be false. Update the Mac app and try again.");
            }
            Psbt.Entry redeem = Psbt.find(map, Psbt.IN_REDEEM_SCRIPT);
            if (redeem != null && type != BtcWallet.Type.P2SH_P2WPKH) {
                throw refuse("Input " + (i + 1) + " carries " + inputFieldProblem(Psbt.IN_REDEEM_SCRIPT) + ", which this phone does not sign.");
            }
            if (redeem == null && type == BtcWallet.Type.P2SH_P2WPKH) {
                throw refuse("Input " + (i + 1) + " is a Nested SegWit (P2SH) coin without its redeem script, so the phone can't tell what it signs.");
            }
            Owned own = ownedBy(map, type, true, fp, network, wallet, utxo.script, "Input " + (i + 1));
            if (own == null) {
                throw refuse("Input " + (i + 1) + " is not a coin of this wallet (no key derivation for fingerprint " + fpHex
                        + "). Transactions that mix in other people's coins (coinjoin, payjoin, multisig) are not supported.");
            }
            if (redeem != null && !Arrays.equals(redeem.value, BtcWallet.redeemScript(own.pubkey))) {
                throw refuse("Input " + (i + 1) + " names a redeem script that is not this wallet's key's (BIP-49: 0x0014 ‖ HASH160 of the key).");
            }
            Psbt.Entry sh = Psbt.find(map, Psbt.IN_SIGHASH_TYPE);
            int hashType = type.ecdsa() ? BtcTx.SIGHASH_ALL : BtcTx.SIGHASH_DEFAULT;
            if (sh != null) {
                long v = new BtcTx.Reader(sh.value).u32();
                boolean ok = type.ecdsa() ? v == BtcTx.SIGHASH_ALL : v == BtcTx.SIGHASH_DEFAULT || v == BtcTx.SIGHASH_ALL;
                if (!ok) throw refuse("Input " + (i + 1) + " asks for signature hash type 0x" + Long.toHexString(v)
                        + ". Only SIGHASH_ALL (and DEFAULT for Taproot) is signed: other types let the transaction be changed after you sign.");
                hashType = (int) v;
            }
            totalIn = addMoney(totalIn, utxo.value);
            ins.add(new SignInput(i, type, own.account, own.change, own.index, own.pubkey, utxo.value, utxo.script, hashType,
                    BtcScript.address(utxo.script, network), wallet.addressPathString(type, own.account, own.change, own.index),
                    nwu != null));
        }
        if (amounts != null) {
            for (SignInput in : ins) {
                String conflict = amounts.conflict(tx.inputs.get(in.index).outpoint(), in.amount, in.script);
                if (conflict != null) throw refuse("Input " + (in.index + 1) + " (" + conflict + "). Wrong coin amounts from "
                        + "your Mac can trick a wallet into paying a huge fee.");
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
            BtcWallet.Type type = typeOf(kind);
            Owned own = type == null ? null : ownedBy(map, type, false, fp, network, wallet, o.script, "Output " + (i + 1));
            if (type == null) noOwnClaim(map, fp, i);
            if (own != null && type == BtcWallet.Type.P2SH_P2WPKH) {
                Psbt.Entry redeem = Psbt.find(map, Psbt.OUT_REDEEM_SCRIPT);
                if (redeem != null && !Arrays.equals(redeem.value, BtcWallet.redeemScript(own.pubkey))) {
                    throw refuse("Output " + (i + 1) + " names a redeem script that is not this wallet's key's.");
                }
            }
            // Change ✓ only on the change chain of an account AND script type this PSBT spends from,
            // within the gap limit; an own receive address ✓ only within the gap limit. Any other key
            // of this wallet is a normal output with a WARNING naming its full path.
            boolean inWindow = own != null && own.index <= ownIndexLimit(ins, type, own.account);
            boolean otherAccount = own != null && own.change == 1 && !spendsFrom(ins, type, own.account);
            boolean isChange = own != null && own.change == 1 && inWindow && !otherAccount;
            boolean isOwnReceive = own != null && own.change == 0 && inWindow;
            String elsewhere = own == null || isChange || isOwnReceive ? null
                    : otherAccount ? "it is change for a different account or address type than the coins spent"
                    : "it is far beyond the addresses your wallet app scans (gap limit)";
            String path = own == null ? null : wallet.addressPathString(type, own.account, own.change, own.index);
            outs.add(new Out(i, o.value, kind, address, isChange, isOwnReceive, elsewhere, path,
                    own == null ? null : BtcWallet.accountLabel(type, own.account)));
            if (isChange) change = addMoney(change, o.value);
            else sent = addMoney(sent, o.value);
        }
        if (totalOut > totalIn) {
            throw refuse("The outputs (" + btc(totalOut, network) + ") are worth more than the coins spent (" + btc(totalIn, network) + ").");
        }
        int[] scriptSig = new int[ins.size()], witness = new int[ins.size()];
        for (int k = 0; k < ins.size(); k++) {
            SignInput in = ins.get(k);
            switch (in.type) {
                case P2WPKH: witness[k] = P2WPKH_WITNESS; break;
                case P2SH_P2WPKH: scriptSig[k] = P2SH_P2WPKH_SCRIPTSIG; witness[k] = P2WPKH_WITNESS; break;
                case P2PKH: scriptSig[k] = P2PKH_SCRIPTSIG; break;
                default: witness[k] = P2TR_WITNESS + (in.hashType == BtcTx.SIGHASH_ALL ? 1 : 0);
            }
        }
        long vsize = tx.vsize(scriptSig, witness);
        BtcPsbtReview r = new BtcPsbtReview(network, psbt, ins, outs, totalIn, totalOut, sent, change, vsize,
                walletKey(network, fpHex));
        r.render(safety, wallet);
        return r;
    }

    /** The account type that pays to a script of this kind (P2SH: Nested SegWit only), or null. */
    static BtcWallet.Type typeOf(BtcScript.Kind kind) {
        switch (kind) {
            case P2WPKH: return BtcWallet.Type.P2WPKH;
            case P2TR: return BtcWallet.Type.P2TR;
            case P2SH: return BtcWallet.Type.P2SH_P2WPKH;
            case P2PKH: return BtcWallet.Type.P2PKH;
            default: return null;
        }
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
                if (Arrays.equals(o.fingerprint, fp)) (type.ecdsa() ? mine : wrongKind).add(new Psbt.Derivation(e.keyData, o, 0));
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
        BtcWallet.Type pathType = p.length == 5 && (p[0] & Bip32.HARDENED) != 0 ? BtcWallet.Type.forPurpose(p[0] & ~Bip32.HARDENED) : null;
        if (pathType != null && pathType != type) {
            // e.g. a BIP-84 key named for a P2SH output: the key may be ours, but the script is not its type's
            throw refuse(what + " names key path " + shown + " (" + pathType.label + "), which does not fit its script type ("
                    + type.label + ").");
        }
        if (p.length != 5 || p[0] != (type.purpose | Bip32.HARDENED) || p[1] != (network.coinType | Bip32.HARDENED)
                || (p[2] & Bip32.HARDENED) == 0 || (p[2] & ~Bip32.HARDENED) >= BtcWallet.ACCOUNTS
                || (p[3] != 0 && p[3] != 1) || p[4] < 0 || p[4] > BtcWallet.MAX_PSBT_INDEX) {
            throw refuse(what + " uses key path " + shown + ", outside this wallet's " + network.label + " accounts (m/"
                    + type.purpose + "'/" + network.coinType + "'/0'…" + (BtcWallet.ACCOUNTS - 1) + "'/0|1/i).");
        }
        int account = p[2] & ~Bip32.HARDENED;
        byte[] pub = wallet.publicKey(type, account, p[3], p[4]);
        byte[] expectKey = type.ecdsa() ? pub : Arrays.copyOfRange(pub, 1, 33);
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
                throw refuse("Output " + (index + 1) + " claims to be this wallet's, but it is not an address type the phone derives "
                        + "(Native SegWit, Taproot, Nested SegWit or Legacy).");
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
        return AddressKeys.BTC_WALLET + network.wire + ":" + fingerprintHex.toLowerCase(Locale.ROOT);
    }

    // ------------------------------------------------------------------ rendering

    private void render(AddressSafety safety, BtcWallet wallet) {
        List<MessageReview.Row> rows = summary;
        rows.add(row(network.test() ? TEST_NETWORK : "Network", network.test()
                ? network.label + ": test coins with no value. Never use this for real bitcoin." : network.label));
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
            rows.add(row("Send", btc(o.value, network) + " to\n" + BtcScript.grouped(o.address, 5) + "\n" + BtcScript.kindLabel(o.kind) + " address"));
            if (o.ownReceive) {
                rows.add(row("Your own address ✓", "This wallet's receiving address " + o.path + " (checked by the phone)."));
            } else if (o.ownElsewhere) {
                rows.add(row(WARNING, "To your wallet: " + o.ownAccount + ", path " + o.path + ", which your wallet app may not show"
                        + " (" + o.elsewhereReason + "). The coins stay yours, but you may have to look for them. "
                        + "Sign only if you meant to send them there."));
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
        rows.add(row(feeLabel(inputs), btc(fee, network) + " (" + feeRate + " sat/vB)"));
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
        String lock = lockTimeWarning(psbt.tx, network, System.currentTimeMillis() / 1000);
        if (lock != null) rows.add(row(WARNING, lock));
        String relative = relativeLockWarning(psbt.tx);
        if (relative != null) rows.add(row(WARNING, relative));

        // technical details
        for (SignInput in : inputs) {
            details.add(row("Input " + (in.index + 1), psbt.tx.inputs.get(in.index).outpoint() + "\n" + btc(in.amount, network)
                    + " · " + sats(in.amount) + "\n" + in.address + "\n" + in.path + " · " + in.type.label
                    + (in.hashType == BtcTx.SIGHASH_ALL ? " · SIGHASH_ALL" : " · SIGHASH_DEFAULT")));
        }
        for (Out o : outputs) {
            String what = o.kind == BtcScript.Kind.OP_RETURN ? "OP_RETURN data " + BtcCrypto.hex(psbt.tx.outputs.get(o.index).script)
                    : o.address + "\n" + BtcScript.kindLabel(o.kind) + (o.change ? " · change " + o.path : o.ownReceive || o.ownElsewhere ? " · own " + o.path : "");
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

    // ------------------------------------------------------------------ lock time

    /** nLockTime at or above this is a unix time, below it a block height (consensus rule). */
    static final long LOCKTIME_THRESHOLD = 500_000_000L;
    /** WARNING when a time lock is more than this far past the phone's clock (7 days). */
    static final long LOCK_WARN_SECONDS = 7L * 24 * 3600;
    /** WARNING when a height lock is more than this many blocks (one week) past the ESTIMATED tip. */
    static final long LOCK_WARN_BLOCKS = 1008;
    /**
     * The tip estimate counts blocks at the protocol's target of 600 s from an anchor block, then
     * adds an explicit margin of {@link #TIP_MARGIN_PER_MILLE}‰ of those blocks, because real blocks
     * come a little faster than the target while hash rate grows (about 586 s on average since the
     * 2024 halving, i.e. ~2.4% more blocks than at 600 s). The margin keeps the estimate from falling
     * behind the real tip, so a wallet that sets nLockTime to the current height (anti fee sniping,
     * e.g. Bitcoin Core, Sparrow) does not trigger the warning; and because it matches the observed
     * drift instead of overshooting it, a lock more than about a week (1008 blocks, plus a day or so
     * of estimate error by 2026) past the real tip is warned. (A faster fixed rate such as 580 s/block
     * would run ~1,300 blocks ahead of the real tip by late 2026, leaving locks up to ~16 days out silent.)
     */
    static final long SECONDS_PER_BLOCK = 600;
    /** Extra blocks added to the 600 s/block count, per thousand (2.4% ≈ a 586 s real average). */
    static final long TIP_MARGIN_PER_MILLE = 24;
    /** The phone's clock is never taken to be earlier than this (2026-09-01; a reset clock reads 1970). */
    static final long CLOCK_FLOOR = 1_788_220_800L;
    /** Mainnet anchor: block 840,000 (the 2024 halving) at 1713571767. */
    static final long MAIN_ANCHOR_HEIGHT = 840_000L, MAIN_ANCHOR_TIME = 1_713_571_767L;
    /** Signet anchor: block 326,197 (this project's first signet transaction) at about 1791890000. */
    static final long SIGNET_ANCHOR_HEIGHT = 326_197L, SIGNET_ANCHOR_TIME = 1_791_890_000L;

    /**
     * A WARNING for a lock time far in the future, or null. The offline phone knows neither the
     * date nor the chain height for sure: it uses its own clock (never earlier than
     * {@link #CLOCK_FLOOR}) and, for block heights, estimates the tip from an anchor block
     * ({@link #estimatedTip}; Bitcoin and signet only — testnet heights are not estimated
     * because testnet3 and testnet4 share the network name). A lock time only matters when some
     * input's nSequence is not final (0xffffffff).
     */
    static String lockTimeWarning(BtcTx tx, BtcNetwork network, long nowSeconds) {
        long lock = tx.locktime;
        if (lock == 0) return null;
        boolean enforced = false;
        for (BtcTx.Input in : tx.inputs) if (in.sequence != 0xffffffffL) enforced = true;
        if (!enforced) return null;
        long now = Math.max(nowSeconds, CLOCK_FLOOR);
        if (lock >= LOCKTIME_THRESHOLD) {
            if (lock - now <= LOCK_WARN_SECONDS) return null;
            return "This transaction is locked until " + MessageReview.timeLabel(java.math.BigInteger.valueOf(lock))
                    + " (its lock time), more than a week from now by this phone's clock. It can't be mined before then. "
                    + "Sign only if you meant to delay it.";
        }
        long tip = estimatedTip(network, now);
        if (tip < 0) return null;
        if (lock - tip <= LOCK_WARN_BLOCKS) return null;
        return String.format(Locale.ROOT, "This transaction is locked until block %,d (its lock time). This phone estimates "
                + "the chain is near block %,d, so that is about %,d days away. It can't be mined before then. "
                + "Sign only if you meant to delay it.", lock, tip, (lock - tip) / 144);
    }

    /**
     * The estimated chain tip at {@code nowSeconds} (already floored): anchor height + elapsed time
     * at {@link #SECONDS_PER_BLOCK}, plus {@link #TIP_MARGIN_PER_MILLE}‰ of those blocks; −1 where
     * heights are not estimated (testnets).
     */
    static long estimatedTip(BtcNetwork network, long nowSeconds) {
        long anchorHeight, anchorTime;
        if (network == BtcNetwork.BITCOIN) { anchorHeight = MAIN_ANCHOR_HEIGHT; anchorTime = MAIN_ANCHOR_TIME; }
        else if (network == BtcNetwork.SIGNET) { anchorHeight = SIGNET_ANCHOR_HEIGHT; anchorTime = SIGNET_ANCHOR_TIME; }
        else return -1;
        long blocks = Math.max(0, nowSeconds - anchorTime) / SECONDS_PER_BLOCK;
        return anchorHeight + blocks + blocks * TIP_MARGIN_PER_MILLE / 1000;
    }

    /** BIP-68 nSequence bits: relative lock disabled; lock in 512-second units instead of blocks; the value. */
    static final long SEQUENCE_LOCK_DISABLE = 1L << 31, SEQUENCE_LOCK_TYPE_TIME = 1L << 22, SEQUENCE_LOCK_MASK = 0xffff;

    /**
     * A WARNING for a relative lock time (BIP-68) longer than a week, or null. With transaction
     * version 2 or more, an input whose nSequence has the disable bit (1&lt;&lt;31) clear can't be
     * mined until that many blocks (or 512-second units, with bit 1&lt;&lt;22) after the coin it spends
     * confirmed. (RBF's 0xfffffffd and the usual final values have the disable bit set.)
     */
    static String relativeLockWarning(BtcTx tx) {
        if (tx.version < 2) return null;
        String worst = null;
        long worstSeconds = 0;
        for (int i = 0; i < tx.inputs.size(); i++) {
            long seq = tx.inputs.get(i).sequence;
            if ((seq & SEQUENCE_LOCK_DISABLE) != 0) continue;
            long value = seq & SEQUENCE_LOCK_MASK;
            boolean time = (seq & SEQUENCE_LOCK_TYPE_TIME) != 0;
            long seconds = time ? value * 512 : value * 600;
            if (time ? seconds <= LOCK_WARN_SECONDS : value <= LOCK_WARN_BLOCKS) continue;
            if (worst != null && seconds <= worstSeconds) continue;
            worstSeconds = seconds;
            worst = "Input " + (i + 1) + " can't be mined until " + (time
                    ? String.format(Locale.ROOT, "about %,d days", seconds / 86_400)
                    : String.format(Locale.ROOT, "%,d blocks (about %,d days)", value, value / 144))
                    + " after the coin it spends was confirmed (a relative lock time, BIP-68). Sign only if you meant to delay it.";
        }
        return worst;
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

    /**
     * "Network fee", or, when some coins' amounts come only from the Mac (Taproot coins sent without
     * their previous transaction), "Network fee (amounts of N coins stated by your Mac)". Taproot
     * signatures commit to every input's amount, so a false amount can't produce a valid transaction;
     * the label only says where the fee's inputs came from.
     */
    static String feeLabel(List<SignInput> inputs) {
        int unproven = 0;
        for (SignInput in : inputs) if (!in.amountProven) unproven++;
        if (unproven == 0) return "Network fee";
        return "Network fee (" + (unproven == 1 ? "amount of 1 coin" : "amounts of " + unproven + " coins") + " stated by your Mac)";
    }

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
