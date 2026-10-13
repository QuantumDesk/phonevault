package dev.phonevault.signer;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Signs exactly the inputs a {@link BtcPsbtReview} listed, with keys derived from the BIP-39 seed
 * inside the seed-key window, and returns the PSBT with the signatures added (PSBT_IN_PARTIAL_SIG
 * for SegWit v0, PSBT_IN_TAP_KEY_SIG for Taproot). The host finalizes, verifies and broadcasts.
 *
 * <ul>
 *   <li>P2WPKH: BIP-143 sighash (SIGHASH_ALL), ECDSA with RFC 6979 nonces, low-S, DER + 0x01.</li>
 *   <li>P2TR key path: BIP-341 sighash (DEFAULT, or ALL when the PSBT asks for it), BIP-340 Schnorr
 *       with the BIP-86 tweak (no script tree) and fresh auxiliary randomness; 64 bytes (65 with ALL).</li>
 * </ul>
 * Every derived key is checked against the public key the review verified, and every signature is
 * verified before it leaves; private keys are destroyed in all paths.
 */
final class BtcPsbtSigner {
    private BtcPsbtSigner() {}

    static byte[] sign(BtcPsbtReview review, byte[] seed, SecureRandom random) {
        return sign(review, seed, random, null);
    }

    /** @param fixedAux test seam: the BIP-340 aux randomness to use (null in production) */
    static byte[] sign(BtcPsbtReview review, byte[] seed, SecureRandom random, byte[] fixedAux) {
        BtcTx tx = review.psbt.tx;
        int n = tx.inputs.size();
        long[] amounts = new long[n];
        byte[][] scripts = new byte[n][];
        for (BtcPsbtReview.SignInput in : review.inputs) {
            amounts[in.index] = in.amount;
            scripts[in.index] = in.script;
        }
        for (int i = 0; i < n; i++) if (scripts[i] == null) throw new IllegalStateException("every input must be reviewed");

        List<List<Psbt.Entry>> additions = new ArrayList<>();
        for (int i = 0; i < n; i++) additions.add(new ArrayList<Psbt.Entry>());
        Map<String, Bip32.Key> accountKeys = new HashMap<>();
        Bip32.Key master = Bip32.master(seed);
        try {
            for (BtcPsbtReview.SignInput in : review.inputs) {
                String k = in.type + "/" + in.account;
                Bip32.Key account = accountKeys.get(k);
                if (account == null) {
                    account = Bip32.derive(master, in.type.purpose | Bip32.HARDENED,
                            review.network.coinType | Bip32.HARDENED, in.account | Bip32.HARDENED);
                    accountKeys.put(k, account);
                }
                Bip32.Key key = Bip32.derive(account, in.change, in.addressIndex);
                try {
                    if (!Arrays.equals(key.pub, in.pubkey)) throw new IllegalStateException("derived key differs from the reviewed key");
                    if (in.type == BtcWallet.Type.P2WPKH) {
                        byte[] scriptCode = BtcScript.p2pkhScript(BtcCrypto.hash160(key.pub));
                        byte[] digest = tx.sighashSegwitV0(in.index, scriptCode, in.amount, BtcTx.SIGHASH_ALL);
                        byte[] der = BtcCrypto.signEcdsa(key.privateKey(), digest);
                        byte[] sig = Arrays.copyOf(der, der.length + 1);
                        sig[der.length] = (byte) BtcTx.SIGHASH_ALL;
                        additions.get(in.index).add(Psbt.entry(Psbt.IN_PARTIAL_SIG, key.pub, sig));
                    } else {
                        byte[] tweaked = BtcCrypto.taprootTweakedPrivate(key.privateKey());
                        try {
                            byte[] digest = tx.sighashTaproot(in.index, amounts, scripts, in.hashType);
                            byte[] aux = fixedAux != null ? fixedAux.clone() : BtcCrypto.randomAux(random);
                            byte[] sig64 = BtcCrypto.signSchnorr(tweaked, digest, aux);
                            Arrays.fill(aux, (byte) 0);
                            byte[] outputKey = Arrays.copyOfRange(in.script, 2, 34);
                            if (!BtcCrypto.verifySchnorr(outputKey, digest, sig64)) throw new IllegalStateException("Taproot signature does not verify against the output key");
                            byte[] sig = in.hashType == BtcTx.SIGHASH_DEFAULT ? sig64 : Arrays.copyOf(sig64, 65);
                            if (in.hashType != BtcTx.SIGHASH_DEFAULT) sig[64] = (byte) in.hashType;
                            additions.get(in.index).add(Psbt.entry(Psbt.IN_TAP_KEY_SIG, new byte[0], sig));
                        } finally {
                            Arrays.fill(tweaked, (byte) 0);
                        }
                    }
                } finally {
                    key.destroy();
                }
            }
        } finally {
            master.destroy();
            for (Bip32.Key k : accountKeys.values()) k.destroy();
        }
        return review.psbt.serializeWith(additions);
    }
}
