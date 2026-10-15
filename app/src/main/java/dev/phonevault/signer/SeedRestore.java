package dev.phonevault.signer;

import org.web3j.crypto.MnemonicUtils;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Import an existing BIP39 recovery phrase. Pure validation logic (no Android, no storage) so the
 * rules are unit-tested: exact word count, every word in the BIP39 English list, and a valid
 * checksum. Restore is the ONLY proof of recoverability — the mandatory backup check
 * ({@link BackupCheck}) proves the user copied the words this device generated, not that an
 * arbitrary phrase actually restores. This is the inverse path.
 */
final class SeedRestore {
    static final int WORD_COUNT = 24;

    /** The word count Phone Vault accepts. Other BIP39 lengths (12/15/18/21) are refused for now. */
    static final class RestoreException extends Exception {
        RestoreException(String message) { super(message); }
    }

    private SeedRestore() {}

    /** Lowercase, trim, collapse internal whitespace. Never changes the words themselves. */
    static String normalize(String raw) {
        if (raw == null) return "";
        return raw.trim().toLowerCase(Locale.ROOT).replaceAll("\\s+", " ");
    }

    static String[] words(String raw) {
        String n = normalize(raw);
        return n.isEmpty() ? new String[0] : n.split(" ");
    }

    /** 1-based indices of entered words that are not in the BIP39 list (for per-word UI feedback). */
    static List<Integer> unknownWordPositions(String raw) {
        Set<String> list = new HashSet<>(MnemonicUtils.getWords());
        List<Integer> bad = new ArrayList<>();
        String[] w = words(raw);
        for (int i = 0; i < w.length; i++) {
            if (!list.contains(w[i])) bad.add(i + 1);
        }
        return bad;
    }

    /**
     * Validate a candidate phrase and return the normalized mnemonic ready to store. Throws with a
     * specific, non-secret reason (never echoes a word) so the UI can guide correction.
     */
    static String validate(String raw) throws RestoreException {
        String[] w = words(raw);
        if (w.length == 0) throw new RestoreException("Enter your " + WORD_COUNT + "-word recovery phrase");
        if (w.length != WORD_COUNT) {
            throw new RestoreException("Expected " + WORD_COUNT + " words, found " + w.length);
        }
        List<Integer> unknown = unknownWordPositions(raw);
        if (!unknown.isEmpty()) {
            throw new RestoreException("Word " + unknown.get(0) + " is not a valid recovery word");
        }
        String mnemonic = String.join(" ", w);
        if (!MnemonicUtils.validateMnemonic(mnemonic)) {
            throw new RestoreException("Recovery phrase checksum is invalid: re-check the words and their order");
        }
        return mnemonic;
    }

    /** Derived EVM address for the normalized phrase (for the confirm-before-commit step). */
    static String deriveAddress(String mnemonic, int accountIndex) {
        return SeedVault.deriveEvm(mnemonic, "", accountIndex).getAddress();
    }

    /** BIP39 prefix autocomplete for the word-entry keyboard (empty prefix → empty). */
    static List<String> suggestions(String prefix, int max) {
        List<String> out = new ArrayList<>();
        if (prefix == null || prefix.isEmpty()) return out;
        String p = prefix.toLowerCase(Locale.ROOT);
        for (String word : MnemonicUtils.getWords()) {
            if (word.startsWith(p)) {
                out.add(word);
                if (out.size() >= max) break;
            }
        }
        return out;
    }

    static boolean isWord(String candidate) {
        if (candidate == null) return false;
        return new HashSet<>(MnemonicUtils.getWords()).contains(candidate.toLowerCase(Locale.ROOT));
    }

    /** All 2048 BIP39 words (immutable copy) for building an on-device keyboard. */
    static List<String> wordList() {
        return new ArrayList<>(MnemonicUtils.getWords());
    }
}
