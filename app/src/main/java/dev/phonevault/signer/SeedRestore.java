package dev.phonevault.signer;

import org.web3j.crypto.MnemonicUtils;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Import an existing BIP39 recovery phrase. Pure validation logic (no Android, no storage) so the
 * rules are unit-tested: a BIP39 word count (12, 15, 18, 21 or 24 — the phone CREATES 24-word
 * phrases only, but restores any standard length), every word in the BIP39 English list, and a valid
 * checksum. Restore is the ONLY proof of recoverability — the mandatory backup check
 * ({@link BackupCheck}) proves the user copied the words this device generated, not that an
 * arbitrary phrase actually restores. This is the inverse path.
 */
final class SeedRestore {
    /** The BIP39 lengths a restore accepts (128 to 256 bits of entropy, in 32-bit steps). */
    static final int[] WORD_COUNTS = {12, 15, 18, 21, 24};
    /** The length Phone Vault creates (256 bits). */
    static final int CREATE_WORD_COUNT = 24;
    static final String WORD_COUNTS_TEXT = "12, 15, 18, 21 or 24";

    /** True for a BIP39 length this phone restores. web3j alone also accepts 3, 6 and 9 words: never enough. */
    static boolean isWordCount(int count) {
        for (int n : WORD_COUNTS) if (n == count) return true;
        return false;
    }

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
        return validate(raw, 0);
    }

    /**
     * As {@link #validate(String)}; {@code expected} is the word count the user chose before typing
     * (0: any BIP39 length). A phrase of another length is refused with both counts named.
     */
    static String validate(String raw, int expected) throws RestoreException {
        if (expected != 0 && !isWordCount(expected)) throw new IllegalArgumentException("not a BIP39 word count");
        String[] w = words(raw);
        if (w.length == 0) {
            throw new RestoreException(expected != 0 ? "Enter your " + expected + "-word recovery phrase"
                    : "Enter your recovery phrase (" + WORD_COUNTS_TEXT + " words)");
        }
        if (expected != 0 && w.length != expected) {
            throw new RestoreException("Expected " + expected + " words, found " + w.length);
        }
        if (!isWordCount(w.length)) {
            throw new RestoreException("Expected " + WORD_COUNTS_TEXT + " words, found " + w.length);
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
