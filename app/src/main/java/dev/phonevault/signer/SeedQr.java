package dev.phonevault.signer;

import com.google.zxing.EncodeHintType;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import com.google.zxing.qrcode.decoder.Mode;
import com.google.zxing.qrcode.encoder.ByteMatrix;
import com.google.zxing.qrcode.encoder.Encoder;
import com.google.zxing.qrcode.encoder.QRCode;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import org.web3j.crypto.MnemonicUtils;

/**
 * SeedQR, per SeedSigner's specification
 * (https://github.com/SeedSigner/seedsigner/blob/dev/docs/seed_qr/README.md), so a backup made here
 * is a SeedQR any compatible wallet reads:
 * <ul>
 *   <li><b>Standard SeedQR</b>: each word's BIP-39 index (0-2047) as exactly four digits, concatenated
 *   (96 digits for 24 words), in QR numeric mode, error correction L. 24 words: version 3 (29x29);
 *   12 words: version 2 (25x25).</li>
 *   <li><b>CompactSeedQR</b>: the 11-bit indices concatenated with the BIP-39 checksum bits dropped,
 *   i.e. the raw entropy (32 bytes for 24 words), in QR byte (binary) mode, no ECI, error
 *   correction L. 24 words: version 2 (25x25); 12 words: version 1 (21x21).</li>
 * </ul>
 * The QR symbol itself comes from ZXing (the library that draws the receive-address QR). Its
 * {@link Encoder} picks the data mode from the content, so this class checks that the result is the
 * mode, version and error-correction level the spec requires and refuses otherwise (it never
 * silently shows a code another wallet would read differently). The data is the recovery phrase in
 * another form: callers keep it inside the PIN-gated sensitive flow and {@link Modules#wipe} it.
 */
final class SeedQr {
    enum Format { COMPACT, STANDARD }

    private SeedQr() {}

    /** The modules of one SeedQR symbol ({@code true} = dark), without the quiet zone. */
    static final class Modules {
        final int size, version;
        final Format format;
        private final boolean[] dark;

        private Modules(int size, int version, Format format, boolean[] dark) {
            this.size = size;
            this.version = version;
            this.format = format;
            this.dark = dark;
        }

        boolean get(int row, int col) { return dark[row * size + col]; }

        /** Clears every module (the symbol encodes the recovery phrase). */
        void wipe() { Arrays.fill(dark, false); }
    }

    /** BIP-39 word indices (0-2047). Validates the word count, every word and the checksum. */
    static int[] indices(String[] words) {
        if (words == null || (words.length != 12 && words.length != 24))
            throw new IllegalArgumentException("SeedQR needs 12 or 24 words");
        List<String> list = MnemonicUtils.getWords();
        int[] out = new int[words.length];
        for (int i = 0; i < words.length; i++) {
            int index = words[i] == null ? -1 : list.indexOf(words[i]);
            if (index < 0) {
                Arrays.fill(out, 0);
                throw new IllegalArgumentException("Word " + (i + 1) + " is not a BIP-39 word");
            }
            out[i] = index;
        }
        // The checksum: a mistyped-but-valid word must never become a SeedQR of a different seed.
        byte[] entropy = entropyOf(out);
        try {
            String expected = MnemonicUtils.generateMnemonic(entropy);
            String[] check = expected.split(" ");
            if (!check[check.length - 1].equals(words[words.length - 1])) {
                Arrays.fill(out, 0);
                throw new IllegalArgumentException("Recovery phrase checksum does not match");
            }
            Arrays.fill(check, null);
        } finally {
            Arrays.fill(entropy, (byte) 0);
        }
        return out;
    }

    /** Standard SeedQR payload: four zero-padded digits per word. */
    static String standardDigits(String[] words) {
        int[] idx = indices(words);
        StringBuilder digits = new StringBuilder(idx.length * 4);
        for (int i : idx) digits.append(String.format(java.util.Locale.ROOT, "%04d", i));
        Arrays.fill(idx, 0);
        return digits.toString();
    }

    /** CompactSeedQR payload: the BIP-39 entropy (16 or 32 bytes), checksum bits dropped. */
    static byte[] compactBytes(String[] words) {
        int[] idx = indices(words);
        try { return entropyOf(idx); } finally { Arrays.fill(idx, 0); }
    }

    /** 11 bits per index, MSB first; the first 32 bits of each 33 (= words*11 - words/3 bits) kept. */
    private static byte[] entropyOf(int[] idx) {
        int bits = idx.length * 11 - idx.length / 3;
        byte[] out = new byte[bits / 8];
        for (int bit = 0; bit < bits; bit++) {
            int value = (idx[bit / 11] >> (10 - bit % 11)) & 1;
            if (value != 0) out[bit / 8] |= (byte) (0x80 >> (bit % 8));
        }
        return out;
    }

    /** The SeedQR specification defines 12 and 24-word phrases only (15, 18 and 21 words have no SeedQR). */
    static boolean supports(int wordCount) { return wordCount == 12 || wordCount == 24; }

    /** Modules per side for this word count and format: 21, 25 or 29. */
    static int gridSize(int wordCount, Format format) { return 17 + 4 * version(wordCount, format); }

    /** QR version the spec prescribes for this word count and format. */
    static int version(int wordCount, Format format) {
        if (wordCount == 24) return format == Format.COMPACT ? 2 : 3;
        if (wordCount == 12) return format == Format.COMPACT ? 1 : 2;
        throw new IllegalArgumentException("SeedQR needs 12 or 24 words");
    }

    static Modules encode(String[] words, Format format) {
        int version = version(words == null ? 0 : words.length, format);
        String content;
        Mode mode;
        if (format == Format.STANDARD) {
            content = standardDigits(words);
            mode = Mode.NUMERIC;
        } else {
            byte[] entropy = compactBytes(words);
            // ISO-8859-1 maps every byte 0x00-0xFF to one char and back; ZXing's default byte-mode
            // charset is ISO-8859-1, and with no CHARACTER_SET hint it writes no ECI header, as the
            // spec requires. (A charset hint would add an ECI segment and change the symbol.)
            content = new String(entropy, StandardCharsets.ISO_8859_1);
            Arrays.fill(entropy, (byte) 0);
            mode = Mode.BYTE;
        }
        // ZXing chooses numeric/alphanumeric/byte from the content. Random entropy is effectively
        // never all-alphanumeric (about 1 in 10^24), but if it were, the symbol would not be the
        // byte-mode code the spec defines: refuse instead of showing a different encoding.
        if (Encoder.chooseMode(content) != mode)
            throw new IllegalStateException("This seed cannot be shown as a " + format + " SeedQR");
        Map<EncodeHintType, Object> hints = new EnumMap<>(EncodeHintType.class);
        hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.L);
        hints.put(EncodeHintType.QR_VERSION, version);
        QRCode qr;
        try {
            qr = Encoder.encode(content, ErrorCorrectionLevel.L, hints);
        } catch (com.google.zxing.WriterException e) {
            throw new IllegalStateException("SeedQR could not be generated", e);
        }
        ByteMatrix matrix = qr.getMatrix();
        try {
            if (qr.getMode() != mode || qr.getECLevel() != ErrorCorrectionLevel.L
                    || qr.getVersion().getVersionNumber() != version
                    || matrix.getWidth() != 17 + 4 * version || matrix.getHeight() != matrix.getWidth())
                throw new IllegalStateException("SeedQR encoding did not match the specification");
            int n = matrix.getWidth();
            boolean[] dark = new boolean[n * n];
            for (int y = 0; y < n; y++)
                for (int x = 0; x < n; x++) dark[y * n + x] = matrix.get(x, y) == 1;
            return new Modules(n, version, format, dark);
        } finally {
            matrix.clear((byte) 0);
        }
    }
}
