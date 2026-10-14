package dev.phonevault.signer;

import static org.junit.Assert.*;

import com.google.zxing.common.BitMatrix;
import com.google.zxing.common.DecoderResult;
import com.google.zxing.qrcode.decoder.Decoder;
import java.util.List;
import org.junit.Test;

/**
 * SeedQR against SeedSigner's published test vectors
 * (https://github.com/SeedSigner/seedsigner/blob/dev/docs/seed_qr/README.md, "Test SeedQRs").
 * These mnemonics are public test vectors, never wallet data. Each vector checks the payload
 * (digit stream / CompactSeedQR bytes, from the spec's bytestream) and then decodes the generated
 * QR matrix with ZXing's own decoder: mode, version, error-correction level and payload must match.
 */
public class SeedQrTest {
    /** {mnemonic, Standard SeedQR digit stream, CompactSeedQR bytes as hex}. Vectors 1-9 of the spec. */
    static final String[][] VECTORS = {
        {"attack pizza motion avocado network gather crop fresh patrol unusual wild holiday candy pony ranch winter theme error hybrid van cereal salon goddess expire",
         "011513251154012711900771041507421289190620080870026613431420201617920614089619290300152408010643",
         "0e74b64107f94cc0ccfae6a13dcbec3662154fec67e0e00999c07892597d190a"},
        {"atom solve joy ugly ankle message setup typical bean era cactus various odor refuse element afraid meadow quick medal plate wisdom swap noble shallow",
         "011416550964188800731119157218870156061002561932122514430573003611011405110613292018175411971576",
         "0e59dde276009317f1275f1389888078c99368d1e82489b5f629531fc5b6a56e"},
        {"sound federal bonus bleak light raise false engage round stock update render quote truck quality fringe palace foot recipe labor glow tortoise potato still",
         "166206750203018810361417065805941507171219081456140818651401074412730727143709940798183613501710",
         "cfca8c658bc81962549252bc7ac3ba5b0b01d26bcae89f2b5ecebe263dcb2a36"},
        {"forum undo fragile fade shy sign arrest garment culture tube off merit",
         "073318950739065415961602009907670428187212261116",
         "5bbd9d71a8ec7990831aff359d426545"},
        {"good battle boil exact add seed angle hurry success glad carbon whisper",
         "080301540200062600251559007008931730078802752004",
         "6462686427203385c2337dd84c5089fd"},
        {"approve fruit lens brass ring actual stool coin doll boss strong rate",
         "008607501025021714880023171503630517020917211425",
         "0acbba008d9ba005f5996b40a3475cd9"},
        // 7-9: CompactSeedQR bytes containing \n, \r and \r\n
        {"dignity utility vacant shiver thought canoe feel multiply item youth actor coyote",
         "049619221923158517990268067811630950204300210397",
         "3e1e0bc1e31e0e4315348b76dfec0a98"},
        {"corn voice scrap arrow original diamond trial property benefit choose junk lock",
         "038719631547010112530489185713790169032209701051",
         "307eaf058659ca7a7a0d63152509e541"},
        {"vocal tray giggle tool duck letter category pattern train magnet excite swamp",
         "196218530783182905421028028912901848107106301753",
         "f55cf587f2543d01090d0ae710bd3b6d"},
    };

    @Test public void payloadsMatchSeedSignerVectors() {
        for (String[] v : VECTORS) {
            String[] words = v[0].split(" ");
            assertEquals(v[0], v[1], SeedQr.standardDigits(words));
            assertEquals(v[0], v[2], Hex.of(SeedQr.compactBytes(words)));
        }
    }

    @Test public void compactSymbolDecodesToTheVectorBytes() throws Exception {
        for (String[] v : VECTORS) {
            String[] words = v[0].split(" ");
            SeedQr.Modules m = SeedQr.encode(words, SeedQr.Format.COMPACT);
            int expectedSize = words.length == 24 ? 25 : 21;
            assertEquals(expectedSize, m.size);
            assertEquals(words.length == 24 ? 2 : 1, m.version);
            DecoderResult r = new Decoder().decode(bits(m));
            assertEquals("L", r.getECLevel());
            List<byte[]> segments = r.getByteSegments();
            assertNotNull("byte mode", segments);
            assertEquals(1, segments.size());
            assertEquals(v[0], v[2], Hex.of(segments.get(0)));
        }
    }

    @Test public void standardSymbolDecodesToTheVectorDigits() throws Exception {
        for (String[] v : VECTORS) {
            String[] words = v[0].split(" ");
            SeedQr.Modules m = SeedQr.encode(words, SeedQr.Format.STANDARD);
            assertEquals(words.length == 24 ? 29 : 25, m.size);
            DecoderResult r = new Decoder().decode(bits(m));
            assertEquals("L", r.getECLevel());
            assertNull("numeric mode has no byte segments", r.getByteSegments());
            assertEquals(v[1], r.getText());
        }
    }

    /** The printed card (tools/backup-card/make_card.py) pre-fills these modules; they must match. */
    @Test public void cardPrePrintedPatternsMatchThePhone() {
        for (SeedQr.Format f : SeedQr.Format.values()) {
            for (String[] v : VECTORS) {
                String[] words = v[0].split(" ");
                if (words.length != 24) continue;
                SeedQr.Modules m = SeedQr.encode(words, f);
                Boolean[][] fixed = functionPatterns(m.version);
                for (int r = 0; r < m.size; r++)
                    for (int c = 0; c < m.size; c++)
                        if (fixed[r][c] != null)
                            assertEquals(f + " module " + (r + 1) + "," + (c + 1), fixed[r][c], m.get(r, c));
            }
        }
    }

    @Test public void rejectsBadPhrases() {
        String[] good = VECTORS[0][0].split(" ");
        String[] badChecksum = good.clone();
        badChecksum[23] = "abandon";
        assertRejected(badChecksum);
        String[] notAWord = good.clone();
        notAWord[3] = "notaword";
        assertRejected(notAWord);
        assertRejected(java.util.Arrays.copyOf(good, 18));
        assertRejected(null);
    }

    @Test public void wipeClearsTheSymbol() {
        SeedQr.Modules m = SeedQr.encode(VECTORS[0][0].split(" "), SeedQr.Format.COMPACT);
        m.wipe();
        for (int r = 0; r < m.size; r++) for (int c = 0; c < m.size; c++) assertFalse(m.get(r, c));
    }

    private static void assertRejected(String[] words) {
        for (SeedQr.Format f : SeedQr.Format.values()) {
            try { SeedQr.encode(words, f); fail("accepted " + f); }
            catch (IllegalArgumentException expected) { }
        }
    }

    /** Same rules as make_card.py's function_patterns(): finders + separators, timing, alignment, dark module. */
    static Boolean[][] functionPatterns(int version) {
        int n = 17 + 4 * version;
        Boolean[][] cells = new Boolean[n][n];
        int[][] corners = {{0, 0}, {0, n - 7}, {n - 7, 0}};
        for (int[] o : corners)
            for (int r = -1; r < 8; r++)
                for (int c = -1; c < 8; c++) {
                    int rr = o[0] + r, cc = o[1] + c;
                    if (rr < 0 || cc < 0 || rr >= n || cc >= n) continue;
                    boolean inside = r >= 0 && r <= 6 && c >= 0 && c <= 6;
                    cells[rr][cc] = inside && (r == 0 || r == 6 || c == 0 || c == 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4));
                }
        for (int i = 8; i < n - 8; i++) { cells[6][i] = i % 2 == 0; cells[i][6] = i % 2 == 0; }
        int a = n - 7;
        for (int r = -2; r <= 2; r++)
            for (int c = -2; c <= 2; c++) cells[a + r][a + c] = Math.max(Math.abs(r), Math.abs(c)) != 1;
        cells[4 * version + 9][8] = true;
        return cells;
    }

    private static BitMatrix bits(SeedQr.Modules m) {
        BitMatrix b = new BitMatrix(m.size);
        for (int r = 0; r < m.size; r++) for (int c = 0; c < m.size; c++) if (m.get(r, c)) b.set(c, r);
        return b;
    }
}
