package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public final class TokenListTest {
    /** The file packaged as R.raw.tokens (and compiled into the companion). */
    static byte[] bundledBytes() throws Exception {
        for (String path : new String[] {"src/main/res/raw/tokens.json", "app/src/main/res/raw/tokens.json"}) {
            File f = new File(path);
            if (f.isFile()) return Files.readAllBytes(f.toPath());
        }
        throw new AssertionError("tokens.json not found from " + new File(".").getAbsolutePath());
    }

    static TokenList bundled() throws Exception { return TokenList.loadPinned(bundledBytes()); }

    @Test public void bundledListMatchesItsPinnedHashAndLoads() throws Exception {
        assertEquals(TokenList.PINNED_SHA256, TokenList.sha256Hex(bundledBytes()));
        TokenList list = bundled();
        assertTrue(list.available());
        assertEquals(30, list.size());
    }

    @Test public void everyAllowListedChainHasUsdcAndOnlyAllowListedChainsAppear() throws Exception {
        TokenList list = bundled();
        // Independent second entry of the issuer-published USDC addresses (Circle), per chain.
        String[][] usdc = {
                {"1", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"},
                {"10", "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85"},
                {"137", "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359"},
                {"8453", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"},
                {"42161", "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"},
                {"11155111", "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"},
        };
        for (String[] entry : usdc) {
            TokenList.Token t = list.lookup(Long.parseLong(entry[0]), entry[1]);
            assertNotNull("USDC on chain " + entry[0], t);
            assertEquals("USDC", t.symbol);
            assertEquals(6, t.decimals);
            assertEquals(entry[1], t.checksumAddress());
        }
        TokenList.Token weth = list.lookup(1, "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2");
        assertEquals("WETH", weth.symbol);
        assertEquals(18, weth.decimals);
        assertEquals(8, list.lookup(1, "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599").decimals);
        assertEquals("USDT", list.lookup(1, "0xdAC17F958D2ee523a2206206994597C13D831ec7").symbol);
        assertEquals("DAI", list.lookup(1, "0x6B175474E89094C44Da98b954EedeAC495271d0F").symbol);
        // chain-scoped: Ethereum's USDC address means nothing on Polygon
        assertNull(list.lookup(137, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"));
    }

    @Test public void aChangedByteIsRefusedByThePin() throws Exception {
        byte[] bytes = bundledBytes();
        String text = new String(bytes, StandardCharsets.UTF_8).replace("\"decimals\": 6", "\"decimals\": 18");
        try {
            TokenList.loadPinned(text.getBytes(StandardCharsets.UTF_8));
            fail("tampered list loaded");
        } catch (TokenList.InvalidTokenListException expected) {
            assertTrue(expected.getMessage().contains("does not match the pinned"));
        }
        // …even though the tampered text is itself well-formed
        assertEquals(30, TokenList.parse(text).size());
        try { TokenList.loadPinned(new byte[0]); fail(); } catch (TokenList.InvalidTokenListException expected) { }
    }

    private static final String USDC = "{\"chainId\": 1, \"address\": \"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48\", \"symbol\": \"USDC\", \"name\": \"USD Coin\", \"decimals\": 6}";

    private static String list(String... tokens) { return "{\"version\": 1, \"tokens\": [" + String.join(",", tokens) + "]}"; }

    @Test public void strictRulesRefuseBadLists() {
        String[] bad = {
                "{\"version\": 1, \"tokens\": []}",
                "{\"version\": 2, \"tokens\": [" + USDC + "]}",
                "{\"version\": 1, \"version\": 1, \"tokens\": [" + USDC + "]}",
                "{\"version\": 1, \"tokens\": [" + USDC + "], \"extra\": 1}",
                list(USDC.replace("\"decimals\": 6}", "\"decimals\": 6, \"logo\": \"x\"}")),
                list(USDC.replace("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")),
                list(USDC.replace("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB4")),
                list(USDC.replace("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "0x0000000000000000000000000000000000000000")),
                list(USDC.replace("\"chainId\": 1", "\"chainId\": 56")),
                list(USDC.replace("\"chainId\": 1", "\"chainId\": \"1\"")),
                list(USDC.replace("\"decimals\": 6", "\"decimals\": 37")),
                list(USDC.replace("\"decimals\": 6", "\"decimals\": 6.0")),
                list(USDC.replace("\"decimals\": 6", "\"decimals\": -1")),
                list(USDC.replace("\"USDC\"", "\"USD₮\"")),
                list(USDC.replace("\"USDC\"", "\"USD C\"")),
                list(USDC.replace("\"USDC\"", "\"\"")),
                list(USDC.replace("\"USD Coin\"", "\"USD\\nCoin\"")),
                list(USDC, USDC),
                list(USDC, USDC.replace("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "0xdAC17F958D2ee523a2206206994597C13D831ec7")),
                list(USDC) + " x",
        };
        for (String text : bad) {
            try {
                TokenList.parse(text);
                fail("accepted: " + text);
            } catch (TokenList.InvalidTokenListException expected) {
                // refused as a whole
            }
        }
    }

    @Test public void unavailableListRecognizesNothingAndSaysWhy() {
        TokenList list = TokenList.unavailable("hash mismatch");
        assertTrue(!list.available());
        assertEquals("hash mismatch", list.problem());
        assertNull(list.lookup(1, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"));
    }
}
