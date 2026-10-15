package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.json.JSONObject;
import org.junit.Test;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/** Plain-language review: recognizers, warnings, and that the review comes from the signed object. */
public final class MessageReviewTest {
    private static final String COW = "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826";
    private static final String OTHER = "0x1111111111111111111111111111111111111111";

    private static MessageReview typedReview(String vector, String chainId, String wallet) throws Exception {
        return typedReviewOf(MessageSigningVectorsTest.vector(vector, "typedData"), chainId, wallet);
    }

    private static MessageReview typedReviewOf(String typedData, String chainId, String wallet) throws Exception {
        JSONObject json = MessageRequestTest.typed(typedData).put("chainId", chainId);
        return MessageReview.of(MessageRequest.parse(json), wallet);
    }

    private static MessageReview personalReview(byte[] bytes, String chainId, String wallet) throws Exception {
        JSONObject json = MessageRequestTest.personal(Numeric.toHexString(bytes)).put("chainId", chainId);
        return MessageReview.of(MessageRequest.parse(json), wallet);
    }

    // ------------------------------------------------------------------ EIP-2612 / DAI permit

    @Test public void eip2612PermitShowsSpenderTokenUnlimitedAmountAndDeadline() throws Exception {
        MessageReview r = typedReview("eip2612-permit-unlimited", "0x1", COW);
        assertEquals(MessageReview.Category.PERMIT, r.category);
        assertEquals("Review token permission", r.title);
        assertEquals("Token spending permission", r.summaryValue("Action"));
        assertEquals("EIP-2612 Permit", r.detailValue("Standard"));
        assertEquals("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", r.summaryValue("Spender"));
        assertTrue(r.summaryValue("Amount").startsWith("UNLIMITED"));
        assertTrue(r.summaryValue("Token (contract)").startsWith("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"));
        assertTrue(r.summaryValue("Token (contract)").contains("USD Coin"));
        assertEquals("2026-01-01 00:00:00 UTC (1767225600)", r.summaryValue("Signature valid until"));
        assertTrue(r.warns("token allowance"));
        assertFalse(r.warns("owner is not this wallet"));
        assertFalse(r.warns("your Mac is on"));
        assertEquals("Approve permission & sign", r.signLabel);
    }

    @Test public void permitForAnotherOwnerAndAnotherChainIsFlagged() throws Exception {
        MessageReview r = typedReview("eip2612-permit-unlimited", "0x2105", OTHER);
        assertTrue(r.warns("owner is not this wallet"));
        assertTrue(r.warns("Ethereum Mainnet (chain ID 1), but your Mac is on Base (chain ID 8453)"));
        // The chain mismatch is a DANGER row, directly after the action.
        assertEquals(MessageReview.DANGER, r.summary.get(1).label);
    }

    @Test public void daiStylePermitWithAllowedTrueIsUnlimited() throws Exception {
        String dai = "{\"types\":{\"EIP712Domain\":[{\"name\":\"name\",\"type\":\"string\"},{\"name\":\"version\",\"type\":\"string\"},"
                + "{\"name\":\"chainId\",\"type\":\"uint256\"},{\"name\":\"verifyingContract\",\"type\":\"address\"}],"
                + "\"Permit\":[{\"name\":\"holder\",\"type\":\"address\"},{\"name\":\"spender\",\"type\":\"address\"},"
                + "{\"name\":\"nonce\",\"type\":\"uint256\"},{\"name\":\"expiry\",\"type\":\"uint256\"},{\"name\":\"allowed\",\"type\":\"bool\"}]},"
                + "\"primaryType\":\"Permit\",\"domain\":{\"name\":\"Dai Stablecoin\",\"version\":\"1\",\"chainId\":1,"
                + "\"verifyingContract\":\"0x6B175474E89094C44Da98b954EedeAC495271d0F\"},"
                + "\"message\":{\"holder\":\"" + COW + "\",\"spender\":\"" + OTHER + "\",\"nonce\":0,\"expiry\":0,\"allowed\":true}}";
        MessageReview r = typedReviewOf(dai, "0x1", COW);
        assertEquals(MessageReview.Category.PERMIT, r.category);
        assertTrue(r.summaryValue("Amount").startsWith("UNLIMITED"));
        assertEquals("No expiry (expiry = 0)", r.summaryValue("Signature valid until"));
    }

    // ------------------------------------------------------------------ Permit2

    @Test public void permit2SingleFlagsUnlimitedAndNeverExpiring() throws Exception {
        MessageReview r = typedReview("permit2-single", "0x1", COW);
        assertEquals(MessageReview.Category.PERMIT2, r.category);
        assertEquals("0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD", r.summaryValue("Spender"));
        assertEquals("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", r.summaryValue("Token"));
        assertTrue(r.summaryValue("Amount").startsWith("UNLIMITED (maximum possible amount)"));
        assertEquals("Never (no expiry)", r.summaryValue("Allowance expires"));
        assertEquals("2026-01-01 00:00:00 UTC (1767225600)", r.summaryValue("Signature valid until"));
        assertFalse(r.warns("canonical Permit2"));
    }

    @Test public void permit2BatchListsEveryToken() throws Exception {
        MessageReview r = typedReview("permit2-batch", "0x1", COW);
        assertEquals(MessageReview.Category.PERMIT2, r.category);
        assertEquals("1000000 raw units (token decimals unverified)", r.summaryValue("Amount 1"));
        assertTrue(r.summaryValue("Amount 2").startsWith("UNLIMITED"));
        assertEquals("0xdAC17F958D2ee523a2206206994597C13D831ec7", r.summaryValue("Token 2"));
        assertTrue(r.summaryValue("Allowance expires 2").startsWith("0 (Permit2"));
        assertEquals("2026-01-01 00:00:00 UTC (1767225600)", r.summaryValue("Allowance expires 1"));
    }

    @Test public void permit2TransferFromIsAOneTimeTransfer() throws Exception {
        MessageReview r = typedReview("permit2-transfer-from", "0x1", COW);
        assertEquals(MessageReview.Category.PERMIT2, r.category);
        assertEquals("Review token transfer permission", r.title);
        assertEquals("250000000000000000000 raw units (token decimals unverified)", r.summaryValue("Amount"));
        assertEquals("1", r.summaryValue("Nonce"));
    }

    @Test public void permit2ShapeOnANonCanonicalContractIsWarned() throws Exception {
        String moved = MessageSigningVectorsTest.vector("permit2-single", "typedData")
                .replace("0x000000000022D473030F116dDEE9F6B43aC78BA3", "0x000000000022d473030f116ddee9f6b43ac78ba4");
        MessageReview r = typedReviewOf(moved, "0x1", COW);
        assertEquals(MessageReview.Category.PERMIT2, r.category);
        assertTrue(r.warns("canonical Permit2"));
    }

    // ------------------------------------------------------------------ orders & generic

    @Test public void seaportOrderGetsTheOrderWarning() throws Exception {
        MessageReview r = typedReview("seaport-like-order", "0x1", COW);
        assertEquals(MessageReview.Category.ORDER, r.category);
        assertTrue(r.warns("This signs an order"));
        assertTrue(r.subtitle.startsWith("This signs an order"));
        assertEquals("1 item(s): see Details", r.summaryValue("You offer"));
        assertFalse(r.warns("offerer is not this wallet"));
        assertTrue(typedReview("seaport-like-order", "0x1", OTHER).warns("offerer is not this wallet"));
    }

    @Test public void genericTypedDataShowsWhoIsAskingAndTheFullTreeUnderDetails() throws Exception {
        MessageReview r = typedReview("sig-util-v4-nested-arrays", "0x1", COW);
        assertEquals(MessageReview.Category.TYPED_DATA, r.category);
        assertEquals("Ether Mail", r.summaryValue("Requested by (domain name)"));
        assertEquals("1", r.summaryValue("Domain version"));
        assertEquals("Ethereum Mainnet (chain ID 1)", r.summaryValue("Network in message"));
        assertEquals("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC", r.summaryValue("Contract (verifying contract)"));
        String details = r.details.toString();
        assertTrue(details.contains("message.from.name · string: \"Cow\""));
        assertTrue(details.contains("message.to[0].wallets[2] · address: 0xB0B0b0b0b0b0B000000000000000000000000000"));
        assertTrue(details.contains("Signing digest: " + MessageSigningVectorsTest.vector("sig-util-v4-nested-arrays", "digest")));
        assertTrue(details.contains("Type definition: Mail(Person from,Person[] to,string contents)Person(string name,address[] wallets)"));
    }

    @Test public void everyLeafOfTheSignedTreeIsInDetails() throws Exception {
        MessageReview r = typedReview("all-atomic-types", "0x2105", COW);
        String details = r.details.toString();
        // Each leaf the encoder hashes appears once, from the same parsed tree.
        for (String expected : new String[] {
                "message.i8 · int8: -128",
                "message.i256 · int256: -57896044618658097711785492504343953926634992332820282019728792003956564819968",
                "message.u8 · uint8: 255",
                "message.u256 · uint256: 115792089237316195423570985008687907853269984665640564039457584007913129639935 (maximum possible value)",
                "message.u160hex · uint160: 65280",
                "message.b1 · bytes1: 0x7f",
                "message.dyn · bytes: 0xdeadbeef",
                "message.empty · bytes: 0x",
                "message.yes · bool: true",
                "message.text · string: \"line1\\nline2 ünicode 👋\"",
                "message.fixed[1] · uint256: 2",
                "message.grid[1] · address[]: (empty list)",
                "message.leaves[1].note · string: \"x\"",
                "message.none · int16[]: (empty list)",
                "message.neg · int64: -1",
                "domain.salt · bytes32: 0xabababababababababababababababababababababababababababababababab",
                "domain.name · string: \"Kitchen é😀\""}) {
            assertTrue("missing " + expected, details.contains(expected));
        }
        assertTrue(r.warns("maximum-value number"));
        assertFalse(r.warns("your Mac is on"));
    }

    @Test public void domainWithoutChainIdIsWarned() throws Exception {
        String noChain = MessageSigningVectorsTest.vector("eip712-mail", "typedData")
                .replace("{\"name\":\"chainId\",\"type\":\"uint256\"},", "")
                .replace("\"chainId\":1,", "");
        MessageReview r = typedReviewOf(noChain, "0x1", COW);
        assertTrue(r.warns("does not name a network"));
        assertEquals("Not specified", r.summaryValue("Network in message"));
    }

    @Test public void spenderFieldsInUnknownMessagesAreWarned() throws Exception {
        String custom = "{\"types\":{\"EIP712Domain\":[{\"name\":\"name\",\"type\":\"string\"}],"
                + "\"Grant\":[{\"name\":\"operator\",\"type\":\"address\"},{\"name\":\"until\",\"type\":\"uint64\"}]},"
                + "\"primaryType\":\"Grant\",\"domain\":{\"name\":\"Some App\"},"
                + "\"message\":{\"operator\":\"" + OTHER + "\",\"until\":5}}";
        MessageReview r = typedReviewOf(custom, "0x1", COW);
        assertEquals(MessageReview.Category.TYPED_DATA, r.category);
        assertTrue(r.warns("spender or operator (operator 0x1111111111111111111111111111111111111111)"));
        assertTrue(r.warns("does not name a network"));
        assertEquals("0x1111111111111111111111111111111111111111", r.summaryValue("operator"));
    }

    @Test public void stringsCannotHideCharactersFromTheReview() throws Exception {
        assertEquals("a\\u{202E}b\\u{200B}c\\nd", MessageReview.visible("a\u202eb\u200bc\nd"));
        String sneaky = MessageSigningVectorsTest.vector("eip712-mail", "typedData").replace("Hello, Bob!", "Hello, \\u202eBob!");
        MessageReview r = typedReviewOf(sneaky, "0x1", COW);
        assertTrue(r.details.toString().contains("\"Hello, \\u{202E}Bob!\""));
    }

    // ------------------------------------------------------------------ personal_sign

    @Test public void siweMessageIsParsedAndCheckedAgainstTheWallet() throws Exception {
        byte[] siwe = Numeric.hexStringToByteArray(MessageSigningVectorsTest.vector("personal-siwe", "message"));
        MessageReview r = personalReview(siwe, "0x1", COW);
        assertEquals(MessageReview.Category.SIGN_IN, r.category);
        assertEquals("example.com", r.summaryValue("Website (as claimed)"));
        assertEquals("0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826", r.summaryValue("Account in message"));
        assertEquals("https://example.com/login", r.summaryValue("URI"));
        assertEquals("Ethereum Mainnet (chain ID 1)", r.summaryValue("Network in message"));
        assertEquals("32891756", r.summaryValue("Nonce"));
        assertEquals("2026-09-27T12:00:00Z", r.summaryValue("Issued at"));
        assertEquals("2026-09-28T12:00:00Z", r.summaryValue("Expires"));
        assertEquals("https://example.com/my-web2-claim.json", r.summaryValue("Resource 2"));
        assertFalse(r.warns("NOT this wallet"));
        assertFalse(r.warns("differs from the site the message names"));

        MessageReview other = personalReview(siwe, "0x2105", OTHER);
        assertTrue(other.warns("NOT this wallet"));
        assertTrue(other.warns("names chain 1 but your Mac is on Base"));
    }

    @Test public void siweVariantsParseOrAreFlagged() throws Exception {
        String base = "https://app.example.org wants you to sign in with your Ethereum account:\n"
                + "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826\n\n\n"
                + "URI: https://evil.example.net/\nVersion: 1\nChain ID: 1\nNonce: abcdefgh12\nIssued At: 2026-09-27T12:00:00.000+02:00\n"
                + "Not Before: 2026-09-27T12:00:00Z\nRequest ID: 42";
        Siwe s = Siwe.parse(base);
        assertEquals("https", s.scheme);
        assertEquals("app.example.org", s.domain);
        assertNull(s.statement);
        assertEquals("42", s.requestId);
        MessageReview r = personalReview(base.getBytes(StandardCharsets.UTF_8), "0x1", COW);
        assertEquals(MessageReview.Category.SIGN_IN, r.category);
        assertTrue(r.warns("site in the URI (evil.example.net) differs"));

        String broken = base.replace("Nonce: abcdefgh12\n", "");
        MessageReview b = personalReview(broken.getBytes(StandardCharsets.UTF_8), "0x1", COW);
        assertEquals(MessageReview.Category.MESSAGE, b.category);
        assertTrue(b.warns("is not a valid sign-in message"));
        assertTrue(personalReview(base.replace("Version: 1", "Version: 2").getBytes(StandardCharsets.UTF_8), "0x1", COW)
                .warns("is not a valid sign-in message"));
        assertTrue(personalReview(base.replace("app.example.org wants", "trusted.com@evil.io wants").getBytes(StandardCharsets.UTF_8), "0x1", COW)
                .warns("is not a valid sign-in message"));
    }

    private static String siweFor(String domain, String uri) {
        return domain + " wants you to sign in with your Ethereum account:\n"
                + "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826\n\n\n"
                + "URI: " + uri + "\nVersion: 1\nChain ID: 1\nNonce: abcdefgh12\nIssued At: 2026-09-27T12:00:00Z";
    }

    private static MessageReview withOrigin(String text, String origin) throws Exception {
        JSONObject json = MessageRequestTest.personal(Numeric.toHexString(text.getBytes(StandardCharsets.UTF_8)));
        if (origin != null) json.put("origin", origin);
        return MessageReview.of(MessageRequest.parse(json), COW);
    }

    @Test public void siweLookalikeDomainsAreShownInPunycodeWithDanger() throws Exception {
        // Cyrillic "а" (U+0430) in place of the Latin "a"
        String fake = "uniswаp.org";
        MessageReview r = personalReview(siweFor(fake, "https://uniswаp.org/").getBytes(StandardCharsets.UTF_8), "0x1", COW);
        assertEquals(MessageReview.Category.SIGN_IN, r.category);
        String ascii = java.net.IDN.toASCII(fake);
        assertTrue(ascii, ascii.startsWith("xn--"));
        assertEquals(ascii, r.summaryValue("Website (as claimed)"));
        assertTrue(r.warns("lookalike characters"));
        assertTrue(r.warns("which is really " + ascii));
        assertTrue(MessageReview.lockedSummary(MessageRequest.parse(MessageRequestTest.personal(
                Numeric.toHexString(siweFor(fake, "https://x.org/").getBytes(StandardCharsets.UTF_8))))).contains(ascii));
        // fullwidth letters that nameprep maps to plain ASCII are still flagged
        MessageReview wide = personalReview(siweFor("ｕniswap.org", "https://uniswap.org/").getBytes(StandardCharsets.UTF_8), "0x1", COW);
        assertEquals("uniswap.org", wide.summaryValue("Website (as claimed)"));
        assertTrue(wide.warns("lookalike characters"));
        // a plain ASCII domain (with port) is not
        MessageReview plain = personalReview(siweFor("App.Example.org:8443", "https://app.example.org:8443/").getBytes(StandardCharsets.UTF_8), "0x1", COW);
        assertEquals("app.example.org:8443", plain.summaryValue("Website (as claimed)"));
        assertFalse(plain.warns("lookalike"));
        assertFalse(plain.warns("differs from the site the message names"));
        // a name with no valid ASCII form is a malformed sign-in
        StringBuilder longLabel = new StringBuilder("é");
        while (longLabel.length() < 70) longLabel.append('a');
        assertTrue(personalReview(siweFor(longLabel + ".org", "https://x.org/").getBytes(StandardCharsets.UTF_8), "0x1", COW)
                .warns("is not a valid sign-in message"));
    }

    @Test public void signingAddressRowNamesTheActualAccount() throws Exception {
        org.web3j.crypto.Credentials key = TestKeys.EVM_KEY;
        String addr = key.getAddress();
        MessageRequest req = MessageRequest.parse(MessageRequestTest.personal(Numeric.toHexString("hi".getBytes(StandardCharsets.UTF_8))));
        String checksummed = org.web3j.crypto.Keys.toChecksumAddress(addr);
        assertEquals(checksummed, new MessageApprovalSession(req, key).review.detailValue("Signing address"));
        assertNull(new MessageApprovalSession(req, key).review.detailValue("Signing address · Account 1"));
        SigningAccount second = new SigningAccount(1, "Account 2", false, "73c5da0a", addr);
        assertEquals(checksummed, new MessageApprovalSession(req, key, second).review.detailValue("Signing address · Account 2"));
        // shown once: the review's top ("Signing with") names it; the row is under the details
        assertNull(new MessageApprovalSession(req, key, second).review.summaryValue("Signing address · Account 2"));
        SigningAccount passphrase = new SigningAccount(0, "Account 1", true, "1a2b3c4d", addr);
        assertEquals(checksummed, new MessageApprovalSession(req, key, passphrase).review
                .detailValue("Signing address · Account 1 (passphrase wallet)"));
        // typed data and sign-in use the same row
        MessageRequest typed = MessageRequest.parse(MessageRequestTest.typed(MessageSigningVectorsTest.vector("permit2-single", "typedData")));
        assertEquals(checksummed, new MessageApprovalSession(typed, key, second).review.detailValue("Signing address · Account 2"));
        MessageRequest siwe = MessageRequest.parse(MessageRequestTest.personal(MessageSigningVectorsTest.vector("personal-siwe", "message")));
        assertEquals(checksummed, new MessageApprovalSession(siwe, key, second).review.detailValue("Signing address · Account 2"));
        try {
            new MessageApprovalSession(req, key, new SigningAccount(1, "Account 2", false, "73c5da0a", OTHER));
            org.junit.Assert.fail("review built for a different account than the key");
        } catch (IllegalArgumentException expected) { }
    }

    @Test public void hostReportedOriginIsShownAndComparedWithTheSignIn() throws Exception {
        // shown, marked as the Mac's claim, on every message kind
        MessageReview plain = withOrigin("Hello", "https://app.uniswap.org");
        String row = plain.summaryValue(MessageReview.ORIGIN_LABEL);
        assertTrue(row, row.startsWith("app.uniswap.org\n") && row.contains("can't verify"));
        assertNull(withOrigin("Hello", null).summaryValue(MessageReview.ORIGIN_LABEL));
        JSONObject typed = MessageRequestTest.typed(MessageSigningVectorsTest.vector("permit2-single", "typedData"))
                .put("origin", "http://localhost:5173");
        assertTrue(MessageReview.of(MessageRequest.parse(typed), COW).summaryValue(MessageReview.ORIGIN_LABEL).startsWith("http://localhost:5173\n"));

        // sign-in for the same host (port and case ignored): no mismatch
        MessageReview same = withOrigin(siweFor("app.uniswap.org", "https://app.uniswap.org/"), "https://app.uniswap.org");
        assertEquals("app.uniswap.org\nReported by your Mac (browser or WalletConnect). This phone can't verify it.",
                same.summaryValue(MessageReview.ORIGIN_LABEL));
        assertFalse(same.warns("phishing"));
        // with an origin the CHECK says the Mac named the site; without one, that the phone cannot see it
        assertTrue(same.warns("Your Mac reported the site above; this phone can't verify it. Only sign if you opened this site yourself."));
        assertFalse(same.warns("cannot see which site asked"));
        MessageReview noOrigin = withOrigin(siweFor("app.uniswap.org", "https://app.uniswap.org/"), null);
        assertTrue(noOrigin.warns("This phone cannot see which site asked. Only sign if you opened app.uniswap.org yourself"));
        assertFalse(noOrigin.warns("Your Mac reported the site"));
        for (MessageReview.Row r : same.summary) {
            if (r.value.startsWith("Your Mac reported")) assertEquals("CHECK · WEBSITE", ReviewStyle.heading(r));
        }
        assertEquals("Sign in", same.summaryValue("Action"));
        assertEquals("Sign-In with Ethereum (EIP-4361)", same.detailValue("Standard"));
        assertFalse(withOrigin(siweFor("localhost:3000", "http://localhost:3000/"), "http://localhost:3000").warns("phishing"));
        // sign-in for another site than the one that asked: DANGER
        MessageReview phish = withOrigin(siweFor("app.uniswap.org", "https://app.uniswap.org/"), "https://uniswap-airdrop.io");
        assertTrue(phish.warns("This sign-in is for app.uniswap.org, but the request came from uniswap-airdrop.io. A site may be phishing you."));
        // a lookalike sign-in domain compared in its ASCII form
        assertTrue(withOrigin(siweFor("app.uniswаp.org", "https://x.org/"), "https://app.uniswap.org").warns("may be phishing you"));
        assertFalse(withOrigin(siweFor("app.uniswаp.org", "https://x.org/"), "https://" + java.net.IDN.toASCII("app.uniswаp.org"))
                .warns("may be phishing you"));
    }

    @Test public void originFieldContract() throws Exception {
        String[] ok = {"https://app.uniswap.org", "https://a.b-c.example:8443", "https://xn--unswap-b1a.org", "http://localhost",
                "http://localhost:3000", "http://127.0.0.1:8080", "http://[::1]:5173", "https://localhost"};
        for (String o : ok) {
            MessageRequest r = MessageRequest.parse(MessageRequestTest.personal("0x6869").put("origin", o));
            assertEquals(o, r.origin);
        }
        StringBuilder longHost = new StringBuilder("https://");
        while (longHost.length() < 256) longHost.append("a.");
        longHost.append("io");
        String[] bad = {"", "app.uniswap.org", "https://App.uniswap.org", "https://app.uniswap.org/", "https://app.uniswap.org/path",
                "http://app.uniswap.org", "https://user@app.uniswap.org", "https://app.uniswap.org:0", "https://app.uniswap.org:65536",
                "https://app.uniswap.org:080", "https://ünï.org", "https://.org", "https://a..org", "https://a.org.", "http://localhost.evil.com",
                "http://127.0.0.2", "https://app.uniswap.org?x", "https://app.uniswap.org#x", " https://a.org", "https://a.org ",
                "javascript:alert(1)", longHost.toString()};
        for (String o : bad) {
            try {
                MessageRequest.parse(MessageRequestTest.personal("0x6869").put("origin", o));
                org.junit.Assert.fail("accepted origin " + o);
            } catch (org.json.JSONException expected) {
                assertTrue(expected.getMessage(), expected.getMessage().contains("origin"));
            }
        }
        // only a string
        try {
            MessageRequest.parse(MessageRequestTest.personal("0x6869").put("origin", 5));
            org.junit.Assert.fail();
        } catch (org.json.JSONException expected) { }
        // typed data too
        assertEquals("https://app.uniswap.org", MessageRequest.parse(MessageRequestTest.typed(
                MessageSigningVectorsTest.vector("permit2-single", "typedData")).put("origin", "https://app.uniswap.org")).origin);
        // never on transactions
        JSONObject tx = new JSONObject().put("id", "t-1").put("method", "signEip1559").put("chainId", "0x1").put("nonce", "0x0")
                .put("maxPriorityFeePerGas", "0x1").put("maxFeePerGas", "0x2").put("gasLimit", "0x5208")
                .put("to", OTHER).put("value", "0x1").put("data", "0x").put("origin", "https://app.uniswap.org");
        try {
            Eip1559Request.parse(tx);
            org.junit.Assert.fail("origin accepted on a transaction");
        } catch (org.json.JSONException expected) {
            assertTrue(expected.getMessage().contains("unknown=[origin]"));
        }
        // through the strict USB frame parser, as the companion sends it
        JSONObject frame = AccessoryTransport.parseStrictRequest(
                "{\"id\":\"m-1\",\"method\":\"personal_sign\",\"chainId\":\"0x1\",\"message\":\"0x6869\",\"origin\":\"https://app.uniswap.org\"}");
        assertEquals("https://app.uniswap.org", MessageRequest.parse(frame).origin);
    }

    @Test public void plainTextIsShownVerbatim() throws Exception {
        MessageReview r = personalReview("Hello\r\nworld\tok".getBytes(StandardCharsets.UTF_8), "0x1", COW);
        assertEquals(MessageReview.Category.MESSAGE, r.category);
        assertEquals("Hello\r\nworld\tok", r.summaryValue("Message"));
    }

    @Test public void unreadableBytesGetTheUnreadableWarningAndHex() throws Exception {
        byte[] hash = Numeric.hexStringToByteArray(MessageSigningVectorsTest.vector("personal-binary-32", "message"));
        MessageReview r = personalReview(hash, "0x1", COW);
        assertEquals(MessageReview.Category.UNREADABLE, r.category);
        assertTrue(r.warns("Unreadable data"));
        assertTrue(r.warns("exactly 32 bytes"));
        assertEquals(MessageSigningVectorsTest.vector("personal-binary-32", "message"), r.summaryValue("Data (hex)"));
        assertEquals("Sign unreadable data", r.signLabel);
        String[] unreadable = {"a\u202eb", "zero\u200bwidth", "bell\u0007", "cr\ronly", "   ", "\ufeffbom", "private\ue000"};
        for (String text : unreadable) {
            assertEquals(text, MessageReview.Category.UNREADABLE,
                    personalReview(text.getBytes(StandardCharsets.UTF_8), "0x1", COW).category);
        }
        assertEquals(MessageReview.Category.UNREADABLE,
                personalReview(new byte[] {(byte) 0xc3, 0x28}, "0x1", COW).category); // invalid UTF-8
        assertEquals(MessageReview.Category.MESSAGE,
                personalReview("Grüße 👋 日本".getBytes(StandardCharsets.UTF_8), "0x1", COW).category);
    }

    @Test public void lockedSummaryNamesTheKindWithoutAnIdentity() throws Exception {
        String siwe = MessageReview.lockedSummary(MessageRequest.parse(MessageRequestTest.personal(
                MessageSigningVectorsTest.vector("personal-siwe", "message"))));
        assertTrue(siwe.startsWith("Sign-in request from example.com"));
        String raw = MessageReview.lockedSummary(MessageRequest.parse(MessageRequestTest.personal(
                MessageSigningVectorsTest.vector("personal-binary-32", "message"))));
        assertTrue(raw.contains("UNREADABLE"));
        String typed = MessageReview.lockedSummary(MessageRequest.parse(MessageRequestTest.typed(
                MessageSigningVectorsTest.vector("permit2-single", "typedData"))));
        assertTrue(typed.startsWith("Typed-data signature (PermitSingle) from Permit2"));
    }

    @Test public void reviewDigestIsTheSignedDigest() throws Exception {
        MessageRequest request = MessageRequest.parse(MessageRequestTest.typed(
                MessageSigningVectorsTest.vector("permit2-batch", "typedData")));
        MessageApprovalSession session = new MessageApprovalSession(request, MessageSigningVectorsTest.COW);
        String shown = null;
        for (MessageReview.Row row : session.review.details) if (row.label.equals("Signing digest")) shown = row.value;
        assertNotNull(shown);
        JSONObject response = session.signIfIdentityUnchanged(MessageSigningVectorsTest.COW);
        assertEquals(shown, response.getString("digest"));
        assertEquals(MessageSigningVectorsTest.vector("permit2-batch", "digest"), shown);
        assertEquals(MessageSigningVectorsTest.vector("permit2-batch", "signature"), response.getString("signature"));
    }

    @Test public void timeLabelsCoverEdgeValues() {
        assertEquals("1970-01-01 00:00:00 UTC (0)", MessageReview.timeLabel(BigInteger.ZERO));
        assertTrue(MessageReview.timeLabel(BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE)).startsWith("No expiry"));
        assertTrue(MessageReview.timeLabel(BigInteger.valueOf(253402300800L)).startsWith("No practical expiry"));
    }

    /**
     * Default-ignorable code points that are NOT category Cf (U+034F, variation selectors, Hangul
     * fillers, …) force the unreadable-data path in personal_sign and are escaped by visible().
     */
    @Test public void invisibleDefaultIgnorableCharactersAreFlagged() throws Exception {
        String hidden = "I agree\u034F to the terms\uFE0F";
        MessageRequest b = MessageRequest.parse(new JSONObject().put("id", "b").put("method", "personal_sign")
                .put("chainId", "0x1").put("message", Numeric.toHexString(hidden.getBytes(StandardCharsets.UTF_8))));
        assertNull("hidden-char message is not shown as readable text", b.personal.text);
        assertEquals(MessageReview.Category.UNREADABLE,
                MessageReview.of(b, "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826").category);

        assertEquals("Uni\\u{034F}swap", MessageReview.visible("Uni\u034Fswap"));
        assertEquals("Uni\\u{3164}swap", MessageReview.visible("Uni\u3164swap"));
        assertEquals("Uni\\u{115F}swap", MessageReview.visible("Uni\u115Fswap"));
        assertEquals("Uni\\u{FE0F}swap", MessageReview.visible("Uni\uFE0Fswap"));
        assertEquals("Uni\\u{200B}swap", MessageReview.visible("Uni\u200Bswap"));
        assertEquals("Uni\\u{E0041}swap", MessageReview.visible("Uni" + new String(Character.toChars(0xE0041)) + "swap"));
        for (int cp : new int[] {0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180B, 0x180F, 0x3164, 0xFE00, 0xFE0F,
                0xFFA0, 0xE0000, 0xE0FFF, 0x200B, 0x00AD}) {
            assertFalse(Integer.toHexString(cp), PersonalMessage.printable(cp));
        }
        for (int cp : new int[] {'A', 0xE9, 0xAC00 /* Hangul syllable */, 0x1F600 /* emoji */}) {
            assertTrue(Integer.toHexString(cp), PersonalMessage.printable(cp));
        }
    }
}
