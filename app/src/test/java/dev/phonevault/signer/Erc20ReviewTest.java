package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Keys;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionDecoder;
import org.web3j.utils.Numeric;

import java.math.BigInteger;

public final class Erc20ReviewTest {
    private static final Credentials KEY = TestKeys.EVM_KEY;
    private static final String USDC_ETH = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    private static final String DAI_ETH = "0x6B175474E89094C44Da98b954EedeAC495271d0F";
    private static final String WBTC_ETH = "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599";
    private static final String USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
    private static final String UNKNOWN = "0x2222222222222222222222222222222222222222";
    private static final String BOB = "0x1111111111111111111111111111111111111111";
    private static final String SPENDER = "0x3333333333333333333333333333333333333333";
    private static final BigInteger MAX = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE);

    private static String word(String address) { return "000000000000000000000000" + Numeric.cleanHexPrefix(address).toLowerCase(); }
    private static String word(BigInteger v) { return String.format("%64s", v.toString(16)).replace(' ', '0'); }
    static String transfer(String to, BigInteger amount) { return "0xa9059cbb" + word(to) + word(amount); }
    static String approve(String spender, BigInteger amount) { return "0x095ea7b3" + word(spender) + word(amount); }
    static String increase(String spender, BigInteger amount) { return "0x39509351" + word(spender) + word(amount); }
    static String transferFrom(String from, String to, BigInteger amount) { return "0x23b872dd" + word(from) + word(to) + word(amount); }

    private static JSONObject request(String chainHex, String to, String data) throws Exception {
        return new JSONObject().put("id", "tok-1").put("method", "signEip1559").put("chainId", chainHex)
                .put("nonce", "0x7").put("maxPriorityFeePerGas", "0x3b9aca00").put("maxFeePerGas", "0x77359400")
                .put("gasLimit", "0xfde8").put("to", to).put("value", "0x0").put("data", data);
    }

    private static TransactionReview review(String chainHex, String to, String data) throws Exception {
        return new ApprovalSession(Eip1559Request.parse(request(chainHex, to, data)), KEY, TokenListTest.bundled()).review;
    }

    private static String value(TransactionReview r, String label) {
        for (MessageReview.Row row : r.summary) if (row.label.equals(label)) return row.value;
        for (MessageReview.Row row : r.details) if (row.label.equals(label)) return row.value;
        return null;
    }

    private static int count(TransactionReview r, String label) {
        int n = 0;
        for (MessageReview.Row row : r.summary) if (row.label.equals(label)) n++;
        return n;
    }

    // ------------------------------------------------------------------ formatting

    @Test public void formatsExactValuesTrimmingOnlyTrailingZeros() {
        assertEquals("50", Units.format(BigInteger.valueOf(50_000_000), 6, true));
        assertEquals("0", Units.format(BigInteger.ZERO, 6, true));
        assertEquals("0", Units.format(BigInteger.ZERO, 0, true));
        assertEquals("0.000001", Units.format(BigInteger.ONE, 6, true));
        assertEquals("0.000000000000000001", Units.format(BigInteger.ONE, 18, true));
        assertEquals("1.234567890123456789", Units.format(new BigInteger("1234567890123456789"), 18, true));
        assertEquals("1.5", Units.format(new BigInteger("1500000000000000000"), 18, true));
        assertEquals("0.12345678", Units.format(BigInteger.valueOf(12_345_678), 8, true));
        assertEquals("1,000", Units.format(BigInteger.valueOf(1_000_000_000), 6, true));
        assertEquals("1,234,567.000001", Units.format(new BigInteger("1234567000001"), 6, true));
        assertEquals("100", Units.format(BigInteger.valueOf(100), 0, true));
        // the full uint256 range stays exact: no rounding, no exponent
        assertEquals("115,792,089,237,316,195,423,570,985,008,687,907,853,269,984,665,640,564,039,457.584007913129639935",
                Units.format(MAX, 18, true));
        assertEquals("115,792,089,237,316,195,423,570,985,008,687,907,853,269,984,665,640,564,039,457,584,007,913,129,639,935 base units",
                Erc20Call.baseUnits(MAX));
        assertEquals("1 base unit", Erc20Call.baseUnits(BigInteger.ONE));
    }

    // ------------------------------------------------------------------ known tokens

    @Test public void knownUsdcTransferReadsAsSend50Usdc() throws Exception {
        TransactionReview r = review("0x1", USDC_ETH, transfer(BOB, BigInteger.valueOf(50_000_000)));
        assertEquals("Send 50 USDC", r.title);
        assertEquals("Send 50 USDC to " + Keys.toChecksumAddress(BOB), value(r, "Action"));
        assertEquals("50 USDC", value(r, "Amount"));
        assertEquals(Keys.toChecksumAddress(BOB), value(r, "Recipient"));
        assertEquals("USD Coin (USDC), 6 decimals, from the token list built into this phone", value(r, "Token"));
        assertEquals(USDC_ETH, value(r, "Token contract"));
        assertEquals("0 ETH (only the fee below)", value(r, "Native value sent"));
        assertEquals("50000000 (uint256)", value(r, "Amount in base units"));
        assertEquals("transfer(address,uint256) · selector 0xa9059cbb", value(r, "Function"));
        // no account description given: the row names no account number (never a guessed "Account 1")
        assertEquals(Keys.toChecksumAddress(KEY.getAddress()), value(r, "From"));
        assertNull(value(r, "From · Account 1"));
        assertEquals("Ethereum Mainnet (chain ID 1)", value(r, "Network"));
        assertEquals(0, count(r, "WARNING"));
        assertEquals(0, count(r, "DANGER"));
        assertEquals("Approve & sign", r.signLabel);
        assertTrue(r.lockedSummary.startsWith("Send 50 USDC to 0x"));
        assertTrue(r.reviewPrompt.contains("token contract"));
    }

    // ------------------------------------------------------------------ which account signs

    @Test public void fromRowNamesTheActualSigningAccount() throws Exception {
        Eip1559Request transfer = Eip1559Request.parse(request("0x1", USDC_ETH, transfer(BOB, BigInteger.valueOf(50_000_000))));
        String checksummed = Keys.toChecksumAddress(KEY.getAddress());
        SigningAccount second = new SigningAccount(1, "Account 2", false, "73c5da0a", KEY.getAddress());
        TransactionReview r2 = new ApprovalSession(transfer, KEY, TokenListTest.bundled(), null, second).review;
        assertEquals(checksummed, value(r2, "From · Account 2"));
        assertNull(value(r2, "From · Account 1"));
        // shown once on screen: the review's top says "Signing with"; the From row is in the technical details
        for (MessageReview.Row row : r2.summary) assertFalse(row.label, row.label.startsWith("From"));
        boolean inDetails = false;
        for (MessageReview.Row row : r2.details) inDetails |= row.label.equals("From · Account 2");
        assertTrue(inDetails);
        SigningAccount passphrase = new SigningAccount(0, "Account 1", true, "1a2b3c4d", KEY.getAddress());
        TransactionReview rp = new ApprovalSession(transfer, KEY, TokenListTest.bundled(), null, passphrase).review;
        assertEquals(checksummed, value(rp, "From · Account 1 (passphrase wallet)"));
        SigningAccount named = new SigningAccount(2, "Savings", false, "73c5da0a", KEY.getAddress());
        assertEquals(checksummed, value(new ApprovalSession(transfer, KEY, TokenListTest.bundled(), null, named).review, "From · Savings"));
        // swaps, NFT calls and native transfers use the same row
        Eip1559Request nativeSend = Eip1559Request.parse(new JSONObject(request("0x1", BOB, "0x").toString()).put("value", "0x1"));
        assertEquals(checksummed, value(new ApprovalSession(nativeSend, KEY, TokenListTest.bundled(), null, second).review, "From · Account 2"));
        // an account description for another key is a bug, never shown
        SigningAccount other = new SigningAccount(1, "Account 2", false, "73c5da0a", BOB);
        try {
            new ApprovalSession(transfer, KEY, TokenListTest.bundled(), null, other);
            fail("review built for a different account than the key");
        } catch (IllegalArgumentException expected) { }
    }

    // ------------------------------------------------------------------ fee alarm

    private static TransactionReview feeReview(String chain, String to, String value, String data, String gasLimit, String maxFee) throws Exception {
        JSONObject j = request(chain, to, data).put("value", value).put("gasLimit", gasLimit).put("maxFeePerGas", maxFee)
                .put("maxPriorityFeePerGas", "0x0");
        return new ApprovalSession(Eip1559Request.parse(j), KEY, TokenListTest.bundled()).review;
    }

    private static boolean dangerContains(TransactionReview r, String fragment) {
        for (MessageReview.Row row : r.summary) if (row.label.equals("DANGER") && row.value.contains(fragment)) return true;
        return false;
    }

    @Test public void absurdMaximumFeesAreDanger() throws Exception {
        String usdc = transfer(BOB, BigInteger.valueOf(50_000_000));
        // normal: 65,000 gas at 2 gwei = 0.00013 ETH
        assertEquals(0, count(review("0x1", USDC_ETH, usdc), "DANGER"));
        // 0.05 ETH exactly is not above the cap; 0.05 ETH + 1 wei is
        BigInteger gwei = BigInteger.TEN.pow(9);
        String limit = "0x" + BigInteger.valueOf(50_000).toString(16);
        String fee1 = "0x" + gwei.multiply(BigInteger.valueOf(1000)).toString(16);           // 50,000 × 1000 gwei = 0.05 ETH
        assertEquals(0, count(feeReview("0x1", USDC_ETH, "0x0", usdc, limit, fee1), "DANGER"));
        String fee2 = "0x" + gwei.multiply(BigInteger.valueOf(1000)).add(BigInteger.ONE).toString(16);
        TransactionReview high = feeReview("0x1", USDC_ETH, "0x0", usdc, limit, fee2);
        assertTrue(high.text(), dangerContains(high, "far more than a normal fee on Ethereum Mainnet"));
        // the same cap on an L2
        assertTrue(dangerContains(feeReview("0x2105", USDC_BASE, "0x0", usdc, limit, fee2), "far more than a normal fee on Base"));
        // Polygon: 50 POL, so 0.05 POL-worth is nothing
        assertEquals(0, count(feeReview("0x89", BOB, "0x1", "0x", limit, fee2), "DANGER"));
        String pol = "0x" + gwei.multiply(BigInteger.valueOf(1_000_001)).toString(16);         // 50,000 × 1,000,001 gwei ≈ 50.00005 POL
        assertTrue(dangerContains(feeReview("0x89", BOB, "0xde0b6b3a7640000000", "0x", limit, pol), "far more than a normal fee on Polygon"));
        // a fee larger than the ETH sent, above the 0.005 ETH floor: 0.01 ETH fee for 0.001 ETH
        String fee10m = "0x" + gwei.multiply(BigInteger.valueOf(200)).toString(16);            // 50,000 × 200 gwei = 0.01 ETH
        TransactionReview tiny = feeReview("0x1", BOB, "0x38d7ea4c68000", "0x", limit, fee10m);
        assertTrue(tiny.text(), dangerContains(tiny, "is more than the 0.001 ETH being sent"));
        // below the floor a fee larger than a dust transfer is not flagged
        String fee1m = "0x" + gwei.multiply(BigInteger.valueOf(20)).toString(16);              // 0.001 ETH
        assertEquals(0, count(feeReview("0x1", BOB, "0x1", "0x", limit, fee1m), "DANGER"));
        assertEquals(TransactionReview.feeDangerCap(1), BigInteger.TEN.pow(16).multiply(BigInteger.valueOf(5)));
    }

    @Test public void decimalsComeFromTheListPerToken() throws Exception {
        assertEquals("1.5 DAI", value(review("0x1", DAI_ETH, transfer(BOB, new BigInteger("1500000000000000000"))), "Amount"));
        assertEquals("0.000000000000000001 DAI", value(review("0x1", DAI_ETH, transfer(BOB, BigInteger.ONE)), "Amount"));
        assertEquals("0.12345678 WBTC", value(review("0x1", WBTC_ETH, transfer(BOB, BigInteger.valueOf(12_345_678))), "Amount"));
        assertEquals("0.000001 USDC", value(review("0x2105", USDC_BASE, transfer(BOB, BigInteger.ONE)), "Amount"));
        assertEquals("0 USDC", value(review("0x1", USDC_ETH, transfer(BOB, BigInteger.ZERO)), "Amount"));
    }

    @Test public void maxApprovalIsUnlimitedWithABigDanger() throws Exception {
        TransactionReview r = review("0x1", USDC_ETH, approve(SPENDER, MAX));
        assertEquals("UNLIMITED permission", r.title);
        assertEquals("Allow " + Keys.toChecksumAddress(SPENDER) + " to spend UNLIMITED USDC", value(r, "Action"));
        assertEquals("UNLIMITED USDC", value(r, "Allowance"));
        assertEquals(Keys.toChecksumAddress(SPENDER), value(r, "Spender (gets permission)"));
        assertTrue(value(r, "DANGER").startsWith("UNLIMITED allowance"));
        assertTrue(value(r, "DANGER").contains("ALL of this wallet's USDC"));
        assertEquals("Approve UNLIMITED & sign", r.signLabel);
        assertEquals(MAX + " (uint256)", value(r, "Allowance in base units"));
    }

    @Test public void unlimitedStartsAtTwoToThe255() throws Exception {
        BigInteger half = BigInteger.ONE.shiftLeft(255);
        assertEquals("UNLIMITED USDC", value(review("0x1", USDC_ETH, approve(SPENDER, half)), "Allowance"));
        TransactionReview below = review("0x1", USDC_ETH, approve(SPENDER, half.subtract(BigInteger.ONE)));
        assertEquals(Units.format(half.subtract(BigInteger.ONE), 6, true) + " USDC", value(below, "Allowance"));
        assertTrue(value(below, "DANGER").contains("will be able to take up to"));
        assertEquals("Approve permission & sign", below.signLabel);
    }

    @Test public void limitedApprovalAndRevoke() throws Exception {
        TransactionReview r = review("0x1", USDC_ETH, approve(SPENDER, BigInteger.valueOf(50_000_000)));
        assertEquals("Allow " + Keys.toChecksumAddress(SPENDER) + " to spend 50 USDC", value(r, "Action"));
        assertEquals("50 USDC", value(r, "Allowance"));
        assertTrue(value(r, "DANGER").contains("up to 50 USDC"));
        TransactionReview revoke = review("0x1", USDC_ETH, approve(SPENDER, BigInteger.ZERO));
        assertEquals("Revoke permission", revoke.title);
        assertTrue(value(revoke, "Action").startsWith("Revoke " + Keys.toChecksumAddress(SPENDER)));
        assertEquals(0, count(revoke, "DANGER"));
    }

    @Test public void increaseAllowanceIsReviewedAsAPermission() throws Exception {
        TransactionReview r = review("0x1", USDC_ETH, increase(SPENDER, BigInteger.valueOf(2_500_000)));
        assertEquals("Increase " + Keys.toChecksumAddress(SPENDER) + "'s allowance by 2.5 USDC", value(r, "Action"));
        assertEquals("2.5 USDC", value(r, "Allowance increase"));
        assertTrue(value(r, "DANGER").contains("can't see the current allowance"));
        assertEquals("increaseAllowance(address,uint256) · selector 0x39509351", value(r, "Function"));
        TransactionReview max = review("0x1", USDC_ETH, increase(SPENDER, MAX));
        assertEquals("UNLIMITED USDC", value(max, "Allowance increase"));
        assertEquals("Approve UNLIMITED & sign", max.signLabel);
        assertEquals(Eip1559Request.Kind.TOKEN_INCREASE_ALLOWANCE, Eip1559Request.parse(request("0x1", USDC_ETH, increase(SPENDER, MAX))).kind);
    }

    @Test public void transferFromShowsBothAddresses() throws Exception {
        String alice = "0x4444444444444444444444444444444444444444";
        TransactionReview r = review("0x1", USDC_ETH, transferFrom(alice, BOB, BigInteger.valueOf(7_000_000)));
        assertEquals("Move 7 USDC", r.title);
        assertEquals("Move 7 USDC from " + Keys.toChecksumAddress(alice) + " to " + Keys.toChecksumAddress(BOB), value(r, "Action"));
        assertEquals(Keys.toChecksumAddress(alice), value(r, "Take from (token owner)"));
        assertTrue(value(r, "WARNING").contains("not from this wallet"));
        TransactionReview own = review("0x1", USDC_ETH, transferFrom(KEY.getAddress(), BOB, BigInteger.ONE));
        assertTrue(value(own, "Take from (token owner)").endsWith("(this wallet)"));
    }

    @Test public void sendingToATokenContractIsFlagged() throws Exception {
        TransactionReview r = review("0x1", USDC_ETH, transfer(DAI_ETH, BigInteger.ONE));
        assertTrue(value(r, "WARNING").contains("itself a token contract (DAI)"));
        TransactionReview self = review("0x1", USDC_ETH, transfer(USDC_ETH, BigInteger.ONE));
        assertTrue(value(self, "WARNING").contains("token contract"));
    }

    // ------------------------------------------------------------------ unknown tokens

    @Test public void unknownContractShowsRawBaseUnitsAndNeverASymbol() throws Exception {
        TransactionReview r = review("0x1", UNKNOWN, transfer(BOB, BigInteger.valueOf(50_000_000)));
        assertEquals("Unknown token transfer", r.title);
        assertEquals("Send 50,000,000 base units of unknown token contract " + UNKNOWN + " to " + BOB, value(r, "Action"));
        assertEquals("50,000,000 base units (raw amount; token unknown)", value(r, "Amount"));
        assertEquals(UNKNOWN, value(r, "Unknown token contract"));
        assertTrue(value(r, "WARNING").startsWith("Unknown token contract " + UNKNOWN));
        assertTrue(value(r, "WARNING").contains("can't be verified"));
        assertNull(value(r, "Token"));
        assertNull(r.token);
        for (String symbol : new String[] {"USDC", "USDT", "DAI", "WETH", "WBTC", "ETH "}) {
            assertFalse("guessed " + symbol, r.text().replace("0 ETH (only the fee below)", "").contains(symbol));
        }
    }

    @Test public void listedAddressOnAnotherChainIsUnknown() throws Exception {
        // Ethereum's USDC address on Base is not USDC.
        TransactionReview r = review("0x2105", USDC_ETH, transfer(BOB, BigInteger.valueOf(50_000_000)));
        assertNull(r.token);
        assertEquals(USDC_ETH, value(r, "Unknown token contract"));
    }

    @Test public void unknownUnlimitedApprovalIsStillUnlimited() throws Exception {
        TransactionReview r = review("0x1", UNKNOWN, approve(SPENDER, MAX));
        assertEquals("UNLIMITED (raw value ≥ 2^255)", value(r, "Allowance"));
        assertTrue(value(r, "DANGER").contains("UNLIMITED"));
        assertTrue(value(r, "WARNING").contains("NFT"));
        assertEquals("Approve UNLIMITED & sign", r.signLabel);
    }

    @Test public void refusedListMeansEverythingUnknownWithAReason() throws Exception {
        TransactionReview r = new ApprovalSession(Eip1559Request.parse(request("0x1", USDC_ETH,
                transfer(BOB, BigInteger.valueOf(50_000_000)))), KEY, TokenList.unavailable("hash mismatch")).review;
        assertNull(r.token);
        assertTrue(r.text().contains("failed its integrity check"));
        assertTrue(r.text().contains("hash mismatch"));
        assertEquals("50,000,000 base units (raw amount; token unknown)", value(r, "Amount"));
    }

    @Test public void nativeTransferReviewIsUnchanged() throws Exception {
        TransactionReview r = new ApprovalSession(Eip1559Request.parse(request("0xaa36a7", BOB, "0x")
                .put("value", "0xde0b6b3a7640000")), KEY, TokenListTest.bundled()).review;
        assertEquals("Review transfer", r.title);
        assertEquals("Send ETH", value(r, "Action"));
        assertEquals("1 ETH", value(r, "Send"));
        assertEquals(BOB, value(r, "Recipient"));
        assertEquals("None", value(r, "Contract data"));
        // the native coin by name: POL on Polygon
        TransactionReview pol = new ApprovalSession(Eip1559Request.parse(request("0x89", BOB, "0x")
                .put("value", "0xde0b6b3a7640000")), KEY, TokenListTest.bundled()).review;
        assertEquals("Send POL", value(pol, "Action"));
    }

    // ------------------------------------------------------------------ strict calldata

    private static void refused(String chain, String to, String data, String value) {
        try {
            Eip1559Request.parse(new JSONObject(request(chain, to, data).toString()).put("value", value));
            fail("accepted " + data + " value " + value);
        } catch (JSONException expected) {
            // refused before any review exists
        } catch (Exception other) {
            throw new AssertionError(other);
        }
    }

    @Test public void malformedCalldataIsRefused() {
        String ok = transfer(BOB, BigInteger.TEN);
        refused("0x1", USDC_ETH, ok + "00", "0x0");                              // one trailing byte
        refused("0x1", USDC_ETH, ok + word(BigInteger.ONE), "0x0");              // a trailing word
        refused("0x1", USDC_ETH, ok.substring(0, ok.length() - 2), "0x0");      // truncated
        refused("0x1", USDC_ETH, "0xa9059cbb", "0x0");                           // selector only
        refused("0x1", USDC_ETH, "0xa905", "0x0");                               // partial selector
        refused("0x1", USDC_ETH, ok + "0", "0x0");                               // odd length
        refused("0x1", USDC_ETH, "0xdeadbeef" + word(BOB) + word(BigInteger.TEN), "0x0");      // unknown selector
        refused("0x1", USDC_ETH, "0x23b872dd" + word(BOB) + word(BigInteger.TEN), "0x0");      // transferFrom too short
        refused("0x1", USDC_ETH, transferFrom(BOB, BOB, BigInteger.ONE) + "00", "0x0");        // transferFrom trailing
        refused("0x1", USDC_ETH, increase(SPENDER, BigInteger.ONE) + word(BigInteger.ONE), "0x0");
        refused("0x1", USDC_ETH, "0xa9059cbb01" + word(BOB).substring(2) + word(BigInteger.TEN), "0x0"); // dirty padding
        refused("0x1", USDC_ETH, "0x23b872dd" + word(BOB) + "ff" + word(BOB).substring(2) + word(BigInteger.TEN), "0x0");
        refused("0x1", USDC_ETH, transfer("0x0000000000000000000000000000000000000000", BigInteger.ONE), "0x0");
        refused("0x1", USDC_ETH, transferFrom("0x0000000000000000000000000000000000000000", BOB, BigInteger.ONE), "0x0");
        refused("0x1", USDC_ETH, increase(SPENDER, BigInteger.ONE), "0x1");     // native value on a token call
        refused("0x1", USDC_ETH, transferFrom(BOB, SPENDER, BigInteger.ONE), "0x1");
    }

    @Test public void signedTransactionCarriesExactlyTheReviewedCall() throws Exception {
        for (String data : new String[] {
                transfer(BOB, BigInteger.valueOf(50_000_000)), approve(SPENDER, MAX),
                increase(SPENDER, BigInteger.ONE), transferFrom(SPENDER, BOB, BigInteger.TEN)}) {
            ApprovalSession session = new ApprovalSession(Eip1559Request.parse(request("0x1", USDC_ETH, data)), KEY, TokenListTest.bundled());
            RawTransaction decoded = TransactionDecoder.decode(session.signIfIdentityUnchanged(KEY).getString("signedTransaction"));
            assertEquals(USDC_ETH.toLowerCase(), decoded.getTo());
            assertEquals(BigInteger.ZERO, decoded.getValue());
            assertEquals(Numeric.cleanHexPrefix(data), Numeric.cleanHexPrefix(decoded.getData()));
            // and the review's decoded arguments are the calldata's
            Erc20Call call = Erc20Call.decode(decoded.getData().startsWith("0x") ? decoded.getData() : "0x" + decoded.getData());
            assertEquals(session.request.tokenCall.amount, call.amount);
            assertEquals(session.request.tokenCall.party, call.party);
            assertEquals(session.request.tokenCall.function, call.function);
        }
    }
}
