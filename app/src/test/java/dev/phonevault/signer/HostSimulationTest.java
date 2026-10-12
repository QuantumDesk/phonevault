package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;
import org.web3j.crypto.Credentials;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;

/**
 * The Mac's optional simulation claim (hostSimulation): strict parsing, never signed, and the
 * contradiction check against what the phone decoded (vault-os/docs/simulation.md).
 */
public final class HostSimulationTest {
    private static final Credentials KEY = Credentials.create("4c0883a69102937d6231471b5dbb6204fe51296170827966f278a5e6f4f4f5f");
    private static final String ME = KEY.getAddress().toLowerCase();
    private static final String USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
    private static final String DAI = "0x6b175474e89094c44da98b954eedeac495271d0f";
    private static final String WETH = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2";
    private static final String UNKNOWN = "0x2222222222222222222222222222222222222222";
    private static final String OTHER = "0x7f3a9c04e2b16d58a41c0f9e6b2d7a8c5e1f4b93";
    private static final String SPENDER = "0x3333333333333333333333333333333333333333";
    private static final BigInteger E6 = BigInteger.TEN.pow(6), E18 = BigInteger.TEN.pow(18);
    // gas 0xfde8 (65000) × max fee 0x77359400 (2 gwei) = 130000 gwei
    private static final BigInteger MAX_FEE = BigInteger.valueOf(65000L).multiply(BigInteger.valueOf(2_000_000_000L));

    // ------------------------------------------------------------------ helpers

    private static JSONObject request(String chain, String to, String value, String data) throws JSONException {
        return new JSONObject().put("id", "sim-1").put("method", "signEip1559").put("chainId", chain)
                .put("nonce", "0x7").put("maxPriorityFeePerGas", "0x3b9aca00").put("maxFeePerGas", "0x77359400")
                .put("gasLimit", "0xfde8").put("to", to).put("value", value).put("data", data);
    }

    private static JSONObject change(String asset, String delta) throws JSONException {
        return new JSONObject().put("asset", asset).put("delta", delta);
    }

    private static JSONObject token(String asset, String delta, String symbol, int decimals) throws JSONException {
        return change(asset, delta).put("symbol", symbol).put("decimals", decimals);
    }

    private static JSONObject claim(JSONObject... changes) throws JSONException {
        return new JSONObject().put("changes", new JSONArray(Arrays.asList(changes))).put("node", "ethereum-rpc.publicnode.com").put("block", "0x18f603b");
    }

    private static JSONObject with(JSONObject request, JSONObject claim) throws JSONException {
        return new JSONObject(request.toString()).put("hostSimulation", claim);
    }

    private static ApprovalSession session(JSONObject json) throws Exception {
        return new ApprovalSession(Eip1559Request.parse(json), KEY, TokenListTest.bundled());
    }

    private static SimulationCheck.Result check(JSONObject request, JSONObject... changes) throws Exception {
        return session(with(request, claim(changes))).hostSimulation;
    }

    private static void refused(JSONObject json, String fragment) {
        try {
            Eip1559Request.parse(json);
            fail("accepted " + json);
        } catch (JSONException expected) {
            assertTrue(expected.getMessage() + " should mention " + fragment, expected.getMessage().contains(fragment));
        }
    }

    private static String fee(BigInteger wei) { return wei.negate().toString(); }

    private static JSONObject usdcTransfer(String to, BigInteger amount) throws JSONException {
        return request("0x1", USDC, "0x0", Erc20ReviewTest.transfer(to, amount));
    }

    // ------------------------------------------------------------------ parsing

    @Test public void theFieldIsOptional() throws Exception {
        ApprovalSession s = session(usdcTransfer(OTHER, E6));
        assertNull(s.request.hostSimulation);
        assertNull(s.hostSimulation);
    }

    @Test public void aValidClaimParsesExactly() throws Exception {
        JSONObject json = with(usdcTransfer(OTHER, E6), claim(token(USDC, "-1000000", "USDC", 6),
                change("native", "-1300000000000").put("symbol", "ETH").put("decimals", 18),
                change(UNKNOWN, "5").put("tokenId", "42")));
        HostSimulation sim = Eip1559Request.parse(json).hostSimulation;
        assertNotNull(sim);
        assertEquals(3, sim.changes.size());
        assertEquals(new BigInteger("-1000000"), sim.changes.get(0).delta);
        assertEquals(Integer.valueOf(6), sim.changes.get(0).decimals);
        assertTrue(sim.changes.get(1).nativeCoin());
        assertEquals(BigInteger.valueOf(42), sim.changes.get(2).tokenId);
        assertEquals("ethereum-rpc.publicnode.com", sim.node);
        assertEquals(BigInteger.valueOf(0x18f603bL), sim.block);
        // an empty change list is a valid claim ("nothing changes")
        assertTrue(Eip1559Request.parse(with(usdcTransfer(OTHER, E6), claim())).hostSimulation.changes.isEmpty());
    }

    @Test public void theClaimHasAnExactFieldSet() throws Exception {
        JSONObject base = usdcTransfer(OTHER, E6);
        refused(with(base, claim().put("extra", 1)), "unknown=[extra]");
        JSONObject noNode = claim(); noNode.remove("node");
        refused(with(base, noNode), "missing=[node]");
        JSONObject noBlock = claim(); noBlock.remove("block");
        refused(with(base, noBlock), "missing=[block]");
        refused(with(base, claim(change(USDC, "-1").put("note", "x"))), "unknown=[note]");
        refused(with(base, claim(new JSONObject().put("asset", USDC))), "missing=[delta]");
        refused(with(base, claim(new JSONObject().put("delta", "-1"))), "missing=[asset]");
        refused(new JSONObject(base.toString()).put("hostSimulation", "{}"), "must be an object");
        refused(new JSONObject(base.toString()).put("hostSimulation", new JSONObject().put("changes", "x").put("node", "a").put("block", "0x1")), "must be an array");
        // the transaction's own fields stay exact: hostSimulation does not open the schema to anything else
        refused(with(base, claim()).put("simulation", 1), "unknown=[simulation]");
    }

    @Test public void numbersAndStringsAreCanonicalAndBounded() throws Exception {
        JSONObject base = usdcTransfer(OTHER, E6);
        for (String bad : new String[]{"0", "-0", "+5", "05", "-05", "1.5", "1e6", " 1", "0x10", ""}) {
            refused(with(base, claim(change(USDC, bad))), "delta");
        }
        refused(with(base, claim(change(USDC, "1" + "0".repeat(78)))), "delta"); // 79 digits
        refused(with(base, claim(change(USDC, BigInteger.ONE.shiftLeft(256).toString()))), "256 bits");
        refused(with(base, claim(new JSONObject().put("asset", USDC).put("delta", -5))), "must be a string");
        refused(with(base, claim(change("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "-1"))), "lower-case");
        refused(with(base, claim(change("ETH", "-1"))), "lower-case");
        refused(with(base, claim(change("0x0000000000000000000000000000000000000000", "-1"))), "zero address");
        refused(with(base, claim(change("native", "-1").put("tokenId", "1"))), "no tokenId");
        refused(with(base, claim(change(UNKNOWN, "1").put("tokenId", "01"))), "tokenId");
        refused(with(base, claim(change(UNKNOWN, "1").put("tokenId", "1").put("decimals", 0))), "no decimals");
        refused(with(base, claim(change(USDC, "-1").put("decimals", 6.5))), "integer");
        refused(with(base, claim(change(USDC, "-1").put("decimals", "6"))), "integer");
        refused(with(base, claim(change(USDC, "-1").put("decimals", 37))), "decimals out of range");
        refused(with(base, claim(change(USDC, "-1").put("decimals", -1))), "decimals out of range");
        refused(with(base, claim(change(USDC, "-1").put("symbol", "US DC"))), "symbol");
        refused(with(base, claim(change(USDC, "-1").put("symbol", "ABCDEFGHIJKLMNOPQ"))), "symbol");
        refused(with(base, claim(change(USDC, "-1").put("symbol", ""))), "symbol");
        refused(with(base, claim().put("node", "https://ethereum-rpc.publicnode.com/")), "host name");
        refused(with(base, claim().put("node", "a".repeat(101))), "host name");
        refused(with(base, claim().put("node", "")), "host name");
        refused(with(base, claim().put("block", "0x01")), "Non-canonical");
        refused(with(base, claim().put("block", 26173499)), "must be a string");
        refused(with(base, claim().put("block", "0x8000000000000000")), "block out of range");
    }

    @Test public void sizeIsLimitedAndAssetsAreUnique() throws Exception {
        JSONObject base = usdcTransfer(OTHER, E6);
        JSONObject[] many = new JSONObject[HostSimulation.MAX_CHANGES + 1];
        for (int i = 0; i < many.length; i++) many[i] = change(UNKNOWN, "1").put("tokenId", String.valueOf(i));
        refused(with(base, claim(many)), "more than 16");
        assertEquals(16, Eip1559Request.parse(with(base, claim(Arrays.copyOf(many, 16)))).hostSimulation.changes.size());
        refused(with(base, claim(change(USDC, "-1"), change(USDC, "-2"))), "twice");
        refused(with(base, claim(change("native", "-1"), change("native", "-2"))), "twice");
        // the same contract with different token IDs is fine; with the same ID it is not
        refused(with(base, claim(change(UNKNOWN, "1").put("tokenId", "7"), change(UNKNOWN, "-1").put("tokenId", "7"))), "twice");
    }

    @Test public void messageRequestsDoNotTakeTheField() throws Exception {
        JSONObject msg = new JSONObject().put("id", "m-1").put("method", "personal_sign").put("chainId", "0x1")
                .put("message", "0x68656c6c6f").put("hostSimulation", claim());
        try {
            MessageRequest.parse(msg);
            fail("a message request accepted hostSimulation");
        } catch (JSONException expected) {
            assertTrue(expected.getMessage().contains("unknown=[hostSimulation]"));
        }
    }

    @Test public void theClaimIsNeverSigned() throws Exception {
        // same transaction, with a claim (even a lying one) and without: byte-identical signature and hash
        JSONObject plain = usdcTransfer(OTHER, BigInteger.valueOf(100).multiply(E6));
        JSONObject lying = with(plain, claim(token(USDC, "100000000", "USDC", 6), change("native", "5000000000000000000")));
        JSONObject a = session(plain).signIfIdentityUnchanged(KEY);
        JSONObject b = session(lying).signIfIdentityUnchanged(KEY);
        assertEquals(a.getString("signedTransaction"), b.getString("signedTransaction"));
        assertEquals(a.getString("transactionHash"), b.getString("transactionHash"));
        // and the phone's own review is identical too: the claim only adds the separate box
        assertEquals(session(plain).review.text(), session(lying).review.text());
        assertTrue(session(lying).hostSimulation.contradicts);
    }

    @Test public void theSharedVectorFromTheMacParsesAndMatches() throws Exception {
        // produced by the companion (sim.rs) from a recorded eth_simulateV1 answer; asserted there byte for byte
        String text;
        try (java.io.InputStream in = HostSimulationTest.class.getClassLoader().getResourceAsStream("host-simulation-vector.json")) {
            text = new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        }
        JSONObject vector = new JSONObject(text);
        JSONObject r = vector.getJSONObject("request");
        JSONObject json = new JSONObject().put("id", "vec-1").put("method", "signEip1559").put("chainId", r.getString("chainId")).put("nonce", "0x0")
                .put("maxPriorityFeePerGas", r.getString("maxPriorityFeePerGas")).put("maxFeePerGas", r.getString("maxFeePerGas"))
                .put("gasLimit", r.getString("gasLimit")).put("to", r.getString("to")).put("value", r.getString("value")).put("data", r.getString("data"))
                .put("hostSimulation", vector.getJSONObject("hostSimulation"));
        // through the real USB parser, as the companion's request line arrives
        SimulationCheck.Result s = session(AccessoryTransport.parseStrictRequest(json.toString())).hostSimulation;
        assertFalse(s.text(), s.contradicts);
        assertEquals("−0.00006611246757516 ETH\n−100 USDC", value(s, "The Mac says your balance changes by"));
    }

    // ------------------------------------------------------------------ contradictions: token transfers

    @Test public void anHonestTokenTransferClaimMatches() throws Exception {
        SimulationCheck.Result r = check(usdcTransfer(OTHER, BigInteger.valueOf(100).multiply(E6)),
                token(USDC, "-100000000", "USDC", 6), change("native", "-1300000000000"));
        assertFalse(r.text(), r.contradicts);
        assertTrue(r.unexplained.isEmpty());
        assertEquals("−100 USDC\n−0.0000013 ETH", value(r, "The Mac says your balance changes by"));
        assertTrue(value(r, "Simulated by the Mac").contains("ethereum-rpc.publicnode.com at block 26173499"));
        assertTrue(value(r, "Simulated by the Mac").contains("cannot check"));
        assertNull(value(r, MessageReview.DANGER));
        assertEquals(SimulationCheck.BOX_TITLE, r.title);
        assertTrue(r.title.contains("NOT VERIFIED BY THIS PHONE"));
    }

    @Test public void aClaimThatHidesTheTransferContradicts() throws Exception {
        JSONObject req = usdcTransfer(OTHER, BigInteger.valueOf(100).multiply(E6));
        // the Mac says the USDC stays (no change at all)
        SimulationCheck.Result none = check(req, change("native", "-1300000000000"));
        assertTrue(none.contradicts);
        assertTrue(value(none, MessageReview.DANGER).startsWith(SimulationCheck.MISMATCH));
        assertTrue(value(none, MessageReview.DANGER), value(none, MessageReview.DANGER).contains("For USDC the phone decoded −100 USDC; the Mac claims no change."));
        // a smaller amount
        assertTrue(check(req, token(USDC, "-1000000", "USDC", 6)).contradicts);
        // a gain instead of a loss
        assertTrue(check(req, token(USDC, "100000000", "USDC", 6)).contradicts);
        // rounding of a rebasing token is tolerated (2 base units), more is not
        assertFalse(check(req, token(USDC, "-99999998", "USDC", 6)).contradicts);
        assertTrue(check(req, token(USDC, "-99999997", "USDC", 6)).contradicts);
    }

    @Test public void aClaimOfGainsWhereThePhoneSeesOnlyOutflowContradicts() throws Exception {
        JSONObject req = usdcTransfer(OTHER, BigInteger.valueOf(100).multiply(E6));
        SimulationCheck.Result r = check(req, token(USDC, "-100000000", "USDC", 6), token(WETH, "31200000000000000", "WETH", 18));
        assertTrue(r.contradicts);
        assertTrue(value(r, MessageReview.DANGER), value(r, MessageReview.DANGER).contains("The Mac claims you gain 0.0312 WETH"));
        // a native gain on a token transfer, too
        assertTrue(check(req, token(USDC, "-100000000", "USDC", 6), change("native", "1000")).contradicts);
    }

    @Test public void aDifferentTokenOrLabelContradicts() throws Exception {
        JSONObject req = usdcTransfer(OTHER, BigInteger.valueOf(100).multiply(E6));
        // the Mac moves DAI instead of USDC: USDC missing (contradiction) and DAI unexplained
        SimulationCheck.Result r = check(req, token(DAI, "-100000000000000000000", "DAI", 18));
        assertTrue(r.contradicts);
        assertEquals(1, r.unexplained.size());
        // the Mac labels the phone's USDC contract "DAI", or with other decimals
        assertTrue(check(req, token(USDC, "-100000000", "DAI", 6)).contradicts);
        assertTrue(check(req, token(USDC, "-100000000", "USDC", 18)).contradicts);
        // the native coin under another name
        assertTrue(check(req, token(USDC, "-100000000", "USDC", 6), change("native", "-1").put("symbol", "POL")).contradicts);
    }

    @Test public void anExtraOutflowIsFlaggedButIsNotAContradiction() throws Exception {
        SimulationCheck.Result r = check(usdcTransfer(OTHER, BigInteger.valueOf(100).multiply(E6)),
                token(USDC, "-100000000", "USDC", 6), token(DAI, "-5000000000000000000", "DAI", 18));
        assertFalse(r.contradicts);
        assertEquals(Collections.singletonList("−5 DAI"), r.unexplained);
        assertTrue(value(r, MessageReview.WARNING).contains("does not explain"));
    }

    @Test public void aTransferToYourselfChangesNothing() throws Exception {
        JSONObject req = usdcTransfer(ME, BigInteger.valueOf(100).multiply(E6));
        assertFalse(check(req, change("native", "-1")).contradicts);
        assertTrue(check(req, token(USDC, "-100000000", "USDC", 6)).contradicts);
    }

    @Test public void unknownTokensUseTheMacsLabelOnlyInQuotes() throws Exception {
        JSONObject req = request("0x1", UNKNOWN, "0x0", Erc20ReviewTest.transfer(OTHER, BigInteger.valueOf(500)));
        SimulationCheck.Result r = check(req, token(UNKNOWN, "-500", "USDC", 6));
        assertFalse(r.contradicts);
        assertEquals("−500 base units of unknown token 0x2222222222222222222222222222222222222222 (the Mac calls it \"USDC\", 6 decimals; unverified)",
                value(r, "The Mac says your balance changes by"));
    }

    // ------------------------------------------------------------------ native coin and the fee

    @Test public void theNativeChangeIsBoundedByTheFeeOnEthereum() throws Exception {
        JSONObject req = request("0x1", OTHER, "0x6f05b59d3b20000", "0x"); // 0.5 ETH
        BigInteger half = new BigInteger("500000000000000000");
        assertFalse(check(req, change("native", half.add(BigInteger.valueOf(42_000_000_000_000L)).negate().toString())).contradicts);
        assertFalse(check(req, change("native", half.add(MAX_FEE).negate().toString())).contradicts);
        // more than value + maximum fee: impossible for this transaction
        assertTrue(check(req, change("native", half.add(MAX_FEE).add(BigInteger.valueOf(3)).negate().toString())).contradicts);
        // less than the value: the Mac understates what leaves
        SimulationCheck.Result under = check(req, change("native", "-1000"));
        assertTrue(under.contradicts);
        assertTrue(value(under, MessageReview.DANGER), value(under, MessageReview.DANGER).contains("For ETH the phone decoded −0.5 ETH to −0.50013 ETH (with the maximum network fee)"));
        // nothing at all
        assertTrue(check(req).contradicts);
    }

    @Test public void rollupsHaveNoOfflineLowerBound() throws Exception {
        JSONObject req = request("0x2105", OTHER, "0x6f05b59d3b20000", "0x"); // Base: L1 data fee is unbounded offline
        assertFalse(check(req, change("native", "-600000000000000000")).contradicts);
        assertTrue(check(req, change("native", "-400000000000000000")).contradicts);
    }

    @Test public void nativeToAListedTokenContractMayComeBackAsThatToken() throws Exception {
        // WETH deposit by plain transfer: ETH out, WETH in
        JSONObject req = request("0x1", WETH, "0x6f05b59d3b20000", "0x");
        SimulationCheck.Result r = check(req, change("native", "-500000000000000000"), token(WETH, "500000000000000000", "WETH", 18));
        assertFalse(r.text(), r.contradicts);
        // but not as some other token
        assertTrue(check(req, change("native", "-500000000000000000"), token(USDC, "1000000", "USDC", 6)).contradicts);
    }

    // ------------------------------------------------------------------ approvals

    @Test public void anApprovalMovesNothing() throws Exception {
        JSONObject unlimited = request("0x1", USDC, "0x0", Erc20ReviewTest.approve(SPENDER, BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE)));
        assertFalse(check(unlimited, change("native", "-900000000000")).contradicts);
        assertFalse(check(unlimited).contradicts);
        SimulationCheck.Result r = check(unlimited, token(USDC, "-100000000", "USDC", 6));
        assertTrue(r.contradicts);
        assertTrue(value(r, MessageReview.DANGER).contains("For USDC the phone decoded no change; the Mac claims −100 USDC."));
        assertTrue(check(unlimited, token(USDC, "5", "USDC", 6)).contradicts);
        assertTrue(check(request("0x1", USDC, "0x0", Erc20ReviewTest.increase(SPENDER, E6)), token(DAI, "1", "DAI", 18)).contradicts);
    }

    @Test public void anUnknownContractsApproveOrTransferFromMayBeEitherStandard() throws Exception {
        // transferFrom(OTHER → me, 7) on an unlisted contract: 7 base units, or NFT #7
        JSONObject req = request("0x1", UNKNOWN, "0x0", Erc20ReviewTest.transferFrom(OTHER, ME, BigInteger.valueOf(7)));
        assertFalse(check(req, change(UNKNOWN, "7")).contradicts);
        assertFalse(check(req, change(UNKNOWN, "1").put("tokenId", "7")).contradicts);
        assertTrue(check(req, change(UNKNOWN, "100")).contradicts);
        assertTrue(check(req, change(UNKNOWN, "-1").put("tokenId", "7")).contradicts);
    }

    // ------------------------------------------------------------------ NFTs

    @Test public void nftTransfersMatchByTokenId() throws Exception {
        String data = Calldata.call("42842e0e", Calldata.a(ME), Calldata.a(OTHER), Calldata.u(1));
        JSONObject req = request("0x1", UNKNOWN, "0x0", data);
        assertFalse(check(req, change(UNKNOWN, "-1").put("tokenId", "1"), change("native", "-1")).contradicts);
        assertTrue(check(req, change(UNKNOWN, "1").put("tokenId", "1")).contradicts);
        assertTrue("the NFT must leave", check(req).contradicts);
        assertTrue("another token ID", check(req, change(UNKNOWN, "-1").put("tokenId", "2")).contradicts);
        // setApprovalForAll moves nothing
        String approveAll = Calldata.call("a22cb465", Calldata.a(SPENDER), new org.web3j.abi.datatypes.Bool(true));
        assertFalse(check(request("0x1", UNKNOWN, "0x0", approveAll)).contradicts);
        assertTrue(check(request("0x1", UNKNOWN, "0x0", approveAll), change(UNKNOWN, "-1").put("tokenId", "3")).unexplained.size() == 1);
    }

    // ------------------------------------------------------------------ swaps

    @Test public void swapClaimsAreCheckedAgainstTheDecodedMinimums() throws Exception {
        // 100 USDC → at least 0.0312 ETH, through the Universal Router
        BigInteger min = new BigInteger("31200000000000000");
        String data = Calldata.execute(SwapReviewTest.cmds(0x00, 0x0c), Arrays.asList(
                Calldata.v3Swap(Calldata.ADDRESS_THIS, BigInteger.valueOf(100).multiply(E6), min, Calldata.v3Path(USDC, 500, WETH), true),
                Calldata.unwrap(Calldata.MSG_SENDER, min)), BigInteger.valueOf(SwapReviewTest.DEADLINE));
        JSONObject req = request("0x1", SwapReviewTest.UR_ETH, "0x0", data);
        // honest: −100 USDC, +0.0315 ETH less the fee
        SimulationCheck.Result ok = check(req, token(USDC, "-100000000", "USDC", 6), change("native", "31400000000000000"));
        assertFalse(ok.text(), ok.contradicts);
        assertEquals("−100 USDC\n+0.0314 ETH", value(ok, "The Mac says your balance changes by"));
        // below the decoded minimum (more than the fee can explain)
        assertTrue(check(req, token(USDC, "-100000000", "USDC", 6), change("native", "1000")).contradicts);
        // gives more USDC than the decoded exact input
        assertTrue(check(req, token(USDC, "-200000000", "USDC", 6), change("native", "31400000000000000")).contradicts);
        // a gain of a token the route never pays out
        assertTrue(check(req, token(USDC, "-100000000", "USDC", 6), change("native", "31400000000000000"), token(DAI, "1", "DAI", 18)).contradicts);
        // the Mac claims nothing leaves
        assertTrue(check(req, change("native", "31400000000000000")).contradicts);
    }

    @Test public void ethInSwapsCountTheValue() throws Exception {
        String data = Calldata.execute(SwapReviewTest.cmds(0x0b, 0x00), Arrays.asList(
                Calldata.wrap(Calldata.ADDRESS_THIS, Calldata.CONTRACT_BALANCE),
                Calldata.v3Swap(Calldata.MSG_SENDER, Calldata.CONTRACT_BALANCE, BigInteger.valueOf(2500).multiply(E6), Calldata.v3Path(WETH, 500, USDC), false)),
                BigInteger.valueOf(SwapReviewTest.DEADLINE));
        JSONObject req = request("0x1", SwapReviewTest.UR_ETH, "0xde0b6b3a7640000", data);
        assertFalse(check(req, change("native", "-1000100000000000000"), token(USDC, "2600000000", "USDC", 6)).contradicts);
        assertTrue("fewer USDC than the minimum", check(req, change("native", "-1000100000000000000"), token(USDC, "2400000000", "USDC", 6)).contradicts);
        assertTrue("the ETH stays", check(req, change("native", "-100000000000000"), token(USDC, "2600000000", "USDC", 6)).contradicts);
    }

    private static String value(SimulationCheck.Result r, String label) {
        for (MessageReview.Row row : r.rows) if (row.label.equals(label)) return row.value;
        return null;
    }
}
