package dev.phonevault.signer;

import static dev.phonevault.signer.Calldata.a;
import static dev.phonevault.signer.Calldata.b;
import static dev.phonevault.signer.Calldata.u;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;
import org.web3j.abi.datatypes.Bool;
import org.web3j.abi.datatypes.DynamicArray;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Keys;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionDecoder;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.util.Arrays;

public final class NftReviewTest {
    private static final Credentials KEY = TestKeys.EVM_KEY;
    private static final String ME = KEY.getAddress();
    private static final String UNI_V3_POS = "0xC36442b4a4522E871399CD717aBDD847Ab11FE88"; // listed, Ethereum
    private static final String UNKNOWN_NFT = "0x5555555555555555555555555555555555555555";
    private static final String USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    private static final String OPERATOR = "0x3333333333333333333333333333333333333333";
    private static final String BOB = "0x1111111111111111111111111111111111111111";

    static String setApprovalForAll(String operator, boolean approved) { return Calldata.call("a22cb465", a(operator), new Bool(approved)); }
    static String safeTransfer721(String from, String to, long id) { return Calldata.call("42842e0e", a(from), a(to), u(id)); }
    static String safeTransfer721Data(String from, String to, long id, byte[] data) { return Calldata.call("b88d4fde", a(from), a(to), u(id), b(data)); }
    static String safeTransfer1155(String from, String to, long id, long amount, byte[] data) {
        return Calldata.call("f242432a", a(from), a(to), u(id), u(amount), b(data));
    }
    static String safeBatch1155(String from, String to, long[] ids, long[] amounts) {
        Uint256[] i = new Uint256[ids.length], m = new Uint256[amounts.length];
        for (int k = 0; k < ids.length; k++) i[k] = u(ids[k]);
        for (int k = 0; k < amounts.length; k++) m[k] = u(amounts[k]);
        return Calldata.call("2eb2c2d6", a(from), a(to), new DynamicArray<>(Uint256.class, Arrays.asList(i)),
                new DynamicArray<>(Uint256.class, Arrays.asList(m)), b(new byte[0]));
    }

    private static JSONObject request(String chain, String to, String data, String value) throws JSONException {
        return SwapReviewTest.request(chain, to, value, data);
    }

    private static TransactionReview review(String to, String data) throws Exception {
        return new ApprovalSession(Eip1559Request.parse(request("0x1", to, data, "0x0")), KEY, TokenListTest.bundled()).review;
    }

    private static String value(TransactionReview r, String label) { return SwapReviewTest.value(r, label); }

    @Test public void setApprovalForAllIsAFullScreenDanger() throws Exception {
        TransactionReview r = review(UNKNOWN_NFT, setApprovalForAll(OPERATOR, true));
        assertEquals("Permission for EVERY NFT", r.title);
        assertTrue(value(r, "DANGER").startsWith("Lets " + OPERATOR + " move EVERY NFT in this collection, now and in future"));
        assertEquals("Let " + OPERATOR + " move EVERY NFT in unknown collection " + UNKNOWN_NFT + ", now and in future", value(r, "Action"));
        assertEquals(OPERATOR, value(r, "Operator (gets permission)"));
        assertTrue(SwapReviewTest.has(r, "WARNING", "Unknown collection " + UNKNOWN_NFT));
        assertEquals("Approve ALL NFTs & sign", r.signLabel);
        assertEquals(1, r.parties.size());
        assertEquals(RecipientHistory.Role.APPROVE, r.parties.get(0).role);
        assertEquals("setApprovalForAll(address,bool) · selector 0xa22cb465", value(r, "Function"));
    }

    @Test public void revokeIsPlain() throws Exception {
        TransactionReview r = review(UNI_V3_POS, setApprovalForAll(OPERATOR, false));
        assertEquals("Revoke NFT permission", r.title);
        assertEquals("Revoke " + OPERATOR + "'s permission to move your NFTs in Uniswap V3 Positions", value(r, "Action"));
        assertEquals(0, SwapReviewTest.count(r, "DANGER"));
        assertEquals("Uniswap V3 Positions (ERC-721, from the list built into this phone)", value(r, "Collection"));
        assertTrue(r.parties.isEmpty());
    }

    @Test public void erc721SafeTransferWithAndWithoutData() throws Exception {
        TransactionReview r = review(UNI_V3_POS, safeTransfer721(ME, BOB, 4242));
        assertEquals("Send NFT #4242", r.title);
        assertEquals("Send NFT #4242 of Uniswap V3 Positions from " + Keys.toChecksumAddress(ME) + " to " + BOB, value(r, "Action"));
        assertEquals("#4242", value(r, "Token ID"));
        assertTrue(value(r, "From (current owner)").endsWith("(this wallet)"));
        assertEquals(0, SwapReviewTest.count(r, "WARNING"));
        assertEquals(RecipientHistory.Role.SEND, r.parties.get(0).role);

        TransactionReview d = review(UNI_V3_POS, safeTransfer721Data(ME, BOB, 7, new byte[] {1, 2, 3}));
        assertTrue(SwapReviewTest.has(d, "WARNING", "passes 3 bytes of data"));
        assertEquals("0x010203", value(d, "Data for the recipient"));

        TransactionReview notMine = review(UNI_V3_POS, safeTransfer721(OPERATOR, BOB, 1));
        assertTrue(SwapReviewTest.has(notMine, "WARNING", "not from this wallet"));
    }

    @Test public void erc1155SingleAndBatch() throws Exception {
        TransactionReview s = review(UNKNOWN_NFT, safeTransfer1155(ME, BOB, 9, 3, new byte[0]));
        assertEquals("Send 3 × NFT #9", s.title);
        assertEquals("3", value(s, "Amount"));
        TransactionReview b = review(UNKNOWN_NFT, safeBatch1155(ME, BOB, new long[] {1, 2, 3}, new long[] {10, 20, 30}));
        assertEquals("Send 3 NFT items", b.title);
        assertEquals("#2 × 20", value(b, "Item 2"));
        // mismatched lengths are refused
        try {
            Eip1559Request.parse(request("0x1", UNKNOWN_NFT, safeBatch1155(ME, BOB, new long[] {1, 2}, new long[] {1}), "0x0"));
            fail("accepted mismatched batch");
        } catch (JSONException expected) {
            assertTrue(expected.getMessage().contains("differ in length"));
        }
    }

    @Test public void approveAndTransferFromOnAListedCollectionAreNfts() throws Exception {
        TransactionReview approve = review(UNI_V3_POS, Erc20ReviewTest.approve(OPERATOR, BigInteger.valueOf(77)));
        assertEquals("Permission for NFT #77", approve.title);
        assertTrue(value(approve, "DANGER").contains("take NFT #77"));
        assertNull("never 'tokens' for an NFT collection", value(approve, "Allowance"));
        TransactionReview move = review(UNI_V3_POS, Erc20ReviewTest.transferFrom(ME, BOB, BigInteger.valueOf(77)));
        assertEquals("Move NFT #77", move.title);
        assertTrue(value(move, "Function").contains("ERC-721 meaning"));
    }

    @Test public void unknownContractApproveOrTransferFromShowsBothMeanings() throws Exception {
        TransactionReview approve = review(UNKNOWN_NFT, Erc20ReviewTest.approve(OPERATOR, BigInteger.valueOf(77)));
        assertTrue(SwapReviewTest.has(approve, "WARNING", "Two possible meanings"));
        assertTrue(SwapReviewTest.has(approve, "WARNING", "lets " + OPERATOR + " take NFT #77"));
        assertEquals("77 base units (raw uint256; symbol and decimals unknown)", value(approve, "Allowance"));
        TransactionReview move = review(UNKNOWN_NFT, Erc20ReviewTest.transferFrom(ME, BOB, BigInteger.valueOf(77)));
        assertTrue(SwapReviewTest.has(move, "WARNING", "moves NFT #77"));
        // a listed ERC-20 is never read as an NFT
        TransactionReview usdc = review(USDC, Erc20ReviewTest.approve(OPERATOR, BigInteger.valueOf(77)));
        assertTrue(!usdc.text().contains("Two possible meanings"));
    }

    @Test public void strictNftCalldata() {
        String ok = setApprovalForAll(OPERATOR, true);
        String two = ok.substring(0, ok.length() - 1) + "2";                         // bool = 2
        String dirty = "0xa22cb465" + "01" + ok.substring(12);                       // dirty address padding
        String[] bad = {two, dirty, ok + "00", ok.substring(0, ok.length() - 2), setApprovalForAll("0x0000000000000000000000000000000000000000", true),
                safeTransfer721(ME, "0x0000000000000000000000000000000000000000", 1)};
        for (String data : bad) {
            try {
                Eip1559Request.parse(request("0x1", UNKNOWN_NFT, data, "0x0"));
                fail("accepted " + data);
            } catch (JSONException expected) {
                // refused before any review
            }
        }
        try {
            Eip1559Request.parse(request("0x1", UNKNOWN_NFT, safeTransfer721(ME, BOB, 1), "0x1"));
            fail("accepted native value on an NFT call");
        } catch (JSONException expected) {
            assertTrue(expected.getMessage().contains("must not include native value"));
        }
    }

    @Test public void signedNftCallIsTheReviewedCall() throws Exception {
        String data = safeTransfer721(ME, BOB, 4242);
        ApprovalSession s = new ApprovalSession(Eip1559Request.parse(request("0x1", UNI_V3_POS, data, "0x0")), KEY, TokenListTest.bundled());
        RawTransaction decoded = TransactionDecoder.decode(s.signIfIdentityUnchanged(KEY).getString("signedTransaction"));
        assertEquals(Numeric.cleanHexPrefix(data), Numeric.cleanHexPrefix(decoded.getData()));
        NftCall again = NftCall.decode("0x" + Numeric.cleanHexPrefix(decoded.getData()));
        assertEquals(s.request.nftCall.party, again.party);
        assertEquals(s.request.nftCall.tokenIds, again.tokenIds);
    }

    @Test public void collectionListIsChecksummedAndAllowListed() {
        for (String[] e : NftCollections.ENTRIES) {
            assertEquals(e[1], Keys.toChecksumAddress(e[1]));
            assertTrue(Eip1559Request.supportedChain(Long.parseLong(e[0])));
            assertNotNull(NftCollections.lookup(Long.parseLong(e[0]), e[1].toLowerCase()));
        }
        assertNull(NftCollections.lookup(8453, UNI_V3_POS)); // Base has a different position manager
    }
}
