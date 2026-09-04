package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.json.JSONObject;
import org.junit.Test;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.SignedRawTransaction;
import org.web3j.crypto.TransactionDecoder;
import org.web3j.crypto.transaction.type.Transaction1559;
import org.web3j.crypto.transaction.type.TransactionType;
import org.web3j.utils.Numeric;

public final class EvmSignerTest {
    private static final Credentials FIXED_TEST_KEY = Credentials.create(
            "4c0883a69102937d6231471b5dbb6204fe51296170827966f278a5e6f4f4f5f");
    private static final Credentials DIFFERENT_TEST_KEY = Credentials.create(
            "6c0883a69102937d6231471b5dbb6204fe51296170827966f278a5e6f4f4f5f");

    @Test public void parsesAndSignsCanonicalEip1559Request() throws Exception {
        Eip1559Request request = Eip1559Request.parse(new JSONObject()
                .put("id", "round-trip-1")
                .put("method", "signEip1559")
                .put("chainId", "0xaa36a7")
                .put("nonce", "0x0")
                .put("maxPriorityFeePerGas", "0x3b9aca00")
                .put("maxFeePerGas", "0x77359400")
                .put("gasLimit", "0x5208")
                .put("to", "0x1111111111111111111111111111111111111111")
                .put("value", "0x0")
                .put("data", "0x"));

        JSONObject response = EvmSigner.sign(request, FIXED_TEST_KEY);

        assertEquals("approved", response.getString("status"));
        assertEquals(FIXED_TEST_KEY.getAddress(), response.getString("address"));
        assertTrue("EIP-1559 payload must use typed transaction envelope 0x02",
                response.getString("signedTransaction").startsWith("0x02"));
        assertEquals(66, response.getString("transactionHash").length());

        RawTransaction decoded = TransactionDecoder.decode(response.getString("signedTransaction"));
        assertTrue(decoded instanceof SignedRawTransaction);
        assertEquals(TransactionType.EIP1559, decoded.getType());
        assertEquals(request.nonce, decoded.getNonce());
        assertEquals(request.gasLimit, decoded.getGasLimit());
        assertEquals(request.to, decoded.getTo());
        assertEquals(request.value, decoded.getValue());
        assertEquals(Numeric.cleanHexPrefix(request.data), Numeric.cleanHexPrefix(decoded.getData()));
        Transaction1559 typed = (Transaction1559) decoded.getTransaction();
        assertEquals(request.chainId, typed.getChainId());
        assertEquals(request.maxPriorityFeePerGas, typed.getMaxPriorityFeePerGas());
        assertEquals(request.maxFeePerGas, typed.getMaxFeePerGas());
        ((SignedRawTransaction) decoded).verify(FIXED_TEST_KEY.getAddress());
    }

    @Test(expected = org.json.JSONException.class)
    public void rejectsPriorityFeeAboveMaximumFee() throws Exception {
        Eip1559Request.parse(new JSONObject()
                .put("id", "bad-fee")
                .put("method", "signEip1559")
                .put("chainId", "0x1")
                .put("nonce", "0x0")
                .put("maxPriorityFeePerGas", "0x3")
                .put("maxFeePerGas", "0x2")
                .put("gasLimit", "0x5208")
                .put("to", "0x1111111111111111111111111111111111111111")
                .put("value", "0x0")
                .put("data", "0x"));
    }

    @Test(expected = org.json.JSONException.class)
    public void rejectsNonCanonicalQuantity() throws Exception {
        Eip1559Request.quantity("0x00");
    }

    @Test public void decodesSelectorShapedTransferWithoutAssumingInterface() throws Exception {
        Eip1559Request request = Eip1559Request.parse(baseRequest()
                .put("to", "0x2222222222222222222222222222222222222222")
                .put("data", "0xa9059cbb0000000000000000000000001111111111111111111111111111111111111111"
                        + "000000000000000000000000000000000000000000000000000000000000007b"));

        assertEquals(Eip1559Request.Kind.TOKEN_TRANSFER, request.kind);
        assertEquals("Token transfer (interface unverified)", request.transactionTypeLabel());
        assertEquals("0x1111111111111111111111111111111111111111", request.displayedRecipient);
        assertEquals("0x1111111111111111111111111111111111111111", request.displayedRecipientLabel());
        assertEquals("0x2222222222222222222222222222222222222222", request.contractLabel());
        assertEquals("123 raw uint256 argument (token decimals unverified)", request.displayedAmountLabel());
        assertEquals("Selector 0xa9059cbb: transfer(address,uint256); contract interface and semantics unverified",
                request.contractDataLabel());
        assertEquals("Warning", request.contractWarningTitle());
        assertTrue(request.contractWarningLabel().contains("cannot verify the contract interface"));
        assertTrue(request.contractWarningLabel().contains("execution semantics"));
        assertTrue(request.reviewPrompt().contains("decoded recipient and amount arguments"));
        assertSignedTransactionMatchesReviewedFields(request);
    }

    @Test public void decodesCanonicalTokenApprovalWithoutAssumingInterface() throws Exception {
        Eip1559Request request = Eip1559Request.parse(baseRequest()
                .put("to", "0x2222222222222222222222222222222222222222")
                .put("data", "0x095ea7b30000000000000000000000003333333333333333333333333333333333333333"
                        + "000000000000000000000000000000000000000000000000000000000000007b"));

        assertEquals(Eip1559Request.Kind.TOKEN_APPROVAL, request.kind);
        assertEquals("Token approval (interface unverified)", request.transactionTypeLabel());
        assertEquals("Spender / approved address", request.displayedPartyTitle());
        assertEquals("Allowance / token ID", request.displayedAmountTitle());
        assertEquals("0x3333333333333333333333333333333333333333", request.displayedRecipient);
        assertEquals("123 raw uint256 argument (token decimals unverified)", request.displayedAmountLabel());
        assertEquals("Selector 0x095ea7b3: approve(address,uint256); contract interface and semantics unverified",
                request.contractDataLabel());
        assertTrue(request.reviewPrompt().contains("approved-address"));
        assertTrue(request.reviewPrompt().contains("allowance/token-ID arguments"));
        assertEquals("DANGER", request.contractWarningTitle());
        assertTrue(request.contractWarningLabel().contains("approve(address,uint256)"));
        assertTrue(request.contractWarningLabel().contains("execution semantics"));
    }

    @Test public void labelsMaximumApprovalWithoutAssumingErc20Semantics() throws Exception {
        Eip1559Request request = Eip1559Request.parse(baseRequest()
                .put("data", "0x095ea7b30000000000000000000000003333333333333333333333333333333333333333"
                        + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

        assertEquals(Eip1559Request.Kind.TOKEN_APPROVAL, request.kind);
        assertEquals("MAXIMUM uint256 (commonly unlimited ERC-20 allowance)",
                request.displayedAmountLabel());
    }

    @Test public void displaysEveryFeeInputAndExactChainId() throws Exception {
        Eip1559Request request = Eip1559Request.parse(baseRequest());

        assertEquals("Sepolia Testnet (chain ID 11155111)", request.networkLabel());
        assertEquals("21000 gas (0x5208)", request.gasLimitLabel());
        assertEquals("2 gwei (2000000000 wei, 0x77359400)", request.maxFeePerGasLabel());
        assertEquals("1 gwei (1000000000 wei, 0x3b9aca00)", request.maxPriorityFeePerGasLabel());
        assertEquals("0.000042 native token (42000000000000 wei)", request.maximumFeeEth());
        assertTrue(request.reviewPrompt().contains("signing address"));
    }

    @Test public void approvalBindsReviewedSigningIdentity() throws Exception {
        Eip1559Request request = Eip1559Request.parse(baseRequest());
        ApprovalSession approval = new ApprovalSession(request, FIXED_TEST_KEY);

        assertEquals(org.web3j.crypto.Keys.toChecksumAddress(FIXED_TEST_KEY.getAddress()),
                approval.signerAddressLabel());
        JSONObject response = approval.signIfIdentityUnchanged(
                Credentials.create(FIXED_TEST_KEY.getEcKeyPair()));
        assertEquals(FIXED_TEST_KEY.getAddress(), response.getString("address"));

        try {
            approval.signIfIdentityUnchanged(DIFFERENT_TEST_KEY);
            fail("changed signing identity unexpectedly passed approval binding");
        } catch (IllegalStateException expected) {
            assertTrue(expected.getMessage().contains("changed after review"));
        }
    }

    @Test public void checksumsMixedAddressForHumanDisplayWithoutChangingSignedValue() throws Exception {
        Eip1559Request request = Eip1559Request.parse(baseRequest()
                .put("to", "0x52908400098527886e0f7030069857d2e4169ee7"));

        assertEquals("0x52908400098527886e0f7030069857d2e4169ee7", request.to);
        assertEquals("0x52908400098527886E0F7030069857D2E4169EE7", request.displayedRecipientLabel());
    }

    @Test(expected = org.json.JSONException.class)
    public void rejectsOpaqueContractCall() throws Exception {
        Eip1559Request.parse(baseRequest().put("data", "0x095ea7b3"));
    }

    @Test(expected = org.json.JSONException.class)
    public void rejectsSelectorShapedTransferWithNativeValue() throws Exception {
        Eip1559Request.parse(baseRequest()
                .put("value", "0x1")
                .put("data", "0xa9059cbb0000000000000000000000001111111111111111111111111111111111111111"
                        + "000000000000000000000000000000000000000000000000000000000000007b"));
    }

    @Test(expected = org.json.JSONException.class)
    public void rejectsSelectorShapedApprovalWithNativeValue() throws Exception {
        Eip1559Request.parse(baseRequest()
                .put("value", "0x1")
                .put("data", "0x095ea7b30000000000000000000000003333333333333333333333333333333333333333"
                        + "000000000000000000000000000000000000000000000000000000000000007b"));
    }

    @Test(expected = org.json.JSONException.class)
    public void rejectsSelectorShapedApprovalWithNonZeroAddressPadding() throws Exception {
        Eip1559Request.parse(baseRequest()
                .put("data", "0x095ea7b30100000000000000000000003333333333333333333333333333333333333333"
                        + "000000000000000000000000000000000000000000000000000000000000007b"));
    }

    @Test(expected = org.json.JSONException.class)
    public void rejectsZeroDestination() throws Exception {
        Eip1559Request.parse(baseRequest().put("to", "0x0000000000000000000000000000000000000000"));
    }

    @Test(expected = org.json.JSONException.class)
    public void rejectsUnknownTransactionField() throws Exception {
        Eip1559Request.parse(baseRequest().put("gasPrice", "0x1"));
    }

    @Test(expected = org.json.JSONException.class)
    public void rejectsMissingDataFieldInsteadOfAssumingSemantics() throws Exception {
        JSONObject request = baseRequest();
        request.remove("data");
        Eip1559Request.parse(request);
    }

    @Test(expected = org.json.JSONException.class)
    public void rejectsRequestIdWithControlCharacters() throws Exception {
        Eip1559Request.parse(baseRequest().put("id", "request\n2"));
    }

    private static void assertSignedTransactionMatchesReviewedFields(Eip1559Request request)
            throws Exception {
        JSONObject response = EvmSigner.sign(request, FIXED_TEST_KEY);
        RawTransaction decoded = TransactionDecoder.decode(response.getString("signedTransaction"));
        assertTrue(decoded instanceof SignedRawTransaction);
        assertEquals(TransactionType.EIP1559, decoded.getType());
        assertEquals(request.chainId, ((Transaction1559) decoded.getTransaction()).getChainId());
        assertEquals(request.nonce, decoded.getNonce());
        assertEquals(request.gasLimit, decoded.getGasLimit());
        assertEquals(request.to, decoded.getTo());
        assertEquals(request.value, decoded.getValue());
        assertEquals(Numeric.cleanHexPrefix(request.data), Numeric.cleanHexPrefix(decoded.getData()));
        ((SignedRawTransaction) decoded).verify(FIXED_TEST_KEY.getAddress());
    }

    private static JSONObject baseRequest() throws Exception {
        return new JSONObject()
                .put("id", "test")
                .put("method", "signEip1559")
                .put("chainId", "0xaa36a7")
                .put("nonce", "0x0")
                .put("maxPriorityFeePerGas", "0x3b9aca00")
                .put("maxFeePerGas", "0x77359400")
                .put("gasLimit", "0x5208")
                .put("to", "0x1111111111111111111111111111111111111111")
                .put("value", "0x0")
                .put("data", "0x");
    }
}
