package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;
import org.web3j.rlp.RlpEncoder;
import org.web3j.rlp.RlpList;
import org.web3j.rlp.RlpString;
import org.web3j.utils.Numeric;

import java.math.BigInteger;

/** EIP-7702 delegation is refused by name: type-4 requests, 0x05 authorization tuples, typed-data delegations. */
public final class Eip7702Test {
    private static final String DELEGATE = "0x63c0c19a282a1b52b07dd5a65b58948a07dae32b"; // e.g. a "smart account" implementation

    private static JSONObject tx() throws JSONException {
        return new JSONObject().put("id", "t7702").put("method", "signEip1559").put("chainId", "0x1").put("nonce", "0x0")
                .put("maxPriorityFeePerGas", "0x1").put("maxFeePerGas", "0x2").put("gasLimit", "0x5208")
                .put("to", "0x1111111111111111111111111111111111111111").put("value", "0x0").put("data", "0x");
    }

    private static void delegationRefused(JSONObject json, boolean message) {
        try {
            if (message) MessageRequest.parse(json);
            else Eip1559Request.parse(json);
            fail("accepted " + json);
        } catch (RequestRefusal r) {
            assertEquals(RequestRefusal.DELEGATION_TITLE, r.title);
            assertTrue(r.getMessage(), r.getMessage().startsWith("Account delegation (EIP-7702) is not supported: it can hand control of this wallet to a contract"));
        } catch (JSONException other) {
            throw new AssertionError("refused without the delegation message: " + other.getMessage());
        }
    }

    @Test public void typeFourTransactionsAreRefusedByName() throws Exception {
        delegationRefused(tx().put("type", "0x4"), false);
        delegationRefused(tx().put("authorizationList", "[]"), false);
        delegationRefused(tx().put("type", "0x4").put("authorizationList", "[{\"chainId\":\"0x1\"}]"), false);
        // any other extra field stays a schema error, and the plain request still works
        try {
            Eip1559Request.parse(tx().put("type", "0x2"));
            fail("accepted an unknown field");
        } catch (RequestRefusal r) {
            fail("type 0x2 is not a delegation");
        } catch (JSONException expected) {
            assertTrue(expected.getMessage().contains("unknown=[type]"));
        }
        assertEquals(Eip1559Request.Kind.NATIVE_TRANSFER, Eip1559Request.parse(tx()).kind);
    }

    @Test public void theSignerOnlyEverEncodesTypeTwo() throws Exception {
        org.web3j.crypto.Credentials key = org.web3j.crypto.Credentials.create("4c0883a69102937d6231471b5dbb6204fe51296170827966f278a5e6f4f4f5f");
        String signed = EvmSigner.sign(Eip1559Request.parse(tx()), key).getString("signedTransaction");
        assertTrue(signed.startsWith("0x02"));
    }

    static byte[] authorization(long chainId, String address, long nonce) {
        byte[] rlp = RlpEncoder.encode(new RlpList(RlpString.create(BigInteger.valueOf(chainId)),
                RlpString.create(Numeric.hexStringToByteArray(address)), RlpString.create(BigInteger.valueOf(nonce))));
        byte[] out = new byte[rlp.length + 1];
        out[0] = 0x05;
        System.arraycopy(rlp, 0, out, 1, rlp.length);
        return out;
    }

    @Test public void authorizationTuplesAreRecognized() {
        assertTrue(Eip7702.isAuthorizationTuple(authorization(1, DELEGATE, 0)));
        assertTrue(Eip7702.isAuthorizationTuple(authorization(0, DELEGATE, 123456789)));       // chain 0 = every chain
        assertTrue(Eip7702.isAuthorizationTuple(authorization(8453, DELEGATE, 7)));
        assertFalse(Eip7702.isAuthorizationTuple("hello".getBytes()));
        assertFalse(Eip7702.isAuthorizationTuple(new byte[] {0x05}));
        assertFalse(Eip7702.isAuthorizationTuple(new byte[] {0x05, 0x41, 0x42}));                   // 0x05 then text
        byte[] a = authorization(1, DELEGATE, 0);
        byte[] extra = java.util.Arrays.copyOf(a, a.length + 1);
        assertFalse("trailing byte", Eip7702.isAuthorizationTuple(extra));
        assertFalse("truncated", Eip7702.isAuthorizationTuple(java.util.Arrays.copyOf(a, a.length - 1)));
    }

    @Test public void personalSignOfAnAuthorizationIsRefused() throws Exception {
        delegationRefused(new JSONObject().put("id", "m").put("method", "personal_sign").put("chainId", "0x1")
                .put("message", Numeric.toHexString(authorization(1, DELEGATE, 0))), true);
        // an ordinary message is still accepted
        assertNotNull(MessageRequest.parse(new JSONObject().put("id", "m").put("method", "personal_sign").put("chainId", "0x1")
                .put("message", "0x48656c6c6f")));
    }

    private static String typed(String primary, String fields, String message) {
        return "{\"types\":{\"EIP712Domain\":[{\"name\":\"name\",\"type\":\"string\"},{\"name\":\"chainId\",\"type\":\"uint256\"}],"
                + "\"" + primary + "\":" + fields + "},\"primaryType\":\"" + primary + "\",\"domain\":{\"name\":\"Wallet\",\"chainId\":1},"
                + "\"message\":" + message + "}";
    }

    @Test public void typedDataDelegationsAreRefused() throws Exception {
        String authFields = "[{\"name\":\"chainId\",\"type\":\"uint256\"},{\"name\":\"address\",\"type\":\"address\"},{\"name\":\"nonce\",\"type\":\"uint256\"}]";
        String authMsg = "{\"chainId\":1,\"address\":\"" + DELEGATE + "\",\"nonce\":0}";
        for (String primary : new String[] {"Authorization", "SetCodeAuthorization", "Eip7702Authorization"}) {
            delegationRefused(new JSONObject().put("id", "t").put("method", "eth_signTypedData_v4").put("chainId", "0x1")
                    .put("typedData", typed(primary, authFields, authMsg)), true);
        }
        String delegationFields = "[{\"name\":\"delegate\",\"type\":\"address\"},{\"name\":\"delegator\",\"type\":\"address\"},{\"name\":\"salt\",\"type\":\"uint256\"}]";
        String delegationMsg = "{\"delegate\":\"" + DELEGATE + "\",\"delegator\":\"" + DELEGATE + "\",\"salt\":1}";
        delegationRefused(new JSONObject().put("id", "t").put("method", "eth_signTypedData_v4").put("chainId", "0x1")
                .put("typedData", typed("Delegation", delegationFields, delegationMsg)), true);
        // an "Authorization" without a nonce/address pair (e.g. a login) is ordinary typed data
        String loginFields = "[{\"name\":\"user\",\"type\":\"string\"}]";
        assertNotNull(MessageRequest.parse(new JSONObject().put("id", "t").put("method", "eth_signTypedData_v4").put("chainId", "0x1")
                .put("typedData", typed("Authorization", loginFields, "{\"user\":\"alice\"}"))));
    }
}
