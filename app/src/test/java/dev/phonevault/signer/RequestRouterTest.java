package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.json.JSONObject;
import org.junit.Test;
import org.web3j.crypto.Credentials;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.function.Supplier;

/**
 * RequestRouter's decisions: what a LOCKED phone shows for a held request (and that it decodes
 * only), when an unlocked phone refuses a request as not ready, and that getAddress answers only
 * the active account. Plus the call-site guards for the parts that need the phone (USB threads).
 */
public final class RequestRouterTest {
    private static final String UNDECODABLE =
            "Your Mac sent a request this phone cannot decode. It will be refused after you unlock.";
    private static final Supplier<TokenList> NO_TOKENS = () -> TokenList.unavailable("test");

    private static JSONObject tx() throws Exception {
        return new JSONObject().put("id", "t1").put("method", "signEip1559").put("chainId", "0x1").put("nonce", "0x0")
                .put("maxPriorityFeePerGas", "0x1").put("maxFeePerGas", "0x2").put("gasLimit", "0x5208")
                .put("to", "0x1111111111111111111111111111111111111111").put("value", "0x0").put("data", "0x");
    }

    @Test public void lockedGateDescribesHeldRequests() throws Exception {
        JSONObject getAddress = new JSONObject().put("id", "a-1").put("method", "getAddress");
        assertEquals("Your Mac asks for your receiving address. Unlock to continue.",
                RequestRouter.lockedSummary(getAddress, NO_TOKENS));
        assertEquals("exact schema even for display", UNDECODABLE,
                RequestRouter.lockedSummary(new JSONObject(getAddress.toString()).put("chainId", "0x1"), NO_TOKENS));

        JSONObject attest = new JSONObject().put("id", "a-2").put("method", "attest").put("challenge", "ab".repeat(32));
        assertEquals("Your Mac asks this phone to prove it is genuine Phone Vault hardware and firmware. Unlock to continue.",
                RequestRouter.lockedSummary(attest, NO_TOKENS));
        assertEquals(UNDECODABLE, RequestRouter.lockedSummary(attest.put("challenge", "zz"), NO_TOKENS));

        TokenList tokens = NO_TOKENS.get();
        assertEquals(TransactionReview.build(Eip1559Request.parse(tx()), null, tokens).lockedSummary,
                RequestRouter.lockedSummary(tx(), () -> tokens));
        String refused = RequestRouter.lockedSummary(tx().put("type", "0x4"), NO_TOKENS);
        assertTrue("a refusal by name says so: " + refused, refused.startsWith(RequestRefusal.DELEGATION)
                && refused.endsWith(" It will be refused after you unlock."));
        assertEquals(UNDECODABLE, RequestRouter.lockedSummary(new JSONObject().put("id", "x").put("method", "nope"), NO_TOKENS));
        assertEquals(UNDECODABLE, RequestRouter.lockedSummary(new JSONObject(), NO_TOKENS));

        int[] loads = {0};
        RequestRouter.lockedSummary(getAddress, () -> { loads[0]++; return NO_TOKENS.get(); });
        assertEquals("the token list is read only for a transaction", 0, loads[0]);
    }

    @Test public void unlockedPhoneRefusesUntilTheWalletIsReady() {
        assertNull(RequestRouter.notReady(true, true, true, true, false, false, false, true));
        boolean[][] notReady = {
                {false, true, true, true, false, false},  // not operational
                {true, false, true, true, false, false},  // locked
                {true, true, false, true, false, false},  // no wallet loaded
                {true, true, true, false, false, false},  // backup not checked
                {true, true, true, true, true, false},    // a sensitive flow has the screen
                {true, true, true, true, false, true},    // a replacement is in progress
        };
        for (boolean[] c : notReady) {
            assertEquals(RequestRouter.NOT_READY, RequestRouter.notReady(c[0], c[1], c[2], c[3], c[4], c[5], false, true));
            assertEquals("the first reason wins", RequestRouter.NOT_READY, RequestRouter.notReady(c[0], c[1], c[2], c[3], c[4], c[5], true, false));
        }
        assertEquals(RequestRouter.CHOOSE_ACCOUNT, RequestRouter.notReady(true, true, true, true, false, false, true, true));
        assertEquals(RequestRouter.CHOOSE_ACCOUNT, RequestRouter.notReady(true, true, true, true, false, false, false, false));
        assertEquals("Wallet is not ready: unlock and complete the backup check first", RequestRouter.NOT_READY);
        assertEquals("Wallet is not ready: finish choosing the account on the phone, then try again", RequestRouter.CHOOSE_ACCOUNT);
    }

    @Test public void getAddressAnswersTheActiveAccountOnly() throws Exception {
        Credentials key = TestKeys.EVM_KEY;
        SigningAccount active = new SigningAccount(2, "Savings", false, null, key.getAddress());
        JSONObject r = RequestRouter.addressAnswer("a-1", key, active);
        Set<String> keys = new HashSet<>();
        for (Iterator<String> it = r.keys(); it.hasNext(); ) keys.add(it.next());
        assertEquals("no label, no fingerprint, no passphrase", Set.of("id", "status", "address", "account", "wallet"), keys);
        assertEquals("ok", r.getString("status"));
        assertEquals(key.getAddress(), r.getString("address"));
        assertEquals("3", r.getString("account"));
        assertEquals("standard", r.getString("wallet"));
        assertEquals("passphrase", RequestRouter.addressAnswer("a-2", key,
                new SigningAccount(0, "Account 1", true, "abcd1234", key.getAddress())).getString("wallet"));

        SigningAccount other = new SigningAccount(0, "Account 1", false, null, "0x2222222222222222222222222222222222222222");
        for (Object[] c : new Object[][] {{null, active}, {key, null}, {key, other}}) {
            try {
                RequestRouter.addressAnswer("a-3", (Credentials) c[0], (SigningAccount) c[1]);
                fail("answered with a key that is not the active account's");
            } catch (IllegalStateException expected) {
                assertEquals("Wallet is not ready: finish choosing the account on the phone", expected.getMessage());
            }
        }
    }

    /** The parts that need the phone: a locked phone holds and answers nothing; replies are sent under stateLock. */
    @Test public void routerCallSites() throws Exception {
        String route = SourceGuard.definition("\n    void onRequest(AccessoryTransport source, JSONObject json) {");
        assertTrue("only the live connection", route.startsWith("\n    void onRequest(AccessoryTransport source, JSONObject json) {\n        if (source != host.transport()) return;"));
        int gate = route.indexOf("if (!host.unlocked()) {");
        String locked = route.substring(gate, route.indexOf("return;", gate));
        assertTrue(locked.contains("synchronized (stateLock) { host.heldRequest().holdIfLocked(host.unlocked(), host.transport(), source, json, body); }"));
        assertEquals("a locked phone answers nothing", -1, locked.indexOf("send"));
        assertEquals("one hold site", 1, SourceGuard.count("\\.holdIfLocked\\("));
        assertTrue("readiness is checked under stateLock before any dispatch",
                route.indexOf("String refusal = notReady(") < route.indexOf("btc.handleBitcoin("));
        assertTrue(route.contains("source.send(addressAnswer(id, host.signingKey(), host.activeAccount()));"));
        assertTrue("getAddress re-checks the session under stateLock",
                route.contains("if (s != host.session() || source != host.transport() || !host.unlocked() || !host.backupVerified() || host.sensitiveActive()) return;"));
        assertTrue(route.contains("final ApprovalDecision decision = host.claimApproval(source, id);"));
        assertTrue("MainActivity delegates", SourceGuard.mainActivity()
                .contains("@Override public void onRequest(AccessoryTransport source, JSONObject json) { router.onRequest(source, json); }"));
    }
}
