package dev.phonevault.signer;

import android.app.Activity;

import org.json.JSONObject;
import org.web3j.crypto.Credentials;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

/**
 * One USB request from the live connection, on the transport's reader thread (or the crypto
 * thread for a request held behind the lock): while LOCKED it is only decoded for the gate and
 * held (nothing is answered); unlocked it must find the wallet ready, then getAddress is answered
 * under stateLock, attestation runs on its own thread, Bitcoin goes to BtcScreens, and a signing
 * request takes the one approval slot and gets its review (ApprovalScreens). The connection
 * lifecycle (attach, disconnect, lock) stays in MainActivity. Decisions without Android state
 * are static and unit-tested (RequestRouterTest).
 */
final class RequestRouter {
    /** What the router borrows from MainActivity beyond {@link VaultHost}. */
    interface Host extends VaultHost {
        /** The request held behind the lock (guarded by stateLock). */
        HeldRequest heldRequest();
        /** UI thread: show a held request on the PIN gate, if the gate is up and {@code source} is still the live connection. */
        void showHeldOnGate(AccessoryTransport source, String label, String body);
        /** A passphrase is being typed or confirmed. */
        boolean passphraseEntry();
        SigningAccount activeAccount();
        /** Every account of the open wallet(s), address → name (AccountScreens). */
        Map<String, String> ownAccountNames();
    }

    static final String NOT_READY = "Wallet is not ready: unlock and complete the backup check first";
    static final String CHOOSE_ACCOUNT = "Wallet is not ready: finish choosing the account on the phone, then try again";
    /** The genuine check (USB "attest") is already running, or failed on this phone. */
    static final String GENUINE_CHECK_FAILED = "The genuine check could not finish. Unplug, reconnect and try again.";

    private final Host host;
    private final Activity activity;
    private final Pages pages;
    private final Object stateLock;
    private final ApprovalScreens approvals;
    private final BtcScreens btc;
    /**
     * Device attestation (USB "attest", AttestationKey) runs on its own thread so a StrongBox key
     * generation (seconds on the Titan M) never delays signing work on cryptoExecutor; one at a time.
     */
    private final ExecutorService attestExecutor = Executors.newSingleThreadExecutor();
    private final AtomicBoolean attesting = new AtomicBoolean(false);
    private final AttestationProtocol.ChallengeLog attestChallenges = new AttestationProtocol.ChallengeLog();
    private TokenList tokenList;

    RequestRouter(Host host, ApprovalScreens approvals, BtcScreens btc) {
        this.host = host;
        this.activity = host.activity();
        this.pages = host.pages();
        this.stateLock = host.stateLock();
        this.approvals = approvals;
        this.btc = btc;
    }

    /** onDestroy: no attestation runs after the activity is gone. */
    void shutdown() { attestExecutor.shutdownNow(); }

    /**
     * What the locked gate shows for a request it holds. Decoded for display only; a request this
     * phone cannot decode (or refuses by name) is described as such and refused after unlock.
     */
    static String lockedSummary(JSONObject json, Supplier<TokenList> tokens) {
        try {
            if ("getAddress".equals(json.optString("method"))) {
                Eip1559Request.requireExactFields(json, "id", "method");
                return "Your Mac asks for your receiving address. Unlock to continue.";
            } else if (AttestationProtocol.handles(json.optString("method"))) {
                // Held like getAddress: the answer names the wallet address, and nothing
                // leaves a locked phone (device-attestation.md, "Locked phone").
                AttestationProtocol.parseChallenge(json);
                return "Your Mac asks this phone to prove it is genuine Phone Vault hardware and firmware. Unlock to continue.";
            } else if (MessageRequest.handles(json.optString("method"))) {
                return MessageReview.lockedSummary(MessageRequest.parse(json));
            } else if (BtcRequest.handles(json.optString("method"))) {
                return BtcRequest.lockedSummary(json);
            } else {
                return TransactionReview.build(Eip1559Request.parse(json), null, tokens.get()).lockedSummary;
            }
        } catch (Exception e) {
            return e instanceof RequestRefusal ? e.getMessage() + " It will be refused after you unlock."
                    : "Your Mac sent a request this phone cannot decode. It will be refused after you unlock.";
        }
    }

    /**
     * Why an unlocked phone cannot take a request now (null: it can). Sensitive screens, an
     * unchecked backup, a wallet replacement and passphrase typing all exclude USB requests.
     */
    static String notReady(boolean operational, boolean unlocked, boolean walletLoaded, boolean backupVerified,
                           boolean sensitiveFlow, boolean replacing, boolean passphraseEntry, boolean hasActiveAccount) {
        if (!operational || !unlocked || !walletLoaded || !backupVerified || sensitiveFlow || replacing) return NOT_READY;
        if (passphraseEntry || !hasActiveAccount) return CHOOSE_ACCOUNT;
        return null;
    }

    /**
     * getAddress: the ACTIVE account, plus which one it is (1-based number, standard/passphrase)
     * so the companion can label its pairing. No label, no fingerprint, no passphrase. Refused
     * unless the key in memory is the active account's.
     */
    static JSONObject addressAnswer(String id, Credentials key, SigningAccount account) {
        if (key == null || account == null || !account.address.equalsIgnoreCase(key.getAddress())) {
            throw new IllegalStateException("Wallet is not ready: finish choosing the account on the phone");
        }
        return Pages.json("id", id, "status", "ok", "address", key.getAddress(),
                "account", account.accountNumber(), "wallet", account.walletKind());
    }

    void onRequest(AccessoryTransport source, JSONObject json) {
        if (source != host.transport()) return;
        if (!host.unlocked()) {
            // Gate mode: decode for the lock screen, hold, answer nothing.
            final String body = lockedSummary(json, this::tokens);
            synchronized (stateLock) { host.heldRequest().holdIfLocked(host.unlocked(), host.transport(), source, json, body); }
            activity.runOnUiThread(() -> host.showHeldOnGate(source, "INCOMING REQUEST", body));
            return;
        }
        String id = json.optString("id", "unknown");
        final int s = host.session();
        synchronized (stateLock) {
            String refusal = notReady(host.operational(), host.unlocked(), host.walletLoaded(), host.backupVerified(),
                    host.sensitiveActive(), host.replacement().active(), host.passphraseEntry(), host.activeAccount() != null);
            if (refusal != null) {
                host.sendError(source, id, refusal);
                return;
            }
        }
        if (BtcRequest.handles(json.optString("method"))) {
            btc.handleBitcoin(source, json, id, s);
            return;
        }
        if ("getAddress".equals(json.optString("method"))) {
            try {
                Eip1559Request.requireExactFields(json, "id", "method");
                id = Eip1559Request.validatedId(json.getString("id"));
                synchronized (stateLock) {
                    if (s != host.session() || source != host.transport() || !host.unlocked() || !host.backupVerified() || host.sensitiveActive()) return;
                    source.send(addressAnswer(id, host.signingKey(), host.activeAccount()));
                }
            } catch (Exception e) { host.sendError(source, id, e.getMessage()); }
            return;
        }
        if (AttestationProtocol.handles(json.optString("method"))) {
            answerAttestation(source, json, id, s);
            return;
        }
        final ApprovalDecision decision = host.claimApproval(source, id);
        if (decision == null) return;
        try {
            // The ACTIVE account signs: key and its description are read together.
            final Credentials signer;
            final SigningAccount account;
            synchronized (stateLock) { signer = host.signingKey(); account = host.activeAccount(); }
            if (signer == null || account == null || !account.address.equalsIgnoreCase(signer.getAddress())) {
                throw new IllegalStateException("Wallet is not ready: finish choosing the account on the phone");
            }
            if (MessageRequest.handles(json.optString("method"))) {
                // Parsed once: the review and the digest both come from this object.
                MessageRequest message = MessageRequest.parse(json);
                RequestRefusal.requireFrom(message.from, account.headline(), account.address);
                MessageApprovalSession approval = new MessageApprovalSession(message, signer, account);
                activity.runOnUiThread(() -> approvals.showMessageApproval(source, approval, decision, s));
                return;
            }
            Eip1559Request request = Eip1559Request.parse(json);
            RequestRefusal.requireFrom(request.from, account.headline(), account.address);
            AddressSafety safety = host.safety();
            safety.setOwnAccounts(host.ownAccountNames());
            ApprovalSession approval = new ApprovalSession(request, signer, tokens(), safety, account);
            activity.runOnUiThread(() -> approvals.showApproval(source, approval, decision, s));
        } catch (Exception e) {
            host.finishApproval(decision);
            host.sendError(source, id, e.getMessage());
            if (e instanceof RequestRefusal) {
                RequestRefusal refusal = (RequestRefusal) e;
                activity.runOnUiThread(() -> {
                    if (s != host.session() || !host.unlocked() || source != host.transport() || host.sensitiveActive() || host.approvalDecision() != null) return;
                    pages.showInfo(refusal.title, refusal.getMessage(), host::showHome);
                    Haptics.reject(activity.getWindow().getDecorView());
                });
            }
        }
    }

    /**
     * USB "attest": a fresh StrongBox key attests the host's challenge and signs the binding of
     * that challenge to this wallet's address (AttestationProtocol). No review screen: it signs
     * nothing with the wallet key and reveals nothing beyond the address getAddress already gives
     * an unlocked phone. Runs off the signing thread; one at a time; a challenge is answered once.
     */
    private void answerAttestation(AccessoryTransport source, JSONObject json, String fallbackId, int s) {
        final String id;
        final byte[] challenge;
        try {
            challenge = AttestationProtocol.parseChallenge(json);
            id = json.getString("id");
        } catch (Exception e) { host.sendError(source, fallbackId, e.getMessage()); return; }
        if (!attestChallenges.firstUse(challenge)) { host.sendError(source, id, "This challenge was already answered"); return; }
        if (!attesting.compareAndSet(false, true)) { host.sendError(source, id, GENUINE_CHECK_FAILED); return; }
        final String address;
        synchronized (stateLock) {
            Credentials key = host.signingKey();
            if (s != host.session() || source != host.transport() || !host.unlocked() || !host.walletLoaded() || key == null) {
                attesting.set(false);
                host.sendError(source, id, NOT_READY);
                return;
            }
            address = key.getAddress();
        }
        try {
            attestExecutor.execute(() -> {
                try {
                    AttestationKey.Result r = AttestationKey.attest(challenge, address);
                    JSONObject reply = AttestationProtocol.response(id, address, r.securityLevel, r.chain, r.signature);
                    synchronized (stateLock) {
                        if (s != host.session() || source != host.transport() || !host.unlocked()) return;
                        source.send(reply);
                    }
                } catch (Exception e) {
                    android.util.Log.w("Vault", "genuine check failed: " + e.getClass().getSimpleName());
                    host.sendError(source, id, GENUINE_CHECK_FAILED);
                } finally {
                    attesting.set(false);
                }
            });
        } catch (RejectedExecutionException closing) {
            attesting.set(false);
        }
    }

    /**
     * The token list built into the APK, checked against its pinned SHA-256 on first use. A list
     * that fails the check is not used: every contract is then reviewed as unknown, and the review
     * says the list was refused.
     */
    private synchronized TokenList tokens() {
        if (tokenList != null) return tokenList;
        try (InputStream in = activity.getResources().openRawResource(R.raw.tokens)) {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            for (int n; (n = in.read(buffer)) > 0; ) {
                bytes.write(buffer, 0, n);
                if (bytes.size() > 64 * 1024) break; // loadPinned refuses oversize input
            }
            tokenList = TokenList.loadPinned(bytes.toByteArray());
        } catch (Exception e) {
            tokenList = TokenList.unavailable(e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
        }
        return tokenList;
    }
}
