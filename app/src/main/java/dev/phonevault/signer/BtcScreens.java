package dev.phonevault.signer;

import android.app.Activity;
import android.content.Context;
import android.util.Log;
import android.widget.LinearLayout;
import android.widget.TextView;

import org.json.JSONObject;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;

/**
 * Bitcoin over USB: btcGetAccount (share an account's watch-only key), btcShowAddress (compare an
 * address with the Mac), btcSignPsbt (review and sign), and ☰ → Bitcoin sharing.
 *
 * <p>Same BIP-39 seed and the same PIN window as the EVM accounts. The account public keys of one
 * network are derived on first use in an unlocked session (withSeedKey → VaultKeyStore.
 * withStandardSeed → BtcWallet.derive) and cached in memory until lock; signing derives the
 * input keys from the seed again, inside the window, after the user taps Sign (BtcPsbtSigner),
 * and destroys them. Bitcoin always uses the STANDARD wallet: while a passphrase wallet is open
 * the requests are refused (threat-model.md, "Bitcoin"). Every answer re-checks that the request
 * still owns its slot (RequestOwnership BTC_UNDECIDED / BTC_SHOW) under stateLock, as before.
 */
final class BtcScreens {
    private static final String TAG = "Vault";
    private static final String BTC_PREFS = "bitcoin", BTC_SHARING_KEY = "shared_v1";

    /** What Bitcoin borrows from MainActivity beyond {@link VaultHost}. */
    interface Host extends VaultHost {
        /** Under stateLock: a passphrase wallet is open (Bitcoin is refused then). */
        boolean passphraseWalletOpen();
    }

    private final Host host;
    private final ApprovalScreens approvals;
    private final Activity activity;
    private final Pages pages;
    private final Object stateLock;
    private final ExecutorService cryptoExecutor;
    /**
     * Per network (BtcNetwork ordinal): the STANDARD wallet's Bitcoin account public keys, derived
     * from the seed inside the seed-key window on first use and kept for this unlocked session only
     * (cleared on lock and on any wallet change; never written to disk). Guarded by stateLock.
     */
    private final BtcWallet[] btcWallets = new BtcWallet[BtcNetwork.values().length];
    /** walletId the cached Bitcoin accounts were derived for. */
    private String btcWalletOwner;
    /** Amounts already signed per coin (SegWit fee-attack guard); memory only. */
    private final BtcAmountMemory btcAmounts = new BtcAmountMemory();

    BtcScreens(Host host, ApprovalScreens approvals) {
        this.host = host;
        this.approvals = approvals;
        this.activity = host.activity();
        this.pages = host.pages();
        this.stateLock = host.stateLock();
        this.cryptoExecutor = host.cryptoExecutor();
    }

    /** Forget the cached account keys (lock, wallet change, destroy). */
    void clearWallets() {
        synchronized (stateLock) {
            Arrays.fill(btcWallets, null);
            btcWalletOwner = null;
        }
    }

    /** The saved "shared with the Mac" choices of the standard wallet. Call under stateLock. */
    private BtcSharing btcSharing() {
        return BtcSharing.load(activity.getSharedPreferences(BTC_PREFS, Context.MODE_PRIVATE).getString(BTC_SHARING_KEY, null), host.walletId());
    }

    private void saveBtcSharing(BtcSharing sharing) {
        if (!activity.getSharedPreferences(BTC_PREFS, Context.MODE_PRIVATE).edit().putString(BTC_SHARING_KEY, sharing.encode()).commit()) {
            Log.w(TAG, "Bitcoin sharing choice not saved (the phone will ask again)");
        }
    }

    private interface BtcWalletUse { void use(BtcWallet wallet) throws Exception; }

    /** btcGetAccount / btcShowAddress / btcSignPsbt: one request owns the approval slot until answered. */
    void handleBitcoin(AccessoryTransport source, JSONObject json, String fallbackId, int s) {
        final ApprovalDecision decision = host.claimApproval(source, fallbackId);
        if (decision == null) return;
        String id = fallbackId;
        try {
            final BtcRequest r = BtcRequest.parse(json);
            id = r.id;
            synchronized (stateLock) {
                if (host.passphraseWalletOpen()) {
                    throw new RequestRefusal("Close the passphrase wallet first", "Bitcoin uses the standard wallet (your 24 words "
                            + "without a passphrase). Close the passphrase wallet on the phone (☰ → Passphrase wallet), then send "
                            + "the request again. Nothing was shared or signed.");
                }
                if (host.walletId() == null) throw new IllegalStateException("Wallet is not ready: unlock and complete the backup check first");
            }
            withBtcWallet(r.network, source, r.id, decision, s, wallet -> {
                switch (r.kind) {
                    case GET_ACCOUNT:
                        answerBtcAccount(source, r, wallet, decision, s);
                        break;
                    case SHOW_ADDRESS: {
                        String address = wallet.address(r.type, r.account, r.change, r.index);
                        activity.runOnUiThread(() -> showBtcAddress(source, r, wallet, address, decision, s));
                        break;
                    }
                    default: {
                        // Built once: the review and the signer both use this object.
                        BtcPsbtReview review = BtcPsbtReview.build(r.psbt, r.network, wallet, host.safety(), btcAmounts);
                        activity.runOnUiThread(() -> showBtcApproval(source, r, review, decision, s));
                    }
                }
            });
        } catch (Exception e) {
            failBitcoin(source, id, decision, s, e);
        }
    }

    /** Answer an error, release the slot, and show a refusal's reason on the phone. Any thread. */
    private void failBitcoin(AccessoryTransport source, String id, ApprovalDecision decision, int s, Exception e) {
        host.finishApproval(decision);
        host.sendError(source, id, e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
        activity.runOnUiThread(() -> {
            if (s != host.session() || !host.unlocked() || source != host.transport() || host.sensitiveActive() || host.approvalDecision() != null) return;
            if (e instanceof RequestRefusal) {
                pages.showInfo(((RequestRefusal) e).title, e.getMessage(), host::showHome);
                Haptics.reject(activity.getWindow().getDecorView());
            } else if ("loading".equals(pages.screen())) {
                host.showHome();
            }
        });
    }

    /**
     * Run {@code use} with the standard wallet's Bitcoin accounts for {@code network}: from the
     * session cache, or derived now from the seed (PIN window; a dismissed prompt answers "rejected").
     */
    private void withBtcWallet(BtcNetwork network, AccessoryTransport source, String id, ApprovalDecision decision, int s,
                               BtcWalletUse use) throws Exception {
        BtcWallet cached;
        synchronized (stateLock) {
            String walletId = host.walletId();
            cached = walletId != null && walletId.equals(btcWalletOwner) ? btcWallets[network.ordinal()] : null;
        }
        if (cached != null) {
            use.use(cached);
            return;
        }
        activity.runOnUiThread(() -> {
            if (!host.owns(source, s, decision, RequestOwnership.BTC_UNDECIDED)) { host.finishApproval(decision); return; }
            pages.showLoading("Opening your Bitcoin accounts", "Deriving your " + network.label + " accounts from your recovery phrase…");
            host.withSeedKey("Confirm your PIN to open your Bitcoin accounts", () -> {
                try {
                    cryptoExecutor.execute(() -> {
                        try {
                            final String owner;
                            synchronized (stateLock) {
                                if (!host.owns(source, s, decision, RequestOwnership.BTC_UNDECIDED)) throw new IllegalStateException("Session ended before the Bitcoin accounts opened");
                                owner = host.walletId();
                            }
                            BtcWallet derived = host.vault().withStandardSeed(seed -> BtcWallet.derive(seed, network));
                            synchronized (stateLock) {
                                if (s != host.session() || owner == null || !owner.equals(host.walletId())) {
                                    throw new IllegalStateException("The wallet changed; send the request again");
                                }
                                if (!owner.equals(btcWalletOwner)) {
                                    Arrays.fill(btcWallets, null);
                                    btcWalletOwner = owner;
                                }
                                btcWallets[network.ordinal()] = derived;
                            }
                            use.use(derived);
                        } catch (Exception e) {
                            if (KeystoreFailures.authLapsed(e)) {
                                activity.runOnUiThread(host::forgetConfirmation);
                                failBitcoin(source, id, decision, s, new RequestRefusal("PIN confirmation expired",
                                        "The PIN confirmation expired before your Bitcoin accounts opened. Send the request again. Nothing was shared or signed."));
                            } else {
                                failBitcoin(source, id, decision, s, e);
                            }
                        }
                    });
                } catch (RejectedExecutionException closing) {
                    host.finishApproval(decision);
                }
            }, () -> {
                synchronized (stateLock) { if (host.approvalDecision() != decision) return; }
                decision.cancel();
                source.send(Pages.json("id", id, "status", "rejected"));
                host.finishApproval(decision);
                host.setStatus("Bitcoin request declined · PIN not confirmed");
                host.showHome();
            });
        });
    }

    /** btcGetAccount: answer at once if the user shared this account before; otherwise ask on screen. */
    private void answerBtcAccount(AccessoryTransport source, BtcRequest r, BtcWallet wallet, ApprovalDecision decision, int s) throws Exception {
        boolean shared;
        synchronized (stateLock) { shared = host.walletId() != null && btcSharing().isShared(r.network, r.type, r.account); }
        if (!shared) {
            activity.runOnUiThread(() -> showBtcShare(source, r, wallet, decision, s));
            return;
        }
        JSONObject reply = BtcRequest.accountResponse(r.id, wallet, r.type, r.account);
        synchronized (stateLock) {
            if (host.owns(source, s, decision, RequestOwnership.BTC_UNDECIDED) && decision.beginSigning()) {
                source.send(reply);
                decision.finish();
            }
        }
        host.finishApproval(decision);
        activity.runOnUiThread(() -> {
            if (s != host.session() || !host.unlocked()) return;
            String message = r.network.label + " " + BtcWallet.accountLabel(r.type, r.account) + " sent to your Mac (watch-only, shared before)";
            if ("loading".equals(pages.screen()) && host.approvalDecision() == null) {
                host.setStatus(message);
                host.showHome();
            } else {
                host.showStatus(message);
            }
        });
    }

    private void showBtcShare(AccessoryTransport source, BtcRequest r, BtcWallet wallet, ApprovalDecision decision, int s) {
        if (host.abandonUnlessOwned(source, s, decision, RequestOwnership.BTC_SHOW)) return;
        host.keepScreenOn(true);
        LinearLayout root = pages.page(r.network.test() ? r.network.label.toUpperCase(Locale.ROOT) + " · SHARE ACCOUNT" : "BITCOIN · SHARE ACCOUNT",
                "Share Bitcoin account with the Mac?",
                "Your Mac asks for this account's watch-only key, to show your balance and prepare transactions.");
        root.addView(pages.detail(r.network.test() ? BtcPsbtReview.TEST_NETWORK : "Network", r.network.label));
        root.addView(pages.detail("Account", BtcWallet.accountLabel(r.type, r.account) + "\n" + wallet.accountPathString(r.type, r.account)));
        root.addView(pages.detail("Wallet fingerprint", wallet.fingerprintHex()));
        root.addView(pages.detail("What the Mac will see", "Every address, balance and payment of this account, past and future, "
                + "becomes visible to the Mac and to any software on it. It cannot spend: every payment still needs your approval on this phone."));
        root.addView(pages.detail("Asked once", "If you share, the phone remembers it for this account and network and answers "
                + "this request without asking again."));
        TextView share = VaultTheme.pixelButton(activity, "Share with the Mac", true);
        TextView decline = VaultTheme.pixelButton(activity, "Don't share", false);
        Pages.hardenTouch(share);
        Pages.hardenTouch(decline);
        share.setOnClickListener(v -> {
            JSONObject reply;
            try {
                reply = BtcRequest.accountResponse(r.id, wallet, r.type, r.account);
            } catch (Exception e) {
                failBitcoin(source, r.id, decision, s, e);
                return;
            }
            synchronized (stateLock) {
                if (!host.owns(source, s, decision, RequestOwnership.BTC_UNDECIDED) || !decision.beginSigning()) return;
                BtcSharing sharing = btcSharing();
                sharing.share(r.network, r.type, r.account);
                saveBtcSharing(sharing);
                source.send(reply);
                decision.finish();
            }
            Haptics.confirm(v);
            host.finishApproval(decision);
            host.setStatus("Bitcoin account shared (watch-only)");
            pages.showInfo("Account shared", BtcWallet.accountLabel(r.type, r.account) + " on " + r.network.label
                    + " is now visible to the Mac (watch-only). It cannot spend without this phone.", host::showHome);
        });
        decline.setOnClickListener(v -> {
            if (!decision.reject()) return;
            Haptics.reject(v);
            source.send(Pages.json("id", r.id, "status", "rejected"));
            host.finishApproval(decision);
            host.setStatus("Bitcoin account not shared");
            host.showHome();
        });
        root.addView(share, Pages.matchWrap(pages.dp(16)));
        root.addView(decline, Pages.matchWrap(pages.dp(10)));
        pages.present(root, "btc-share");
    }

    /**
     * ☰ → Bitcoin sharing: the accounts btcGetAccount answers without asking, each revocable. A
     * privacy control only: revoking makes the phone ask again; it cannot recall what the Mac
     * already received, and it never changes what is signed.
     */
    void showBtcSharing() {
        List<String> keys;
        synchronized (stateLock) { keys = host.walletId() != null ? btcSharing().keys() : Collections.emptyList(); }
        LinearLayout root = pages.page("SECURITY / PRIVACY", "Bitcoin sharing",
                "Bitcoin accounts whose watch-only key the Mac receives without asking. Stop sharing to make the phone ask again.");
        if (keys.isEmpty()) {
            pages.card(root, "Nothing shared", "No Bitcoin account is shared. The phone asks before the Mac can see any account.");
        } else {
            pages.card(root, "Already received", "Stopping does not erase what the Mac already received: it can still watch those addresses. "
                    + "It only stops new requests from being answered silently.");
            for (String key : keys) {
                pages.action(root, "Stop sharing · " + BtcSharing.label(key), false, () -> {
                    synchronized (stateLock) {
                        if (host.walletId() == null) return;
                        BtcSharing sharing = btcSharing();
                        sharing.revoke(key);
                        saveBtcSharing(sharing);
                    }
                    host.setStatus("Bitcoin account no longer shared · the phone will ask again");
                    showBtcSharing();
                });
            }
            if (keys.size() > 1) pages.action(root, "Stop sharing all", false, () -> {
                synchronized (stateLock) {
                    if (host.walletId() == null) return;
                    BtcSharing sharing = btcSharing();
                    sharing.revokeAll();
                    saveBtcSharing(sharing);
                }
                host.setStatus("No Bitcoin account is shared · the phone will ask again");
                showBtcSharing();
            });
        }
        pages.action(root, "Back to Security", false, host::showSecurity);
        pages.present(root, "btc-sharing");
    }

    /** btcShowAddress: the address big, for comparison with the Mac; answered only after Done. */
    private void showBtcAddress(AccessoryTransport source, BtcRequest r, BtcWallet wallet, String address,
                                ApprovalDecision decision, int s) {
        if (host.abandonUnlessOwned(source, s, decision, RequestOwnership.BTC_SHOW)) return;
        host.keepScreenOn(true);
        LinearLayout root = pages.page(r.network.test() ? r.network.label.toUpperCase(Locale.ROOT) + " · ADDRESS" : "BITCOIN · RECEIVE ADDRESS",
                "Compare with your Mac", "Check that your Mac shows exactly this address, every group. Only this phone's screen is trusted.");
        root.addView(pages.detail(r.network.test() ? BtcPsbtReview.TEST_NETWORK : "Network", r.network.label));
        LinearLayout box = VaultTheme.box(activity);
        TextView big = VaultTheme.monoText(activity, BtcScript.grouped(address, 4), 24, VaultTheme.INK);
        big.setTextIsSelectable(false);
        box.addView(big);
        root.addView(box, Pages.matchWrap(pages.dp(12)));
        root.addView(pages.detail("Account", BtcWallet.accountLabel(r.type, r.account)));
        root.addView(pages.detail("Path", wallet.addressPathString(r.type, r.account, r.change, r.index)
                + (r.change == 0 ? " (receiving address " : " (change address ") + r.index + ")"));
        root.addView(pages.detail("If anything differs", "Tap Cancel and do not use the address shown on the Mac."));
        TextView done = VaultTheme.pixelButton(activity, "Done: it matches", true);
        TextView cancel = VaultTheme.pixelButton(activity, "Cancel", false);
        Pages.hardenTouch(done);
        Pages.hardenTouch(cancel);
        done.setOnClickListener(v -> {
            JSONObject reply;
            try {
                reply = BtcRequest.addressResponse(r.id, address);
            } catch (Exception e) {
                failBitcoin(source, r.id, decision, s, e);
                return;
            }
            synchronized (stateLock) {
                if (!host.owns(source, s, decision, RequestOwnership.BTC_UNDECIDED) || !decision.beginSigning()) return;
                source.send(reply);
                decision.finish();
            }
            Haptics.confirm(v);
            host.finishApproval(decision);
            host.setStatus("Bitcoin address confirmed on the phone");
            host.showHome();
        });
        cancel.setOnClickListener(v -> {
            if (!decision.reject()) return;
            Haptics.reject(v);
            source.send(Pages.json("id", r.id, "status", "rejected"));
            host.finishApproval(decision);
            host.setStatus("Bitcoin address not confirmed");
            host.showHome();
        });
        root.addView(done, Pages.matchWrap(pages.dp(16)));
        root.addView(cancel, Pages.matchWrap(pages.dp(10)));
        pages.present(root, "btc-address");
    }

    /** btcSignPsbt review, rendered from the BtcPsbtReview built once in handleBitcoin. */
    private void showBtcApproval(AccessoryTransport source, BtcRequest r, BtcPsbtReview review, ApprovalDecision decision, int s) {
        if (host.abandonUnlessOwned(source, s, decision, RequestOwnership.BTC_SHOW)) return;
        List<MessageReview.Row> dangers = ReviewStyle.dangers(review.summary, review.details);
        LinearLayout root = pages.renderReview(review.kicker, review.title, review.subtitle, dangers, null,
                review.summary, review.details, "technical details");
        final String txid = BtcCrypto.hex(BtcCrypto.reversed(review.psbt.tx.txid()));
        approvals.addDecisionControls(root, source, decision, s, ApprovalScreens.SignSpec.withSeed(r.id, review.reviewPrompt, review.signLabel, dangers,
                seed -> {
                    byte[] signed = BtcPsbtSigner.sign(review, seed, host.random());
                    // Remember what each coin was signed as (SegWit fee-attack guard), before it can leave;
                    // only amounts proven by the previous transaction (a lied Taproot amount must not stick).
                    for (BtcPsbtReview.SignInput in : review.inputs) {
                        if (in.amountProven) btcAmounts.record(review.psbt.tx.inputs.get(in.index).outpoint(), in.amount, in.script);
                    }
                    return BtcRequest.signedResponse(r.id, signed);
                },
                "Confirm your PIN to sign this Bitcoin transaction",
                "The signed PSBT was queued for USB. Your Mac finalizes it and sends it to the network; unplugging cannot revoke a signature already received.",
                "Transaction ID (once sent to the network)", response -> {
                    // Nested SegWit and Legacy inputs put their scriptSig (for Legacy: the signature) into the txid
                    try {
                        return BtcCrypto.hex(BtcCrypto.reversed(BtcPsbtSigner.finalTxid(review,
                                java.util.Base64.getDecoder().decode(response.getString("psbt")))));
                    } catch (Exception e) {
                        return txid;
                    }
                }, true, () -> {
                    host.safety().record(review.walletKey, review.parties, System.currentTimeMillis());
                    approvals.offerToSave(review.parties);
                }));
        pages.present(root, "btc-approval");
    }
}
