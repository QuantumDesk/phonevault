package dev.phonevault.signer;

import android.app.Activity;
import android.util.Log;
import android.widget.LinearLayout;
import android.widget.TextView;

import org.json.JSONObject;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;

/**
 * USB listAddresses ({@link AddressListRequest}): "Share N addresses with your Mac?". The request
 * takes the one approval slot like any other; the addresses are derived from the standard wallet
 * inside the PIN window (withSeedKey → VaultKeyStore.standardAddresses), shown in full, and sent
 * only after the user taps Share. Declining answers "rejected". Nothing is remembered: the next
 * request asks again. Refused while a passphrase wallet is open (the Mac only ever sees the
 * standard wallet's addresses this way). Every answer re-checks that the request still owns its
 * slot (RequestOwnership ADDRESSES_UNDECIDED / ADDRESSES_SHOW) under stateLock.
 */
final class AddressShareScreens {
    private static final String TAG = "Vault";

    /** What address sharing borrows from MainActivity beyond {@link VaultHost}. */
    interface Host extends VaultHost {
        /** Under stateLock: a passphrase wallet is open (listAddresses is refused then). */
        boolean passphraseWalletOpen();
    }

    private final Host host;
    private final Activity activity;
    private final Pages pages;
    private final Object stateLock;
    private final ExecutorService cryptoExecutor;

    AddressShareScreens(Host host) {
        this.host = host;
        this.activity = host.activity();
        this.pages = host.pages();
        this.stateLock = host.stateLock();
        this.cryptoExecutor = host.cryptoExecutor();
    }

    /** Refusal shown (and answered) while a passphrase wallet is open. */
    static final String PASSPHRASE_OPEN = "Your Mac can list the addresses of your standard wallet only. Close the passphrase "
            + "wallet on the phone (☰ → Passphrase wallet), then try again. Nothing was shared.";

    /** listAddresses: one request owns the approval slot until it is answered. */
    void handle(AccessoryTransport source, JSONObject json, String fallbackId, int s) {
        final ApprovalDecision decision = host.claimApproval(source, fallbackId);
        if (decision == null) return;
        String id = fallbackId;
        try {
            final AddressListRequest r = AddressListRequest.parse(json);
            id = r.id;
            synchronized (stateLock) {
                if (host.passphraseWalletOpen()) throw new RequestRefusal("Close the passphrase wallet first", PASSPHRASE_OPEN);
                if (host.walletId() == null) throw new IllegalStateException(RequestRouter.NOT_READY);
            }
            activity.runOnUiThread(() -> derive(source, r, decision, s));
        } catch (Exception e) {
            fail(source, id, decision, s, e);
        }
    }

    /** UI thread: PIN window, then derive the addresses on the crypto thread. A dismissed PIN prompt answers "rejected". */
    private void derive(AccessoryTransport source, AddressListRequest r, ApprovalDecision decision, int s) {
        if (!host.owns(source, s, decision, RequestOwnership.ADDRESSES_UNDECIDED)) { host.finishApproval(decision); return; }
        pages.showLoading("Your Mac asks for your addresses", "Deriving them from your recovery phrase…");
        host.withSeedKey("Confirm your PIN to show your addresses", () -> {
            try {
                cryptoExecutor.execute(() -> {
                    try {
                        final String owner;
                        synchronized (stateLock) {
                            if (!host.owns(source, s, decision, RequestOwnership.ADDRESSES_UNDECIDED)) throw new IllegalStateException("Session ended before the addresses were derived");
                            if (host.passphraseWalletOpen()) throw new RequestRefusal("Close the passphrase wallet first", PASSPHRASE_OPEN);
                            owner = host.walletId();
                        }
                        List<String> addresses = host.vault().standardAddresses(r.scheme, r.count);
                        // Account 1 is the wallet's identity under every numbering: a mismatch means the wallet changed.
                        if (owner == null || !addresses.get(0).equalsIgnoreCase(owner)) throw new IllegalStateException("The wallet changed; send the request again");
                        activity.runOnUiThread(() -> show(source, r, addresses, decision, s));
                    } catch (Exception e) {
                        if (KeystoreFailures.authLapsed(e)) {
                            activity.runOnUiThread(host::forgetConfirmation);
                            fail(source, r.id, decision, s, new RequestRefusal("PIN confirmation expired",
                                    "The PIN confirmation expired before your addresses were derived. Send the request again. Nothing was shared."));
                        } else {
                            fail(source, r.id, decision, s, e);
                        }
                    }
                });
            } catch (RejectedExecutionException closing) {
                host.finishApproval(decision);
            }
        }, () -> {
            synchronized (stateLock) { if (host.approvalDecision() != decision || !decision.reject()) return; }
            source.send(Pages.json("id", r.id, "status", "rejected"));
            host.finishApproval(decision);
            host.setStatus("Addresses not shared · PIN not confirmed");
            host.showHome();
        });
    }

    /** "Share N addresses with your Mac?" with every address in full and its path. */
    private void show(AccessoryTransport source, AddressListRequest r, List<String> addresses, ApprovalDecision decision, int s) {
        if (host.abandonUnlessOwned(source, s, decision, RequestOwnership.ADDRESSES_SHOW)) return;
        host.keepScreenOn(true);
        int n = addresses.size();
        LinearLayout root = pages.page("ACCOUNTS · SHARE ADDRESSES",
                "Share " + n + (n == 1 ? " address" : " addresses") + " with your Mac?",
                "Your Mac asks for the first " + (n == 1 ? "address" : n + " addresses") + " of your wallet, to find where your funds are.");
        root.addView(pages.detail("Account numbering", r.scheme.label + " · " + r.scheme.pathPattern()));
        for (int i = 0; i < n; i++) {
            root.addView(pages.detail(AccountBook.defaultName(i), addresses.get(i) + "\n" + r.scheme.pathString(i)));
        }
        root.addView(pages.detail("What your Mac will see", "These addresses, and their balances and history on any network. "
                + "It cannot spend: every payment still needs your approval on this phone."));
        root.addView(pages.detail("Asked every time", "The phone does not remember this choice. Nothing on this phone changes."));
        TextView share = VaultTheme.pixelButton(activity, "Share with your Mac", true);
        TextView decline = VaultTheme.pixelButton(activity, "Don't share", false);
        Pages.hardenTouch(share);
        Pages.hardenTouch(decline);
        share.setOnClickListener(v -> {
            JSONObject reply;
            try {
                reply = r.response(addresses);
            } catch (Exception e) {
                fail(source, r.id, decision, s, e);
                return;
            }
            synchronized (stateLock) {
                if (!host.owns(source, s, decision, RequestOwnership.ADDRESSES_UNDECIDED) || !decision.beginSigning()) return;
                source.send(reply);
                decision.finish();
            }
            Haptics.confirm(v);
            host.finishApproval(decision);
            host.setStatus(n + (n == 1 ? " address" : " addresses") + " shared with your Mac (" + r.scheme.label + " numbering)");
            host.showHome();
        });
        decline.setOnClickListener(v -> {
            if (!decision.reject()) return;
            Haptics.reject(v);
            source.send(Pages.json("id", r.id, "status", "rejected"));
            host.finishApproval(decision);
            host.setStatus("Addresses not shared");
            host.showHome();
        });
        root.addView(share, Pages.matchWrap(pages.dp(16)));
        root.addView(decline, Pages.matchWrap(pages.dp(10)));
        pages.present(root, "addresses-share");
    }

    /** Answer an error, release the slot, and show a refusal's reason on the phone. Any thread. */
    private void fail(AccessoryTransport source, String id, ApprovalDecision decision, int s, Exception e) {
        Log.w(TAG, "listAddresses refused: " + e.getClass().getSimpleName());
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
}
