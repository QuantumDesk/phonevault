package dev.phonevault.signer;

import android.app.Activity;
import android.content.res.ColorStateList;
import android.util.Log;
import android.view.View;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.TextView;

import org.json.JSONObject;
import org.web3j.crypto.Credentials;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.function.Function;

/**
 * The signing reviews and their one decision: the EVM transaction and message reviews, the
 * Sign / Reject controls every review shares (Bitcoin's PSBT review too), and the receipt. Sign
 * re-checks that the request still owns its slot (RequestOwnership, through the host) under
 * stateLock right before the key is used and again before the response is sent, exactly as
 * MainActivity did; a lock in between invalidates the session and nothing is sent.
 */
final class ApprovalScreens {
    private static final String TAG = "Vault";

    /** Produces the response for one reviewed request; runs on the crypto thread under stateLock. */
    interface ReviewedSigner { JSONObject sign(Credentials current) throws Exception; }

    /**
     * Produces the response from the BIP-39 seed (Bitcoin): runs on the crypto thread inside the
     * seed-key window, OUTSIDE stateLock (the decrypt and key derivation take a moment); the
     * response is sent under stateLock only if the session is still the reviewed one.
     */
    interface SeedSigner { JSONObject sign(byte[] seed) throws Exception; }

    /** What one review's Sign and Reject do; the request's session (source, decision, s) is passed beside it. */
    static final class SignSpec {
        final String requestId;
        /** The "I verified…" checkbox text and the Sign button label. */
        final String prompt, signText;
        /** The review's DANGER rows: when any, a second box must state them before Sign unlocks. */
        final List<MessageReview.Row> dangers;
        /** EVM: signs with the live credentials under stateLock. Null when {@link #seedSigner} is set. */
        final ReviewedSigner signer;
        /** Bitcoin: signs from the seed inside the PIN window; {@link #seedWhy} is the PIN prompt's reason. */
        final SeedSigner seedSigner;
        final String seedWhy;
        /** The receipt after a signature: its message, and the label and value of its one card. */
        final String doneMessage, receiptLabel;
        final Function<JSONObject, String> receiptValue;
        /** A transaction (true) or a message (false): picks the receipt wording. */
        final boolean transaction;
        /** Runs on the UI thread once a signature has been sent (may be null). */
        final Runnable afterSigned;

        private SignSpec(String requestId, String prompt, String signText, List<MessageReview.Row> dangers,
                         ReviewedSigner signer, SeedSigner seedSigner, String seedWhy, String doneMessage,
                         String receiptLabel, Function<JSONObject, String> receiptValue, boolean transaction,
                         Runnable afterSigned) {
            this.requestId = requestId;
            this.prompt = prompt;
            this.signText = signText;
            this.dangers = dangers;
            this.signer = signer;
            this.seedSigner = seedSigner;
            this.seedWhy = seedWhy;
            this.doneMessage = doneMessage;
            this.receiptLabel = receiptLabel;
            this.receiptValue = receiptValue;
            this.transaction = transaction;
            this.afterSigned = afterSigned;
        }

        /** EVM: the receipt shows {@code receiptField} of the response. */
        static SignSpec withCredentials(String requestId, String prompt, String signText, List<MessageReview.Row> dangers,
                                        ReviewedSigner signer, String doneMessage, String receiptLabel, String receiptField,
                                        boolean transaction, Runnable afterSigned) {
            return new SignSpec(requestId, prompt, signText, dangers, signer, null, null, doneMessage, receiptLabel,
                    response -> response.optString(receiptField), transaction, afterSigned);
        }

        /** Bitcoin: Sign first opens the seed-key window; a dismissed PIN prompt answers "rejected". */
        static SignSpec withSeed(String requestId, String prompt, String signText, List<MessageReview.Row> dangers,
                                 SeedSigner seedSigner, String seedWhy, String doneMessage, String receiptLabel,
                                 Function<JSONObject, String> receiptValue, boolean transaction, Runnable afterSigned) {
            return new SignSpec(requestId, prompt, signText, dangers, null, seedSigner, seedWhy, doneMessage, receiptLabel,
                    receiptValue, transaction, afterSigned);
        }
    }

    private final VaultHost host;
    private final Activity activity;
    private final Pages pages;
    private final Object stateLock;
    private final ExecutorService cryptoExecutor;
    /** Counterparties of the transaction just signed, offered as "Save as contact" on its receipt. */
    private List<TransactionReview.Party> receiptParties;

    ApprovalScreens(VaultHost host) {
        this.host = host;
        this.activity = host.activity();
        this.pages = host.pages();
        this.stateLock = host.stateLock();
        this.cryptoExecutor = host.cryptoExecutor();
    }

    /** UI thread, after a signature: the receipt offers to save these counterparties as contacts. */
    void offerToSave(List<TransactionReview.Party> parties) { receiptParties = parties; }

    void showApproval(AccessoryTransport source, ApprovalSession approval,
                      ApprovalDecision decision, int s) {
        if (host.abandonUnlessOwned(source, s, decision, RequestOwnership.SHOW_REVIEW)) return;
        // Rendered from the review built with this exact request in ApprovalSession (same object that is signed).
        TransactionReview review = approval.review;
        List<MessageReview.Row> dangers = ReviewStyle.dangers(review.summary, review.details,
                approval.hostSimulation != null ? approval.hostSimulation.rows : null);
        LinearLayout root = pages.renderReview(review.kicker, review.title, review.subtitle, dangers, approval.signingAs,
                review.summary, review.details, "technical details");
        if (approval.hostSimulation != null) {
            // The Mac's claim, in its own box BELOW the phone's own review; display only, never signed.
            SimulationCheck.Result sim = approval.hostSimulation;
            LinearLayout box = VaultTheme.box(activity);
            box.addView(VaultTheme.bodyText(activity, sim.title, 13, sim.contradicts ? VaultTheme.DANGER_INK : VaultTheme.FAINT));
            box.addView(VaultTheme.rule(activity, pages.dp(8), pages.dp(10)));
            for (MessageReview.Row row : sim.rows) box.addView(pages.detail(row));
            root.addView(box, Pages.matchWrap(pages.dp(16)));
        }
        addDecisionControls(root, source, decision, s, SignSpec.withCredentials(approval.request.id, review.reviewPrompt,
                review.signLabel, dangers, approval::signIfIdentityUnchanged,
                "The response was queued for USB. Check your host for receipt and broadcast status. Unplugging cannot revoke a signature already received.",
                "Transaction hash", "transactionHash", true, () -> {
                    // A signature exists: count its counterparties in this phone's history and offer to name them.
                    host.safety().record(approval.reviewedAddress(), review.parties, System.currentTimeMillis());
                    receiptParties = review.parties;
                }));
        pages.present(root, "approval");
    }

    /**
     * The acknowledgement checkbox, Sign and Reject for one request, shared by the transaction,
     * message and Bitcoin reviews: one decision, check → sign → send as one step under stateLock.
     */
    void addDecisionControls(LinearLayout root, AccessoryTransport source, ApprovalDecision decision, int s,
                             SignSpec spec) {
        // Approve needs: the end of the review on screen once, "I verified…", and for a review with
        // a DANGER row a second box that states that danger in words (ApprovalGate).
        ApprovalGate gate = new ApprovalGate(spec.dangers != null && !spec.dangers.isEmpty());
        CheckBox dangerAck = null;
        if (gate.dangerRequired) {
            dangerAck = new CheckBox(activity);
            dangerAck.setText(ReviewStyle.dangerAcknowledgement(spec.dangers));
            VaultTheme.size(dangerAck, VaultTheme.BODY_SIZE);
            dangerAck.setTextColor(VaultTheme.DANGER_INK);
            dangerAck.setButtonTintList(ColorStateList.valueOf(VaultTheme.DANGER_INK));
            dangerAck.setMinHeight(pages.dp(56));
            dangerAck.setPadding(pages.dp(4), pages.dp(18), pages.dp(4), pages.dp(18));
            Pages.hardenTouch(dangerAck);
            root.addView(dangerAck, Pages.matchWrap(pages.dp(12)));
        }
        CheckBox reviewed = new CheckBox(activity);
        reviewed.setText(spec.prompt);
        VaultTheme.size(reviewed, VaultTheme.BODY_SIZE);
        reviewed.setTextColor(VaultTheme.INK);
        reviewed.setMinHeight(pages.dp(56));
        reviewed.setPadding(pages.dp(4), pages.dp(18), pages.dp(4), pages.dp(18));
        Pages.hardenTouch(reviewed);
        root.addView(reviewed, Pages.matchWrap(pages.dp(gate.dangerRequired ? 4 : 12)));
        TextView readToEnd = VaultTheme.bodyText(activity, "Approve unlocks once you have scrolled to the end of this review.", 13, VaultTheme.FAINT);
        root.addView(readToEnd, Pages.matchWrap(pages.dp(4)));
        TextView sign = VaultTheme.pixelButton(activity, spec.signText, true);
        TextView reject = VaultTheme.pixelButton(activity, "Reject request", false);
        Pages.hardenTouch(sign);
        Pages.hardenTouch(reject);
        sign.setEnabled(false);
        Runnable refresh = () -> sign.setEnabled(gate.mayApprove() && decision.state() == ApprovalDecision.State.REVIEW);
        reviewed.setOnCheckedChangeListener((v, checked) -> { gate.setReviewed(checked); refresh.run(); });
        if (dangerAck != null) dangerAck.setOnCheckedChangeListener((v, checked) -> { gate.setDangerAcknowledged(checked); refresh.run(); });
        root.setTag((Pages.ScrollEndWatcher) () -> {
            if (gate.hasReachedEnd()) return;
            gate.reachedEnd();
            readToEnd.setVisibility(View.GONE);
            refresh.run();
        });
        final CheckBox dangerBox = dangerAck;
        reject.setOnClickListener(v -> {
            if (!decision.reject()) return;
            Haptics.reject(v);
            source.send(Pages.json("id", spec.requestId, "status", "rejected"));
            host.finishApproval(decision);
            host.setStatus("Request rejected · no signature created");
            showReceipt("Request rejected", "No signature was created for this request.", null, null, spec.transaction);
        });
        sign.setOnClickListener(v -> {
            synchronized (stateLock) {
                if (!host.owns(source, s, decision, RequestOwnership.SIGN_PRESSED) || !reviewed.isChecked() || !gate.mayApprove()
                        || (dangerBox != null && !dangerBox.isChecked()) || !decision.beginSigning()) return;
            }
            // The decision is now irreversible through Reject. Lock still invalidates queued work.
            Haptics.confirm(v);
            sign.setEnabled(false);
            reject.setEnabled(false);
            reviewed.setEnabled(false);
            if (dangerBox != null) dangerBox.setEnabled(false);
            sign.setText("Signing…");
            host.setStatus("Signing approved request");
            Runnable work = () -> cryptoExecutor.execute(() -> {
                boolean mayHaveLeft = spec.seedSigner == null; // the seed path sends only after signing completes
                try {
                    JSONObject response;
                    if (spec.seedSigner != null) {
                        synchronized (stateLock) {
                            if (!host.owns(source, s, decision, RequestOwnership.SIGNING)) throw new IllegalStateException("Session ended before signing");
                        }
                        JSONObject prepared = host.vault().withStandardSeed(spec.seedSigner::sign);
                        synchronized (stateLock) {
                            if (!host.owns(source, s, decision, RequestOwnership.SIGNING)) throw new IllegalStateException("Session ended before signing");
                            mayHaveLeft = true;
                            if (!source.send(prepared)) throw new IllegalStateException("Signature delivery is uncertain");
                            decision.finish();
                        }
                        response = prepared;
                    } else {
                        synchronized (stateLock) {
                            if (!host.owns(source, s, decision, RequestOwnership.SIGNING))
                                throw new IllegalStateException("Session ended before signing");
                            response = spec.signer.sign(host.signingKey());
                            if (!source.send(response)) throw new IllegalStateException("Signature delivery is uncertain");
                            decision.finish();
                        }
                    }
                    final JSONObject sent = response;
                    activity.runOnUiThread(() -> {
                        if (s != host.session() || !host.unlocked() || host.approvalDecision() != decision) return;
                        host.finishApproval(decision);
                        host.setStatus("Signature created · delivery not confirmed");
                        if (spec.afterSigned != null) spec.afterSigned.run();
                        showReceipt("Signature created", spec.doneMessage, spec.receiptLabel, spec.receiptValue.apply(sent), spec.transaction);
                    });
                } catch (Exception e) {
                    final boolean uncertain = mayHaveLeft;
                    final boolean lapsed = KeystoreFailures.authLapsed(e);
                    host.sendError(source, spec.requestId, uncertain ? e.getMessage()
                            : (lapsed ? "PIN confirmation expired before signing; nothing was signed" : "Not signed: " + e.getMessage()));
                    if (!uncertain) Log.w(TAG, "seed signing failed: " + KeystoreFailures.chain(e));
                    activity.runOnUiThread(() -> {
                        if (s != host.session() || !host.unlocked() || host.approvalDecision() != decision) return;
                        host.finishApproval(decision);
                        if (!uncertain) {
                            host.setStatus("Not signed");
                            showReceipt("Not signed", lapsed
                                    ? "Your PIN confirmation expired before signing finished. No signature left the phone; send the request again."
                                    : "Signing did not complete. No signature left the phone.", null, null, spec.transaction);
                            return;
                        }
                        showReceipt("Check the host", spec.transaction
                                ? "Signing or delivery did not complete normally. A signature may have reached the host. Check before creating another transaction."
                                : "Signing or delivery did not complete normally. A signature may have reached the host. Check before signing again.",
                                null, null, spec.transaction);
                    });
                }
            });
            if (spec.seedSigner == null) {
                work.run();
                return;
            }
            host.withSeedKey(spec.seedWhy, work, () -> {
                synchronized (stateLock) { if (host.approvalDecision() != decision) return; }
                decision.cancel();
                source.send(Pages.json("id", spec.requestId, "status", "rejected"));
                host.finishApproval(decision);
                host.setStatus("Not signed · PIN not confirmed");
                showReceipt("Not signed", "The PIN was not confirmed, so nothing was signed.", null, null, spec.transaction);
            });
        });
        root.addView(sign, Pages.matchWrap(pages.dp(8)));
        root.addView(reject, Pages.matchWrap(pages.dp(10)));
    }

    /** Review for personal_sign / eth_signTypedData_v4, rendered from the parsed request only. */
    void showMessageApproval(AccessoryTransport source, MessageApprovalSession approval,
                             ApprovalDecision decision, int s) {
        if (host.abandonUnlessOwned(source, s, decision, RequestOwnership.SHOW_REVIEW)) return;
        MessageReview review = approval.review;
        List<MessageReview.Row> dangers = ReviewStyle.dangers(review.summary, review.details);
        LinearLayout root = pages.renderReview(review.kicker, review.title, review.subtitle, dangers, approval.signingAs,
                review.summary, review.details, "details");
        addDecisionControls(root, source, decision, s, SignSpec.withCredentials(approval.request.id, review.reviewPrompt,
                review.signLabel, dangers, approval::signIfIdentityUnchanged,
                "The signature was queued for USB. Anyone who receives it can use it as shown on the review; unplugging cannot revoke it.",
                "Signed digest", "digest", false, null));
        pages.present(root, "message-approval");
    }

    void showReceipt(String title, String message, String hash) {
        showReceipt(title, message, "Transaction hash", hash, true);
    }

    void showReceipt(String title, String message, String label, String value, boolean transaction) {
        LinearLayout root = pages.page("REQUEST OUTCOME", title, message);
        if (value != null && !value.isEmpty()) pages.card(root, label, value);
        if (transaction) pages.card(root, "Network status", "This offline phone cannot confirm broadcast, inclusion, or settlement.");
        else pages.card(root, "Where it goes", "This offline phone cannot see how the host or website uses the signature.");
        List<TransactionReview.Party> save = receiptParties;
        receiptParties = null;
        if (save != null && !save.isEmpty()) host.addSaveActions(root, save);
        pages.action(root, "Back to Wallet", true, host::showHome);
        pages.action(root, "Lock now", false, host::lock);
        pages.present(root, "receipt");
    }
}
