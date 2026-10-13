package dev.phonevault.signer;

import org.web3j.crypto.Keys;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * The plain-language review of one {@link Eip1559Request}, built from the SAME parsed object that
 * {@link EvmSigner} signs (via {@link ApprovalSession}); nothing here re-reads the host's JSON.
 * The built-in {@link TokenList} only adds names and decimals for contracts it lists on that
 * chain; an unlisted contract is shown as "Unknown token contract" with the raw amount in base
 * units and no symbol. Rows labelled DANGER or WARNING render in the danger style.
 */
final class TransactionReview {
    static final String DANGER = MessageReview.DANGER;
    static final String WARNING = MessageReview.WARNING;
    static final String KICKER = "TRANSACTION REVIEW";
    static final String SUBTITLE = "Compare these details with your intended action. This phone is the approval screen.";

    final String kicker;
    final String title;
    final String subtitle;
    final List<MessageReview.Row> summary;
    final List<MessageReview.Row> details;
    final String reviewPrompt;
    final String signLabel;
    /** One line for the lock screen while a request waits for unlock. */
    final String lockedSummary;
    /** The listed token for a token call, or null (native transfer or unknown contract). */
    final TokenList.Token token;
    /** The counterparties this transaction sends to or approves: recorded in {@link RecipientHistory} after signing. */
    final List<Party> parties;

    /** One counterparty of a reviewed transaction. */
    static final class Party {
        final String address; // lower-case
        final RecipientHistory.Role role;

        Party(String address, RecipientHistory.Role role) {
            this.address = AddressKeys.canon(address); // lowercase 0x…, or a btc:<network>:<address> key
            this.role = role;
        }
    }

    TransactionReview(String title, List<MessageReview.Row> summary, List<MessageReview.Row> details,
                      String reviewPrompt, String signLabel, String lockedSummary, TokenList.Token token, List<Party> parties) {
        this.kicker = KICKER;
        this.title = title;
        this.subtitle = SUBTITLE;
        this.summary = Collections.unmodifiableList(summary);
        this.details = Collections.unmodifiableList(details);
        this.reviewPrompt = reviewPrompt;
        this.signLabel = signLabel;
        this.lockedSummary = lockedSummary;
        this.token = token;
        this.parties = Collections.unmodifiableList(new ArrayList<>(parties));
    }

    /** @param signerAddress the reviewed signing address (any case); may be null for the locked summary */
    static TransactionReview build(Eip1559Request r, String signerAddress, TokenList tokens) {
        return build(r, signerAddress, tokens, null);
    }

    /**
     * @param safety the phone's address book and recipient history, or null (no history rows; the
     *               locked-screen summary and unit tests of the plain review)
     */
    static TransactionReview build(Eip1559Request r, String signerAddress, TokenList tokens, AddressSafety safety) {
        if (tokens == null) tokens = TokenList.empty();
        if (r.kind == Eip1559Request.Kind.SWAP) return SwapReview.build(r, signerAddress, tokens, safety);
        if (r.kind == Eip1559Request.Kind.NFT_CALL) return NftReview.build(r, signerAddress, tokens, safety);
        if (r.tokenCall != null && NftCollections.lookup(r.chainId, r.to) != null
                && (r.tokenCall.function == Erc20Call.Function.APPROVE || r.tokenCall.function == Erc20Call.Function.TRANSFER_FROM)) {
            // approve/transferFrom on a listed NFT collection: the ERC-721 meaning, never "tokens"
            return NftReview.buildErc721(r, signerAddress, tokens, safety);
        }
        List<MessageReview.Row> rows = new ArrayList<>();
        List<MessageReview.Row> details = new ArrayList<>();
        String signer = signerAddress == null ? null : signerAddress.toLowerCase(Locale.ROOT);
        String network = r.networkLabel();

        if (r.kind == Eip1559Request.Kind.NATIVE_TRANSFER) {
            rows.add(row("Action", r.transactionTypeLabel()));
            rows.add(row("Send", r.valueEth()));
            rows.add(row("Recipient", r.displayedRecipientLabel()));
            if (safety != null) rows.addAll(safety.rows(signer, r.to, RecipientHistory.Role.SEND));
            String known = knownContract(r.chainId, r.to, tokens);
            if (known != null) {
                rows.add(row(WARNING, "This address is " + known + ". Native coin sent straight to it, without a function "
                        + "call, is usually lost. Check that you meant to send " + r.nativeSymbol() + " here."));
            } else {
                rows.add(row("Contract check", "The offline phone can't tell whether this address is a wallet or a contract."));
            }
            addCommon(rows, r, signer);
            rows.add(row("Maximum fee", r.maximumFeeEth()));
            addFeeDetails(details, r);
            details.add(row("Contract data", "None"));
            String locked = r.transactionTypeLabel() + " · " + r.valueEth() + " to " + shortAddress(r.displayedRecipientLabel())
                    + " · " + network + ". Unlock to review every field before anything is signed.";
            List<Party> parties = new ArrayList<>();
            parties.add(new Party(r.to, RecipientHistory.Role.SEND));
            return new TransactionReview("Review transfer", rows, details,
                    "I verified the signing address, network, recipient, amount, and maximum fee shown above.",
                    "Approve & sign", locked, null, parties);
        }

        Erc20Call call = r.tokenCall;
        TokenList.Token token = tokens.lookup(r.chainId, r.to);
        String contract = r.contractLabel();
        String party = Keys.toChecksumAddress(call.party);
        String amount = token != null ? Erc20Call.formatUnits(call.amount, token.decimals) + " " + token.symbol
                : Erc20Call.baseUnits(call.amount);
        String assetName = token != null ? token.symbol : "tokens of unknown token contract " + contract;
        // what the Action sentence calls the amount: never a guessed symbol for an unlisted contract
        String phrase = token != null ? amount : amount + " of unknown token contract " + contract;
        String action;
        String title;
        String signLabel = "Approve & sign";
        String prompt;
        switch (call.function) {
            case TRANSFER:
                action = "Send " + phrase + " to " + party;
                title = token != null ? "Send " + amount : "Unknown token transfer";
                prompt = "I verified the signing address, network, token contract, recipient, amount, and maximum fee shown above.";
                break;
            case TRANSFER_FROM:
                action = "Move " + phrase + " from " + Keys.toChecksumAddress(call.from) + " to " + party;
                title = token != null ? "Move " + amount : "Unknown token transferFrom";
                prompt = "I verified the signing address, network, token contract, source, recipient, amount, and maximum fee shown above.";
                break;
            case APPROVE:
                if (call.unlimited()) action = "Allow " + party + " to spend UNLIMITED " + assetName;
                else if (call.amount.signum() == 0) action = "Revoke " + party + "'s permission to spend " + assetName + " (allowance set to 0)";
                else action = "Allow " + party + " to spend " + phrase;
                title = call.unlimited() ? "UNLIMITED permission" : call.amount.signum() == 0 ? "Revoke permission" : "Review permission";
                signLabel = call.unlimited() ? "Approve UNLIMITED & sign" : "Approve permission & sign";
                prompt = "I verified the signing address, network, token contract, spender, allowance, and maximum fee shown above.";
                break;
            default: // INCREASE_ALLOWANCE
                action = call.unlimited() ? "Allow " + party + " to spend UNLIMITED " + assetName
                        : "Increase " + party + "'s allowance by " + phrase;
                title = call.unlimited() ? "UNLIMITED permission" : "Review permission";
                signLabel = call.unlimited() ? "Approve UNLIMITED & sign" : "Approve permission & sign";
                prompt = "I verified the signing address, network, token contract, spender, allowance increase, and maximum fee shown above.";
                break;
        }

        rows.add(row("Action", action));
        if (!tokens.available()) {
            rows.add(row(WARNING, "The token list built into this app failed its integrity check, so no token is recognized. "
                    + "Treat every token contract as unknown. (" + tokens.problem() + ")"));
        }
        if (token == null) rows.add(row(WARNING, unknownTokenWarning(call, contract)));

        // amount
        String amountTitle = call.function == Erc20Call.Function.INCREASE_ALLOWANCE ? "Allowance increase"
                : call.function.grantsAllowance() ? "Allowance" : "Amount";
        String amountValue = call.unlimited() ? "UNLIMITED" + (token == null ? " (raw value ≥ 2^255)" : " " + token.symbol)
                : token != null ? amount : amount + " (raw uint256; symbol and decimals unknown)";
        rows.add(row(amountTitle, amountValue));

        // parties
        RecipientHistory.Role role = call.function.grantsAllowance() ? RecipientHistory.Role.APPROVE : RecipientHistory.Role.SEND;
        if (call.function == Erc20Call.Function.TRANSFER_FROM) {
            String from = Keys.toChecksumAddress(call.from);
            rows.add(row("Take from (token owner)", call.from.equals(signer) ? from + " (this wallet)" : from));
            rows.add(row("Recipient", party));
        } else {
            rows.add(row(call.function.grantsAllowance() ? "Spender (gets permission)" : "Recipient", party));
        }
        if (safety != null) rows.addAll(safety.rows(signer, call.party, role));
        if (token == null && (call.function == Erc20Call.Function.APPROVE || call.function == Erc20Call.Function.TRANSFER_FROM)) {
            // ERC-721 shares these two selectors. An unlisted contract could be either; both meanings are shown.
            rows.add(row(WARNING, "Two possible meanings: this contract is in neither the token list nor the NFT list built "
                    + "into this phone, and ERC-721 NFTs use the same function. If it is an NFT collection, this call "
                    + (call.function == Erc20Call.Function.APPROVE
                    ? "lets " + party + " take NFT #" + call.amount + " from this wallet."
                    : "moves NFT #" + call.amount + " from " + Keys.toChecksumAddress(call.from) + " to " + party + ".")
                    + " Sign only if you know which kind of contract this is."));
        }

        // token identity
        if (token != null) {
            rows.add(row("Token", token.name + " (" + token.symbol + "), " + token.decimals
                    + " decimals, from the token list built into this phone"));
            rows.add(row("Token contract", contract));
        } else {
            rows.add(row("Unknown token contract", contract));
        }

        // native value: the parser refuses nonzero value on token calls; shown anyway so the screen
        // states it, and flagged if that rule ever changes.
        if (r.value.signum() == 0) rows.add(row("Native value sent", "0 " + r.nativeSymbol() + " (only the fee below)"));
        else rows.add(row(WARNING, "This token call ALSO sends " + r.valueEth() + " to the contract."));

        // what can go wrong, in words
        String danger = callWarning(call, token, party, signer, amount, assetName);
        if (danger != null) rows.add(row(call.function.grantsAllowance() && call.amount.signum() != 0 ? DANGER : WARNING, danger));
        if (!call.function.grantsAllowance() && tokens.lookup(r.chainId, call.party) != null) {
            rows.add(row(WARNING, "The recipient is itself a token contract (" + tokens.lookup(r.chainId, call.party).symbol
                    + "). Tokens sent to a token contract are usually lost."));
        } else if (!call.function.grantsAllowance() && call.party.equals(r.to)) {
            rows.add(row(WARNING, "The recipient is the token contract itself. Tokens sent there are usually lost."));
        }

        addCommon(rows, r, signer);
        rows.add(row("Maximum fee", r.maximumFeeEth()));

        details.add(row("Function", call.function.signature + " · selector 0x" + call.function.selector));
        details.add(row(amountTitle + " in base units", call.amount.toString() + " (uint256)"));
        addFeeDetails(details, r);
        details.add(row("Contract data", r.data));

        String locked = action + " · " + network + ". Unlock to review every field before anything is signed.";
        List<Party> parties = new ArrayList<>();
        if (!(call.function.grantsAllowance() && call.amount.signum() == 0)) parties.add(new Party(call.party, role));
        return new TransactionReview(title, rows, details, prompt, signLabel, locked, token, parties);
    }

    /** "the USDC token contract", "a Uniswap router contract" …, or null when the phone knows nothing about the address. */
    static String knownContract(long chainId, String address, TokenList tokens) {
        TokenList.Token t = tokens == null ? null : tokens.lookup(chainId, address);
        if (t != null) return "the " + t.symbol + " token contract";
        NftCollections.Collection c = NftCollections.lookup(chainId, address);
        if (c != null) return "the " + c.name + " NFT contract";
        if (UniswapRouters.lookup(chainId, address) != null) return "a Uniswap router contract";
        return null;
    }

    private static String unknownTokenWarning(Erc20Call call, String contract) {
        return "Unknown token contract " + contract + ". It is not in the token list built into this phone, so its "
                + "name, symbol and decimals can't be verified: the amount is shown in raw base units ("
                + Erc20Call.formatUnits(call.amount, 0) + " base units could be a tiny fraction of a token or many whole "
                + "tokens). The phone also can't verify that this contract behaves like a token"
                + (call.function == Erc20Call.Function.APPROVE ? "; approve can also hand over an NFT." : ".");
    }

    private static String callWarning(Erc20Call call, TokenList.Token token, String party, String signer,
                                      String amount, String assetName) {
        switch (call.function) {
            case APPROVE:
                if (call.unlimited()) {
                    return "UNLIMITED allowance: " + party + " will be able to take ALL of this wallet's " + assetName
                            + ", now and in the future, until you revoke it. Approve only a contract you trust completely.";
                }
                if (call.amount.signum() == 0) return null;
                return party + " will be able to take up to " + amount + " from this wallet at any time, until the "
                        + "allowance is used up or changed. This replaces any earlier allowance for this spender.";
            case INCREASE_ALLOWANCE:
                if (call.unlimited()) {
                    return "UNLIMITED allowance: " + party + " will be able to take ALL of this wallet's " + assetName
                            + ", now and in the future, until you revoke it. Approve only a contract you trust completely.";
                }
                return "Adds " + amount + " to whatever " + party + " may already take from this wallet. This offline "
                        + "phone can't see the current allowance, so the total permission may be larger.";
            case TRANSFER_FROM:
                if (call.from.equals(signer)) {
                    return "transferFrom takes tokens from this wallet using an allowance it granted to itself. A plain "
                            + "transfer is the normal way to send; check why this form is used.";
                }
                return "transferFrom takes tokens from " + Keys.toChecksumAddress(call.from) + ", not from this wallet, "
                        + "using an allowance that address gave this wallet. Check that you mean to use that permission.";
            default:
                return null;
        }
    }

    static void addCommon(List<MessageReview.Row> rows, Eip1559Request r, String signer) {
        rows.add(row("Network", r.networkLabel()));
        if (signer != null) rows.add(row("From · Account 1", Keys.toChecksumAddress(signer)));
    }

    static void addFeeDetails(List<MessageReview.Row> details, Eip1559Request r) {
        details.add(row("Maximum fee in wei", r.maximumFeeWeiLabel()));
        details.add(row("What the fee covers", r.feeCoverageLabel()));
        details.add(row("Gas limit", r.gasLimitLabel()));
        details.add(row("Maximum fee per gas", r.maxFeePerGasLabel()));
        details.add(row("Priority fee per gas", r.maxPriorityFeePerGasLabel()));
        details.add(row("Nonce", r.nonce.toString()));
    }

    static String shortAddress(String address) {
        return address.length() > 14 ? address.substring(0, 8) + "…" + address.substring(address.length() - 6) : address;
    }

    static MessageReview.Row row(String label, String value) { return new MessageReview.Row(label, value); }

    /** Every row, summary then details, one per line (tests and logs of the review model, never keys). */
    String text() {
        StringBuilder out = new StringBuilder(title).append('\n');
        for (MessageReview.Row row : summary) out.append(row).append('\n');
        for (MessageReview.Row row : details) out.append(row).append('\n');
        return out.toString();
    }
}
