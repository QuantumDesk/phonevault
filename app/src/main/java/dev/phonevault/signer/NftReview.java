package dev.phonevault.signer;

import org.web3j.crypto.Keys;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import static dev.phonevault.signer.TransactionReview.DANGER;
import static dev.phonevault.signer.TransactionReview.WARNING;
import static dev.phonevault.signer.TransactionReview.row;

/**
 * Plain-language review of NFT calls (ERC-721 and ERC-1155), built from the same parsed
 * {@link Eip1559Request} that is signed. The collection's name comes only from the built-in
 * {@link NftCollections} list; any other contract is an "unknown collection" (never a guessed or
 * host-supplied name).
 */
final class NftReview {
    private NftReview() {}

    static String collectionLabel(long chainId, String contract) {
        NftCollections.Collection c = NftCollections.lookup(chainId, contract);
        return c != null ? c.name + " (" + c.standard + ", from the list built into this phone)"
                : "Unknown collection " + Keys.toChecksumAddress(contract) + " (its name is not in the list built into this phone)";
    }

    private static String shortCollection(long chainId, String contract) {
        NftCollections.Collection c = NftCollections.lookup(chainId, contract);
        return c != null ? c.name : "unknown collection " + Keys.toChecksumAddress(contract);
    }

    /** setApprovalForAll / safeTransferFrom / safeBatchTransferFrom. */
    static TransactionReview build(Eip1559Request r, String signerAddress, TokenList tokens, AddressSafety safety, String fromLabel) {
        NftCall call = r.nftCall;
        String signer = signerAddress == null ? null : signerAddress.toLowerCase(Locale.ROOT);
        List<MessageReview.Row> rows = new ArrayList<>();
        List<MessageReview.Row> details = new ArrayList<>();
        List<TransactionReview.Party> parties = new ArrayList<>();
        String collection = shortCollection(r.chainId, r.to);
        String party = Keys.toChecksumAddress(call.party);
        String title, action, prompt, signLabel = "Approve & sign";

        if (call.function == NftCall.Function.SET_APPROVAL_FOR_ALL) {
            if (call.approved) {
                title = "Permission for EVERY NFT";
                action = "Let " + party + " move EVERY NFT in " + collection + ", now and in future";
                rows.add(row("Action", action));
                rows.add(row(DANGER, "Lets " + party + " move EVERY NFT in this collection, now and in future, including NFTs "
                        + "this wallet receives later, without asking again, until you revoke it. Scammers ask for exactly "
                        + "this. Approve only a marketplace or app you trust completely."));
                rows.add(row("Operator (gets permission)", party));
                if (safety != null) rows.addAll(safety.rows(signer, call.party, RecipientHistory.Role.APPROVE));
                parties.add(new TransactionReview.Party(call.party, RecipientHistory.Role.APPROVE));
                signLabel = "Approve ALL NFTs & sign";
                prompt = "I verified the collection, the operator, the network, and that it may move ALL my NFTs in this collection.";
            } else {
                title = "Revoke NFT permission";
                action = "Revoke " + party + "'s permission to move your NFTs in " + collection;
                rows.add(row("Action", action));
                rows.add(row("Operator (loses permission)", party));
                if (safety != null && safety.contactName(call.party) != null) {
                    rows.add(row(AddressSafety.CONTACT, safety.contactName(call.party) + " (named on this phone)"));
                }
                prompt = "I verified the collection, the operator, and the network shown above.";
            }
        } else {
            boolean batch = call.function == NftCall.Function.SAFE_BATCH_TRANSFER_1155;
            String what = what(call);
            title = batch ? "Send " + call.tokenIds.size() + " NFT items" : "Send " + what;
            action = "Send " + what + " of " + collection + " from " + Keys.toChecksumAddress(call.from) + " to " + party;
            rows.add(row("Action", action));
            rows.add(row("Recipient", party));
            if (safety != null) rows.addAll(safety.rows(signer, call.party, RecipientHistory.Role.SEND));
            parties.add(new TransactionReview.Party(call.party, RecipientHistory.Role.SEND));
            if (batch) {
                for (int i = 0; i < call.tokenIds.size(); i++) {
                    rows.add(row("Item " + (i + 1), "#" + call.tokenIds.get(i) + " × " + call.amounts.get(i)));
                }
            } else {
                rows.add(row("Token ID", "#" + call.tokenIds.get(0)));
                if (call.function.erc1155()) rows.add(row("Amount", call.amounts.get(0).toString()));
            }
            String from = Keys.toChecksumAddress(call.from);
            rows.add(row("From (current owner)", call.from.equals(signer) ? from + " (this wallet)" : from));
            if (!call.from.equals(signer)) {
                rows.add(row(WARNING, "The NFT is taken from " + from + ", not from this wallet, using a permission that "
                        + "address gave this wallet. Check that you mean to use that permission."));
            }
            if (call.party.equals(r.to)) rows.add(row(WARNING, "The recipient is the NFT contract itself. NFTs sent there are usually lost."));
            if (call.data.length > 0) {
                rows.add(row(WARNING, "Also passes " + call.data.length + " bytes of data to the recipient, which the phone "
                        + "cannot interpret (see Details)."));
                details.add(row("Data for the recipient", "0x" + Abi.toHex(call.data)));
            }
            prompt = "I verified the collection, item, recipient, network, and maximum fee shown above.";
        }

        rows.add(row(NftCollections.lookup(r.chainId, r.to) != null ? "Collection" : WARNING, collectionLabel(r.chainId, r.to)));
        rows.add(row("Collection contract", Keys.toChecksumAddress(r.to)));
        TokenList.Token fungible = tokens.lookup(r.chainId, r.to);
        if (fungible != null) {
            rows.add(row(WARNING, "This contract is the " + fungible.symbol + " token in the list built into this phone, not "
                    + "an NFT collection. An NFT call to it is unexpected."));
        }
        rows.add(row("Native value sent", "0 " + r.nativeSymbol() + " (only the fee below)"));
        TransactionReview.addCommon(rows, details, r, signer, fromLabel);
        TransactionReview.addMaximumFee(rows, r);

        details.add(0, row("Function", call.function.signature + " · selector 0x" + call.function.selector));
        TransactionReview.addFeeDetails(details, r);
        details.add(row("Contract data", r.data));
        String locked = action + " · " + r.networkLabel() + ". Unlock to review every field before anything is signed.";
        return new TransactionReview(title, rows, details, prompt, signLabel, locked, null, parties);
    }

    private static String what(NftCall call) {
        if (call.function == NftCall.Function.SAFE_BATCH_TRANSFER_1155) return call.tokenIds.size() + " NFT items";
        if (call.function.erc1155()) return call.amounts.get(0) + " × NFT #" + call.tokenIds.get(0);
        return "NFT #" + call.tokenIds.get(0);
    }

    /** approve(to, tokenId) / transferFrom(from, to, tokenId) on a collection in {@link NftCollections}. */
    static TransactionReview buildErc721(Eip1559Request r, String signerAddress, TokenList tokens, AddressSafety safety, String fromLabel) {
        Erc20Call call = r.tokenCall;
        String signer = signerAddress == null ? null : signerAddress.toLowerCase(Locale.ROOT);
        List<MessageReview.Row> rows = new ArrayList<>();
        List<MessageReview.Row> details = new ArrayList<>();
        List<TransactionReview.Party> parties = new ArrayList<>();
        String collection = shortCollection(r.chainId, r.to);
        String party = Keys.toChecksumAddress(call.party);
        BigInteger id = call.amount;
        String title, action, prompt, signLabel;
        if (call.function == Erc20Call.Function.APPROVE) {
            title = "Permission for NFT #" + id;
            action = "Allow " + party + " to take NFT #" + id + " of " + collection;
            rows.add(row("Action", action));
            rows.add(row(DANGER, party + " will be able to take NFT #" + id + " from this wallet at any time, until it "
                    + "moves or the approval is changed."));
            rows.add(row("Spender (gets permission)", party));
            if (safety != null) rows.addAll(safety.rows(signer, call.party, RecipientHistory.Role.APPROVE));
            parties.add(new TransactionReview.Party(call.party, RecipientHistory.Role.APPROVE));
            signLabel = "Approve permission & sign";
            prompt = "I verified the collection, the NFT, the spender, and the network shown above.";
        } else {
            title = "Move NFT #" + id;
            String from = Keys.toChecksumAddress(call.from);
            action = "Move NFT #" + id + " of " + collection + " from " + from + " to " + party;
            rows.add(row("Action", action));
            rows.add(row("Recipient", party));
            if (safety != null) rows.addAll(safety.rows(signer, call.party, RecipientHistory.Role.SEND));
            parties.add(new TransactionReview.Party(call.party, RecipientHistory.Role.SEND));
            rows.add(row("From (current owner)", call.from.equals(signer) ? from + " (this wallet)" : from));
            if (!call.from.equals(signer)) {
                rows.add(row(WARNING, "The NFT is taken from " + from + ", not from this wallet, using a permission that "
                        + "address gave this wallet."));
            }
            rows.add(row("Note", "transferFrom does not check that the recipient can receive NFTs; an NFT sent to a "
                    + "contract that cannot handle it may be stuck forever."));
            signLabel = "Approve & sign";
            prompt = "I verified the collection, the NFT, the recipient, and the network shown above.";
        }
        rows.add(row("Token ID", "#" + id));
        rows.add(row("Collection", collectionLabel(r.chainId, r.to)));
        rows.add(row("Collection contract", Keys.toChecksumAddress(r.to)));
        rows.add(row("Native value sent", "0 " + r.nativeSymbol() + " (only the fee below)"));
        TransactionReview.addCommon(rows, details, r, signer, fromLabel);
        TransactionReview.addMaximumFee(rows, r);
        details.add(row("Function", call.function.signature + " · selector 0x" + call.function.selector + " (ERC-721 meaning: this contract is a listed NFT collection)"));
        TransactionReview.addFeeDetails(details, r);
        details.add(row("Contract data", r.data));
        String locked = action + " · " + r.networkLabel() + ". Unlock to review every field before anything is signed.";
        return new TransactionReview(title, rows, details, prompt, signLabel, locked, null, parties);
    }
}
