package dev.phonevault.signer;

import org.json.JSONException;
import org.json.JSONObject;
import org.web3j.crypto.Keys;
import org.web3j.utils.Numeric;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

final class Eip1559Request {
    private static final int MAX_ID_LENGTH = 128;
    private static final int MAX_QUANTITY_BITS = 256;
    private static final BigInteger UINT256_MAX = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE);
    private static final Set<String> REQUEST_FIELDS = new HashSet<>(Arrays.asList(
            "id", "method", "chainId", "nonce", "maxPriorityFeePerGas",
            "maxFeePerGas", "gasLimit", "to", "value", "data"));

    enum Kind {
        NATIVE_TRANSFER, TOKEN_TRANSFER, TOKEN_APPROVAL, TOKEN_TRANSFER_FROM, TOKEN_INCREASE_ALLOWANCE,
        /** setApprovalForAll / safeTransferFrom (ERC-721, ERC-1155): {@link #nftCall}. */
        NFT_CALL,
        /** A call to a pinned Uniswap router: {@link #swap}. */
        SWAP
    }

    final String id;
    final long chainId;
    final BigInteger nonce;
    final BigInteger maxPriorityFeePerGas;
    final BigInteger maxFeePerGas;
    final BigInteger gasLimit;
    final String to;
    final BigInteger value;
    final String data;
    final Kind kind;
    final String displayedRecipient;
    final BigInteger displayedAmount;
    /** The decoded ERC-20 call for token kinds; null for a native transfer. */
    final Erc20Call tokenCall;
    /** The decoded NFT call for {@link Kind#NFT_CALL}; otherwise null. */
    final NftCall nftCall;
    /** The decoded router call for {@link Kind#SWAP}; otherwise null. */
    final SwapPlan swap;

    private Eip1559Request(String id, long chainId, BigInteger nonce,
                           BigInteger maxPriorityFeePerGas, BigInteger maxFeePerGas,
                           BigInteger gasLimit, String to, BigInteger value, String data,
                           Kind kind, String displayedRecipient, BigInteger displayedAmount, Erc20Call tokenCall,
                           NftCall nftCall, SwapPlan swap) {
        this.id = id;
        this.chainId = chainId;
        this.nonce = nonce;
        this.maxPriorityFeePerGas = maxPriorityFeePerGas;
        this.maxFeePerGas = maxFeePerGas;
        this.gasLimit = gasLimit;
        this.to = to;
        this.value = value;
        this.data = data;
        this.kind = kind;
        this.displayedRecipient = displayedRecipient;
        this.displayedAmount = displayedAmount;
        this.tokenCall = tokenCall;
        this.nftCall = nftCall;
        this.swap = swap;
    }

    static Eip1559Request parse(JSONObject json) throws JSONException {
        // The only transaction this phone builds is EIP-1559 (type 0x02): the request has no type
        // field and EvmSigner always encodes 0x02. A host asking for an EIP-7702 set-code
        // transaction (type 0x04, authorizationList) gets an explicit refusal, not a schema error.
        if (json.has("authorizationList") || "0x4".equals(json.optString("type")) || "0x04".equals(json.optString("type"))
                || "4".equals(json.optString("type"))) {
            throw RequestRefusal.delegation("type-4 set-code transaction");
        }
        requireExactFields(json, REQUEST_FIELDS);
        if (!"signEip1559".equals(json.getString("method"))) {
            throw new JSONException("Unsupported method");
        }
        String id = validatedId(json.getString("id"));
        BigInteger chainIdValue = quantity(json.getString("chainId"));
        // BigInteger.longValueExact needs API 31; the APK advertises minSdk 28. Equivalent check.
        if (chainIdValue.signum() < 0 || chainIdValue.bitLength() > 63) {
            throw new JSONException("chainId out of range");
        }
        long chainId = chainIdValue.longValue();
        BigInteger nonce = quantity(json.getString("nonce"));
        BigInteger priority = quantity(json.getString("maxPriorityFeePerGas"));
        BigInteger fee = quantity(json.getString("maxFeePerGas"));
        BigInteger gas = quantity(json.getString("gasLimit"));
        String to = json.getString("to");
        BigInteger value = quantity(json.getString("value"));
        String data = json.getString("data");

        if (chainId <= 0) throw new JSONException("chainId must be positive");
        if (!supportedChain(chainId)) throw new JSONException("Unsupported network: no reviewed chain profile for " + chainId);
        if (!to.matches("0x[0-9a-fA-F]{40}")) throw new JSONException("Invalid destination address");
        if (nonce.signum() < 0 || priority.signum() < 0 || fee.signum() < 0 || gas.signum() <= 0 || value.signum() < 0) {
            throw new JSONException("Transaction quantities must not be negative");
        }
        if (priority.compareTo(fee) > 0) throw new JSONException("Priority fee exceeds maximum fee");
        if (!Numeric.containsHexPrefix(data) || !data.matches("0x[0-9a-fA-F]*") || ((data.length() - 2) & 1) != 0) {
            throw new JSONException("data must be even-length 0x-prefixed hex");
        }
        if (nonce.bitLength() > MAX_QUANTITY_BITS || priority.bitLength() > MAX_QUANTITY_BITS
                || fee.bitLength() > MAX_QUANTITY_BITS || gas.bitLength() > MAX_QUANTITY_BITS
                || value.bitLength() > MAX_QUANTITY_BITS) {
            throw new JSONException("Transaction quantity exceeds 256 bits");
        }

        String normalizedTo = normalizeAddress(to);
        Kind kind;
        String recipient;
        BigInteger displayedAmount;
        Erc20Call call = null;
        NftCall nft = null;
        SwapPlan swap = null;
        String selector = data.length() >= 10 ? data.substring(2, 10).toLowerCase(java.util.Locale.ROOT) : null;
        UniswapRouters.Router router = UniswapRouters.lookup(chainId, normalizedTo);
        if ("0x".equals(data)) {
            kind = Kind.NATIVE_TRANSFER;
            recipient = normalizedTo;
            displayedAmount = value;
        } else if (router != null) {
            // Every call to a pinned router is decoded in full or refused (SwapPlan.CANNOT_EXPLAIN).
            swap = SwapDecoder.decode(router, data, value);
            kind = Kind.SWAP;
            recipient = normalizedTo;
            displayedAmount = value;
        } else if (selector != null && NftCall.handles(selector)) {
            nft = NftCall.decode(data);
            if (value.signum() != 0) throw new JSONException(nft.function.signature + " must not include native value");
            kind = Kind.NFT_CALL;
            recipient = nft.party;
            displayedAmount = nft.tokenIds.isEmpty() ? BigInteger.ZERO : nft.tokenIds.get(0);
        } else if (selector != null && !Erc20Call.handles(selector)) {
            // Refuse by default: calldata the phone cannot fully decode is never offered for blind approval.
            throw RequestRefusal.unknownCall(Keys.toChecksumAddress(normalizedTo), selector);
        } else {
            call = parseTokenCall(data, value);
            kind = kindOf(call.function);
            recipient = call.party;
            displayedAmount = call.amount;
        }
        return new Eip1559Request(id, chainId, nonce, priority, fee, gas,
                normalizedTo, value, data.toLowerCase(java.util.Locale.ROOT), kind, recipient, displayedAmount, call, nft, swap);
    }

    static String validatedId(String id) throws JSONException {
        if (id == null || id.length() > MAX_ID_LENGTH
                || !id.matches("[A-Za-z0-9._:-]+")) {
            throw new JSONException("Invalid request id");
        }
        return id;
    }

    static void requireExactFields(JSONObject json, String... expected) throws JSONException {
        requireExactFields(json, new HashSet<>(Arrays.asList(expected)));
    }

    private static void requireExactFields(JSONObject json, Set<String> expected)
            throws JSONException {
        Set<String> actual = new HashSet<>();
        Iterator<String> keys = json.keys();
        while (keys.hasNext()) actual.add(keys.next());
        if (!actual.equals(expected)) {
            Set<String> missing = new HashSet<>(expected);
            missing.removeAll(actual);
            Set<String> unknown = new HashSet<>(actual);
            unknown.removeAll(expected);
            throw new JSONException("Request fields do not match schema; missing="
                    + missing + ", unknown=" + unknown);
        }
    }

    private static Erc20Call parseTokenCall(String data, BigInteger value) throws JSONException {
        Erc20Call call = Erc20Call.decode(data);
        // Unchanged rule: a token call carries no native value, so the review never has to explain one.
        if (value.signum() != 0) throw new JSONException(call.function.signature + " must not include native value");
        return call;
    }

    private static Kind kindOf(Erc20Call.Function function) {
        switch (function) {
            case TRANSFER: return Kind.TOKEN_TRANSFER;
            case APPROVE: return Kind.TOKEN_APPROVAL;
            case TRANSFER_FROM: return Kind.TOKEN_TRANSFER_FROM;
            default: return Kind.TOKEN_INCREASE_ALLOWANCE;
        }
    }

    /** approve or increaseAllowance: grants a spender permission. */
    boolean grantsAllowance() {
        return kind == Kind.TOKEN_APPROVAL || kind == Kind.TOKEN_INCREASE_ALLOWANCE;
    }

    private static String normalizeAddress(String address) throws JSONException {
        String normalized = "0x" + Numeric.cleanHexPrefix(address).toLowerCase(java.util.Locale.ROOT);
        if (normalized.matches("0x0{40}")) throw new JSONException("Zero destination address is not allowed");
        return normalized;
    }

    static BigInteger quantity(String value) throws JSONException {
        try {
            if (!value.matches("0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)")) {
                throw new JSONException("Non-canonical hex quantity: " + value);
            }
            return new BigInteger(value.substring(2), 16);
        } catch (ArithmeticException | NumberFormatException exception) {
            throw new JSONException("Invalid quantity: " + value);
        }
    }

    String networkLabel() {
        return networkLabel(chainId);
    }

    /** Also used by message review, so both screens name networks identically. */
    static String networkLabel(long chainId) {
        if (chainId == 1) return "Ethereum Mainnet (chain ID 1)";
        if (chainId == 8453) return "Base (chain ID 8453)";
        if (chainId == 42161) return "Arbitrum One (chain ID 42161)";
        if (chainId == 10) return "Optimism (chain ID 10)";
        if (chainId == 137) return "Polygon (chain ID 137)";
        if (chainId == 11155111) return "Sepolia Testnet (chain ID 11155111)";
        return "Unknown network (chain ID " + chainId + ")";
    }

    static boolean supportedChain(long id) {
        return id == 1 || id == 11155111 || id == 8453 || id == 10 || id == 42161 || id == 137;
    }

    String feeCoverageLabel() {
        if (chainId == 1 || chainId == 11155111)
            return "This bounds execution gas, not the amount sent. Actual execution fees may be lower.";
        if (chainId == 10 || chainId == 8453)
            return "Not a total fee cap. This network may also charge L1 data and operator fees that this offline phone cannot independently bound.";
        if (chainId == 42161)
            return "This is the transaction gas bound. L1 posting charges and network-specific accounting cannot be independently checked offline.";
        return "Execution gas bound only. Verify network-specific charges with your host; this phone has no live network state.";
    }

    String displayedRecipientLabel() {
        return Keys.toChecksumAddress(displayedRecipient);
    }

    String contractLabel() {
        return Keys.toChecksumAddress(to);
    }

    /** The native coin's ticker for the allow-listed chains; "native token" when unknown. */
    String nativeSymbol() {
        if (chainId == 137) return "POL";
        if (chainId == 1 || chainId == 11155111 || chainId == 8453 || chainId == 10 || chainId == 42161) return "ETH";
        return "native token";
    }

    String valueEth() {
        return new BigDecimal(value).movePointLeft(18).stripTrailingZeros().toPlainString() + " " + nativeSymbol();
    }

    String transactionTypeLabel() {
        if (kind == Kind.NATIVE_TRANSFER) return "Native token transfer";
        if (kind == Kind.TOKEN_TRANSFER) return "Token transfer (interface unverified)";
        if (kind == Kind.TOKEN_TRANSFER_FROM) return "Token transferFrom (interface unverified)";
        if (kind == Kind.TOKEN_INCREASE_ALLOWANCE) return "Token allowance increase (interface unverified)";
        return "Token approval (interface unverified)";
    }

    String displayedAmountLabel() {
        if (kind == Kind.NATIVE_TRANSFER) return valueEth();
        if (grantsAllowance() && UINT256_MAX.equals(displayedAmount)) {
            return "MAXIMUM uint256 (commonly unlimited ERC-20 allowance)";
        }
        return displayedAmount.toString() + " raw uint256 argument (token decimals unverified)";
    }

    String displayedAmountTitle() {
        return grantsAllowance() ? "Allowance / token ID" : "Send";
    }

    String displayedPartyTitle() {
        return grantsAllowance() ? "Spender / approved address" : "Recipient";
    }

    String contractDataLabel() {
        if (kind == Kind.NATIVE_TRANSFER) return "None";
        if (kind == Kind.TOKEN_TRANSFER) {
            return "Selector 0xa9059cbb: transfer(address,uint256); contract interface and semantics unverified";
        }
        if (kind == Kind.TOKEN_APPROVAL) {
            return "Selector 0x095ea7b3: approve(address,uint256); contract interface and semantics unverified";
        }
        return "Selector 0x" + tokenCall.function.selector + ": " + tokenCall.function.signature
                + "; contract interface and semantics unverified";
    }

    String reviewPrompt() {
        if (grantsAllowance()) {
            return "I verified the signing address, network, target contract, decoded approved-address and allowance/token-ID arguments, and maximum fee shown above.";
        }
        if (kind == Kind.TOKEN_TRANSFER || kind == Kind.TOKEN_TRANSFER_FROM) {
            return "I verified the signing address, network, target contract, decoded recipient and amount arguments, and maximum fee shown above.";
        }
        return "I verified the signing address, network, recipient, amount, and maximum fee shown above.";
    }

    String contractWarningTitle() {
        return grantsAllowance() ? "DANGER" : "Warning";
    }

    String contractWarningLabel() {
        if (kind == Kind.TOKEN_TRANSFER) {
            return "The 0xa9059cbb selector resembles transfer(address,uint256), but the offline signer cannot verify the contract interface, execution semantics, token identity, or decimals.";
        }
        if (kind == Kind.TOKEN_TRANSFER_FROM) {
            return "transferFrom(address,address,uint256) moves tokens out of the decoded source address using an allowance. The offline signer cannot verify the contract interface, execution semantics, token identity, or decimals.";
        }
        if (kind == Kind.TOKEN_INCREASE_ALLOWANCE) {
            return "increaseAllowance(address,uint256) adds to an existing allowance. The offline signer cannot verify the contract interface, execution semantics, token identity, decimals, or the current allowance.";
        }
        if (kind == Kind.TOKEN_APPROVAL) {
            return "approve(address,uint256) may grant a fungible-token allowance or approve an NFT. The offline signer cannot verify the contract interface, execution semantics, token identity, or decimals.";
        }
        return "Offline signer cannot verify whether the recipient is a contract or what code it may execute.";
    }

    /** Upper bound on what execution can cost, in the native coin: gas limit × max fee per gas. */
    String maximumFeeEth() {
        BigInteger maximumFeeWei = gasLimit.multiply(maxFeePerGas);
        String nativeAmount = new BigDecimal(maximumFeeWei).movePointLeft(18)
                .stripTrailingZeros().toPlainString();
        return "up to " + nativeAmount + " " + nativeSymbol();
    }

    String maximumFeeWeiLabel() {
        return gasLimit.multiply(maxFeePerGas).toString() + " wei (gas limit × max fee per gas)";
    }

    String gasLimitLabel() {
        return gasLimit + " gas (" + canonicalQuantity(gasLimit) + ")";
    }

    String maxFeePerGasLabel() {
        return feeRateLabel(maxFeePerGas);
    }

    String maxPriorityFeePerGasLabel() {
        return feeRateLabel(maxPriorityFeePerGas);
    }

    private static String feeRateLabel(BigInteger wei) {
        String gwei = new BigDecimal(wei).movePointLeft(9).stripTrailingZeros().toPlainString();
        return gwei + " gwei (" + wei + " wei, " + canonicalQuantity(wei) + ")";
    }

    private static String canonicalQuantity(BigInteger value) {
        return "0x" + value.toString(16);
    }
}
