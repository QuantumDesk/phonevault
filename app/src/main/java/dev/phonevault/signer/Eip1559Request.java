package dev.phonevault.signer;

import org.json.JSONException;
import org.json.JSONObject;
import org.web3j.crypto.Keys;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

final class Eip1559Request {
    private static final int MAX_ID_LENGTH = 128;
    private static final int MAX_QUANTITY_BITS = 256;
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
    /**
     * Optional signer the host expects (lowercase 0x address), or null. Not part of what is
     * signed: a request naming another account than the phone's active one is refused
     * ({@link RequestRefusal#requireFrom}).
     */
    final String from;
    /**
     * The Mac's simulation claim, or null. Display only: never signed ({@link EvmSigner} does not
     * read it) and never used to decode the transaction.
     */
    final HostSimulation hostSimulation;

    private Eip1559Request(String id, long chainId, BigInteger nonce,
                           BigInteger maxPriorityFeePerGas, BigInteger maxFeePerGas,
                           BigInteger gasLimit, String to, BigInteger value, String data,
                           Kind kind, String displayedRecipient, BigInteger displayedAmount, Erc20Call tokenCall,
                           NftCall nftCall, SwapPlan swap, String from, HostSimulation hostSimulation) {
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
        this.from = from;
        this.hostSimulation = hostSimulation;
    }

    static Eip1559Request parse(JSONObject json) throws JSONException {
        // The only transaction this phone builds is EIP-1559 (type 0x02): the request has no type
        // field and EvmSigner always encodes 0x02. A host asking for an EIP-7702 set-code
        // transaction (type 0x04, authorizationList) gets an explicit refusal, not a schema error.
        if (json.has("authorizationList") || "0x4".equals(json.optString("type")) || "0x04".equals(json.optString("type"))
                || "4".equals(json.optString("type"))) {
            throw RequestRefusal.delegation("type-4 set-code transaction");
        }
        // Exact field set: the required fields plus only the optional ones actually present
        // (from: the account the host expects; hostSimulation: the Mac's untrusted claim).
        String from = optionalFrom(json);
        Set<String> fields = new HashSet<>(REQUEST_FIELDS);
        if (from != null) fields.add("from");
        if (json.has(HostSimulation.FIELD)) fields.add(HostSimulation.FIELD);
        requireExactFields(json, fields);
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
        HostSimulation hostSimulation = json.has(HostSimulation.FIELD) ? HostSimulation.parse(json.get(HostSimulation.FIELD)) : null;

        if (chainId <= 0) throw new JSONException("chainId must be positive");
        if (!supportedChain(chainId)) throw new JSONException("Unsupported network: no reviewed chain profile for " + chainId);
        if (!Addresses.isEvm(to)) throw new JSONException("Invalid destination address");
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
                normalizedTo, value, data.toLowerCase(java.util.Locale.ROOT), kind, recipient, displayedAmount,
                call, nft, swap, from, hostSimulation);
    }

    /**
     * The optional {@code from} field (WalletConnect / extension requests name their account): a
     * strict 0x + 40 hex string, returned lowercase; null when absent. Anything else is refused.
     */
    static String optionalFrom(JSONObject json) throws JSONException {
        if (!json.has("from")) return null;
        Object value = json.get("from");
        if (!(value instanceof String) || !Addresses.isEvm((String) value)) {
            throw new JSONException("from must be a 0x address with 40 hex characters");
        }
        return Addresses.lowercase((String) value);
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

    private static String normalizeAddress(String address) throws JSONException {
        String normalized = "0x" + Numeric.cleanHexPrefix(address).toLowerCase(java.util.Locale.ROOT);
        if (Addresses.isZero(normalized)) throw new JSONException("Zero destination address is not allowed");
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
        return "Execution gas bound only. Verify network-specific charges on your Mac; this phone has no live network state.";
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
        return Units.format(value, 18, false) + " " + nativeSymbol();
    }

    String transactionTypeLabel() {
        if (kind == Kind.NATIVE_TRANSFER) return "Send " + nativeSymbol(); // "Send ETH", "Send POL"
        if (kind == Kind.TOKEN_TRANSFER) return "Token transfer (interface unverified)";
        if (kind == Kind.TOKEN_TRANSFER_FROM) return "Token transferFrom (interface unverified)";
        if (kind == Kind.TOKEN_INCREASE_ALLOWANCE) return "Token allowance increase (interface unverified)";
        return "Token approval (interface unverified)";
    }

    /** Upper bound on what execution can cost, in the native coin: gas limit × max fee per gas. */
    String maximumFeeEth() {
        BigInteger maximumFeeWei = gasLimit.multiply(maxFeePerGas);
        return "up to " + Units.format(maximumFeeWei, 18, false) + " " + nativeSymbol();
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
        String gwei = Units.format(wei, 9, false);
        return gwei + " gwei (" + wei + " wei, " + canonicalQuantity(wei) + ")";
    }

    private static String canonicalQuantity(BigInteger value) {
        return "0x" + value.toString(16);
    }
}
