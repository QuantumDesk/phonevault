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
    private static final int TOKEN_CALL_DATA_BYTES = 68;
    private static final String TOKEN_TRANSFER_SELECTOR = "a9059cbb";
    private static final String TOKEN_APPROVE_SELECTOR = "095ea7b3";
    private static final BigInteger UINT256_MAX = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE);
    private static final Set<String> REQUEST_FIELDS = new HashSet<>(Arrays.asList(
            "id", "method", "chainId", "nonce", "maxPriorityFeePerGas",
            "maxFeePerGas", "gasLimit", "to", "value", "data"));

    enum Kind { NATIVE_TRANSFER, TOKEN_TRANSFER, TOKEN_APPROVAL }

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

    private Eip1559Request(String id, long chainId, BigInteger nonce,
                           BigInteger maxPriorityFeePerGas, BigInteger maxFeePerGas,
                           BigInteger gasLimit, String to, BigInteger value, String data,
                           Kind kind, String displayedRecipient, BigInteger displayedAmount) {
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
    }

    static Eip1559Request parse(JSONObject json) throws JSONException {
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
        if ("0x".equals(data)) {
            kind = Kind.NATIVE_TRANSFER;
            recipient = normalizedTo;
            displayedAmount = value;
        } else {
            TokenCall call = parseTokenCall(data, value);
            kind = call.kind;
            recipient = call.party;
            displayedAmount = call.amount;
        }
        return new Eip1559Request(id, chainId, nonce, priority, fee, gas,
                normalizedTo, value, data.toLowerCase(), kind, recipient, displayedAmount);
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

    private static TokenCall parseTokenCall(String data, BigInteger value) throws JSONException {
        String clean = Numeric.cleanHexPrefix(data);
        if (clean.length() != TOKEN_CALL_DATA_BYTES * 2) {
            throw new JSONException("Only canonical transfer(address,uint256) and approve(address,uint256) calldata is supported");
        }
        String selector = clean.substring(0, 8).toLowerCase();
        Kind kind;
        String partyName;
        String callName;
        if (TOKEN_TRANSFER_SELECTOR.equals(selector)) {
            kind = Kind.TOKEN_TRANSFER;
            partyName = "recipient";
            callName = "transfer(address,uint256)";
        } else if (TOKEN_APPROVE_SELECTOR.equals(selector)) {
            kind = Kind.TOKEN_APPROVAL;
            partyName = "approved address";
            callName = "token approval";
        } else {
            throw new JSONException("Only canonical transfer(address,uint256) and approve(address,uint256) calldata is supported");
        }
        if (value.signum() != 0) throw new JSONException(callName + " must not include native value");
        String addressWord = clean.substring(8, 72);
        if (!addressWord.substring(0, 24).matches("0{24}")) {
            throw new JSONException(partyName + " has non-zero ABI padding");
        }
        String party = normalizeAddress("0x" + addressWord.substring(24));
        BigInteger amount = new BigInteger(clean.substring(72, 136), 16);
        return new TokenCall(kind, party, amount);
    }

    private static String normalizeAddress(String address) throws JSONException {
        String normalized = "0x" + Numeric.cleanHexPrefix(address).toLowerCase();
        if (normalized.matches("0x0{40}")) throw new JSONException("Zero destination address is not allowed");
        return normalized;
    }

    private static final class TokenCall {
        final Kind kind;
        final String party;
        final BigInteger amount;

        TokenCall(Kind kind, String party, BigInteger amount) {
            this.kind = kind;
            this.party = party;
            this.amount = amount;
        }
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
        if (chainId == 1) return "Ethereum Mainnet (chain ID 1)";
        if (chainId == 8453) return "Base (chain ID 8453)";
        if (chainId == 42161) return "Arbitrum One (chain ID 42161)";
        if (chainId == 10) return "Optimism (chain ID 10)";
        if (chainId == 137) return "Polygon (chain ID 137)";
        if (chainId == 11155111) return "Sepolia Testnet (chain ID 11155111)";
        return "Unknown network (chain ID " + chainId + ")";
    }

    String displayedRecipientLabel() {
        return Keys.toChecksumAddress(displayedRecipient);
    }

    String contractLabel() {
        return Keys.toChecksumAddress(to);
    }

    String valueEth() {
        return new BigDecimal(value).movePointLeft(18).stripTrailingZeros().toPlainString() + " native token";
    }

    String transactionTypeLabel() {
        if (kind == Kind.NATIVE_TRANSFER) return "Native token transfer";
        if (kind == Kind.TOKEN_TRANSFER) return "Token transfer (interface unverified)";
        return "Token approval (interface unverified)";
    }

    String displayedAmountLabel() {
        if (kind == Kind.NATIVE_TRANSFER) return valueEth();
        if (kind == Kind.TOKEN_APPROVAL && UINT256_MAX.equals(displayedAmount)) {
            return "MAXIMUM uint256 (commonly unlimited ERC-20 allowance)";
        }
        return displayedAmount.toString() + " raw uint256 argument (token decimals unverified)";
    }

    String displayedAmountTitle() {
        return kind == Kind.TOKEN_APPROVAL ? "Allowance / token ID" : "Send";
    }

    String displayedPartyTitle() {
        return kind == Kind.TOKEN_APPROVAL ? "Spender / approved address" : "Recipient";
    }

    String contractDataLabel() {
        if (kind == Kind.NATIVE_TRANSFER) return "None";
        if (kind == Kind.TOKEN_TRANSFER) {
            return "Selector 0xa9059cbb: transfer(address,uint256); contract interface and semantics unverified";
        }
        return "Selector 0x095ea7b3: approve(address,uint256); contract interface and semantics unverified";
    }

    String reviewPrompt() {
        if (kind == Kind.TOKEN_APPROVAL) {
            return "I verified the signing address, network, target contract, decoded approved-address and allowance/token-ID arguments, and maximum fee shown above.";
        }
        if (kind == Kind.TOKEN_TRANSFER) {
            return "I verified the signing address, network, target contract, decoded recipient and amount arguments, and maximum fee shown above.";
        }
        return "I verified the signing address, network, recipient, amount, and maximum fee shown above.";
    }

    String contractWarningTitle() {
        return kind == Kind.TOKEN_APPROVAL ? "DANGER" : "Warning";
    }

    String contractWarningLabel() {
        if (kind == Kind.TOKEN_TRANSFER) {
            return "The 0xa9059cbb selector resembles transfer(address,uint256), but the offline signer cannot verify the contract interface, execution semantics, token identity, or decimals.";
        }
        if (kind == Kind.TOKEN_APPROVAL) {
            return "approve(address,uint256) may grant a fungible-token allowance or approve an NFT. The offline signer cannot verify the contract interface, execution semantics, token identity, or decimals.";
        }
        return "Offline signer cannot verify whether the recipient is a contract or what code it may execute.";
    }

    String maximumFeeEth() {
        BigInteger maximumFeeWei = gasLimit.multiply(maxFeePerGas);
        String nativeAmount = new BigDecimal(maximumFeeWei).movePointLeft(18)
                .stripTrailingZeros().toPlainString();
        return nativeAmount + " native token (" + maximumFeeWei + " wei)";
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
