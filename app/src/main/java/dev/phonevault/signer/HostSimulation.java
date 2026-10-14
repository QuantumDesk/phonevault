package dev.phonevault.signer;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * The Mac's claim about what a transaction will do to this wallet's balances: the optional
 * {@code hostSimulation} field of a {@code signEip1559} request (vault-os/docs/simulation.md).
 *
 * <p>It is UNTRUSTED display data. It is never part of what is signed ({@link EvmSigner} reads
 * only the transaction fields), it never replaces the phone's own decoding, and the review shows
 * it in a separate box labelled as the Mac's claim. {@link SimulationCheck} compares it with what
 * the phone decoded and flags a claim that contradicts it.
 *
 * <p>Parsing is strict, like the rest of the request: exact field sets, canonical numbers, bounded
 * sizes. A malformed claim refuses the whole request (a host that sends one is broken or hostile).
 * <pre>
 * "hostSimulation": {
 *   "changes": [ {"asset": "native" | "0x…40 lower-case hex", "delta": "-123" (decimal, non-zero),
 *                 "symbol"?: "USDC", "decimals"?: 6, "tokenId"?: "1" (NFTs; excludes decimals)} ],
 *   "node": "ethereum-rpc.publicnode.com",   // host[:port] the Mac simulated on
 *   "block": "0x18f603b"                     // block the simulation ran on top of
 * }
 * </pre>
 */
final class HostSimulation {
    static final String FIELD = "hostSimulation";
    static final String NATIVE = "native";
    static final int MAX_CHANGES = 16;
    static final int MAX_NODE_LENGTH = 100;
    static final int MAX_SYMBOL_LENGTH = 16;
    static final int MAX_DECIMALS = 36;
    private static final int MAX_DIGITS = 78; // 2^256 has 78 decimal digits
    private static final BigInteger UINT256_LIMIT = BigInteger.ONE.shiftLeft(256);
    private static final Set<String> FIELDS = new HashSet<>(Arrays.asList("changes", "node", "block"));
    private static final Set<String> CHANGE_REQUIRED = new HashSet<>(Arrays.asList("asset", "delta"));
    private static final Set<String> CHANGE_ALLOWED = new HashSet<>(Arrays.asList("asset", "delta", "symbol", "decimals", "tokenId"));

    /** One claimed balance change of the signing wallet. */
    static final class Change {
        /** {@link #NATIVE} or a lower-case 0x address. */
        final String asset;
        /** Non-null for an NFT (ERC-721/1155 token ID). */
        final BigInteger tokenId;
        /** Signed change in base units (wei, token base units, NFT count); never zero. */
        final BigInteger delta;
        /** The Mac's label; may be null. Never trusted for a token the phone lists itself. */
        final String symbol;
        /** The Mac's decimals; null when absent (always absent for an NFT). */
        final Integer decimals;

        Change(String asset, BigInteger tokenId, BigInteger delta, String symbol, Integer decimals) {
            this.asset = asset;
            this.tokenId = tokenId;
            this.delta = delta;
            this.symbol = symbol;
            this.decimals = decimals;
        }

        boolean nft() { return tokenId != null; }
        boolean nativeCoin() { return NATIVE.equals(asset); }
        String key() { return key(asset, tokenId); }
        static String key(String asset, BigInteger tokenId) { return tokenId == null ? asset : asset + "#" + tokenId; }
    }

    final List<Change> changes;
    final String node;
    final BigInteger block;

    private HostSimulation(List<Change> changes, String node, BigInteger block) {
        this.changes = Collections.unmodifiableList(changes);
        this.node = node;
        this.block = block;
    }

    /** Parses the field's value; throws for anything outside the schema. */
    static HostSimulation parse(Object raw) throws JSONException {
        if (!(raw instanceof JSONObject)) throw new JSONException("hostSimulation must be an object");
        JSONObject json = (JSONObject) raw;
        exactFields(json, FIELDS, FIELDS, "hostSimulation");
        Object changesRaw = json.get("changes");
        if (!(changesRaw instanceof JSONArray)) throw new JSONException("hostSimulation.changes must be an array");
        JSONArray array = (JSONArray) changesRaw;
        if (array.length() > MAX_CHANGES) throw new JSONException("hostSimulation lists more than " + MAX_CHANGES + " changes");
        List<Change> changes = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < array.length(); i++) {
            Change c = change(array.get(i));
            if (!seen.add(c.key())) throw new JSONException("hostSimulation lists " + c.key() + " twice");
            changes.add(c);
        }
        String node = string(json.get("node"), "hostSimulation.node");
        if (node.length() > MAX_NODE_LENGTH || !node.matches("[A-Za-z0-9.-]+(:[0-9]{1,5})?")) {
            throw new JSONException("hostSimulation.node must be a host name");
        }
        BigInteger block = Eip1559Request.quantity(string(json.get("block"), "hostSimulation.block"));
        if (block.bitLength() > 63) throw new JSONException("hostSimulation.block out of range");
        return new HostSimulation(changes, node.toLowerCase(Locale.ROOT), block);
    }

    private static Change change(Object raw) throws JSONException {
        if (!(raw instanceof JSONObject)) throw new JSONException("hostSimulation change must be an object");
        JSONObject json = (JSONObject) raw;
        exactFields(json, CHANGE_REQUIRED, CHANGE_ALLOWED, "hostSimulation change");
        String asset = string(json.get("asset"), "asset");
        if (!NATIVE.equals(asset) && !Addresses.isEvmLowercase(asset)) {
            throw new JSONException("hostSimulation asset must be \"native\" or a lower-case 0x address");
        }
        if (Addresses.isZero(asset)) throw new JSONException("hostSimulation asset must not be the zero address");
        String deltaText = string(json.get("delta"), "delta");
        if (!deltaText.matches("-?[1-9][0-9]{0," + (MAX_DIGITS - 1) + "}")) {
            throw new JSONException("hostSimulation delta must be a non-zero canonical decimal integer");
        }
        BigInteger delta = new BigInteger(deltaText);
        if (delta.abs().compareTo(UINT256_LIMIT) >= 0) throw new JSONException("hostSimulation delta exceeds 256 bits");
        BigInteger tokenId = null;
        if (json.has("tokenId")) {
            if (NATIVE.equals(asset)) throw new JSONException("the native coin has no tokenId");
            String id = string(json.get("tokenId"), "tokenId");
            if (!id.matches("0|[1-9][0-9]{0," + (MAX_DIGITS - 1) + "}")) throw new JSONException("hostSimulation tokenId must be a canonical decimal integer");
            tokenId = new BigInteger(id);
            if (tokenId.compareTo(UINT256_LIMIT) >= 0) throw new JSONException("hostSimulation tokenId exceeds 256 bits");
        }
        String symbol = null;
        if (json.has("symbol")) {
            symbol = string(json.get("symbol"), "symbol");
            if (symbol.isEmpty() || symbol.length() > MAX_SYMBOL_LENGTH || !symbol.matches("[A-Za-z0-9.+_-]+")) {
                throw new JSONException("hostSimulation symbol must be 1-" + MAX_SYMBOL_LENGTH + " letters, digits or .+_-");
            }
        }
        Integer decimals = null;
        if (json.has("decimals")) {
            if (tokenId != null) throw new JSONException("an NFT change has no decimals");
            Object d = json.get("decimals");
            // Integer or Long only: a JSON fraction or exponent ("6.0", "6e0") parses as a Double
            if (!(d instanceof Integer || d instanceof Long)) throw new JSONException("hostSimulation decimals must be an integer");
            long v = ((Number) d).longValue();
            if (v < 0 || v > MAX_DECIMALS) throw new JSONException("hostSimulation decimals out of range");
            decimals = (int) v;
        }
        return new Change(asset, tokenId, delta, symbol, decimals);
    }

    private static String string(Object v, String what) throws JSONException {
        if (!(v instanceof String)) throw new JSONException(what + " must be a string");
        return (String) v;
    }

    private static void exactFields(JSONObject json, Set<String> required, Set<String> allowed, String what) throws JSONException {
        Set<String> actual = new HashSet<>();
        Iterator<String> keys = json.keys();
        while (keys.hasNext()) actual.add(keys.next());
        if (!actual.containsAll(required) || !allowed.containsAll(actual)) {
            Set<String> missing = new HashSet<>(required);
            missing.removeAll(actual);
            Set<String> unknown = new HashSet<>(actual);
            unknown.removeAll(allowed);
            throw new JSONException(what + " fields do not match schema; missing=" + missing + ", unknown=" + unknown);
        }
    }
}
