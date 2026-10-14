package dev.phonevault.signer;

import org.json.JSONException;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * The USB {@code attest} method, minus the keystore (that is {@link AttestationKey}). Pure Java so
 * the request schema, the binding message and the response shape are unit-tested on the JVM
 * (AttestationProtocolTest) against the same vectors the companion uses
 * ({@code app/src/test/resources/attestation-vectors.json}). Design and threat model:
 * vault-os/docs/device-attestation.md.
 *
 * <pre>
 * → {"id":"…","method":"attest","challenge":"&lt;16..64 bytes, lowercase hex&gt;"}
 * ← {"id":"…","status":"ok","version":"1","address":"0x…","securityLevel":"StrongBox"|"TrustedEnvironment",
 *    "certificates":"&lt;base64 DER leaf&gt;,…,&lt;base64 DER root&gt;","signature":"0x&lt;DER ECDSA&gt;"}
 * binding = "PhoneVault-attest-v1" ‖ 0x00 ‖ len(challenge) ‖ challenge ‖ address (20 bytes)
 * </pre>
 *
 * <p>The binding is signed by a FRESH attestation key, never by the wallet key: proving which
 * wallet this genuine device holds must not cost a wallet signature the user did not approve.
 */
final class AttestationProtocol {
    static final String METHOD = "attest";
    static final String DOMAIN = "PhoneVault-attest-v1";
    static final int MIN_CHALLENGE = 16;
    static final int MAX_CHALLENGE = 64;
    /** Challenges answered in this process; a host must never get two attestations for one. */
    static final int REMEMBERED_CHALLENGES = 64;

    private AttestationProtocol() {}

    static boolean handles(String method) { return METHOD.equals(method); }

    /** Schema-exact request: id, method, challenge (lowercase hex, 16..64 bytes). */
    static byte[] parseChallenge(JSONObject json) throws JSONException {
        Eip1559Request.requireExactFields(json, "id", "method", "challenge");
        Eip1559Request.validatedId(json.getString("id"));
        if (!METHOD.equals(json.getString("method"))) throw new JSONException("Not an attestation request");
        Object raw = json.get("challenge");
        if (!(raw instanceof String)) throw new JSONException("challenge must be a string");
        String hex = (String) raw;
        if (hex.length() % 2 != 0 || hex.length() < 2 * MIN_CHALLENGE || hex.length() > 2 * MAX_CHALLENGE
                || !hex.matches("[0-9a-f]+")) {
            throw new JSONException("challenge must be " + MIN_CHALLENGE + ".." + MAX_CHALLENGE + " bytes of lowercase hex");
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        return out;
    }

    /** "PhoneVault-attest-v1" ‖ 0x00 ‖ len ‖ challenge ‖ 20-byte address. */
    static byte[] bindingMessage(byte[] challenge, String address) {
        if (challenge.length < MIN_CHALLENGE || challenge.length > MAX_CHALLENGE) throw new IllegalArgumentException("challenge length");
        byte[] addr = addressBytes(address);
        byte[] domain = DOMAIN.getBytes(StandardCharsets.US_ASCII);
        byte[] out = new byte[domain.length + 2 + challenge.length + addr.length];
        int p = 0;
        System.arraycopy(domain, 0, out, p, domain.length); p += domain.length;
        out[p++] = 0;
        out[p++] = (byte) challenge.length;
        System.arraycopy(challenge, 0, out, p, challenge.length); p += challenge.length;
        System.arraycopy(addr, 0, out, p, addr.length);
        return out;
    }

    static byte[] addressBytes(String address) {
        if (!Addresses.isEvm(address)) throw new IllegalArgumentException("address");
        byte[] out = new byte[20];
        for (int i = 0; i < 20; i++) out[i] = (byte) Integer.parseInt(address.substring(2 + 2 * i, 4 + 2 * i), 16);
        return out;
    }

    static JSONObject response(String id, String address, String securityLevel, List<byte[]> chain, byte[] signature)
            throws JSONException {
        if (!"StrongBox".equals(securityLevel) && !"TrustedEnvironment".equals(securityLevel)) throw new IllegalArgumentException("securityLevel");
        if (chain.size() < 2) throw new IllegalArgumentException("chain");
        StringBuilder certs = new StringBuilder();
        for (byte[] der : chain) {
            if (certs.length() > 0) certs.append(',');
            certs.append(Base64.getEncoder().encodeToString(der));
        }
        StringBuilder sig = new StringBuilder("0x");
        for (byte b : signature) sig.append(String.format(Locale.ROOT, "%02x", b & 0xff));
        JSONObject o = new JSONObject();
        o.put("id", id);
        o.put("status", "ok");
        o.put("version", "1");
        o.put("address", address.toLowerCase(Locale.ROOT));
        o.put("securityLevel", securityLevel);
        o.put("certificates", certs.toString());
        o.put("signature", sig.toString());
        return o;
    }

    /** Remembers recent challenges; {@link #firstUse} is false for a repeat. Thread-safe. */
    static final class ChallengeLog {
        private final ArrayDeque<String> order = new ArrayDeque<>();
        private final Set<String> seen = new HashSet<>();

        synchronized boolean firstUse(byte[] challenge) {
            String key = Base64.getEncoder().encodeToString(challenge);
            if (seen.contains(key)) return false;
            seen.add(key);
            order.addLast(key);
            if (order.size() > REMEMBERED_CHALLENGES) seen.remove(order.removeFirst());
            return true;
        }
    }
}
