package dev.phonevault.signer;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

/**
 * The USB "attest" message format (vault-os/docs/device-attestation.md). The binding message must
 * match the shared vectors byte for byte (the companion's Rust tests read the same file), the
 * request schema is exact, the response has exactly the fields the companion accepts, and the
 * attestation path never touches the wallet key.
 */
public final class AttestationProtocolTest {

    static JSONObject vectors() throws Exception {
        try (InputStream in = AttestationProtocolTest.class.getClassLoader().getResourceAsStream("attestation-vectors.json")) {
            if (in == null) throw new IllegalStateException("attestation-vectors.json missing from test resources");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            for (int n; (n = in.read(buffer)) > 0; ) out.write(buffer, 0, n);
            return new JSONObject(new String(out.toByteArray(), StandardCharsets.UTF_8));
        }
    }

    static JSONObject request(String challenge) throws Exception {
        JSONObject r = new JSONObject();
        r.put("id", "a-1");
        r.put("method", "attest");
        r.put("challenge", challenge);
        return r;
    }

    @Test public void bindingMessageMatchesTheSharedVectors() throws Exception {
        JSONObject v = vectors();
        assertEquals(AttestationProtocol.DOMAIN, v.getString("domain"));
        JSONArray list = v.getJSONArray("vectors");
        assertEquals(3, list.length());
        for (int i = 0; i < list.length(); i++) {
            JSONObject t = list.getJSONObject(i);
            byte[] m = AttestationProtocol.bindingMessage(Hex.bytes(t.getString("challenge")), t.getString("address"));
            assertArrayEquals(t.getString("name"), Hex.bytes(t.getString("message")), m);
        }
    }

    @Test public void bindingMessageLayoutIsFixed() {
        byte[] challenge = new byte[32];
        Arrays.fill(challenge, (byte) 7);
        byte[] m = AttestationProtocol.bindingMessage(challenge, "0x52908400098527886E0F7030069857D2E4169EE7");
        byte[] domain = "PhoneVault-attest-v1".getBytes(StandardCharsets.US_ASCII);
        assertEquals(domain.length + 2 + 32 + 20, m.length);
        assertArrayEquals(domain, Arrays.copyOf(m, domain.length));
        assertEquals(0, m[domain.length]);
        assertEquals(32, m[domain.length + 1]);
        // mixed-case input addresses give the same bytes as lowercase
        assertArrayEquals(m, AttestationProtocol.bindingMessage(challenge, "0x52908400098527886e0f7030069857d2e4169ee7"));
        // never an Ethereum-signable shape: not the EIP-191 0x19 prefix, not RLP, not 32 bytes
        assertTrue(m[0] != 0x19 && m.length != 32);
        try { AttestationProtocol.bindingMessage(new byte[15], "0x52908400098527886e0f7030069857d2e4169ee7"); fail(); } catch (IllegalArgumentException expected) { }
        try { AttestationProtocol.bindingMessage(new byte[65], "0x52908400098527886e0f7030069857d2e4169ee7"); fail(); } catch (IllegalArgumentException expected) { }
        try { AttestationProtocol.bindingMessage(challenge, "0x1234"); fail(); } catch (IllegalArgumentException expected) { }
    }

    @Test public void requestSchemaIsExact() throws Exception {
        String ok32 = "00".repeat(16) + "ab".repeat(16);
        assertEquals(32, AttestationProtocol.parseChallenge(request(ok32)).length);
        assertEquals(16, AttestationProtocol.parseChallenge(request("ff".repeat(16))).length);
        assertEquals(64, AttestationProtocol.parseChallenge(request("01".repeat(64))).length);
        String[] bad = {"ff".repeat(15), "ff".repeat(65), "FF".repeat(16), "f".repeat(33), "zz".repeat(16), "0x" + "ff".repeat(16), ""};
        for (String b : bad) {
            try { AttestationProtocol.parseChallenge(request(b)); fail("accepted challenge " + b); } catch (org.json.JSONException expected) { }
        }
        JSONObject extra = request(ok32);
        extra.put("chainId", "0x1");
        try { AttestationProtocol.parseChallenge(extra); fail("unknown field accepted"); } catch (org.json.JSONException expected) { }
        JSONObject missing = new JSONObject().put("id", "a-1").put("method", "attest");
        try { AttestationProtocol.parseChallenge(missing); fail("missing challenge accepted"); } catch (org.json.JSONException expected) { }
        JSONObject badId = request(ok32).put("id", "spaces are not allowed");
        try { AttestationProtocol.parseChallenge(badId); fail("bad id accepted"); } catch (org.json.JSONException expected) { }
        JSONObject numeric = new JSONObject().put("id", "a-1").put("method", "attest").put("challenge", 12345);
        try { AttestationProtocol.parseChallenge(numeric); fail("non-string challenge accepted"); } catch (org.json.JSONException expected) { }
    }

    @Test public void responseHasExactlyTheCompanionsFields() throws Exception {
        byte[] a = {0x30, 0x01, 0x00}, b = {0x30, 0x02, 0x01, 0x02};
        JSONObject r = AttestationProtocol.response("a-1", "0x52908400098527886E0F7030069857D2E4169EE7", "StrongBox",
                Arrays.asList(a, b), new byte[] {0x30, 0x06, (byte) 0xff});
        Set<String> keys = new HashSet<>();
        for (java.util.Iterator<String> it = r.keys(); it.hasNext(); ) keys.add(it.next());
        assertEquals(new HashSet<>(Arrays.asList("id", "status", "version", "address", "securityLevel", "certificates", "signature")), keys);
        assertEquals("ok", r.getString("status"));
        assertEquals("1", r.getString("version"));
        assertEquals("0x52908400098527886e0f7030069857d2e4169ee7", r.getString("address"));
        assertEquals(Base64.getEncoder().encodeToString(a) + "," + Base64.getEncoder().encodeToString(b), r.getString("certificates"));
        assertEquals("0x3006ff", r.getString("signature"));
        try { AttestationProtocol.response("a-1", "0x52908400098527886e0f7030069857d2e4169ee7", "Software", Arrays.asList(a, b), new byte[1]); fail(); } catch (IllegalArgumentException expected) { }
        try { AttestationProtocol.response("a-1", "0x52908400098527886e0f7030069857d2e4169ee7", "StrongBox", Arrays.asList(a), new byte[1]); fail(); } catch (IllegalArgumentException expected) { }
    }

    @Test public void signatureOverTheBindingVerifiesLikeTheCompanionChecksIt() throws Exception {
        // Same algorithm the phone uses (SHA256withECDSA, P-256, DER); the companion verifies with
        // ring's ECDSA_P256_SHA256_ASN1 over the identical bytes.
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair k = g.generateKeyPair();
        byte[] challenge = Hex.bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] m = AttestationProtocol.bindingMessage(challenge, "0x52908400098527886e0f7030069857d2e4169ee7");
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(k.getPrivate()); s.update(m);
        byte[] sig = s.sign();
        Signature v = Signature.getInstance("SHA256withECDSA");
        v.initVerify(k.getPublic()); v.update(m);
        assertTrue(v.verify(sig));
        byte[] other = AttestationProtocol.bindingMessage(challenge, "0xde709f2102306220921060314715629080e2fb77");
        v.initVerify(k.getPublic()); v.update(other);
        assertFalse("a different address must not verify", v.verify(sig));
    }

    @Test public void aChallengeIsAnsweredOnce() {
        AttestationProtocol.ChallengeLog log = new AttestationProtocol.ChallengeLog();
        byte[] c = new byte[32];
        assertTrue(log.firstUse(c));
        assertFalse(log.firstUse(c.clone()));
        for (int i = 1; i <= AttestationProtocol.REMEMBERED_CHALLENGES; i++) { byte[] x = new byte[32]; x[0] = (byte) i; x[1] = (byte) (i >> 8); x[2] = 1; assertTrue(log.firstUse(x)); }
        assertTrue("bounded memory: the oldest entry falls out", log.firstUse(c));
    }

    // ------------------------------------------------------------------ source guards

    @Test public void attestationNeverUsesTheWalletKeyOrExtraPrivileges() throws Exception {
        String code = SourceGuard.code(SourceGuard.source("AttestationKey.java"));
        for (String banned : new String[] {"Credentials", "Sign.", "EvmSigner", "VaultKeyStore", "SeedVault",
                "setDevicePropertiesAttestationIncluded", "setUniqueIdIncluded", "setAttestKeyAlias", "importKey", "setKeyEntry"}) {
            assertEquals(banned + " in AttestationKey", -1, code.indexOf(banned));
        }
        assertTrue(code.contains("setAttestationChallenge(challenge)"));
        assertTrue(code.contains("deleteEntry(ALIAS)"));
        String proto = SourceGuard.code(SourceGuard.source("AttestationProtocol.java"));
        assertEquals(-1, proto.indexOf("Credentials"));
    }

    @Test public void attestationRunsOffTheSigningThread() throws Exception {
        String body = SourceGuard.definition("private void answerAttestation(");
        assertTrue(body.contains("attestExecutor.execute("));
        assertEquals("attestation must not queue behind signing", -1, body.indexOf("cryptoExecutor"));
        assertTrue("a challenge is answered once", body.contains("attestChallenges.firstUse("));
        assertEquals("no wallet signature", -1, body.indexOf("Sign.sign"));
    }
}
