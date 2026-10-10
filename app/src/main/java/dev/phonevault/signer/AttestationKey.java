package dev.phonevault.signer;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;

/**
 * One device attestation (vault-os/docs/device-attestation.md): a fresh EC P-256 key generated in
 * StrongBox (the Titan M) with the host's challenge as its attestation challenge, its certificate
 * chain, and its signature over {@link AttestationProtocol#bindingMessage}. The key is deleted
 * afterwards; nothing about it persists and it can sign nothing else.
 *
 * <p>No new permission: {@code setDevicePropertiesAttestationIncluded} is NOT used. It adds
 * brand/device/model ID attestation, which nothing in the verdict relies on, and ID attestation
 * fails outright (CANNOT_ATTEST_IDS) on devices whose provisioned IDs differ from the running
 * build's properties, as a custom OS's may. The wallet key is not involved at all.
 *
 * <p>TEE fallback only if StrongBox key generation fails; the result says which, and the companion
 * never rates a TEE attestation GENUINE.
 */
final class AttestationKey {
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String ALIAS = "phone-vault-attest-v1";
    private static final Object LOCK = new Object();

    static final class Result {
        final String securityLevel;
        final List<byte[]> chain;
        final byte[] signature;
        Result(String securityLevel, List<byte[]> chain, byte[] signature) {
            this.securityLevel = securityLevel; this.chain = chain; this.signature = signature;
        }
    }

    private AttestationKey() {}

    static Result attest(byte[] challenge, String address) throws Exception {
        byte[] message = AttestationProtocol.bindingMessage(challenge, address);
        synchronized (LOCK) {
            try {
                return run(challenge, message, true);
            } catch (Exception strongBoxFailed) {
                // StrongBoxUnavailableException, or a Titan M error during generation: say so by
                // attesting from the TEE; the host decides what that is worth.
                return run(challenge, message, false);
            }
        }
    }

    private static Result run(byte[] challenge, byte[] message, boolean strongBox) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
        if (keyStore.containsAlias(ALIAS)) keyStore.deleteEntry(ALIAS);
        try {
            KeyGenParameterSpec.Builder spec = new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge);
            if (strongBox) spec.setIsStrongBoxBacked(true);
            KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE);
            generator.initialize(spec.build());
            KeyPair pair = generator.generateKeyPair();
            Certificate[] certificates = keyStore.getCertificateChain(ALIAS);
            if (certificates == null || certificates.length < 2) throw new IllegalStateException("no attestation chain");
            List<byte[]> chain = new ArrayList<>(certificates.length);
            for (Certificate c : certificates) chain.add(c.getEncoded());
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(pair.getPrivate());
            signer.update(message);
            return new Result(strongBox ? "StrongBox" : "TrustedEnvironment", chain, signer.sign());
        } finally {
            try { if (keyStore.containsAlias(ALIAS)) keyStore.deleteEntry(ALIAS); } catch (Exception ignored) { /* next run deletes it first */ }
        }
    }
}
