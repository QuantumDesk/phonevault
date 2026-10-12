package dev.phonevault.signer;

import java.util.List;
import java.util.Locale;

/**
 * EIP-7702 (account delegation) recognition, so the phone can refuse it by name.
 *
 * <p>A 7702 authorization is a signature over {@code keccak256(0x05 ‖ rlp([chain_id, address,
 * nonce]))}; once included in a type-4 transaction it makes this account run the named
 * contract's code — effectively handing the wallet to that contract. This phone never builds a
 * type-4 transaction (EvmSigner only encodes type 0x02, and {@link Eip1559Request#parse} refuses
 * a request that asks for one). A {@code personal_sign} or EIP-712 digest can never equal a 7702
 * authorization digest (their preimages start with 0x19), so the message checks below are
 * defense in depth: they stop a host from passing an authorization tuple — or a typed-data
 * "delegation" — off as an ordinary message the user might sign without understanding it.
 */
final class Eip7702 {
    private Eip7702() {}

    static final int MAGIC = 0x05;

    /** True for bytes shaped like {@code 0x05 ‖ rlp([chain_id, address(20 bytes), nonce])}. */
    static boolean isAuthorizationTuple(byte[] b) {
        if (b == null || b.length < 2 || (b[0] & 0xff) != MAGIC) return false;
        try {
            int[] list = header(b, 1);
            if (list[2] != 1) return false;
            int at = list[0], end = list[0] + list[1];
            if (end != b.length) return false;
            int items = 0;
            boolean addressSecond = false;
            while (at < end) {
                int[] item = header(b, at);
                if (item[2] == 1) return false; // nested list
                if (items == 1) addressSecond = item[1] == 20;
                at = item[0] + item[1];
                items++;
            }
            return at == end && items == 3 && addressSecond;
        } catch (IndexOutOfBoundsException | IllegalArgumentException e) {
            return false;
        }
    }

    /** {payload start, payload length, 1 if list}. */
    private static int[] header(byte[] b, int at) {
        int p = b[at] & 0xff;
        if (p < 0x80) return new int[] {at, 1, 0};
        if (p <= 0xb7) return new int[] {at + 1, p - 0x80, 0};
        if (p <= 0xbf) return new int[] {at + 1 + (p - 0xb7), length(b, at + 1, p - 0xb7), 0};
        if (p <= 0xf7) return new int[] {at + 1, p - 0xc0, 1};
        return new int[] {at + 1 + (p - 0xf7), length(b, at + 1, p - 0xf7), 1};
    }

    private static int length(byte[] b, int at, int n) {
        if (n > 3) throw new IllegalArgumentException("RLP length too large");
        int len = 0;
        for (int i = 0; i < n; i++) len = (len << 8) | (b[at + i] & 0xff);
        if (at + n + len > b.length) throw new IndexOutOfBoundsException();
        return len;
    }

    /**
     * Typed data that asks for account delegation: a primary type named for EIP-7702, an
     * "Authorization"-style type carrying a nonce and an address (a 7702 tuple in EIP-712 dress),
     * or an ERC-7710 "Delegation" (delegation-framework permission over a delegated account).
     */
    static String typedDataDelegation(Eip712.TypedData t) {
        String p = t.primaryType.toLowerCase(Locale.ROOT);
        if (p.contains("7702")) return "typed data " + t.primaryType;
        if (p.equals("delegation") || p.equals("signeddelegation")) return "typed-data account delegation (" + t.primaryType + ")";
        if (p.contains("authorization")) {
            List<Eip712.Field> fields = t.types.get(t.primaryType);
            boolean nonce = false, address = false;
            if (fields != null) {
                for (Eip712.Field f : fields) {
                    String n = f.name.toLowerCase(Locale.ROOT);
                    if (n.equals("nonce")) nonce = true;
                    if (f.type.equals("address") && (n.equals("address") || n.contains("contract") || n.contains("delegat")
                            || n.contains("implementation") || n.contains("code"))) address = true;
                }
            }
            if (nonce && address) return "typed-data authorization tuple (" + t.primaryType + ")";
        }
        return null;
    }
}
