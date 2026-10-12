package dev.phonevault.signer;

import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Bool;
import org.web3j.abi.datatypes.DynamicArray;
import org.web3j.abi.datatypes.DynamicBytes;
import org.web3j.abi.datatypes.DynamicStruct;
import org.web3j.abi.datatypes.StaticStruct;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.generated.Int24;
import org.web3j.abi.datatypes.generated.Uint128;
import org.web3j.abi.datatypes.generated.Uint160;
import org.web3j.abi.datatypes.generated.Uint24;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.abi.datatypes.generated.Uint48;
import org.web3j.utils.Numeric;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Hand-built router and NFT calldata for the tests, encoded with web3j's ABI encoder — an
 * implementation independent of the phone's {@link Abi} decoder.
 */
final class Calldata {
    private Calldata() {}

    static final String MSG_SENDER = "0x0000000000000000000000000000000000000001";
    static final String ADDRESS_THIS = "0x0000000000000000000000000000000000000002";
    static final String ETH = "0x0000000000000000000000000000000000000000";
    static final BigInteger CONTRACT_BALANCE = BigInteger.ONE.shiftLeft(255);

    @SafeVarargs
    static byte[] args(Type<?>... types) {
        return Numeric.hexStringToByteArray(FunctionEncoder.encodeConstructor(Arrays.<Type>asList(types)));
    }

    static String call(String selector, Type<?>... types) {
        return "0x" + selector + FunctionEncoder.encodeConstructor(Arrays.<Type>asList(types));
    }

    static Address a(String address) { return new Address(address); }
    static Uint256 u(BigInteger v) { return new Uint256(v); }
    static Uint256 u(long v) { return new Uint256(BigInteger.valueOf(v)); }
    static DynamicBytes b(byte[] v) { return new DynamicBytes(v); }

    // ------------------------------------------------------------------ Universal Router

    static String execute(byte[] commands, List<byte[]> inputs, BigInteger deadline) {
        List<DynamicBytes> in = new ArrayList<>();
        for (byte[] i : inputs) in.add(new DynamicBytes(i));
        DynamicArray<DynamicBytes> array = new DynamicArray<>(DynamicBytes.class, in);
        return deadline == null ? call("24856bc3", b(commands), array) : call("3593564c", b(commands), array, u(deadline));
    }

    static byte[] v3Path(Object... tokenFeeToken) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Object o : tokenFeeToken) {
            byte[] bytes = o instanceof String ? Numeric.hexStringToByteArray((String) o)
                    : Numeric.toBytesPadded(BigInteger.valueOf((Integer) o), 3);
            out.write(bytes, 0, bytes.length);
        }
        return out.toByteArray();
    }

    static byte[] v3Swap(String recipient, BigInteger amount, BigInteger limit, byte[] path, boolean payerIsUser) {
        return args(a(recipient), u(amount), u(limit), b(path), new Bool(payerIsUser));
    }

    static byte[] v3Swap21(String recipient, BigInteger amount, BigInteger limit, byte[] path, boolean payerIsUser) {
        return args(a(recipient), u(amount), u(limit), b(path), new Bool(payerIsUser),
                new DynamicArray<>(Uint256.class, new ArrayList<Uint256>()));
    }

    static byte[] v2Swap(String recipient, BigInteger amount, BigInteger limit, List<String> path, boolean payerIsUser) {
        List<Address> p = new ArrayList<>();
        for (String s : path) p.add(a(s));
        return args(a(recipient), u(amount), u(limit), new DynamicArray<>(Address.class, p), new Bool(payerIsUser));
    }

    static byte[] wrap(String recipient, BigInteger amount) { return args(a(recipient), u(amount)); }
    static byte[] unwrap(String recipient, BigInteger min) { return args(a(recipient), u(min)); }
    static byte[] sweep(String token, String recipient, BigInteger min) { return args(a(token), a(recipient), new Uint160(min)); }
    static byte[] payPortion(String token, String recipient, long bips) { return args(a(token), a(recipient), u(bips)); }
    static byte[] transfer(String token, String recipient, BigInteger value) { return args(a(token), a(recipient), u(value)); }

    static byte[] permit2Permit(String token, BigInteger amount, long expiration, long nonce, String spender, long sigDeadline) {
        StaticStruct details = new StaticStruct(a(token), new Uint160(amount), new Uint48(BigInteger.valueOf(expiration)),
                new Uint48(BigInteger.valueOf(nonce)));
        StaticStruct single = new StaticStruct(details, a(spender), u(sigDeadline));
        return args(single, b(new byte[65]));
    }

    // ------------------------------------------------------------------ V4

    static byte[] v4(byte[] actions, byte[]... params) {
        List<DynamicBytes> p = new ArrayList<>();
        for (byte[] x : params) p.add(new DynamicBytes(x));
        return args(b(actions), new DynamicArray<>(DynamicBytes.class, p));
    }

    static StaticStruct poolKey(String c0, String c1, int fee, int tickSpacing, String hooks) {
        return new StaticStruct(a(c0), a(c1), new Uint24(BigInteger.valueOf(fee)), new Int24(BigInteger.valueOf(tickSpacing)), a(hooks));
    }

    static byte[] v4ExactInSingle(StaticStruct key, boolean zeroForOne, BigInteger amountIn, BigInteger minOut) {
        return args(new DynamicStruct(key, new Bool(zeroForOne), new Uint128(amountIn), new Uint128(minOut), b(new byte[0])));
    }

    static byte[] v4ExactInSingle21(StaticStruct key, boolean zeroForOne, BigInteger amountIn, BigInteger minOut) {
        return args(new DynamicStruct(key, new Bool(zeroForOne), new Uint128(amountIn), new Uint128(minOut), u(0), b(new byte[0])));
    }

    static byte[] currencyAmount(String currency, BigInteger amount) { return args(a(currency), u(amount)); }
    static byte[] settle(String currency, BigInteger amount, boolean payerIsUser) { return args(a(currency), u(amount), new Bool(payerIsUser)); }
    static byte[] take(String currency, String recipient, BigInteger amount) { return args(a(currency), a(recipient), u(amount)); }

    // ------------------------------------------------------------------ SwapRouter02

    static String exactInputSingle(String in, String out, int fee, String recipient, BigInteger amountIn, BigInteger min) {
        return call("04e45aaf", new StaticStruct(a(in), a(out), new Uint24(BigInteger.valueOf(fee)), a(recipient), u(amountIn), u(min), new Uint160(BigInteger.ZERO)));
    }

    static String multicall(BigInteger deadline, String... calls) {
        List<DynamicBytes> c = new ArrayList<>();
        for (String s : calls) c.add(new DynamicBytes(Numeric.hexStringToByteArray(s)));
        DynamicArray<DynamicBytes> array = new DynamicArray<>(DynamicBytes.class, c);
        return deadline == null ? call("ac9650d8", array) : call("5ae401dc", u(deadline), array);
    }
}
