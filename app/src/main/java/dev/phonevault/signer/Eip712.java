package dev.phonevault.signer;

import org.web3j.crypto.Hash;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * EIP-712 typed structured data ({@code eth_signTypedData_v4}): strict parse, then hash.
 *
 * <p>The JSON is parsed ONCE into an immutable tree of typed values ({@link Struct} /
 * {@link Value}). The digest is computed from that tree at construction and the review screen
 * is rendered from the same tree, so what is shown and what is signed cannot come from two
 * different interpretations of the input. Anything the encoder would have to guess about is
 * refused: unknown or unused types, missing or extra fields, nulls, fractional or out-of-range
 * numbers, wrong-length bytes, bad address checksums, oversized payloads.
 *
 * <p>The companion recomputes the digest with an independent Rust implementation of the same
 * rules (companion/src-tauri/src/message.rs); both are tested against the same vectors.
 */
final class Eip712 {
    // ---- limits (documented in vault-os/docs/message-signing.md)
    static final int MAX_TYPED_DATA_BYTES = 24 * 1024;
    static final int MAX_STRUCT_TYPES = 32;
    static final int MAX_FIELDS_PER_STRUCT = 48;
    static final int MAX_ARRAY_LENGTH = 128;
    static final int MAX_ARRAY_DIMENSIONS = 3;
    static final int MAX_VALUES = 1024;
    static final int MAX_DYNAMIC_BYTES = 4096;
    static final int MAX_STRING_BYTES = 4096;
    static final int MAX_NAME_LENGTH = 64;
    static final int MAX_INTEGER_LITERAL = 80;

    static final String DOMAIN_TYPE = "EIP712Domain";
    /** The only domain fields EIP-712 defines, in the only order it allows. */
    private static final String[][] DOMAIN_FIELDS = {
            {"name", "string"}, {"version", "string"}, {"chainId", "uint256"},
            {"verifyingContract", "address"}, {"salt", "bytes32"}};

    private static final Pattern IDENTIFIER = Pattern.compile("[A-Za-z_$][A-Za-z0-9_$]*");
    private static final Pattern RESERVED_NAME = Pattern.compile(
            "(u?int|bytes|u?fixed)[0-9x]*|bool|address|string|byte|function|tuple");
    private static final Pattern TYPE = Pattern.compile("([A-Za-z_$][A-Za-z0-9_$]*)((?:\\[(?:[1-9][0-9]{0,3})?\\])*)");
    private static final Pattern DIMENSION = Pattern.compile("\\[([0-9]*)\\]");
    private static final Pattern DECIMAL = Pattern.compile("-?(?:0|[1-9][0-9]*)");
    private static final Pattern HEX_QUANTITY = Pattern.compile("0x[0-9a-fA-F]{1,64}");
    private static final Pattern HEX_BYTES = Pattern.compile("0x[0-9a-fA-F]*");

    enum Kind { BOOL, ADDRESS, UINT, INT, FIXED_BYTES, BYTES, STRING, STRUCT, ARRAY }

    static final class Field {
        final String name;
        final String type;
        Field(String name, String type) { this.name = name; this.type = type; }
    }

    /** One decoded, range-checked value. {@code data} is immutable for every kind. */
    static final class Value {
        final String type;
        final Kind kind;
        /** Boolean | String (address, lowercase 0x…) | BigInteger | byte[] (private copy) |
         *  String (text) | Struct | List&lt;Value&gt; (unmodifiable). */
        private final Object data;

        private Value(String type, Kind kind, Object data) { this.type = type; this.kind = kind; this.data = data; }
        boolean bool() { return (Boolean) data; }
        String address() { return (String) data; }
        BigInteger integer() { return (BigInteger) data; }
        byte[] bytes() { return ((byte[]) data).clone(); }
        String text() { return (String) data; }
        Struct struct() { return (Struct) data; }
        @SuppressWarnings("unchecked") List<Value> elements() { return (List<Value>) data; }
    }

    static final class Struct {
        final String type;
        /** Field values in the order the type declares them. Unmodifiable. */
        final Map<String, Value> fields;
        private Struct(String type, Map<String, Value> fields) { this.type = type; this.fields = fields; }
        Value get(String name) { return fields.get(name); }
    }

    static final class TypedData {
        final Map<String, List<Field>> types;
        final String primaryType;
        final Struct domain;
        final Struct message;
        private final byte[] domainSeparator;
        private final byte[] messageHash;
        private final byte[] digest;

        private TypedData(Map<String, List<Field>> types, String primaryType, Struct domain, Struct message) {
            this.types = types;
            this.primaryType = primaryType;
            this.domain = domain;
            this.message = message;
            this.domainSeparator = hashStruct(types, domain);
            this.messageHash = hashStruct(types, message);
            byte[] preimage = new byte[66];
            preimage[0] = 0x19;
            preimage[1] = 0x01;
            System.arraycopy(domainSeparator, 0, preimage, 2, 32);
            System.arraycopy(messageHash, 0, preimage, 34, 32);
            this.digest = Hash.sha3(preimage);
        }

        byte[] domainSeparator() { return domainSeparator.clone(); }
        byte[] messageHash() { return messageHash.clone(); }
        /** keccak256(0x1901 ‖ domainSeparator ‖ hashStruct(message)): exactly what is signed. */
        byte[] digest() { return digest.clone(); }

        String encodeType(String type) { return Eip712.encodeType(types, type); }

        String domainName() { Value v = domain.get("name"); return v == null ? null : v.text(); }
        String domainVersion() { Value v = domain.get("version"); return v == null ? null : v.text(); }
        BigInteger domainChainId() { Value v = domain.get("chainId"); return v == null ? null : v.integer(); }
        String domainVerifyingContract() { Value v = domain.get("verifyingContract"); return v == null ? null : v.address(); }
        byte[] domainSalt() { Value v = domain.get("salt"); return v == null ? null : v.bytes(); }
    }

    static final class InvalidTypedData extends Exception {
        InvalidTypedData(String message) { super(message); }
    }

    private Eip712() {}

    // ------------------------------------------------------------------ parse

    static TypedData parse(String json) throws InvalidTypedData {
        if (json == null) throw new InvalidTypedData("Typed data is missing");
        if (json.getBytes(StandardCharsets.UTF_8).length > MAX_TYPED_DATA_BYTES) {
            throw new InvalidTypedData("Typed data exceeds " + MAX_TYPED_DATA_BYTES + " bytes");
        }
        Object root;
        try {
            root = StrictJson.parse(json);
        } catch (StrictJson.ParseException e) {
            throw new InvalidTypedData("Typed data is not strict JSON: " + e.getMessage());
        }
        Map<String, Object> top = object(root, "typed data");
        exactKeys(top, "typed data", "types", "primaryType", "domain", "message");

        Map<String, List<Field>> types = parseTypes(top.get("types"));
        if (!(top.get("primaryType") instanceof String)) throw new InvalidTypedData("primaryType must be a string");
        String primaryType = (String) top.get("primaryType");
        if (DOMAIN_TYPE.equals(primaryType)) throw new InvalidTypedData("primaryType must not be EIP712Domain");
        if (!types.containsKey(primaryType)) throw new InvalidTypedData("primaryType " + primaryType + " is not defined in types");

        // Every declared type must be reachable from the message or the domain: an unused
        // definition is not signed and would only be room for confusion (ethers refuses it too).
        Set<String> used = new LinkedHashSet<>();
        used.add(DOMAIN_TYPE);
        used.add(primaryType);
        used.addAll(dependencies(types, primaryType));
        for (String name : types.keySet()) {
            if (!used.contains(name)) throw new InvalidTypedData("Type " + name + " is defined but not used");
        }

        int[] budget = {MAX_VALUES};
        Struct domain = parseStruct(types, DOMAIN_TYPE, top.get("domain"), "domain", budget);
        Struct message = parseStruct(types, primaryType, top.get("message"), "message", budget);
        return new TypedData(types, primaryType, domain, message);
    }

    private static Map<String, List<Field>> parseTypes(Object raw) throws InvalidTypedData {
        Map<String, Object> declared = object(raw, "types");
        if (declared.size() > MAX_STRUCT_TYPES) throw new InvalidTypedData("More than " + MAX_STRUCT_TYPES + " types");
        if (!declared.containsKey(DOMAIN_TYPE)) throw new InvalidTypedData("types must define EIP712Domain");
        LinkedHashMap<String, List<Field>> types = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : declared.entrySet()) {
            String name = entry.getKey();
            if (!validName(name) || RESERVED_NAME.matcher(name).matches()) {
                throw new InvalidTypedData("Invalid type name: " + name);
            }
            if (!(entry.getValue() instanceof List)) throw new InvalidTypedData("Type " + name + " must be a list of fields");
            List<?> list = (List<?>) entry.getValue();
            if (list.size() > MAX_FIELDS_PER_STRUCT) throw new InvalidTypedData("Type " + name + " has too many fields");
            List<Field> fields = new ArrayList<>();
            Set<String> seen = new TreeSet<>();
            for (Object item : list) {
                Map<String, Object> field = object(item, "field of " + name);
                exactKeys(field, "field of " + name, "name", "type");
                if (!(field.get("name") instanceof String) || !(field.get("type") instanceof String)) {
                    throw new InvalidTypedData("Field name and type of " + name + " must be strings");
                }
                String fieldName = (String) field.get("name");
                String fieldType = (String) field.get("type");
                if (!validName(fieldName)) throw new InvalidTypedData("Invalid field name in " + name + ": " + fieldName);
                if (!seen.add(fieldName)) throw new InvalidTypedData("Duplicate field " + fieldName + " in " + name);
                fields.add(new Field(fieldName, fieldType));
            }
            types.put(name, Collections.unmodifiableList(fields));
        }
        // Second pass, once every name is known: each field type must resolve.
        for (Map.Entry<String, List<Field>> entry : types.entrySet()) {
            for (Field field : entry.getValue()) checkFieldType(types, entry.getKey(), field.type);
        }
        List<Field> domain = types.get(DOMAIN_TYPE);
        int cursor = 0;
        for (Field field : domain) {
            while (cursor < DOMAIN_FIELDS.length && !DOMAIN_FIELDS[cursor][0].equals(field.name)) cursor++;
            if (cursor == DOMAIN_FIELDS.length) {
                throw new InvalidTypedData("EIP712Domain field " + field.name + " is unknown or out of order");
            }
            if (!DOMAIN_FIELDS[cursor][1].equals(field.type)) {
                throw new InvalidTypedData("EIP712Domain field " + field.name + " must be " + DOMAIN_FIELDS[cursor][1]);
            }
            cursor++;
        }
        return Collections.unmodifiableMap(types);
    }

    private static void checkFieldType(Map<String, List<Field>> types, String owner, String type) throws InvalidTypedData {
        Matcher m = TYPE.matcher(type);
        if (!m.matches()) throw new InvalidTypedData("Invalid type in " + owner + ": " + type);
        String base = m.group(1);
        String suffix = m.group(2);
        int dimensions = 0;
        Matcher d = DIMENSION.matcher(suffix);
        while (d.find()) {
            dimensions++;
            if (!d.group(1).isEmpty() && Integer.parseInt(d.group(1)) > MAX_ARRAY_LENGTH) {
                throw new InvalidTypedData("Fixed array longer than " + MAX_ARRAY_LENGTH + " in " + owner);
            }
        }
        if (dimensions > MAX_ARRAY_DIMENSIONS) throw new InvalidTypedData("Too many array dimensions in " + owner);
        if (atomicKind(base) != null) return;
        if (DOMAIN_TYPE.equals(base)) throw new InvalidTypedData("EIP712Domain cannot be used as a field type");
        if (!types.containsKey(base)) throw new InvalidTypedData("Unknown type " + base + " in " + owner);
    }

    private static boolean validName(String name) {
        return name.length() <= MAX_NAME_LENGTH && IDENTIFIER.matcher(name).matches();
    }

    /** Atomic/dynamic kind for a base type name, or null if it is not one. */
    static Kind atomicKind(String base) {
        switch (base) {
            case "bool": return Kind.BOOL;
            case "address": return Kind.ADDRESS;
            case "string": return Kind.STRING;
            case "bytes": return Kind.BYTES;
            default: break;
        }
        if (base.startsWith("bytes")) {
            int n = sizeSuffix(base, 5);
            return n >= 1 && n <= 32 ? Kind.FIXED_BYTES : null;
        }
        if (base.startsWith("uint")) {
            int n = sizeSuffix(base, 4);
            return n >= 8 && n <= 256 && n % 8 == 0 ? Kind.UINT : null;
        }
        if (base.startsWith("int")) {
            int n = sizeSuffix(base, 3);
            return n >= 8 && n <= 256 && n % 8 == 0 ? Kind.INT : null;
        }
        return null;
    }

    /** Canonical decimal size after a prefix ("uint256" → 256); -1 when absent or non-canonical. */
    private static int sizeSuffix(String base, int prefix) {
        String digits = base.substring(prefix);
        if (digits.isEmpty() || digits.length() > 3 || digits.charAt(0) == '0') return -1;
        for (int i = 0; i < digits.length(); i++) if (digits.charAt(i) < '0' || digits.charAt(i) > '9') return -1;
        return Integer.parseInt(digits);
    }

    private static Struct parseStruct(Map<String, List<Field>> types, String type, Object raw, String path,
                                      int[] budget) throws InvalidTypedData {
        spend(budget);
        Map<String, Object> json = object(raw, path);
        List<Field> fields = types.get(type);
        Set<String> expected = new LinkedHashSet<>();
        for (Field f : fields) expected.add(f.name);
        if (!json.keySet().equals(expected)) {
            Set<String> missing = new TreeSet<>(expected);
            missing.removeAll(json.keySet());
            Set<String> unknown = new TreeSet<>(json.keySet());
            unknown.removeAll(expected);
            throw new InvalidTypedData(path + " (" + type + ") fields do not match its type; missing="
                    + missing + ", unknown=" + unknown);
        }
        LinkedHashMap<String, Value> values = new LinkedHashMap<>();
        for (Field f : fields) values.put(f.name, parseValue(types, f.type, json.get(f.name), path + "." + f.name, budget));
        return new Struct(type, Collections.unmodifiableMap(values));
    }

    private static Value parseValue(Map<String, List<Field>> types, String type, Object raw, String path,
                                    int[] budget) throws InvalidTypedData {
        if (type.endsWith("]")) {
            spend(budget);
            int open = type.lastIndexOf('[');
            String element = type.substring(0, open);
            String size = type.substring(open + 1, type.length() - 1);
            if (!(raw instanceof List)) throw new InvalidTypedData(path + " must be an array");
            List<?> list = (List<?>) raw;
            if (list.size() > MAX_ARRAY_LENGTH) throw new InvalidTypedData(path + " has more than " + MAX_ARRAY_LENGTH + " elements");
            if (!size.isEmpty() && list.size() != Integer.parseInt(size)) {
                throw new InvalidTypedData(path + " must have exactly " + size + " elements");
            }
            List<Value> out = new ArrayList<>(list.size());
            for (int i = 0; i < list.size(); i++) out.add(parseValue(types, element, list.get(i), path + "[" + i + "]", budget));
            return new Value(type, Kind.ARRAY, Collections.unmodifiableList(out));
        }
        Kind kind = atomicKind(type);
        if (kind == null) return new Value(type, Kind.STRUCT, parseStruct(types, type, raw, path, budget));
        spend(budget);
        switch (kind) {
            case BOOL:
                if (!(raw instanceof Boolean)) throw new InvalidTypedData(path + " must be true or false");
                return new Value(type, kind, raw);
            case ADDRESS: {
                if (!(raw instanceof String) || !Addresses.isEvm((String) raw)) {
                    throw new InvalidTypedData(path + " must be a 0x-prefixed 20-byte address");
                }
                String address = (String) raw;
                if (Addresses.hasMixedCase(address) && !Addresses.isChecksummed(address)) {
                    throw new InvalidTypedData(path + " fails its EIP-55 checksum");
                }
                return new Value(type, kind, Addresses.lowercase(address));
            }
            case UINT:
            case INT: {
                int bits = Integer.parseInt(type.substring(kind == Kind.UINT ? 4 : 3));
                return new Value(type, kind, integer(raw, kind == Kind.INT, bits, path));
            }
            case FIXED_BYTES: {
                int n = Integer.parseInt(type.substring(5));
                byte[] b = hexBytes(raw, path);
                if (b.length != n) throw new InvalidTypedData(path + " must be exactly " + n + " bytes");
                return new Value(type, kind, b);
            }
            case BYTES: {
                byte[] b = hexBytes(raw, path);
                if (b.length > MAX_DYNAMIC_BYTES) throw new InvalidTypedData(path + " exceeds " + MAX_DYNAMIC_BYTES + " bytes");
                return new Value(type, kind, b);
            }
            case STRING: {
                if (!(raw instanceof String)) throw new InvalidTypedData(path + " must be a string");
                if (((String) raw).getBytes(StandardCharsets.UTF_8).length > MAX_STRING_BYTES) {
                    throw new InvalidTypedData(path + " exceeds " + MAX_STRING_BYTES + " bytes");
                }
                return new Value(type, kind, raw);
            }
            default:
                throw new InvalidTypedData("Unsupported type " + type);
        }
    }

    private static BigInteger integer(Object raw, boolean signed, int bits, String path) throws InvalidTypedData {
        BigInteger value;
        if (raw instanceof StrictJson.Num) {
            String literal = ((StrictJson.Num) raw).literal;
            if (!DECIMAL.matcher(literal).matches() || "-0".equals(literal) || literal.length() > MAX_INTEGER_LITERAL) {
                throw new InvalidTypedData(path + " must be a whole number");
            }
            value = new BigInteger(literal);
        } else if (raw instanceof String) {
            String s = (String) raw;
            if (HEX_QUANTITY.matcher(s).matches()) {
                value = new BigInteger(s.substring(2), 16);
            } else if (DECIMAL.matcher(s).matches() && !"-0".equals(s) && s.length() <= MAX_INTEGER_LITERAL) {
                value = new BigInteger(s);
            } else {
                throw new InvalidTypedData(path + " must be a decimal or 0x-hex whole number");
            }
        } else {
            throw new InvalidTypedData(path + " must be a number");
        }
        BigInteger min = signed ? BigInteger.ONE.shiftLeft(bits - 1).negate() : BigInteger.ZERO;
        BigInteger maxExclusive = signed ? BigInteger.ONE.shiftLeft(bits - 1) : BigInteger.ONE.shiftLeft(bits);
        if (value.compareTo(min) < 0 || value.compareTo(maxExclusive) >= 0) {
            throw new InvalidTypedData(path + " is out of range for " + (signed ? "int" : "uint") + bits);
        }
        return value;
    }

    private static byte[] hexBytes(Object raw, String path) throws InvalidTypedData {
        if (!(raw instanceof String) || !HEX_BYTES.matcher((String) raw).matches() || (((String) raw).length() & 1) != 0) {
            throw new InvalidTypedData(path + " must be 0x-prefixed hex bytes");
        }
        String hex = ((String) raw).substring(2);
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        return out;
    }

    private static void spend(int[] budget) throws InvalidTypedData {
        if (--budget[0] < 0) throw new InvalidTypedData("Typed data has more than " + MAX_VALUES + " values");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object raw, String what) throws InvalidTypedData {
        if (!(raw instanceof Map)) throw new InvalidTypedData(what + " must be a JSON object");
        return (Map<String, Object>) raw;
    }

    private static void exactKeys(Map<String, Object> json, String what, String... keys) throws InvalidTypedData {
        if (!json.keySet().equals(new LinkedHashSet<>(Arrays.asList(keys)))) {
            throw new InvalidTypedData(what + " must have exactly the fields " + Arrays.toString(keys));
        }
    }

    // ------------------------------------------------------------------ encode

    /** Struct names reachable from {@code type} (excluding itself). */
    static Set<String> dependencies(Map<String, List<Field>> types, String type) {
        Set<String> found = new TreeSet<>();
        collect(types, type, found);
        found.remove(type);
        return found;
    }

    private static void collect(Map<String, List<Field>> types, String type, Set<String> found) {
        if (!found.add(type)) return;
        for (Field f : types.get(type)) {
            String base = baseType(f.type);
            if (atomicKind(base) == null && types.containsKey(base)) collect(types, base, found);
        }
    }

    static String baseType(String type) {
        int bracket = type.indexOf('[');
        return bracket < 0 ? type : type.substring(0, bracket);
    }

    static String encodeType(Map<String, List<Field>> types, String type) {
        StringBuilder out = new StringBuilder();
        appendType(out, types, type);
        for (String dep : dependencies(types, type)) appendType(out, types, dep); // TreeSet: sorted by name
        return out.toString();
    }

    private static void appendType(StringBuilder out, Map<String, List<Field>> types, String type) {
        out.append(type).append('(');
        List<Field> fields = types.get(type);
        for (int i = 0; i < fields.size(); i++) {
            if (i > 0) out.append(',');
            out.append(fields.get(i).type).append(' ').append(fields.get(i).name);
        }
        out.append(')');
    }

    static byte[] hashStruct(Map<String, List<Field>> types, Struct struct) {
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        data.write(Hash.sha3(encodeType(types, struct.type).getBytes(StandardCharsets.UTF_8)), 0, 32);
        for (Value v : struct.fields.values()) data.write(encodeValue(types, v), 0, 32);
        return Hash.sha3(data.toByteArray());
    }

    private static byte[] encodeValue(Map<String, List<Field>> types, Value v) {
        switch (v.kind) {
            case STRUCT: return hashStruct(types, v.struct());
            case ARRAY: {
                ByteArrayOutputStream concat = new ByteArrayOutputStream();
                for (Value e : v.elements()) concat.write(encodeValue(types, e), 0, 32);
                return Hash.sha3(concat.toByteArray());
            }
            case STRING: return Hash.sha3(v.text().getBytes(StandardCharsets.UTF_8));
            case BYTES: return Hash.sha3(v.bytes());
            case BOOL: return word(v.bool() ? BigInteger.ONE : BigInteger.ZERO);
            case ADDRESS: return word(new BigInteger(v.address().substring(2), 16));
            case UINT:
            case INT: return word(v.integer());
            case FIXED_BYTES: {
                byte[] out = new byte[32];
                byte[] b = v.bytes();
                System.arraycopy(b, 0, out, 0, b.length);
                return out;
            }
            default: throw new IllegalStateException("unreachable");
        }
    }

    /** 32-byte big-endian two's-complement word (values are range-checked at parse time). */
    private static byte[] word(BigInteger value) {
        byte[] out = new byte[32];
        if (value.signum() < 0) Arrays.fill(out, (byte) 0xff);
        byte[] b = value.toByteArray();
        int copy = Math.min(b.length, 32);
        System.arraycopy(b, b.length - copy, out, 32 - copy, copy);
        return out;
    }
}
