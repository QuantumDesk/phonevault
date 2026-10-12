package dev.phonevault.signer;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The user's own contact names for addresses, kept on the phone only (app-private storage, which
 * Android's file-based encryption protects at rest). A name shown on a review comes ONLY from this
 * book — never from the host — so a compromised computer cannot label an attacker's address
 * "Alice". Names are short plain ASCII so they cannot hide or reorder characters.
 *
 * <p>Adding, renaming and deleting need no PIN: the book only labels addresses; it never changes
 * what is signed, and every review still shows the full address.
 */
final class AddressBook {
    static final String FILE = "address-book.json";
    static final int MAX_CONTACTS = 200;
    static final int MAX_NAME = 24;

    /** Bytes in, bytes out; the Android implementation writes atomically into app-private storage. */
    interface Store {
        /** The file's bytes, or null if it does not exist. */
        byte[] read(String name) throws IOException;
        void write(String name, byte[] bytes) throws IOException;
    }

    static final class Contact {
        final String address;  // lower-case
        final String name;
        final long added;

        Contact(String address, String name, long added) {
            this.address = address;
            this.name = name;
            this.added = added;
        }
    }

    static final class InvalidNameException extends Exception {
        InvalidNameException(String message) { super(message); }
    }

    private final Store store;
    private final Map<String, Contact> contacts = new LinkedHashMap<>();
    /** Non-null when the saved book could not be read; the book then starts empty and is not overwritten. */
    private String problem;

    AddressBook(Store store) {
        this.store = store;
        load();
    }

    synchronized String problem() { return problem; }

    private void load() {
        try {
            byte[] bytes = store.read(FILE);
            if (bytes == null) return;
            JSONObject root = new JSONObject(new String(bytes, StandardCharsets.UTF_8));
            if (root.getInt("version") != 1) throw new JSONException("unsupported version");
            JSONArray list = root.getJSONArray("contacts");
            for (int i = 0; i < list.length() && i < MAX_CONTACTS; i++) {
                JSONObject c = list.getJSONObject(i);
                String address = normalize(c.getString("address"));
                String name = validName(c.getString("name"));
                contacts.put(address, new Contact(address, name, c.getLong("added")));
            }
        } catch (IOException | JSONException | InvalidNameException | IllegalArgumentException e) {
            contacts.clear();
            problem = "the saved address book could not be read (" + e.getMessage() + ")";
        }
    }

    /** The saved name for {@code address}, or null. */
    synchronized String name(String address) {
        if (address == null) return null;
        Contact c = contacts.get(address.toLowerCase(Locale.ROOT));
        return c == null ? null : c.name;
    }

    synchronized List<Contact> list() {
        List<Contact> out = new ArrayList<>(contacts.values());
        Collections.sort(out, (a, b) -> a.name.compareToIgnoreCase(b.name));
        return out;
    }

    synchronized int size() { return contacts.size(); }

    /** Adds or renames. Throws for an invalid or duplicate name, a full book, or a storage failure. */
    synchronized void put(String address, String name, long now) throws InvalidNameException, IOException {
        if (problem != null) throw new IOException("The address book on this phone could not be read, so it is not changed: " + problem);
        String key = normalize(address);
        String clean = validName(name);
        for (Contact c : contacts.values()) {
            if (!c.address.equals(key) && c.name.equalsIgnoreCase(clean)) {
                throw new InvalidNameException("Another address is already saved as \"" + c.name + "\". Pick a different name.");
            }
        }
        if (!contacts.containsKey(key) && contacts.size() >= MAX_CONTACTS) {
            throw new InvalidNameException("The address book is full (" + MAX_CONTACTS + " contacts). Delete one first.");
        }
        Contact old = contacts.get(key);
        Map<String, Contact> before = new LinkedHashMap<>(contacts);
        contacts.put(key, new Contact(key, clean, old == null ? now : old.added));
        try {
            save();
        } catch (IOException e) {
            contacts.clear();
            contacts.putAll(before);
            throw e;
        }
    }

    synchronized void remove(String address) throws IOException {
        if (problem != null) throw new IOException("The address book on this phone could not be read, so it is not changed: " + problem);
        String key = normalize(address);
        Contact old = contacts.remove(key);
        if (old == null) return;
        try {
            save();
        } catch (IOException e) {
            contacts.put(key, old);
            throw e;
        }
    }

    private void save() throws IOException {
        try {
            JSONArray list = new JSONArray();
            for (Contact c : contacts.values()) {
                list.put(new JSONObject().put("address", c.address).put("name", c.name).put("added", c.added));
            }
            store.write(FILE, new JSONObject().put("version", 1).put("contacts", list).toString().getBytes(StandardCharsets.UTF_8));
        } catch (JSONException impossible) {
            throw new IOException(impossible);
        }
    }

    /** 1–24 characters: letters, digits, space, '.', '-', apostrophe — starting with a letter or digit, single spaces. */
    static String validName(String name) throws InvalidNameException {
        if (name == null) throw new InvalidNameException("Enter a name.");
        String clean = name.trim();
        if (clean.isEmpty()) throw new InvalidNameException("Enter a name.");
        if (clean.length() > MAX_NAME) throw new InvalidNameException("Use at most " + MAX_NAME + " characters.");
        if (!clean.matches("[A-Za-z0-9][A-Za-z0-9 .'-]*")) {
            throw new InvalidNameException("Use letters, digits, spaces, '.', '-' or an apostrophe, starting with a letter or digit.");
        }
        if (clean.contains("  ")) throw new InvalidNameException("Use single spaces.");
        if (clean.matches("(?i)0x[0-9a-f]*")) throw new InvalidNameException("A name cannot look like an address.");
        return clean;
    }

    static String normalize(String address) {
        if (address == null || !address.matches("0x[0-9a-fA-F]{40}")) throw new IllegalArgumentException("not an address");
        return address.toLowerCase(Locale.ROOT);
    }
}
