package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads the app's own main sources for source-guard tests: checks on code paths only a phone can
 * exercise (UI thread, keystore, USB). Works from the app module or the repository root.
 *
 * <p>Prefer the package-wide helpers ({@link #all}, {@link #definition}, {@link #count}): a guard
 * that names one file silently stops guarding when the code it checks moves to another class.
 */
final class SourceGuard {
    private SourceGuard() {}

    private static final String[] ROOTS = {"src/main/java/dev/phonevault/signer", "app/src/main/java/dev/phonevault/signer"};

    /** The main source directory. */
    static Path dir() {
        for (String root : ROOTS) {
            Path p = Paths.get(root);
            if (Files.isDirectory(p)) return p;
        }
        fail("sources not found from " + Paths.get("").toAbsolutePath());
        return null;
    }

    /** One main source file, e.g. {@code "VaultKeyStore.java"}. */
    static String source(String file) throws IOException {
        Path p = dir().resolve(file);
        if (!Files.exists(p)) fail(file + " not found in " + p.getParent().toAbsolutePath());
        return new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
    }

    static String mainActivity() throws IOException { return source("MainActivity.java"); }

    /** Every main source file of the signer package, file name → text. */
    static Map<String, String> all() throws IOException {
        Map<String, String> files = new TreeMap<>();
        try (DirectoryStream<Path> dir = Files.newDirectoryStream(dir(), "*.java")) {
            for (Path f : dir) files.put(f.getFileName().toString(), new String(Files.readAllBytes(f), StandardCharsets.UTF_8));
        }
        assertTrue("package sources found", files.size() > 20);
        return files;
    }

    /** The one main source file whose text contains {@code signature}; fails if none or several do. */
    static String fileWith(String signature) throws IOException {
        List<String> found = new ArrayList<>();
        for (Map.Entry<String, String> f : all().entrySet()) if (f.getValue().contains(signature)) found.add(f.getKey());
        assertEquals(signature + " should be in exactly one file, found in " + found, 1, found.size());
        return found.get(0);
    }

    /** A member's body, wherever in the package it is defined (see {@link #body}). */
    static String definition(String signature) throws IOException {
        return body(source(fileWith(signature)), signature);
    }

    /** True when any main source file contains {@code literal}. */
    static boolean anyContains(String literal) throws IOException {
        for (String src : all().values()) if (src.contains(literal)) return true;
        return false;
    }

    /** Occurrences of {@code regex} in the code (comments removed) of every main source file. */
    static int count(String regex) throws IOException {
        Pattern p = Pattern.compile(regex);
        int n = 0;
        for (String src : all().values()) {
            Matcher m = p.matcher(code(src));
            while (m.find()) n++;
        }
        return n;
    }

    /** A member's body: from {@code signature} to the first closing brace at member indentation. */
    static String body(String src, String signature) {
        int start = src.indexOf(signature);
        assertTrue(signature + " is missing", start >= 0);
        return src.substring(start, src.indexOf("\n    }\n", start));
    }

    /** The text with block and line comments removed. */
    static String code(String src) {
        return src.replaceAll("(?s)/\\*.*?\\*/", "").replaceAll("//[^\n]*", "");
    }
}
