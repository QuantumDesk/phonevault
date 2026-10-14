package dev.phonevault.signer;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Reads the app's own main sources for source-guard tests: checks on code paths only a phone can
 * exercise (UI thread, keystore, USB). Works from the app module or the repository root.
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

    /** One main source file, e.g. {@code "MainActivity.java"}. */
    static String source(String file) throws IOException {
        Path p = dir().resolve(file);
        if (!Files.exists(p)) fail(file + " not found in " + p.getParent().toAbsolutePath());
        return new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
    }

    static String mainActivity() throws IOException { return source("MainActivity.java"); }

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
