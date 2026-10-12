package dev.phonevault.signer;

import android.content.Context;
import android.util.AtomicFile;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * App-private, atomically replaced files for {@link AddressBook} and {@link RecipientHistory}
 * ({@code files/safety/}). App-private storage is credential-encrypted by Android's file-based
 * encryption, like the wallet's preferences; nothing here is secret key material.
 */
final class FileSafetyStore implements AddressBook.Store {
    private static final int MAX_BYTES = 512 * 1024;
    private final File dir;

    FileSafetyStore(Context context) {
        this.dir = new File(context.getFilesDir(), "safety");
    }

    @Override public byte[] read(String name) throws IOException {
        AtomicFile file = new AtomicFile(new File(dir, name));
        if (!file.getBaseFile().exists()) return null;
        if (file.getBaseFile().length() > MAX_BYTES) throw new IOException(name + " is too large");
        try {
            return file.readFully();
        } catch (FileNotFoundException gone) {
            return null;
        }
    }

    @Override public void write(String name, byte[] bytes) throws IOException {
        if (!dir.isDirectory() && !dir.mkdirs()) throw new IOException("cannot create " + dir);
        AtomicFile file = new AtomicFile(new File(dir, name));
        FileOutputStream out = file.startWrite();
        try {
            out.write(bytes);
            file.finishWrite(out); // fsync + rename
        } catch (IOException e) {
            file.failWrite(out);
            throw e;
        }
    }
}
