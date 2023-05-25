package androidx.startup;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;

public final class InitializationProvider extends ContentProvider {
    public boolean onCreate() {
        Context context = getContext();
        if (context != null) {
            AppInitializer.getInstance(context).discoverAndInitialize();
            return true;
        }
        throw new StartupException("Context cannot be null");
    }

    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        throw new IllegalStateException("Not allowed.");
    }

    public String getType(Uri uri) {
        throw new IllegalStateException("Not allowed.");
    }

    public Uri insert(Uri uri, ContentValues values) {
        throw new IllegalStateException("Not allowed.");
    }

    public int delete(Uri uri, String selection, String[] selectionArgs) {
        throw new IllegalStateException("Not allowed.");
    }

    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        throw new IllegalStateException("Not allowed.");
    }
}
