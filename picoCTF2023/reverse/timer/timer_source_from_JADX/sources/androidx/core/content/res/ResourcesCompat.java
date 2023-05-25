package androidx.core.content.res;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.util.SparseArray;
import android.util.TypedValue;
import androidx.core.util.ObjectsCompat;
import androidx.core.util.Preconditions;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.WeakHashMap;

public final class ResourcesCompat {
    public static final int ID_NULL = 0;
    private static final String TAG = "ResourcesCompat";
    private static final Object sColorStateCacheLock = new Object();
    private static final WeakHashMap<ColorStateListCacheKey, SparseArray<ColorStateListCacheEntry>> sColorStateCaches = new WeakHashMap<>(0);
    private static final ThreadLocal<TypedValue> sTempTypedValue = new ThreadLocal<>();

    public static Drawable getDrawable(Resources res, int id, Resources.Theme theme) throws Resources.NotFoundException {
        if (Build.VERSION.SDK_INT >= 21) {
            return res.getDrawable(id, theme);
        }
        return res.getDrawable(id);
    }

    public static Drawable getDrawableForDensity(Resources res, int id, int density, Resources.Theme theme) throws Resources.NotFoundException {
        if (Build.VERSION.SDK_INT >= 21) {
            return res.getDrawableForDensity(id, density, theme);
        }
        if (Build.VERSION.SDK_INT >= 15) {
            return res.getDrawableForDensity(id, density);
        }
        return res.getDrawable(id);
    }

    public static int getColor(Resources res, int id, Resources.Theme theme) throws Resources.NotFoundException {
        if (Build.VERSION.SDK_INT >= 23) {
            return res.getColor(id, theme);
        }
        return res.getColor(id);
    }

    public static ColorStateList getColorStateList(Resources res, int id, Resources.Theme theme) throws Resources.NotFoundException {
        ColorStateListCacheKey key = new ColorStateListCacheKey(res, theme);
        ColorStateList csl = getCachedColorStateList(key, id);
        if (csl != null) {
            return csl;
        }
        ColorStateList csl2 = inflateColorStateList(res, id, theme);
        if (csl2 != null) {
            addColorStateListToCache(key, id, csl2);
            return csl2;
        } else if (Build.VERSION.SDK_INT >= 23) {
            return Api23Impl.getColorStateList(res, id, theme);
        } else {
            return res.getColorStateList(id);
        }
    }

    private static ColorStateList inflateColorStateList(Resources resources, int resId, Resources.Theme theme) {
        if (isColorInt(resources, resId)) {
            return null;
        }
        try {
            return ColorStateListInflaterCompat.createFromXml(resources, resources.getXml(resId), theme);
        } catch (Exception e) {
            Log.w(TAG, "Failed to inflate ColorStateList, leaving it to the framework", e);
            return null;
        }
    }

    /* JADX WARNING: Code restructure failed: missing block: B:16:0x0031, code lost:
        return null;
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    private static android.content.res.ColorStateList getCachedColorStateList(androidx.core.content.res.ResourcesCompat.ColorStateListCacheKey r5, int r6) {
        /*
            java.lang.Object r0 = sColorStateCacheLock
            monitor-enter(r0)
            java.util.WeakHashMap<androidx.core.content.res.ResourcesCompat$ColorStateListCacheKey, android.util.SparseArray<androidx.core.content.res.ResourcesCompat$ColorStateListCacheEntry>> r1 = sColorStateCaches     // Catch:{ all -> 0x0033 }
            java.lang.Object r1 = r1.get(r5)     // Catch:{ all -> 0x0033 }
            android.util.SparseArray r1 = (android.util.SparseArray) r1     // Catch:{ all -> 0x0033 }
            if (r1 == 0) goto L_0x0030
            int r2 = r1.size()     // Catch:{ all -> 0x0033 }
            if (r2 <= 0) goto L_0x0030
            java.lang.Object r2 = r1.get(r6)     // Catch:{ all -> 0x0033 }
            androidx.core.content.res.ResourcesCompat$ColorStateListCacheEntry r2 = (androidx.core.content.res.ResourcesCompat.ColorStateListCacheEntry) r2     // Catch:{ all -> 0x0033 }
            if (r2 == 0) goto L_0x0030
            android.content.res.Configuration r3 = r2.mConfiguration     // Catch:{ all -> 0x0033 }
            android.content.res.Resources r4 = r5.mResources     // Catch:{ all -> 0x0033 }
            android.content.res.Configuration r4 = r4.getConfiguration()     // Catch:{ all -> 0x0033 }
            boolean r3 = r3.equals(r4)     // Catch:{ all -> 0x0033 }
            if (r3 == 0) goto L_0x002d
            android.content.res.ColorStateList r3 = r2.mValue     // Catch:{ all -> 0x0033 }
            monitor-exit(r0)     // Catch:{ all -> 0x0033 }
            return r3
        L_0x002d:
            r1.remove(r6)     // Catch:{ all -> 0x0033 }
        L_0x0030:
            monitor-exit(r0)     // Catch:{ all -> 0x0033 }
            r0 = 0
            return r0
        L_0x0033:
            r1 = move-exception
            monitor-exit(r0)     // Catch:{ all -> 0x0033 }
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.core.content.res.ResourcesCompat.getCachedColorStateList(androidx.core.content.res.ResourcesCompat$ColorStateListCacheKey, int):android.content.res.ColorStateList");
    }

    private static void addColorStateListToCache(ColorStateListCacheKey key, int resId, ColorStateList value) {
        synchronized (sColorStateCacheLock) {
            WeakHashMap<ColorStateListCacheKey, SparseArray<ColorStateListCacheEntry>> weakHashMap = sColorStateCaches;
            SparseArray<ColorStateListCacheEntry> entries = weakHashMap.get(key);
            if (entries == null) {
                entries = new SparseArray<>();
                weakHashMap.put(key, entries);
            }
            entries.append(resId, new ColorStateListCacheEntry(value, key.mResources.getConfiguration()));
        }
    }

    private static boolean isColorInt(Resources resources, int resId) {
        TypedValue value = getTypedValue();
        resources.getValue(resId, value, true);
        if (value.type < 28 || value.type > 31) {
            return false;
        }
        return true;
    }

    private static TypedValue getTypedValue() {
        ThreadLocal<TypedValue> threadLocal = sTempTypedValue;
        TypedValue tv = threadLocal.get();
        if (tv != null) {
            return tv;
        }
        TypedValue tv2 = new TypedValue();
        threadLocal.set(tv2);
        return tv2;
    }

    private static final class ColorStateListCacheKey {
        final Resources mResources;
        final Resources.Theme mTheme;

        ColorStateListCacheKey(Resources resources, Resources.Theme theme) {
            this.mResources = resources;
            this.mTheme = theme;
        }

        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            ColorStateListCacheKey that = (ColorStateListCacheKey) o;
            if (!this.mResources.equals(that.mResources) || !ObjectsCompat.equals(this.mTheme, that.mTheme)) {
                return false;
            }
            return true;
        }

        public int hashCode() {
            return ObjectsCompat.hash(this.mResources, this.mTheme);
        }
    }

    private static class ColorStateListCacheEntry {
        final Configuration mConfiguration;
        final ColorStateList mValue;

        ColorStateListCacheEntry(ColorStateList value, Configuration configuration) {
            this.mValue = value;
            this.mConfiguration = configuration;
        }
    }

    public static float getFloat(Resources res, int id) {
        if (Build.VERSION.SDK_INT >= 29) {
            return ImplApi29.getFloat(res, id);
        }
        TypedValue value = getTypedValue();
        res.getValue(id, value, true);
        if (value.type == 4) {
            return value.getFloat();
        }
        throw new Resources.NotFoundException("Resource ID #0x" + Integer.toHexString(id) + " type #0x" + Integer.toHexString(value.type) + " is not valid");
    }

    public static Typeface getFont(Context context, int id) throws Resources.NotFoundException {
        if (context.isRestricted()) {
            return null;
        }
        return loadFont(context, id, new TypedValue(), 0, (FontCallback) null, (Handler) null, false, false);
    }

    public static Typeface getCachedFont(Context context, int id) throws Resources.NotFoundException {
        if (context.isRestricted()) {
            return null;
        }
        return loadFont(context, id, new TypedValue(), 0, (FontCallback) null, (Handler) null, false, true);
    }

    public static abstract class FontCallback {
        public abstract void onFontRetrievalFailed(int i);

        public abstract void onFontRetrieved(Typeface typeface);

        public final void callbackSuccessAsync(final Typeface typeface, Handler handler) {
            getHandler(handler).post(new Runnable() {
                public void run() {
                    FontCallback.this.onFontRetrieved(typeface);
                }
            });
        }

        public final void callbackFailAsync(final int reason, Handler handler) {
            getHandler(handler).post(new Runnable() {
                public void run() {
                    FontCallback.this.onFontRetrievalFailed(reason);
                }
            });
        }

        public static Handler getHandler(Handler handler) {
            return handler == null ? new Handler(Looper.getMainLooper()) : handler;
        }
    }

    public static void getFont(Context context, int id, FontCallback fontCallback, Handler handler) throws Resources.NotFoundException {
        Preconditions.checkNotNull(fontCallback);
        if (context.isRestricted()) {
            fontCallback.callbackFailAsync(-4, handler);
            return;
        }
        loadFont(context, id, new TypedValue(), 0, fontCallback, handler, false, false);
    }

    public static Typeface getFont(Context context, int id, TypedValue value, int style, FontCallback fontCallback) throws Resources.NotFoundException {
        if (context.isRestricted()) {
            return null;
        }
        return loadFont(context, id, value, style, fontCallback, (Handler) null, true, false);
    }

    private static Typeface loadFont(Context context, int id, TypedValue value, int style, FontCallback fontCallback, Handler handler, boolean isRequestFromLayoutInflator, boolean isCachedOnly) {
        Resources resources = context.getResources();
        int i = id;
        TypedValue typedValue = value;
        resources.getValue(id, value, true);
        Typeface typeface = loadFont(context, resources, value, id, style, fontCallback, handler, isRequestFromLayoutInflator, isCachedOnly);
        if (typeface != null || fontCallback != null || isCachedOnly) {
            return typeface;
        }
        throw new Resources.NotFoundException("Font resource ID #0x" + Integer.toHexString(id) + " could not be retrieved.");
    }

    /* JADX WARNING: Removed duplicated region for block: B:66:0x00f3  */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    private static android.graphics.Typeface loadFont(android.content.Context r19, android.content.res.Resources r20, android.util.TypedValue r21, int r22, int r23, androidx.core.content.res.ResourcesCompat.FontCallback r24, android.os.Handler r25, boolean r26, boolean r27) {
        /*
            r9 = r20
            r10 = r21
            r11 = r22
            r12 = r23
            r13 = r24
            r14 = r25
            java.lang.String r15 = "ResourcesCompat"
            java.lang.CharSequence r0 = r10.string
            if (r0 == 0) goto L_0x00f8
            java.lang.CharSequence r0 = r10.string
            java.lang.String r8 = r0.toString()
            java.lang.String r0 = "res/"
            boolean r0 = r8.startsWith(r0)
            r7 = -3
            r16 = 0
            if (r0 != 0) goto L_0x0029
            if (r13 == 0) goto L_0x0028
            r13.callbackFailAsync(r7, r14)
        L_0x0028:
            return r16
        L_0x0029:
            android.graphics.Typeface r6 = androidx.core.graphics.TypefaceCompat.findFromCache(r9, r11, r12)
            if (r6 == 0) goto L_0x0035
            if (r13 == 0) goto L_0x0034
            r13.callbackSuccessAsync(r6, r14)
        L_0x0034:
            return r6
        L_0x0035:
            if (r27 == 0) goto L_0x0038
            return r16
        L_0x0038:
            java.lang.String r0 = r8.toLowerCase()     // Catch:{ XmlPullParserException -> 0x00d6, IOException -> 0x00bb }
            java.lang.String r1 = ".xml"
            boolean r0 = r0.endsWith(r1)     // Catch:{ XmlPullParserException -> 0x00d6, IOException -> 0x00bb }
            if (r0 == 0) goto L_0x0097
            android.content.res.XmlResourceParser r0 = r9.getXml(r11)     // Catch:{ XmlPullParserException -> 0x0090, IOException -> 0x0089 }
            androidx.core.content.res.FontResourcesParserCompat$FamilyResourceEntry r1 = androidx.core.content.res.FontResourcesParserCompat.parse(r0, r9)     // Catch:{ XmlPullParserException -> 0x0090, IOException -> 0x0089 }
            r17 = r1
            if (r17 != 0) goto L_0x0068
            java.lang.String r1 = "Failed to find font-family tag"
            android.util.Log.e(r15, r1)     // Catch:{ XmlPullParserException -> 0x0062, IOException -> 0x005c }
            if (r13 == 0) goto L_0x005b
            r13.callbackFailAsync(r7, r14)     // Catch:{ XmlPullParserException -> 0x0062, IOException -> 0x005c }
        L_0x005b:
            return r16
        L_0x005c:
            r0 = move-exception
            r1 = r19
            r10 = r8
            goto L_0x00c1
        L_0x0062:
            r0 = move-exception
            r1 = r19
            r10 = r8
            goto L_0x00dc
        L_0x0068:
            r1 = r19
            r2 = r17
            r3 = r20
            r4 = r22
            r5 = r23
            r18 = r6
            r6 = r24
            r10 = -3
            r7 = r25
            r10 = r8
            r8 = r26
            android.graphics.Typeface r1 = androidx.core.graphics.TypefaceCompat.createFromResourcesFamilyXml(r1, r2, r3, r4, r5, r6, r7, r8)     // Catch:{ XmlPullParserException -> 0x0085, IOException -> 0x0081 }
            return r1
        L_0x0081:
            r0 = move-exception
            r1 = r19
            goto L_0x00b4
        L_0x0085:
            r0 = move-exception
            r1 = r19
            goto L_0x00b8
        L_0x0089:
            r0 = move-exception
            r18 = r6
            r10 = r8
            r1 = r19
            goto L_0x00c1
        L_0x0090:
            r0 = move-exception
            r18 = r6
            r10 = r8
            r1 = r19
            goto L_0x00dc
        L_0x0097:
            r18 = r6
            r10 = r8
            r1 = r19
            android.graphics.Typeface r0 = androidx.core.graphics.TypefaceCompat.createFromResourcesFontFile(r1, r9, r11, r10, r12)     // Catch:{ XmlPullParserException -> 0x00b7, IOException -> 0x00b3 }
            r6 = r0
            if (r13 == 0) goto L_0x00b2
            if (r6 == 0) goto L_0x00a9
            r13.callbackSuccessAsync(r6, r14)     // Catch:{ XmlPullParserException -> 0x00b0, IOException -> 0x00ae }
            goto L_0x00b2
        L_0x00a9:
            r2 = -3
            r13.callbackFailAsync(r2, r14)     // Catch:{ XmlPullParserException -> 0x00b0, IOException -> 0x00ae }
            goto L_0x00b2
        L_0x00ae:
            r0 = move-exception
            goto L_0x00c1
        L_0x00b0:
            r0 = move-exception
            goto L_0x00dc
        L_0x00b2:
            return r6
        L_0x00b3:
            r0 = move-exception
        L_0x00b4:
            r6 = r18
            goto L_0x00c1
        L_0x00b7:
            r0 = move-exception
        L_0x00b8:
            r6 = r18
            goto L_0x00dc
        L_0x00bb:
            r0 = move-exception
            r1 = r19
            r18 = r6
            r10 = r8
        L_0x00c1:
            java.lang.StringBuilder r2 = new java.lang.StringBuilder
            r2.<init>()
            java.lang.String r3 = "Failed to read xml resource "
            r2.append(r3)
            r2.append(r10)
            java.lang.String r2 = r2.toString()
            android.util.Log.e(r15, r2, r0)
            goto L_0x00f1
        L_0x00d6:
            r0 = move-exception
            r1 = r19
            r18 = r6
            r10 = r8
        L_0x00dc:
            java.lang.StringBuilder r2 = new java.lang.StringBuilder
            r2.<init>()
            java.lang.String r3 = "Failed to parse xml resource "
            r2.append(r3)
            r2.append(r10)
            java.lang.String r2 = r2.toString()
            android.util.Log.e(r15, r2, r0)
        L_0x00f1:
            if (r13 == 0) goto L_0x00f7
            r2 = -3
            r13.callbackFailAsync(r2, r14)
        L_0x00f7:
            return r16
        L_0x00f8:
            r1 = r19
            android.content.res.Resources$NotFoundException r0 = new android.content.res.Resources$NotFoundException
            java.lang.StringBuilder r2 = new java.lang.StringBuilder
            r2.<init>()
            java.lang.String r3 = "Resource \""
            r2.append(r3)
            java.lang.String r3 = r9.getResourceName(r11)
            r2.append(r3)
            java.lang.String r3 = "\" ("
            r2.append(r3)
            java.lang.String r3 = java.lang.Integer.toHexString(r22)
            r2.append(r3)
            java.lang.String r3 = ") is not a Font: "
            r2.append(r3)
            r3 = r21
            r2.append(r3)
            java.lang.String r2 = r2.toString()
            r0.<init>(r2)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.core.content.res.ResourcesCompat.loadFont(android.content.Context, android.content.res.Resources, android.util.TypedValue, int, int, androidx.core.content.res.ResourcesCompat$FontCallback, android.os.Handler, boolean, boolean):android.graphics.Typeface");
    }

    static class ImplApi29 {
        private ImplApi29() {
        }

        static float getFloat(Resources res, int id) {
            return res.getFloat(id);
        }
    }

    static class Api23Impl {
        private Api23Impl() {
        }

        static ColorStateList getColorStateList(Resources res, int id, Resources.Theme theme) {
            return res.getColorStateList(id, theme);
        }
    }

    private ResourcesCompat() {
    }

    public static final class ThemeCompat {
        private ThemeCompat() {
        }

        public static void rebase(Resources.Theme theme) {
            if (Build.VERSION.SDK_INT >= 29) {
                ImplApi29.rebase(theme);
            } else if (Build.VERSION.SDK_INT >= 23) {
                ImplApi23.rebase(theme);
            }
        }

        static class ImplApi29 {
            private ImplApi29() {
            }

            static void rebase(Resources.Theme theme) {
                theme.rebase();
            }
        }

        static class ImplApi23 {
            private static Method sRebaseMethod;
            private static boolean sRebaseMethodFetched;
            private static final Object sRebaseMethodLock = new Object();

            private ImplApi23() {
            }

            static void rebase(Resources.Theme theme) {
                synchronized (sRebaseMethodLock) {
                    if (!sRebaseMethodFetched) {
                        try {
                            Method declaredMethod = Resources.Theme.class.getDeclaredMethod("rebase", new Class[0]);
                            sRebaseMethod = declaredMethod;
                            declaredMethod.setAccessible(true);
                        } catch (NoSuchMethodException e) {
                            Log.i(ResourcesCompat.TAG, "Failed to retrieve rebase() method", e);
                        }
                        sRebaseMethodFetched = true;
                    }
                    Method method = sRebaseMethod;
                    if (method != null) {
                        try {
                            method.invoke(theme, new Object[0]);
                        } catch (IllegalAccessException | InvocationTargetException e2) {
                            Log.i(ResourcesCompat.TAG, "Failed to invoke rebase() method via reflection", e2);
                            sRebaseMethod = null;
                        }
                    }
                }
            }
        }
    }
}
