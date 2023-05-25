package androidx.core.graphics;

import android.graphics.Paint;
import android.graphics.Rect;
import android.os.Build;
import androidx.core.util.Pair;

public final class PaintCompat {
    private static final String EM_STRING = "m";
    private static final String TOFU_STRING = "󟿽";
    private static final ThreadLocal<Pair<Rect, Rect>> sRectThreadLocal = new ThreadLocal<>();

    public static boolean hasGlyph(Paint paint, String string) {
        if (Build.VERSION.SDK_INT >= 23) {
            return paint.hasGlyph(string);
        }
        int length = string.length();
        if (length == 1 && Character.isWhitespace(string.charAt(0))) {
            return true;
        }
        float missingGlyphWidth = paint.measureText(TOFU_STRING);
        float emGlyphWidth = paint.measureText(EM_STRING);
        float width = paint.measureText(string);
        if (width == 0.0f) {
            return false;
        }
        if (string.codePointCount(0, string.length()) > 1) {
            if (width > 2.0f * emGlyphWidth) {
                return false;
            }
            float sumWidth = 0.0f;
            int i = 0;
            while (i < length) {
                int charCount = Character.charCount(string.codePointAt(i));
                sumWidth += paint.measureText(string, i, i + charCount);
                i += charCount;
            }
            if (width >= sumWidth) {
                return false;
            }
        }
        if (width != missingGlyphWidth) {
            return true;
        }
        Pair<Rect, Rect> rects = obtainEmptyRects();
        paint.getTextBounds(TOFU_STRING, 0, TOFU_STRING.length(), (Rect) rects.first);
        paint.getTextBounds(string, 0, length, (Rect) rects.second);
        return true ^ ((Rect) rects.first).equals(rects.second);
    }

    /* JADX DEBUG: Multi-variable search result rejected for TypeSearchVarInfo{r2v3, resolved type: android.graphics.BlendMode} */
    /* JADX WARNING: type inference failed for: r2v0 */
    /* JADX WARNING: type inference failed for: r2v1, types: [android.graphics.Xfermode] */
    /* JADX WARNING: type inference failed for: r2v5 */
    /* JADX WARNING: type inference failed for: r2v6 */
    /* JADX WARNING: Multi-variable type inference failed */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public static boolean setBlendMode(android.graphics.Paint r4, androidx.core.graphics.BlendModeCompat r5) {
        /*
            int r0 = android.os.Build.VERSION.SDK_INT
            r1 = 1
            r2 = 0
            r3 = 29
            if (r0 < r3) goto L_0x0012
            if (r5 == 0) goto L_0x000e
            android.graphics.BlendMode r2 = androidx.core.graphics.BlendModeUtils.obtainBlendModeFromCompat(r5)
        L_0x000e:
            r4.setBlendMode(r2)
            return r1
        L_0x0012:
            if (r5 == 0) goto L_0x0027
            android.graphics.PorterDuff$Mode r0 = androidx.core.graphics.BlendModeUtils.obtainPorterDuffFromCompat(r5)
            if (r0 == 0) goto L_0x001f
            android.graphics.PorterDuffXfermode r2 = new android.graphics.PorterDuffXfermode
            r2.<init>(r0)
        L_0x001f:
            r4.setXfermode(r2)
            if (r0 == 0) goto L_0x0025
            goto L_0x0026
        L_0x0025:
            r1 = 0
        L_0x0026:
            return r1
        L_0x0027:
            r4.setXfermode(r2)
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.core.graphics.PaintCompat.setBlendMode(android.graphics.Paint, androidx.core.graphics.BlendModeCompat):boolean");
    }

    private static Pair<Rect, Rect> obtainEmptyRects() {
        ThreadLocal<Pair<Rect, Rect>> threadLocal = sRectThreadLocal;
        Pair<Rect, Rect> rects = threadLocal.get();
        if (rects == null) {
            Pair<Rect, Rect> rects2 = new Pair<>(new Rect(), new Rect());
            threadLocal.set(rects2);
            return rects2;
        }
        ((Rect) rects.first).setEmpty();
        ((Rect) rects.second).setEmpty();
        return rects;
    }

    private PaintCompat() {
    }
}
