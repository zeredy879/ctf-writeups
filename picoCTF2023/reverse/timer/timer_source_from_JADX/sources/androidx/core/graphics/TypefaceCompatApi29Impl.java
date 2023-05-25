package androidx.core.graphics;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.Typeface;
import android.graphics.fonts.Font;
import android.graphics.fonts.FontFamily;
import android.graphics.fonts.FontStyle;
import androidx.constraintlayout.core.motion.utils.TypedValues;
import androidx.core.content.res.FontResourcesParserCompat;
import androidx.core.provider.FontsContractCompat;
import java.io.IOException;
import java.io.InputStream;

public class TypefaceCompatApi29Impl extends TypefaceCompatBaseImpl {
    /* access modifiers changed from: protected */
    public FontsContractCompat.FontInfo findBestInfo(FontsContractCompat.FontInfo[] fonts, int style) {
        throw new RuntimeException("Do not use this function in API 29 or later.");
    }

    /* access modifiers changed from: protected */
    public Typeface createFromInputStream(Context context, InputStream is) {
        throw new RuntimeException("Do not use this function in API 29 or later.");
    }

    /* JADX WARNING: Code restructure failed: missing block: B:33:0x0067, code lost:
        if (r0 != null) goto L_0x006a;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:34:0x0069, code lost:
        return null;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:37:0x006e, code lost:
        if ((r15 & 1) == 0) goto L_0x0073;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:38:0x0070, code lost:
        r5 = androidx.constraintlayout.core.motion.utils.TypedValues.TransitionType.TYPE_DURATION;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:39:0x0073, code lost:
        r5 = 400;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:41:0x0077, code lost:
        if ((r15 & 2) == 0) goto L_0x007c;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:42:0x0079, code lost:
        r4 = 1;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:44:0x0090, code lost:
        return new android.graphics.Typeface.CustomFallbackBuilder(r0.build()).setStyle(new android.graphics.fonts.FontStyle(r5, r4)).build();
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public android.graphics.Typeface createFromFontInfo(android.content.Context r12, android.os.CancellationSignal r13, androidx.core.provider.FontsContractCompat.FontInfo[] r14, int r15) {
        /*
            r11 = this;
            r0 = 0
            android.content.ContentResolver r1 = r12.getContentResolver()
            r2 = 0
            int r3 = r14.length     // Catch:{ Exception -> 0x0091 }
            r4 = 0
            r5 = 0
        L_0x0009:
            r6 = 1
            if (r5 >= r3) goto L_0x0067
            r7 = r14[r5]     // Catch:{ Exception -> 0x0091 }
            android.net.Uri r8 = r7.getUri()     // Catch:{ IOException -> 0x0063 }
            java.lang.String r9 = "r"
            android.os.ParcelFileDescriptor r8 = r1.openFileDescriptor(r8, r9, r13)     // Catch:{ IOException -> 0x0063 }
            if (r8 != 0) goto L_0x0020
            if (r8 == 0) goto L_0x001f
            r8.close()     // Catch:{ IOException -> 0x0063 }
        L_0x001f:
            goto L_0x0064
        L_0x0020:
            android.graphics.fonts.Font$Builder r9 = new android.graphics.fonts.Font$Builder     // Catch:{ all -> 0x0057 }
            r9.<init>(r8)     // Catch:{ all -> 0x0057 }
            int r10 = r7.getWeight()     // Catch:{ all -> 0x0057 }
            android.graphics.fonts.Font$Builder r9 = r9.setWeight(r10)     // Catch:{ all -> 0x0057 }
            boolean r10 = r7.isItalic()     // Catch:{ all -> 0x0057 }
            if (r10 == 0) goto L_0x0034
            goto L_0x0035
        L_0x0034:
            r6 = 0
        L_0x0035:
            android.graphics.fonts.Font$Builder r6 = r9.setSlant(r6)     // Catch:{ all -> 0x0057 }
            int r9 = r7.getTtcIndex()     // Catch:{ all -> 0x0057 }
            android.graphics.fonts.Font$Builder r6 = r6.setTtcIndex(r9)     // Catch:{ all -> 0x0057 }
            android.graphics.fonts.Font r6 = r6.build()     // Catch:{ all -> 0x0057 }
            if (r0 != 0) goto L_0x004e
            android.graphics.fonts.FontFamily$Builder r9 = new android.graphics.fonts.FontFamily$Builder     // Catch:{ all -> 0x0057 }
            r9.<init>(r6)     // Catch:{ all -> 0x0057 }
            r0 = r9
            goto L_0x0051
        L_0x004e:
            r0.addFont(r6)     // Catch:{ all -> 0x0057 }
        L_0x0051:
            if (r8 == 0) goto L_0x0056
            r8.close()     // Catch:{ IOException -> 0x0063 }
        L_0x0056:
            goto L_0x0064
        L_0x0057:
            r6 = move-exception
            if (r8 == 0) goto L_0x0062
            r8.close()     // Catch:{ all -> 0x005e }
            goto L_0x0062
        L_0x005e:
            r9 = move-exception
            r6.addSuppressed(r9)     // Catch:{ IOException -> 0x0063 }
        L_0x0062:
            throw r6     // Catch:{ IOException -> 0x0063 }
        L_0x0063:
            r6 = move-exception
        L_0x0064:
            int r5 = r5 + 1
            goto L_0x0009
        L_0x0067:
            if (r0 != 0) goto L_0x006a
            return r2
        L_0x006a:
            android.graphics.fonts.FontStyle r3 = new android.graphics.fonts.FontStyle     // Catch:{ Exception -> 0x0091 }
            r5 = r15 & 1
            if (r5 == 0) goto L_0x0073
            r5 = 700(0x2bc, float:9.81E-43)
            goto L_0x0075
        L_0x0073:
            r5 = 400(0x190, float:5.6E-43)
        L_0x0075:
            r7 = r15 & 2
            if (r7 == 0) goto L_0x007b
            r4 = 1
            goto L_0x007c
        L_0x007b:
        L_0x007c:
            r3.<init>(r5, r4)     // Catch:{ Exception -> 0x0091 }
            android.graphics.Typeface$CustomFallbackBuilder r4 = new android.graphics.Typeface$CustomFallbackBuilder     // Catch:{ Exception -> 0x0091 }
            android.graphics.fonts.FontFamily r5 = r0.build()     // Catch:{ Exception -> 0x0091 }
            r4.<init>(r5)     // Catch:{ Exception -> 0x0091 }
            android.graphics.Typeface$CustomFallbackBuilder r4 = r4.setStyle(r3)     // Catch:{ Exception -> 0x0091 }
            android.graphics.Typeface r2 = r4.build()     // Catch:{ Exception -> 0x0091 }
            return r2
        L_0x0091:
            r3 = move-exception
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.core.graphics.TypefaceCompatApi29Impl.createFromFontInfo(android.content.Context, android.os.CancellationSignal, androidx.core.provider.FontsContractCompat$FontInfo[], int):android.graphics.Typeface");
    }

    public Typeface createFromFontFamilyFilesResourceEntry(Context context, FontResourcesParserCompat.FontFamilyFilesResourceEntry familyEntry, Resources resources, int style) {
        int i;
        FontFamily.Builder familyBuilder = null;
        try {
            FontResourcesParserCompat.FontFileResourceEntry[] entries = familyEntry.getEntries();
            int length = entries.length;
            int i2 = 0;
            int i3 = 0;
            while (true) {
                int i4 = 1;
                if (i3 >= length) {
                    break;
                }
                FontResourcesParserCompat.FontFileResourceEntry entry = entries[i3];
                try {
                    Font.Builder weight = new Font.Builder(resources, entry.getResourceId()).setWeight(entry.getWeight());
                    if (!entry.isItalic()) {
                        i4 = 0;
                    }
                    Font platformFont = weight.setSlant(i4).setTtcIndex(entry.getTtcIndex()).setFontVariationSettings(entry.getVariationSettings()).build();
                    if (familyBuilder == null) {
                        familyBuilder = new FontFamily.Builder(platformFont);
                    } else {
                        familyBuilder.addFont(platformFont);
                    }
                } catch (IOException e) {
                }
                i3++;
            }
            if (familyBuilder == null) {
                return null;
            }
            if ((style & 1) != 0) {
                i = TypedValues.TransitionType.TYPE_DURATION;
            } else {
                i = 400;
            }
            if ((style & 2) != 0) {
                i2 = 1;
            }
            return new Typeface.CustomFallbackBuilder(familyBuilder.build()).setStyle(new FontStyle(i, i2)).build();
        } catch (Exception e2) {
            return null;
        }
    }

    public Typeface createFromResourcesFontFile(Context context, Resources resources, int id, String path, int style) {
        try {
            Font font = new Font.Builder(resources, id).build();
            return new Typeface.CustomFallbackBuilder(new FontFamily.Builder(font).build()).setStyle(font.getStyle()).build();
        } catch (Exception e) {
            return null;
        }
    }
}
