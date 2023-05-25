package androidx.core.provider;

import android.content.ContentUris;
import android.content.Context;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.content.pm.Signature;
import android.content.res.Resources;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.CancellationSignal;
import androidx.core.content.res.FontResourcesParserCompat;
import androidx.core.provider.FontsContractCompat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

class FontProvider {
    private static final Comparator<byte[]> sByteArrayComparator = new Comparator<byte[]>() {
        public int compare(byte[] l, byte[] r) {
            if (l.length != r.length) {
                return l.length - r.length;
            }
            for (int i = 0; i < l.length; i++) {
                if (l[i] != r[i]) {
                    return l[i] - r[i];
                }
            }
            return 0;
        }
    };

    private FontProvider() {
    }

    static FontsContractCompat.FontFamilyResult getFontFamilyResult(Context context, FontRequest request, CancellationSignal cancellationSignal) throws PackageManager.NameNotFoundException {
        ProviderInfo providerInfo = getProvider(context.getPackageManager(), request, context.getResources());
        if (providerInfo == null) {
            return FontsContractCompat.FontFamilyResult.create(1, (FontsContractCompat.FontInfo[]) null);
        }
        return FontsContractCompat.FontFamilyResult.create(0, query(context, request, providerInfo.authority, cancellationSignal));
    }

    static ProviderInfo getProvider(PackageManager packageManager, FontRequest request, Resources resources) throws PackageManager.NameNotFoundException {
        String providerAuthority = request.getProviderAuthority();
        ProviderInfo info = packageManager.resolveContentProvider(providerAuthority, 0);
        if (info == null) {
            throw new PackageManager.NameNotFoundException("No package found for authority: " + providerAuthority);
        } else if (info.packageName.equals(request.getProviderPackage())) {
            List<byte[]> signatures = convertToByteArrayList(packageManager.getPackageInfo(info.packageName, 64).signatures);
            Collections.sort(signatures, sByteArrayComparator);
            List<List<byte[]>> requestCertificatesList = getCertificates(request, resources);
            for (int i = 0; i < requestCertificatesList.size(); i++) {
                List<byte[]> requestSignatures = new ArrayList<>(requestCertificatesList.get(i));
                Collections.sort(requestSignatures, sByteArrayComparator);
                if (equalsByteArrayList(signatures, requestSignatures)) {
                    return info;
                }
            }
            return null;
        } else {
            throw new PackageManager.NameNotFoundException("Found content provider " + providerAuthority + ", but package was not " + request.getProviderPackage());
        }
    }

    static FontsContractCompat.FontInfo[] query(Context context, FontRequest request, String authority, CancellationSignal cancellationSignal) {
        int resultCode;
        int idColumnIndex;
        Uri fileUri;
        Cursor cursor;
        String str = authority;
        ArrayList<FontsContractCompat.FontInfo> result = new ArrayList<>();
        Uri uri = new Uri.Builder().scheme("content").authority(str).build();
        Uri fileBaseUri = new Uri.Builder().scheme("content").authority(str).appendPath("file").build();
        Cursor cursor2 = null;
        try {
            String[] projection = {"_id", FontsContractCompat.Columns.FILE_ID, FontsContractCompat.Columns.TTC_INDEX, FontsContractCompat.Columns.VARIATION_SETTINGS, FontsContractCompat.Columns.WEIGHT, FontsContractCompat.Columns.ITALIC, FontsContractCompat.Columns.RESULT_CODE};
            int ttcIndex = 1;
            if (Build.VERSION.SDK_INT > 16) {
                cursor = context.getContentResolver().query(uri, projection, "query = ?", new String[]{request.getQuery()}, (String) null, cancellationSignal);
            } else {
                cursor = context.getContentResolver().query(uri, projection, "query = ?", new String[]{request.getQuery()}, (String) null);
            }
            if (cursor2 != null && cursor2.getCount() > 0) {
                int resultCodeColumnIndex = cursor2.getColumnIndex(FontsContractCompat.Columns.RESULT_CODE);
                result = new ArrayList<>();
                int weight = cursor2.getColumnIndex("_id");
                int fileIdColumnIndex = cursor2.getColumnIndex(FontsContractCompat.Columns.FILE_ID);
                int ttcIndexColumnIndex = cursor2.getColumnIndex(FontsContractCompat.Columns.TTC_INDEX);
                int weightColumnIndex = cursor2.getColumnIndex(FontsContractCompat.Columns.WEIGHT);
                int italicColumnIndex = cursor2.getColumnIndex(FontsContractCompat.Columns.ITALIC);
                while (cursor2.moveToNext()) {
                    if (resultCodeColumnIndex != -1) {
                        resultCode = cursor2.getInt(resultCodeColumnIndex);
                    } else {
                        resultCode = 0;
                    }
                    int ttcIndex2 = ttcIndexColumnIndex != -1 ? cursor2.getInt(ttcIndexColumnIndex) : 0;
                    if (fileIdColumnIndex == -1) {
                        idColumnIndex = weight;
                        fileUri = ContentUris.withAppendedId(uri, cursor2.getLong(weight));
                    } else {
                        idColumnIndex = weight;
                        fileUri = ContentUris.withAppendedId(fileBaseUri, cursor2.getLong(fileIdColumnIndex));
                    }
                    int weight2 = weightColumnIndex != -1 ? cursor2.getInt(weightColumnIndex) : 400;
                    boolean italic = italicColumnIndex != -1 && cursor2.getInt(italicColumnIndex) == ttcIndex;
                    int ttcIndex3 = ttcIndex2;
                    int ttcIndex4 = resultCodeColumnIndex;
                    result.add(FontsContractCompat.FontInfo.create(fileUri, ttcIndex3, weight2, italic, resultCode));
                    resultCodeColumnIndex = ttcIndex4;
                    weight = idColumnIndex;
                    ttcIndex = 1;
                }
                int i = weight;
            }
            return (FontsContractCompat.FontInfo[]) result.toArray(new FontsContractCompat.FontInfo[0]);
        } finally {
            if (cursor2 != null) {
                cursor2.close();
            }
        }
    }

    private static List<List<byte[]>> getCertificates(FontRequest request, Resources resources) {
        if (request.getCertificates() != null) {
            return request.getCertificates();
        }
        return FontResourcesParserCompat.readCerts(resources, request.getCertificatesArrayResId());
    }

    private static boolean equalsByteArrayList(List<byte[]> signatures, List<byte[]> requestSignatures) {
        if (signatures.size() != requestSignatures.size()) {
            return false;
        }
        for (int i = 0; i < signatures.size(); i++) {
            if (!Arrays.equals(signatures.get(i), requestSignatures.get(i))) {
                return false;
            }
        }
        return true;
    }

    private static List<byte[]> convertToByteArrayList(Signature[] signatures) {
        List<byte[]> shaList = new ArrayList<>();
        for (Signature byteArray : signatures) {
            shaList.add(byteArray.toByteArray());
        }
        return shaList;
    }
}
