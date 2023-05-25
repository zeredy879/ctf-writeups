package androidx.core.text;

import android.text.TextUtils;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata(mo14702d1 = {"\u0000\b\n\u0000\n\u0002\u0010\u000e\n\u0000\u001a\r\u0010\u0000\u001a\u00020\u0001*\u00020\u0001H\b¨\u0006\u0002"}, mo14703d2 = {"htmlEncode", "", "core-ktx_release"}, mo14704k = 2, mo14705mv = {1, 5, 1}, mo14707xi = 48)
/* compiled from: String.kt */
public final class StringKt {
    public static final String htmlEncode(String $this$htmlEncode) {
        Intrinsics.checkNotNullParameter($this$htmlEncode, "<this>");
        String htmlEncode = TextUtils.htmlEncode($this$htmlEncode);
        Intrinsics.checkNotNullExpressionValue(htmlEncode, "htmlEncode(this)");
        return htmlEncode;
    }
}
