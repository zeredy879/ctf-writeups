package kotlin.collections;

import java.util.Iterator;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.ArrayIteratorsKt;
import kotlin.jvm.internal.Lambda;

@Metadata(mo14702d1 = {"\u0000\f\n\u0000\n\u0002\u0010(\n\u0002\u0010\u0007\n\u0000\u0010\u0000\u001a\b\u0012\u0004\u0012\u00020\u00020\u0001H\n¢\u0006\u0002\b\u0003"}, mo14703d2 = {"<anonymous>", "", "", "invoke"}, mo14704k = 3, mo14705mv = {1, 6, 0}, mo14707xi = 48)
/* compiled from: _Arrays.kt */
final class ArraysKt___ArraysKt$withIndex$6 extends Lambda implements Function0<Iterator<? extends Float>> {
    final /* synthetic */ float[] $this_withIndex;

    /* JADX INFO: super call moved to the top of the method (can break code semantics) */
    ArraysKt___ArraysKt$withIndex$6(float[] fArr) {
        super(0);
        this.$this_withIndex = fArr;
    }

    public final Iterator<Float> invoke() {
        return ArrayIteratorsKt.iterator(this.$this_withIndex);
    }
}
