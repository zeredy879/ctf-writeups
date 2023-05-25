package kotlin.collections;

import java.util.Iterator;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Lambda;

@Metadata(mo14702d1 = {"\u0000\n\n\u0000\n\u0002\u0010(\n\u0002\b\u0002\u0010\u0000\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0001\"\u0004\b\u0000\u0010\u0002H\n¢\u0006\u0002\b\u0003"}, mo14703d2 = {"<anonymous>", "", "T", "invoke"}, mo14704k = 3, mo14705mv = {1, 6, 0}, mo14707xi = 48)
/* compiled from: _Collections.kt */
final class CollectionsKt___CollectionsKt$withIndex$1 extends Lambda implements Function0<Iterator<? extends T>> {
    final /* synthetic */ Iterable<T> $this_withIndex;

    /* JADX INFO: super call moved to the top of the method (can break code semantics) */
    CollectionsKt___CollectionsKt$withIndex$1(Iterable<? extends T> iterable) {
        super(0);
        this.$this_withIndex = iterable;
    }

    public final Iterator<T> invoke() {
        return this.$this_withIndex.iterator();
    }
}
