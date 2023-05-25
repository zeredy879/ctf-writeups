package androidx.core.view;

import android.view.View;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

@Metadata(mo14702d1 = {"\u0000\u0006\n\u0000\n\u0002\u0010\u0002\u0010\u0000\u001a\u00020\u0001H\n"}, mo14703d2 = {"<anonymous>", ""}, mo14704k = 3, mo14705mv = {1, 5, 1}, mo14707xi = 48)
/* compiled from: View.kt */
public final class ViewKt$doOnPreDraw$1 implements Runnable {
    final /* synthetic */ Function1<View, Unit> $action;
    final /* synthetic */ View $this_doOnPreDraw;

    public ViewKt$doOnPreDraw$1(Function1<? super View, Unit> function1, View view) {
        this.$action = function1;
        this.$this_doOnPreDraw = view;
    }

    public final void run() {
        this.$action.invoke(this.$this_doOnPreDraw);
    }
}
