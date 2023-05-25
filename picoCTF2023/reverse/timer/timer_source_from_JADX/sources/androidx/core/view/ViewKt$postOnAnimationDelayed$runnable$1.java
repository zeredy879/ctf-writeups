package androidx.core.view;

import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

@Metadata(mo14702d1 = {"\u0000\u0006\n\u0000\n\u0002\u0010\u0002\u0010\u0000\u001a\u00020\u0001H\n"}, mo14703d2 = {"<anonymous>", ""}, mo14704k = 3, mo14705mv = {1, 5, 1}, mo14707xi = 48)
/* compiled from: View.kt */
public final class ViewKt$postOnAnimationDelayed$runnable$1 implements Runnable {
    final /* synthetic */ Function0<Unit> $action;

    public ViewKt$postOnAnimationDelayed$runnable$1(Function0<Unit> function0) {
        this.$action = function0;
    }

    public final void run() {
        this.$action.invoke();
    }
}
