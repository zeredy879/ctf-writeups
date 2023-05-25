package androidx.core.transition;

import android.transition.Transition;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;

@Metadata(mo14702d1 = {"\u0000\f\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0003H\n"}, mo14703d2 = {"<anonymous>", "", "it", "Landroid/transition/Transition;"}, mo14704k = 3, mo14705mv = {1, 5, 1}, mo14707xi = 48)
/* compiled from: Transition.kt */
public final class TransitionKt$addListener$5 extends Lambda implements Function1<Transition, Unit> {
    public static final TransitionKt$addListener$5 INSTANCE = new TransitionKt$addListener$5();

    public TransitionKt$addListener$5() {
        super(1);
    }

    public /* bridge */ /* synthetic */ Object invoke(Object p1) {
        invoke((Transition) p1);
        return Unit.INSTANCE;
    }

    public final void invoke(Transition it) {
        Intrinsics.checkNotNullParameter(it, "it");
    }
}
