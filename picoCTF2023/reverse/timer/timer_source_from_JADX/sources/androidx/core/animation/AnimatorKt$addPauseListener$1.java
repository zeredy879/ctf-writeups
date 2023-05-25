package androidx.core.animation;

import android.animation.Animator;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;

@Metadata(mo14702d1 = {"\u0000\f\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0003H\n"}, mo14703d2 = {"<anonymous>", "", "it", "Landroid/animation/Animator;"}, mo14704k = 3, mo14705mv = {1, 5, 1}, mo14707xi = 48)
/* compiled from: Animator.kt */
public final class AnimatorKt$addPauseListener$1 extends Lambda implements Function1<Animator, Unit> {
    public static final AnimatorKt$addPauseListener$1 INSTANCE = new AnimatorKt$addPauseListener$1();

    public AnimatorKt$addPauseListener$1() {
        super(1);
    }

    public /* bridge */ /* synthetic */ Object invoke(Object p1) {
        invoke((Animator) p1);
        return Unit.INSTANCE;
    }

    public final void invoke(Animator it) {
        Intrinsics.checkNotNullParameter(it, "it");
    }
}
