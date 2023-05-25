package androidx.core.animation;

import android.animation.Animator;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

@Metadata(mo14702d1 = {"\u0000\u0019\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002*\u0001\u0000\b\n\u0018\u00002\u00020\u0001J\u0010\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005H\u0016J\u0010\u0010\u0006\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005H\u0016¨\u0006\u0007¸\u0006\u0000"}, mo14703d2 = {"androidx/core/animation/AnimatorKt$addPauseListener$listener$1", "Landroid/animation/Animator$AnimatorPauseListener;", "onAnimationPause", "", "animator", "Landroid/animation/Animator;", "onAnimationResume", "core-ktx_release"}, mo14704k = 1, mo14705mv = {1, 5, 1}, mo14707xi = 48)
/* compiled from: Animator.kt */
public final class AnimatorKt$doOnPause$$inlined$addPauseListener$default$1 implements Animator.AnimatorPauseListener {
    final /* synthetic */ Function1 $onPause;

    public AnimatorKt$doOnPause$$inlined$addPauseListener$default$1(Function1 $onPause2) {
        this.$onPause = $onPause2;
    }

    public void onAnimationPause(Animator animator) {
        Intrinsics.checkNotNullParameter(animator, "animator");
        this.$onPause.invoke(animator);
    }

    public void onAnimationResume(Animator animator) {
        Intrinsics.checkNotNullParameter(animator, "animator");
        Animator animator2 = animator;
    }
}
