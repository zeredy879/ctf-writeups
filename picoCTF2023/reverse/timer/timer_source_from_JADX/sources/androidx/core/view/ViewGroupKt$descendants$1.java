package androidx.core.view;

import android.view.View;
import android.view.ViewGroup;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.RestrictedSuspendLambda;
import kotlin.jvm.functions.Function2;
import kotlin.sequences.SequenceScope;

@Metadata(mo14702d1 = {"\u0000\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\u0010\u0000\u001a\u00020\u0001*\b\u0012\u0004\u0012\u00020\u00030\u0002H@"}, mo14703d2 = {"<anonymous>", "", "Lkotlin/sequences/SequenceScope;", "Landroid/view/View;"}, mo14704k = 3, mo14705mv = {1, 5, 1}, mo14707xi = 48)
@DebugMetadata(mo15422c = "androidx.core.view.ViewGroupKt$descendants$1", mo15423f = "ViewGroup.kt", mo15424i = {0, 0, 0, 1, 1}, mo15425l = {97, 99}, mo15426m = "invokeSuspend", mo15427n = {"$this$sequence", "$this$forEach$iv", "child", "$this$sequence", "$this$forEach$iv"}, mo15428s = {"L$0", "L$1", "L$2", "L$0", "L$1"})
/* compiled from: ViewGroup.kt */
final class ViewGroupKt$descendants$1 extends RestrictedSuspendLambda implements Function2<SequenceScope<? super View>, Continuation<? super Unit>, Object> {
    final /* synthetic */ ViewGroup $this_descendants;
    int I$0;
    int I$1;
    private /* synthetic */ Object L$0;
    Object L$1;
    Object L$2;
    int label;

    /* JADX INFO: super call moved to the top of the method (can break code semantics) */
    ViewGroupKt$descendants$1(ViewGroup viewGroup, Continuation<? super ViewGroupKt$descendants$1> continuation) {
        super(2, continuation);
        this.$this_descendants = viewGroup;
    }

    public final Continuation<Unit> create(Object obj, Continuation<?> continuation) {
        ViewGroupKt$descendants$1 viewGroupKt$descendants$1 = new ViewGroupKt$descendants$1(this.$this_descendants, continuation);
        viewGroupKt$descendants$1.L$0 = obj;
        return viewGroupKt$descendants$1;
    }

    public final Object invoke(SequenceScope<? super View> sequenceScope, Continuation<? super Unit> continuation) {
        return ((ViewGroupKt$descendants$1) create(sequenceScope, continuation)).invokeSuspend(Unit.INSTANCE);
    }

    /* JADX WARNING: Code restructure failed: missing block: B:10:0x006e, code lost:
        return r0;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:11:0x006f, code lost:
        r8 = r2;
        r2 = r4;
        r4 = r6;
        r6 = r7;
        r7 = r3;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:13:0x0077, code lost:
        if ((r6 instanceof android.view.ViewGroup) == 0) goto L_0x009c;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:14:0x0079, code lost:
        r9 = androidx.core.view.ViewGroupKt.getDescendants(r6);
        r1.L$0 = r8;
        r1.L$1 = r7;
        r1.L$2 = null;
        r1.I$0 = r5;
        r1.I$1 = r4;
        r1.label = 2;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:15:0x0092, code lost:
        if (r8.yieldAll(r9, (kotlin.coroutines.Continuation<? super kotlin.Unit>) r1) != r0) goto L_0x0095;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:16:0x0094, code lost:
        return r0;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:17:0x0095, code lost:
        r6 = r7;
        r7 = r8;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:18:0x0097, code lost:
        r3 = r6;
        r6 = r4;
        r4 = r2;
        r2 = r7;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:19:0x009c, code lost:
        r6 = r4;
        r3 = r7;
        r4 = r2;
        r2 = r8;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:20:0x00a0, code lost:
        if (r5 < r6) goto L_0x004e;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:22:0x00a5, code lost:
        return kotlin.Unit.INSTANCE;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:7:0x004c, code lost:
        if (r6 > 0) goto L_0x004e;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:8:0x004e, code lost:
        r7 = r5;
        r5 = r5 + 1;
        r9 = r3.getChildAt(r7);
        kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r9, "getChildAt(index)");
        r7 = r9;
        r1.L$0 = r2;
        r1.L$1 = r3;
        r1.L$2 = r7;
        r1.I$0 = r5;
        r1.I$1 = r6;
        r1.label = 1;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:9:0x006c, code lost:
        if (r2.yield(r7, r1) != r0) goto L_0x006f;
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public final java.lang.Object invokeSuspend(java.lang.Object r12) {
        /*
            r11 = this;
            java.lang.Object r0 = kotlin.coroutines.intrinsics.IntrinsicsKt.getCOROUTINE_SUSPENDED()
            int r1 = r11.label
            switch(r1) {
                case 0: goto L_0x003c;
                case 1: goto L_0x0025;
                case 2: goto L_0x0011;
                default: goto L_0x0009;
            }
        L_0x0009:
            java.lang.IllegalStateException r12 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r12.<init>(r0)
            throw r12
        L_0x0011:
            r1 = r11
            r2 = 0
            r3 = 0
            int r4 = r1.I$1
            int r5 = r1.I$0
            java.lang.Object r6 = r1.L$1
            android.view.ViewGroup r6 = (android.view.ViewGroup) r6
            java.lang.Object r7 = r1.L$0
            kotlin.sequences.SequenceScope r7 = (kotlin.sequences.SequenceScope) r7
            kotlin.ResultKt.throwOnFailure(r12)
            goto L_0x0097
        L_0x0025:
            r1 = r11
            r2 = 0
            r3 = 0
            int r4 = r1.I$1
            int r5 = r1.I$0
            java.lang.Object r6 = r1.L$2
            android.view.View r6 = (android.view.View) r6
            java.lang.Object r7 = r1.L$1
            android.view.ViewGroup r7 = (android.view.ViewGroup) r7
            java.lang.Object r8 = r1.L$0
            kotlin.sequences.SequenceScope r8 = (kotlin.sequences.SequenceScope) r8
            kotlin.ResultKt.throwOnFailure(r12)
            goto L_0x0075
        L_0x003c:
            kotlin.ResultKt.throwOnFailure(r12)
            r1 = r11
            java.lang.Object r2 = r1.L$0
            kotlin.sequences.SequenceScope r2 = (kotlin.sequences.SequenceScope) r2
            android.view.ViewGroup r3 = r1.$this_descendants
            r4 = 0
            r5 = 0
            int r6 = r3.getChildCount()
            if (r6 <= 0) goto L_0x00a2
        L_0x004e:
            r7 = r5
            r8 = 1
            int r5 = r5 + r8
            android.view.View r9 = r3.getChildAt(r7)
            java.lang.String r7 = "getChildAt(index)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r9, r7)
            r7 = r9
            r9 = 0
            r1.L$0 = r2
            r1.L$1 = r3
            r1.L$2 = r7
            r1.I$0 = r5
            r1.I$1 = r6
            r1.label = r8
            java.lang.Object r8 = r2.yield(r7, r1)
            if (r8 != r0) goto L_0x006f
            return r0
        L_0x006f:
            r8 = r2
            r2 = r4
            r4 = r6
            r6 = r7
            r7 = r3
            r3 = r9
        L_0x0075:
            boolean r9 = r6 instanceof android.view.ViewGroup
            if (r9 == 0) goto L_0x009c
            r9 = r6
            android.view.ViewGroup r9 = (android.view.ViewGroup) r9
            kotlin.sequences.Sequence r9 = androidx.core.view.ViewGroupKt.getDescendants(r9)
            r1.L$0 = r8
            r1.L$1 = r7
            r10 = 0
            r1.L$2 = r10
            r1.I$0 = r5
            r1.I$1 = r4
            r10 = 2
            r1.label = r10
            java.lang.Object r6 = r8.yieldAll(r9, (kotlin.coroutines.Continuation<? super kotlin.Unit>) r1)
            if (r6 != r0) goto L_0x0095
            return r0
        L_0x0095:
            r6 = r7
            r7 = r8
        L_0x0097:
            r3 = r6
            r6 = r4
            r4 = r2
            r2 = r7
            goto L_0x00a0
        L_0x009c:
            r6 = r4
            r3 = r7
            r4 = r2
            r2 = r8
        L_0x00a0:
            if (r5 < r6) goto L_0x004e
        L_0x00a2:
            kotlin.Unit r0 = kotlin.Unit.INSTANCE
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.core.view.ViewGroupKt$descendants$1.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
