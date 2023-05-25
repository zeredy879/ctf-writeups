package kotlin.sequences;

import java.util.Iterator;
import kotlin.Metadata;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.RestrictedSuspendLambda;
import kotlin.jvm.functions.Function2;

@Metadata(mo14702d1 = {"\u0000\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\u0010\u0000\u001a\u00020\u0001\"\u0004\b\u0000\u0010\u0002\"\u0004\b\u0001\u0010\u0003*\b\u0012\u0004\u0012\u0002H\u00030\u0004H@"}, mo14703d2 = {"<anonymous>", "", "T", "R", "Lkotlin/sequences/SequenceScope;"}, mo14704k = 3, mo14705mv = {1, 6, 0}, mo14707xi = 48)
@DebugMetadata(mo15422c = "kotlin.sequences.SequencesKt___SequencesKt$zipWithNext$2", mo15423f = "_Sequences.kt", mo15424i = {0, 0, 0}, mo15425l = {2693}, mo15426m = "invokeSuspend", mo15427n = {"$this$result", "iterator", "next"}, mo15428s = {"L$0", "L$1", "L$2"})
/* compiled from: _Sequences.kt */
final class SequencesKt___SequencesKt$zipWithNext$2 extends RestrictedSuspendLambda implements Function2<SequenceScope<? super R>, Continuation<? super Unit>, Object> {
    final /* synthetic */ Sequence<T> $this_zipWithNext;
    final /* synthetic */ Function2<T, T, R> $transform;
    private /* synthetic */ Object L$0;
    Object L$1;
    Object L$2;
    int label;

    /* JADX INFO: super call moved to the top of the method (can break code semantics) */
    SequencesKt___SequencesKt$zipWithNext$2(Sequence<? extends T> sequence, Function2<? super T, ? super T, ? extends R> function2, Continuation<? super SequencesKt___SequencesKt$zipWithNext$2> continuation) {
        super(2, continuation);
        this.$this_zipWithNext = sequence;
        this.$transform = function2;
    }

    public final Continuation<Unit> create(Object obj, Continuation<?> continuation) {
        SequencesKt___SequencesKt$zipWithNext$2 sequencesKt___SequencesKt$zipWithNext$2 = new SequencesKt___SequencesKt$zipWithNext$2(this.$this_zipWithNext, this.$transform, continuation);
        sequencesKt___SequencesKt$zipWithNext$2.L$0 = obj;
        return sequencesKt___SequencesKt$zipWithNext$2;
    }

    public final Object invoke(SequenceScope<? super R> sequenceScope, Continuation<? super Unit> continuation) {
        return ((SequencesKt___SequencesKt$zipWithNext$2) create(sequenceScope, continuation)).invokeSuspend(Unit.INSTANCE);
    }

    public final Object invokeSuspend(Object $result) {
        SequenceScope $this$result;
        Iterator iterator;
        Object current;
        SequencesKt___SequencesKt$zipWithNext$2 sequencesKt___SequencesKt$zipWithNext$2;
        Object coroutine_suspended = IntrinsicsKt.getCOROUTINE_SUSPENDED();
        switch (this.label) {
            case 0:
                ResultKt.throwOnFailure($result);
                sequencesKt___SequencesKt$zipWithNext$2 = this;
                SequenceScope $this$result2 = (SequenceScope) sequencesKt___SequencesKt$zipWithNext$2.L$0;
                iterator = sequencesKt___SequencesKt$zipWithNext$2.$this_zipWithNext.iterator();
                if (iterator.hasNext()) {
                    $this$result = $this$result2;
                    current = iterator.next();
                    break;
                } else {
                    return Unit.INSTANCE;
                }
            case 1:
                sequencesKt___SequencesKt$zipWithNext$2 = this;
                current = sequencesKt___SequencesKt$zipWithNext$2.L$2;
                iterator = (Iterator) sequencesKt___SequencesKt$zipWithNext$2.L$1;
                $this$result = (SequenceScope) sequencesKt___SequencesKt$zipWithNext$2.L$0;
                ResultKt.throwOnFailure($result);
                break;
            default:
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
        }
        while (iterator.hasNext()) {
            Object next = iterator.next();
            sequencesKt___SequencesKt$zipWithNext$2.L$0 = $this$result;
            sequencesKt___SequencesKt$zipWithNext$2.L$1 = iterator;
            sequencesKt___SequencesKt$zipWithNext$2.L$2 = next;
            sequencesKt___SequencesKt$zipWithNext$2.label = 1;
            if ($this$result.yield(sequencesKt___SequencesKt$zipWithNext$2.$transform.invoke(current, next), sequencesKt___SequencesKt$zipWithNext$2) == coroutine_suspended) {
                return coroutine_suspended;
            }
            current = next;
        }
        return Unit.INSTANCE;
    }
}
