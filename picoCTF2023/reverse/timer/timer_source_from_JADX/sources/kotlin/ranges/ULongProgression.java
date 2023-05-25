package kotlin.ranges;

import java.util.Iterator;
import kotlin.Metadata;
import kotlin.ULong;
import kotlin.UnsignedKt;
import kotlin.internal.UProgressionUtilKt;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.markers.KMappedMarker;

@Metadata(mo14702d1 = {"\u0000:\n\u0002\u0018\u0002\n\u0002\u0010\u001c\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\t\n\u0002\b\t\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010(\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\b\u0017\u0018\u0000 \u001a2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001\u001aB\"\b\u0000\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0006\u0010\u0004\u001a\u00020\u0002\u0012\u0006\u0010\u0005\u001a\u00020\u0006ø\u0001\u0000¢\u0006\u0002\u0010\u0007J\u0013\u0010\u000f\u001a\u00020\u00102\b\u0010\u0011\u001a\u0004\u0018\u00010\u0012H\u0002J\b\u0010\u0013\u001a\u00020\u0014H\u0016J\b\u0010\u0015\u001a\u00020\u0010H\u0016J\u0012\u0010\u0016\u001a\b\u0012\u0004\u0012\u00020\u00020\u0017H\u0002ø\u0001\u0000J\b\u0010\u0018\u001a\u00020\u0019H\u0016R\u0019\u0010\b\u001a\u00020\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\n\n\u0002\u0010\u000b\u001a\u0004\b\t\u0010\nR\u0019\u0010\f\u001a\u00020\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\n\n\u0002\u0010\u000b\u001a\u0004\b\r\u0010\nR\u0011\u0010\u0005\u001a\u00020\u0006¢\u0006\b\n\u0000\u001a\u0004\b\u000e\u0010\nø\u0001\u0000\u0002\b\n\u0002\b\u0019\n\u0002\b!¨\u0006\u001b"}, mo14703d2 = {"Lkotlin/ranges/ULongProgression;", "", "Lkotlin/ULong;", "start", "endInclusive", "step", "", "(JJJLkotlin/jvm/internal/DefaultConstructorMarker;)V", "first", "getFirst-s-VKNKU", "()J", "J", "last", "getLast-s-VKNKU", "getStep", "equals", "", "other", "", "hashCode", "", "isEmpty", "iterator", "", "toString", "", "Companion", "kotlin-stdlib"}, mo14704k = 1, mo14705mv = {1, 6, 0}, mo14707xi = 48)
/* compiled from: ULongRange.kt */
public class ULongProgression implements Iterable<ULong>, KMappedMarker {
    public static final Companion Companion = new Companion((DefaultConstructorMarker) null);
    private final long first;
    private final long last;
    private final long step;

    public /* synthetic */ ULongProgression(long j, long j2, long j3, DefaultConstructorMarker defaultConstructorMarker) {
        this(j, j2, j3);
    }

    private ULongProgression(long start, long endInclusive, long step2) {
        if (step2 == 0) {
            throw new IllegalArgumentException("Step must be non-zero.");
        } else if (step2 != Long.MIN_VALUE) {
            this.first = start;
            this.last = UProgressionUtilKt.m1262getProgressionLastElement7ftBX0g(start, endInclusive, step2);
            this.step = step2;
        } else {
            throw new IllegalArgumentException("Step must be greater than Long.MIN_VALUE to avoid overflow on negation.");
        }
    }

    /* renamed from: getFirst-s-VKNKU  reason: not valid java name */
    public final long m1284getFirstsVKNKU() {
        return this.first;
    }

    /* renamed from: getLast-s-VKNKU  reason: not valid java name */
    public final long m1285getLastsVKNKU() {
        return this.last;
    }

    public final long getStep() {
        return this.step;
    }

    public final Iterator<ULong> iterator() {
        return new ULongProgressionIterator(m1284getFirstsVKNKU(), m1285getLastsVKNKU(), this.step, (DefaultConstructorMarker) null);
    }

    public boolean isEmpty() {
        int i = (this.step > 0 ? 1 : (this.step == 0 ? 0 : -1));
        int ulongCompare = UnsignedKt.ulongCompare(m1284getFirstsVKNKU(), m1285getLastsVKNKU());
        if (i > 0) {
            if (ulongCompare > 0) {
                return true;
            }
        } else if (ulongCompare < 0) {
            return true;
        }
        return false;
    }

    public boolean equals(Object other) {
        return (other instanceof ULongProgression) && ((isEmpty() && ((ULongProgression) other).isEmpty()) || (m1284getFirstsVKNKU() == ((ULongProgression) other).m1284getFirstsVKNKU() && m1285getLastsVKNKU() == ((ULongProgression) other).m1285getLastsVKNKU() && this.step == ((ULongProgression) other).step));
    }

    public int hashCode() {
        if (isEmpty()) {
            return -1;
        }
        long j = this.step;
        return ((int) (j ^ (j >>> 32))) + (((((int) ULong.m244constructorimpl(m1284getFirstsVKNKU() ^ ULong.m244constructorimpl(m1284getFirstsVKNKU() >>> 32))) * 31) + ((int) ULong.m244constructorimpl(m1285getLastsVKNKU() ^ ULong.m244constructorimpl(m1285getLastsVKNKU() >>> 32)))) * 31);
    }

    public String toString() {
        StringBuilder sb;
        long j;
        if (this.step > 0) {
            sb.append(ULong.m289toStringimpl(m1284getFirstsVKNKU()));
            sb.append("..");
            sb.append(ULong.m289toStringimpl(m1285getLastsVKNKU()));
            sb.append(" step ");
            j = this.step;
        } else {
            sb = new StringBuilder();
            sb.append(ULong.m289toStringimpl(m1284getFirstsVKNKU()));
            sb.append(" downTo ");
            sb.append(ULong.m289toStringimpl(m1285getLastsVKNKU()));
            sb.append(" step ");
            j = -this.step;
        }
        sb.append(j);
        return sb.toString();
    }

    @Metadata(mo14702d1 = {"\u0000\"\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\t\n\u0002\b\u0003\b\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002J(\u0010\u0003\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\tø\u0001\u0000¢\u0006\u0004\b\n\u0010\u000b\u0002\u0004\n\u0002\b\u0019¨\u0006\f"}, mo14703d2 = {"Lkotlin/ranges/ULongProgression$Companion;", "", "()V", "fromClosedRange", "Lkotlin/ranges/ULongProgression;", "rangeStart", "Lkotlin/ULong;", "rangeEnd", "step", "", "fromClosedRange-7ftBX0g", "(JJJ)Lkotlin/ranges/ULongProgression;", "kotlin-stdlib"}, mo14704k = 1, mo14705mv = {1, 6, 0}, mo14707xi = 48)
    /* compiled from: ULongRange.kt */
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }

        /* renamed from: fromClosedRange-7ftBX0g  reason: not valid java name */
        public final ULongProgression m1286fromClosedRange7ftBX0g(long rangeStart, long rangeEnd, long step) {
            return new ULongProgression(rangeStart, rangeEnd, step, (DefaultConstructorMarker) null);
        }
    }
}
