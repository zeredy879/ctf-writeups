package kotlin.ranges;

import kotlin.Metadata;
import kotlin.UInt;
import kotlin.UnsignedKt;
import kotlin.jvm.internal.DefaultConstructorMarker;

@Metadata(mo14702d1 = {"\u00002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010\u000b\n\u0002\b\u0005\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\b\u0007\u0018\u0000 \u00172\u00020\u00012\b\u0012\u0004\u0012\u00020\u00030\u0002:\u0001\u0017B\u0018\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u0012\u0006\u0010\u0005\u001a\u00020\u0003ø\u0001\u0000¢\u0006\u0002\u0010\u0006J\u001b\u0010\n\u001a\u00020\u000b2\u0006\u0010\f\u001a\u00020\u0003H\u0002ø\u0001\u0000¢\u0006\u0004\b\r\u0010\u000eJ\u0013\u0010\u000f\u001a\u00020\u000b2\b\u0010\u0010\u001a\u0004\u0018\u00010\u0011H\u0002J\b\u0010\u0012\u001a\u00020\u0013H\u0016J\b\u0010\u0014\u001a\u00020\u000bH\u0016J\b\u0010\u0015\u001a\u00020\u0016H\u0016R\u001a\u0010\u0005\u001a\u00020\u00038VX\u0004ø\u0001\u0000ø\u0001\u0001¢\u0006\u0006\u001a\u0004\b\u0007\u0010\bR\u001a\u0010\u0004\u001a\u00020\u00038VX\u0004ø\u0001\u0000ø\u0001\u0001¢\u0006\u0006\u001a\u0004\b\t\u0010\bø\u0001\u0000\u0002\b\n\u0002\b\u0019\n\u0002\b!¨\u0006\u0018"}, mo14703d2 = {"Lkotlin/ranges/UIntRange;", "Lkotlin/ranges/UIntProgression;", "Lkotlin/ranges/ClosedRange;", "Lkotlin/UInt;", "start", "endInclusive", "(IILkotlin/jvm/internal/DefaultConstructorMarker;)V", "getEndInclusive-pVg5ArA", "()I", "getStart-pVg5ArA", "contains", "", "value", "contains-WZ4Q5Ns", "(I)Z", "equals", "other", "", "hashCode", "", "isEmpty", "toString", "", "Companion", "kotlin-stdlib"}, mo14704k = 1, mo14705mv = {1, 6, 0}, mo14707xi = 48)
/* compiled from: UIntRange.kt */
public final class UIntRange extends UIntProgression implements ClosedRange<UInt> {
    public static final Companion Companion = new Companion((DefaultConstructorMarker) null);
    /* access modifiers changed from: private */
    public static final UIntRange EMPTY = new UIntRange(-1, 0, (DefaultConstructorMarker) null);

    public /* synthetic */ UIntRange(int i, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(i, i2);
    }

    public /* bridge */ /* synthetic */ boolean contains(Comparable value) {
        return m1281containsWZ4Q5Ns(((UInt) value).m217unboximpl());
    }

    public /* bridge */ /* synthetic */ Comparable getEndInclusive() {
        return UInt.m160boximpl(m1282getEndInclusivepVg5ArA());
    }

    public /* bridge */ /* synthetic */ Comparable getStart() {
        return UInt.m160boximpl(m1283getStartpVg5ArA());
    }

    private UIntRange(int start, int endInclusive) {
        super(start, endInclusive, 1, (DefaultConstructorMarker) null);
    }

    /* renamed from: getStart-pVg5ArA  reason: not valid java name */
    public int m1283getStartpVg5ArA() {
        return m1277getFirstpVg5ArA();
    }

    /* renamed from: getEndInclusive-pVg5ArA  reason: not valid java name */
    public int m1282getEndInclusivepVg5ArA() {
        return m1278getLastpVg5ArA();
    }

    /* renamed from: contains-WZ4Q5Ns  reason: not valid java name */
    public boolean m1281containsWZ4Q5Ns(int value) {
        return UnsignedKt.uintCompare(m1277getFirstpVg5ArA(), value) <= 0 && UnsignedKt.uintCompare(value, m1278getLastpVg5ArA()) <= 0;
    }

    public boolean isEmpty() {
        return UnsignedKt.uintCompare(m1277getFirstpVg5ArA(), m1278getLastpVg5ArA()) > 0;
    }

    public boolean equals(Object other) {
        return (other instanceof UIntRange) && ((isEmpty() && ((UIntRange) other).isEmpty()) || (m1277getFirstpVg5ArA() == ((UIntRange) other).m1277getFirstpVg5ArA() && m1278getLastpVg5ArA() == ((UIntRange) other).m1278getLastpVg5ArA()));
    }

    public int hashCode() {
        if (isEmpty()) {
            return -1;
        }
        return (m1277getFirstpVg5ArA() * 31) + m1278getLastpVg5ArA();
    }

    public String toString() {
        return UInt.m211toStringimpl(m1277getFirstpVg5ArA()) + ".." + UInt.m211toStringimpl(m1278getLastpVg5ArA());
    }

    @Metadata(mo14702d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\b\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002R\u0011\u0010\u0003\u001a\u00020\u0004¢\u0006\b\n\u0000\u001a\u0004\b\u0005\u0010\u0006¨\u0006\u0007"}, mo14703d2 = {"Lkotlin/ranges/UIntRange$Companion;", "", "()V", "EMPTY", "Lkotlin/ranges/UIntRange;", "getEMPTY", "()Lkotlin/ranges/UIntRange;", "kotlin-stdlib"}, mo14704k = 1, mo14705mv = {1, 6, 0}, mo14707xi = 48)
    /* compiled from: UIntRange.kt */
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }

        public final UIntRange getEMPTY() {
            return UIntRange.EMPTY;
        }
    }
}
