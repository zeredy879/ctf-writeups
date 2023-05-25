package kotlin;

import kotlin.jvm.JvmInline;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.ranges.ULongRange;

@JvmInline
@Metadata(mo14702d1 = {"\u0000j\n\u0002\u0018\u0002\n\u0002\u0010\u000f\n\u0000\n\u0002\u0010\t\n\u0002\b\t\n\u0002\u0010\b\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\r\n\u0002\u0010\u000b\n\u0002\u0010\u0000\n\u0002\b\"\n\u0002\u0018\u0002\n\u0002\b\u0012\n\u0002\u0010\u0005\n\u0002\b\u0003\n\u0002\u0010\u0006\n\u0002\b\u0003\n\u0002\u0010\u0007\n\u0002\b\u0007\n\u0002\u0010\n\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u000e\b@\u0018\u0000 |2\b\u0012\u0004\u0012\u00020\u00000\u0001:\u0001|B\u0014\b\u0001\u0012\u0006\u0010\u0002\u001a\u00020\u0003ø\u0001\u0000¢\u0006\u0004\b\u0004\u0010\u0005J\u001b\u0010\b\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u0000H\fø\u0001\u0000¢\u0006\u0004\b\n\u0010\u000bJ\u001b\u0010\f\u001a\u00020\r2\u0006\u0010\t\u001a\u00020\u000eH\nø\u0001\u0000¢\u0006\u0004\b\u000f\u0010\u0010J\u001b\u0010\f\u001a\u00020\r2\u0006\u0010\t\u001a\u00020\u0011H\nø\u0001\u0000¢\u0006\u0004\b\u0012\u0010\u0013J\u001b\u0010\f\u001a\u00020\r2\u0006\u0010\t\u001a\u00020\u0000H\nø\u0001\u0000¢\u0006\u0004\b\u0014\u0010\u0015J\u001b\u0010\f\u001a\u00020\r2\u0006\u0010\t\u001a\u00020\u0016H\nø\u0001\u0000¢\u0006\u0004\b\u0017\u0010\u0018J\u0016\u0010\u0019\u001a\u00020\u0000H\nø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u001a\u0010\u0005J\u001b\u0010\u001b\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u000eH\nø\u0001\u0000¢\u0006\u0004\b\u001c\u0010\u001dJ\u001b\u0010\u001b\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u0011H\nø\u0001\u0000¢\u0006\u0004\b\u001e\u0010\u001fJ\u001b\u0010\u001b\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u0000H\nø\u0001\u0000¢\u0006\u0004\b \u0010\u000bJ\u001b\u0010\u001b\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u0016H\nø\u0001\u0000¢\u0006\u0004\b!\u0010\"J\u001a\u0010#\u001a\u00020$2\b\u0010\t\u001a\u0004\u0018\u00010%HÖ\u0003¢\u0006\u0004\b&\u0010'J\u001b\u0010(\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u000eH\bø\u0001\u0000¢\u0006\u0004\b)\u0010\u001dJ\u001b\u0010(\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u0011H\bø\u0001\u0000¢\u0006\u0004\b*\u0010\u001fJ\u001b\u0010(\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u0000H\bø\u0001\u0000¢\u0006\u0004\b+\u0010\u000bJ\u001b\u0010(\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u0016H\bø\u0001\u0000¢\u0006\u0004\b,\u0010\"J\u0010\u0010-\u001a\u00020\rHÖ\u0001¢\u0006\u0004\b.\u0010/J\u0016\u00100\u001a\u00020\u0000H\nø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b1\u0010\u0005J\u0016\u00102\u001a\u00020\u0000H\bø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b3\u0010\u0005J\u001b\u00104\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u000eH\nø\u0001\u0000¢\u0006\u0004\b5\u0010\u001dJ\u001b\u00104\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u0011H\nø\u0001\u0000¢\u0006\u0004\b6\u0010\u001fJ\u001b\u00104\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u0000H\nø\u0001\u0000¢\u0006\u0004\b7\u0010\u000bJ\u001b\u00104\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u0016H\nø\u0001\u0000¢\u0006\u0004\b8\u0010\"J\u001b\u00109\u001a\u00020\u000e2\u0006\u0010\t\u001a\u00020\u000eH\bø\u0001\u0000¢\u0006\u0004\b:\u0010;J\u001b\u00109\u001a\u00020\u00112\u0006\u0010\t\u001a\u00020\u0011H\bø\u0001\u0000¢\u0006\u0004\b<\u0010\u0013J\u001b\u00109\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u0000H\bø\u0001\u0000¢\u0006\u0004\b=\u0010\u000bJ\u001b\u00109\u001a\u00020\u00162\u0006\u0010\t\u001a\u00020\u0016H\bø\u0001\u0000¢\u0006\u0004\b>\u0010?J\u001b\u0010@\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u0000H\fø\u0001\u0000¢\u0006\u0004\bA\u0010\u000bJ\u001b\u0010B\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u000eH\nø\u0001\u0000¢\u0006\u0004\bC\u0010\u001dJ\u001b\u0010B\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u0011H\nø\u0001\u0000¢\u0006\u0004\bD\u0010\u001fJ\u001b\u0010B\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u0000H\nø\u0001\u0000¢\u0006\u0004\bE\u0010\u000bJ\u001b\u0010B\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u0016H\nø\u0001\u0000¢\u0006\u0004\bF\u0010\"J\u001b\u0010G\u001a\u00020H2\u0006\u0010\t\u001a\u00020\u0000H\nø\u0001\u0000¢\u0006\u0004\bI\u0010JJ\u001b\u0010K\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u000eH\nø\u0001\u0000¢\u0006\u0004\bL\u0010\u001dJ\u001b\u0010K\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u0011H\nø\u0001\u0000¢\u0006\u0004\bM\u0010\u001fJ\u001b\u0010K\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u0000H\nø\u0001\u0000¢\u0006\u0004\bN\u0010\u000bJ\u001b\u0010K\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u0016H\nø\u0001\u0000¢\u0006\u0004\bO\u0010\"J\u001e\u0010P\u001a\u00020\u00002\u0006\u0010Q\u001a\u00020\rH\fø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\bR\u0010\u001fJ\u001e\u0010S\u001a\u00020\u00002\u0006\u0010Q\u001a\u00020\rH\fø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\bT\u0010\u001fJ\u001b\u0010U\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u000eH\nø\u0001\u0000¢\u0006\u0004\bV\u0010\u001dJ\u001b\u0010U\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u0011H\nø\u0001\u0000¢\u0006\u0004\bW\u0010\u001fJ\u001b\u0010U\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u0000H\nø\u0001\u0000¢\u0006\u0004\bX\u0010\u000bJ\u001b\u0010U\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u0016H\nø\u0001\u0000¢\u0006\u0004\bY\u0010\"J\u0010\u0010Z\u001a\u00020[H\b¢\u0006\u0004\b\\\u0010]J\u0010\u0010^\u001a\u00020_H\b¢\u0006\u0004\b`\u0010aJ\u0010\u0010b\u001a\u00020cH\b¢\u0006\u0004\bd\u0010eJ\u0010\u0010f\u001a\u00020\rH\b¢\u0006\u0004\bg\u0010/J\u0010\u0010h\u001a\u00020\u0003H\b¢\u0006\u0004\bi\u0010\u0005J\u0010\u0010j\u001a\u00020kH\b¢\u0006\u0004\bl\u0010mJ\u000f\u0010n\u001a\u00020oH\u0016¢\u0006\u0004\bp\u0010qJ\u0016\u0010r\u001a\u00020\u000eH\bø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\bs\u0010]J\u0016\u0010t\u001a\u00020\u0011H\bø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\bu\u0010/J\u0016\u0010v\u001a\u00020\u0000H\bø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\bw\u0010\u0005J\u0016\u0010x\u001a\u00020\u0016H\bø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\by\u0010mJ\u001b\u0010z\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\u0000H\fø\u0001\u0000¢\u0006\u0004\b{\u0010\u000bR\u0016\u0010\u0002\u001a\u00020\u00038\u0000X\u0004¢\u0006\b\n\u0000\u0012\u0004\b\u0006\u0010\u0007\u0001\u0002\u0001\u00020\u0003ø\u0001\u0000\u0002\b\n\u0002\b\u0019\n\u0002\b!¨\u0006}"}, mo14703d2 = {"Lkotlin/ULong;", "", "data", "", "constructor-impl", "(J)J", "getData$annotations", "()V", "and", "other", "and-VKZWuLQ", "(JJ)J", "compareTo", "", "Lkotlin/UByte;", "compareTo-7apg3OU", "(JB)I", "Lkotlin/UInt;", "compareTo-WZ4Q5Ns", "(JI)I", "compareTo-VKZWuLQ", "(JJ)I", "Lkotlin/UShort;", "compareTo-xj2QHRw", "(JS)I", "dec", "dec-s-VKNKU", "div", "div-7apg3OU", "(JB)J", "div-WZ4Q5Ns", "(JI)J", "div-VKZWuLQ", "div-xj2QHRw", "(JS)J", "equals", "", "", "equals-impl", "(JLjava/lang/Object;)Z", "floorDiv", "floorDiv-7apg3OU", "floorDiv-WZ4Q5Ns", "floorDiv-VKZWuLQ", "floorDiv-xj2QHRw", "hashCode", "hashCode-impl", "(J)I", "inc", "inc-s-VKNKU", "inv", "inv-s-VKNKU", "minus", "minus-7apg3OU", "minus-WZ4Q5Ns", "minus-VKZWuLQ", "minus-xj2QHRw", "mod", "mod-7apg3OU", "(JB)B", "mod-WZ4Q5Ns", "mod-VKZWuLQ", "mod-xj2QHRw", "(JS)S", "or", "or-VKZWuLQ", "plus", "plus-7apg3OU", "plus-WZ4Q5Ns", "plus-VKZWuLQ", "plus-xj2QHRw", "rangeTo", "Lkotlin/ranges/ULongRange;", "rangeTo-VKZWuLQ", "(JJ)Lkotlin/ranges/ULongRange;", "rem", "rem-7apg3OU", "rem-WZ4Q5Ns", "rem-VKZWuLQ", "rem-xj2QHRw", "shl", "bitCount", "shl-s-VKNKU", "shr", "shr-s-VKNKU", "times", "times-7apg3OU", "times-WZ4Q5Ns", "times-VKZWuLQ", "times-xj2QHRw", "toByte", "", "toByte-impl", "(J)B", "toDouble", "", "toDouble-impl", "(J)D", "toFloat", "", "toFloat-impl", "(J)F", "toInt", "toInt-impl", "toLong", "toLong-impl", "toShort", "", "toShort-impl", "(J)S", "toString", "", "toString-impl", "(J)Ljava/lang/String;", "toUByte", "toUByte-w2LRezQ", "toUInt", "toUInt-pVg5ArA", "toULong", "toULong-s-VKNKU", "toUShort", "toUShort-Mh2AYeg", "xor", "xor-VKZWuLQ", "Companion", "kotlin-stdlib"}, mo14704k = 1, mo14705mv = {1, 6, 0}, mo14707xi = 48)
/* compiled from: ULong.kt */
public final class ULong implements Comparable<ULong> {
    public static final Companion Companion = new Companion((DefaultConstructorMarker) null);
    public static final long MAX_VALUE = -1;
    public static final long MIN_VALUE = 0;
    public static final int SIZE_BITS = 64;
    public static final int SIZE_BYTES = 8;
    private final long data;

    /* renamed from: box-impl  reason: not valid java name */
    public static final /* synthetic */ ULong m238boximpl(long j) {
        return new ULong(j);
    }

    /* renamed from: constructor-impl  reason: not valid java name */
    public static long m244constructorimpl(long j) {
        return j;
    }

    /* renamed from: equals-impl  reason: not valid java name */
    public static boolean m250equalsimpl(long j, Object obj) {
        return (obj instanceof ULong) && j == ((ULong) obj).m295unboximpl();
    }

    /* renamed from: equals-impl0  reason: not valid java name */
    public static final boolean m251equalsimpl0(long j, long j2) {
        return j == j2;
    }

    public static /* synthetic */ void getData$annotations() {
    }

    /* renamed from: hashCode-impl  reason: not valid java name */
    public static int m256hashCodeimpl(long j) {
        return (int) ((j >>> 32) ^ j);
    }

    public boolean equals(Object obj) {
        return m250equalsimpl(this.data, obj);
    }

    public int hashCode() {
        return m256hashCodeimpl(this.data);
    }

    /* renamed from: unbox-impl  reason: not valid java name */
    public final /* synthetic */ long m295unboximpl() {
        return this.data;
    }

    public /* bridge */ /* synthetic */ int compareTo(Object other) {
        return UnsignedKt.ulongCompare(m295unboximpl(), ((ULong) other).m295unboximpl());
    }

    private /* synthetic */ ULong(long data2) {
        this.data = data2;
    }

    @Metadata(mo14702d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0002\b\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002R\u0016\u0010\u0003\u001a\u00020\u0004XTø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\n\u0002\u0010\u0005R\u0016\u0010\u0006\u001a\u00020\u0004XTø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\n\u0002\u0010\u0005R\u000e\u0010\u0007\u001a\u00020\bXT¢\u0006\u0002\n\u0000R\u000e\u0010\t\u001a\u00020\bXT¢\u0006\u0002\n\u0000\u0002\b\n\u0002\b\u0019\n\u0002\b!¨\u0006\n"}, mo14703d2 = {"Lkotlin/ULong$Companion;", "", "()V", "MAX_VALUE", "Lkotlin/ULong;", "J", "MIN_VALUE", "SIZE_BITS", "", "SIZE_BYTES", "kotlin-stdlib"}, mo14704k = 1, mo14705mv = {1, 6, 0}, mo14707xi = 48)
    /* compiled from: ULong.kt */
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    /* renamed from: compareTo-7apg3OU  reason: not valid java name */
    private static final int m239compareTo7apg3OU(long arg0, byte other) {
        return UnsignedKt.ulongCompare(arg0, m244constructorimpl(((long) other) & 255));
    }

    /* renamed from: compareTo-xj2QHRw  reason: not valid java name */
    private static final int m243compareToxj2QHRw(long arg0, short other) {
        return UnsignedKt.ulongCompare(arg0, m244constructorimpl(((long) other) & 65535));
    }

    /* renamed from: compareTo-WZ4Q5Ns  reason: not valid java name */
    private static final int m242compareToWZ4Q5Ns(long arg0, int other) {
        return UnsignedKt.ulongCompare(arg0, m244constructorimpl(((long) other) & 4294967295L));
    }

    /* renamed from: compareTo-VKZWuLQ  reason: not valid java name */
    private int m240compareToVKZWuLQ(long other) {
        return UnsignedKt.ulongCompare(m295unboximpl(), other);
    }

    /* renamed from: compareTo-VKZWuLQ  reason: not valid java name */
    private static int m241compareToVKZWuLQ(long arg0, long other) {
        return UnsignedKt.ulongCompare(arg0, other);
    }

    /* renamed from: plus-7apg3OU  reason: not valid java name */
    private static final long m268plus7apg3OU(long arg0, byte other) {
        return m244constructorimpl(m244constructorimpl(((long) other) & 255) + arg0);
    }

    /* renamed from: plus-xj2QHRw  reason: not valid java name */
    private static final long m271plusxj2QHRw(long arg0, short other) {
        return m244constructorimpl(m244constructorimpl(((long) other) & 65535) + arg0);
    }

    /* renamed from: plus-WZ4Q5Ns  reason: not valid java name */
    private static final long m270plusWZ4Q5Ns(long arg0, int other) {
        return m244constructorimpl(m244constructorimpl(((long) other) & 4294967295L) + arg0);
    }

    /* renamed from: plus-VKZWuLQ  reason: not valid java name */
    private static final long m269plusVKZWuLQ(long arg0, long other) {
        return m244constructorimpl(arg0 + other);
    }

    /* renamed from: minus-7apg3OU  reason: not valid java name */
    private static final long m259minus7apg3OU(long arg0, byte other) {
        return m244constructorimpl(arg0 - m244constructorimpl(((long) other) & 255));
    }

    /* renamed from: minus-xj2QHRw  reason: not valid java name */
    private static final long m262minusxj2QHRw(long arg0, short other) {
        return m244constructorimpl(arg0 - m244constructorimpl(((long) other) & 65535));
    }

    /* renamed from: minus-WZ4Q5Ns  reason: not valid java name */
    private static final long m261minusWZ4Q5Ns(long arg0, int other) {
        return m244constructorimpl(arg0 - m244constructorimpl(((long) other) & 4294967295L));
    }

    /* renamed from: minus-VKZWuLQ  reason: not valid java name */
    private static final long m260minusVKZWuLQ(long arg0, long other) {
        return m244constructorimpl(arg0 - other);
    }

    /* renamed from: times-7apg3OU  reason: not valid java name */
    private static final long m279times7apg3OU(long arg0, byte other) {
        return m244constructorimpl(m244constructorimpl(((long) other) & 255) * arg0);
    }

    /* renamed from: times-xj2QHRw  reason: not valid java name */
    private static final long m282timesxj2QHRw(long arg0, short other) {
        return m244constructorimpl(m244constructorimpl(((long) other) & 65535) * arg0);
    }

    /* renamed from: times-WZ4Q5Ns  reason: not valid java name */
    private static final long m281timesWZ4Q5Ns(long arg0, int other) {
        return m244constructorimpl(m244constructorimpl(((long) other) & 4294967295L) * arg0);
    }

    /* renamed from: times-VKZWuLQ  reason: not valid java name */
    private static final long m280timesVKZWuLQ(long arg0, long other) {
        return m244constructorimpl(arg0 * other);
    }

    /* renamed from: div-7apg3OU  reason: not valid java name */
    private static final long m246div7apg3OU(long arg0, byte other) {
        return UnsignedKt.m421ulongDivideeb3DHEI(arg0, m244constructorimpl(((long) other) & 255));
    }

    /* renamed from: div-xj2QHRw  reason: not valid java name */
    private static final long m249divxj2QHRw(long arg0, short other) {
        return UnsignedKt.m421ulongDivideeb3DHEI(arg0, m244constructorimpl(((long) other) & 65535));
    }

    /* renamed from: div-WZ4Q5Ns  reason: not valid java name */
    private static final long m248divWZ4Q5Ns(long arg0, int other) {
        return UnsignedKt.m421ulongDivideeb3DHEI(arg0, m244constructorimpl(((long) other) & 4294967295L));
    }

    /* renamed from: div-VKZWuLQ  reason: not valid java name */
    private static final long m247divVKZWuLQ(long arg0, long other) {
        return UnsignedKt.m421ulongDivideeb3DHEI(arg0, other);
    }

    /* renamed from: rem-7apg3OU  reason: not valid java name */
    private static final long m273rem7apg3OU(long arg0, byte other) {
        return UnsignedKt.m422ulongRemaindereb3DHEI(arg0, m244constructorimpl(((long) other) & 255));
    }

    /* renamed from: rem-xj2QHRw  reason: not valid java name */
    private static final long m276remxj2QHRw(long arg0, short other) {
        return UnsignedKt.m422ulongRemaindereb3DHEI(arg0, m244constructorimpl(((long) other) & 65535));
    }

    /* renamed from: rem-WZ4Q5Ns  reason: not valid java name */
    private static final long m275remWZ4Q5Ns(long arg0, int other) {
        return UnsignedKt.m422ulongRemaindereb3DHEI(arg0, m244constructorimpl(((long) other) & 4294967295L));
    }

    /* renamed from: rem-VKZWuLQ  reason: not valid java name */
    private static final long m274remVKZWuLQ(long arg0, long other) {
        return UnsignedKt.m422ulongRemaindereb3DHEI(arg0, other);
    }

    /* renamed from: floorDiv-7apg3OU  reason: not valid java name */
    private static final long m252floorDiv7apg3OU(long arg0, byte other) {
        return UnsignedKt.m421ulongDivideeb3DHEI(arg0, m244constructorimpl(((long) other) & 255));
    }

    /* renamed from: floorDiv-xj2QHRw  reason: not valid java name */
    private static final long m255floorDivxj2QHRw(long arg0, short other) {
        return UnsignedKt.m421ulongDivideeb3DHEI(arg0, m244constructorimpl(((long) other) & 65535));
    }

    /* renamed from: floorDiv-WZ4Q5Ns  reason: not valid java name */
    private static final long m254floorDivWZ4Q5Ns(long arg0, int other) {
        return UnsignedKt.m421ulongDivideeb3DHEI(arg0, m244constructorimpl(((long) other) & 4294967295L));
    }

    /* renamed from: floorDiv-VKZWuLQ  reason: not valid java name */
    private static final long m253floorDivVKZWuLQ(long arg0, long other) {
        return UnsignedKt.m421ulongDivideeb3DHEI(arg0, other);
    }

    /* renamed from: mod-7apg3OU  reason: not valid java name */
    private static final byte m263mod7apg3OU(long arg0, byte other) {
        return UByte.m90constructorimpl((byte) ((int) UnsignedKt.m422ulongRemaindereb3DHEI(arg0, m244constructorimpl(((long) other) & 255))));
    }

    /* renamed from: mod-xj2QHRw  reason: not valid java name */
    private static final short m266modxj2QHRw(long arg0, short other) {
        return UShort.m350constructorimpl((short) ((int) UnsignedKt.m422ulongRemaindereb3DHEI(arg0, m244constructorimpl(((long) other) & 65535))));
    }

    /* renamed from: mod-WZ4Q5Ns  reason: not valid java name */
    private static final int m265modWZ4Q5Ns(long arg0, int other) {
        return UInt.m166constructorimpl((int) UnsignedKt.m422ulongRemaindereb3DHEI(arg0, m244constructorimpl(((long) other) & 4294967295L)));
    }

    /* renamed from: mod-VKZWuLQ  reason: not valid java name */
    private static final long m264modVKZWuLQ(long arg0, long other) {
        return UnsignedKt.m422ulongRemaindereb3DHEI(arg0, other);
    }

    /* renamed from: inc-s-VKNKU  reason: not valid java name */
    private static final long m257incsVKNKU(long arg0) {
        return m244constructorimpl(1 + arg0);
    }

    /* renamed from: dec-s-VKNKU  reason: not valid java name */
    private static final long m245decsVKNKU(long arg0) {
        return m244constructorimpl(-1 + arg0);
    }

    /* renamed from: rangeTo-VKZWuLQ  reason: not valid java name */
    private static final ULongRange m272rangeToVKZWuLQ(long arg0, long other) {
        return new ULongRange(arg0, other, (DefaultConstructorMarker) null);
    }

    /* renamed from: shl-s-VKNKU  reason: not valid java name */
    private static final long m277shlsVKNKU(long arg0, int bitCount) {
        return m244constructorimpl(arg0 << bitCount);
    }

    /* renamed from: shr-s-VKNKU  reason: not valid java name */
    private static final long m278shrsVKNKU(long arg0, int bitCount) {
        return m244constructorimpl(arg0 >>> bitCount);
    }

    /* renamed from: and-VKZWuLQ  reason: not valid java name */
    private static final long m237andVKZWuLQ(long arg0, long other) {
        return m244constructorimpl(arg0 & other);
    }

    /* renamed from: or-VKZWuLQ  reason: not valid java name */
    private static final long m267orVKZWuLQ(long arg0, long other) {
        return m244constructorimpl(arg0 | other);
    }

    /* renamed from: xor-VKZWuLQ  reason: not valid java name */
    private static final long m294xorVKZWuLQ(long arg0, long other) {
        return m244constructorimpl(arg0 ^ other);
    }

    /* renamed from: inv-s-VKNKU  reason: not valid java name */
    private static final long m258invsVKNKU(long arg0) {
        return m244constructorimpl(~arg0);
    }

    /* renamed from: toByte-impl  reason: not valid java name */
    private static final byte m283toByteimpl(long arg0) {
        return (byte) ((int) arg0);
    }

    /* renamed from: toShort-impl  reason: not valid java name */
    private static final short m288toShortimpl(long arg0) {
        return (short) ((int) arg0);
    }

    /* renamed from: toInt-impl  reason: not valid java name */
    private static final int m286toIntimpl(long arg0) {
        return (int) arg0;
    }

    /* renamed from: toLong-impl  reason: not valid java name */
    private static final long m287toLongimpl(long arg0) {
        return arg0;
    }

    /* renamed from: toUByte-w2LRezQ  reason: not valid java name */
    private static final byte m290toUBytew2LRezQ(long arg0) {
        return UByte.m90constructorimpl((byte) ((int) arg0));
    }

    /* renamed from: toUShort-Mh2AYeg  reason: not valid java name */
    private static final short m293toUShortMh2AYeg(long arg0) {
        return UShort.m350constructorimpl((short) ((int) arg0));
    }

    /* renamed from: toUInt-pVg5ArA  reason: not valid java name */
    private static final int m291toUIntpVg5ArA(long arg0) {
        return UInt.m166constructorimpl((int) arg0);
    }

    /* renamed from: toULong-s-VKNKU  reason: not valid java name */
    private static final long m292toULongsVKNKU(long arg0) {
        return arg0;
    }

    /* renamed from: toFloat-impl  reason: not valid java name */
    private static final float m285toFloatimpl(long arg0) {
        return (float) UnsignedKt.ulongToDouble(arg0);
    }

    /* renamed from: toDouble-impl  reason: not valid java name */
    private static final double m284toDoubleimpl(long arg0) {
        return UnsignedKt.ulongToDouble(arg0);
    }

    /* renamed from: toString-impl  reason: not valid java name */
    public static String m289toStringimpl(long arg0) {
        return UnsignedKt.ulongToString(arg0);
    }

    public String toString() {
        return m289toStringimpl(this.data);
    }
}
