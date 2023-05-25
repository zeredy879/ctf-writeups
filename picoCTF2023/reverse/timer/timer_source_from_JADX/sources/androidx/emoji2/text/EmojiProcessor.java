package androidx.emoji2.text;

import android.os.Build;
import android.text.Editable;
import android.text.Selection;
import android.text.Spannable;
import android.text.TextPaint;
import android.text.method.MetaKeyKeyListener;
import android.view.KeyEvent;
import android.view.inputmethod.InputConnection;
import androidx.core.graphics.PaintCompat;
import androidx.emoji2.text.EmojiCompat;
import androidx.emoji2.text.MetadataRepo;
import java.util.Arrays;

final class EmojiProcessor {
    private static final int ACTION_ADVANCE_BOTH = 1;
    private static final int ACTION_ADVANCE_END = 2;
    private static final int ACTION_FLUSH = 3;
    private final int[] mEmojiAsDefaultStyleExceptions;
    private EmojiCompat.GlyphChecker mGlyphChecker;
    private final MetadataRepo mMetadataRepo;
    private final EmojiCompat.SpanFactory mSpanFactory;
    private final boolean mUseEmojiAsDefaultStyle;

    EmojiProcessor(MetadataRepo metadataRepo, EmojiCompat.SpanFactory spanFactory, EmojiCompat.GlyphChecker glyphChecker, boolean useEmojiAsDefaultStyle, int[] emojiAsDefaultStyleExceptions) {
        this.mSpanFactory = spanFactory;
        this.mMetadataRepo = metadataRepo;
        this.mGlyphChecker = glyphChecker;
        this.mUseEmojiAsDefaultStyle = useEmojiAsDefaultStyle;
        this.mEmojiAsDefaultStyleExceptions = emojiAsDefaultStyleExceptions;
    }

    /* access modifiers changed from: package-private */
    public EmojiMetadata getEmojiMetadata(CharSequence charSequence) {
        ProcessorSm sm = new ProcessorSm(this.mMetadataRepo.getRootNode(), this.mUseEmojiAsDefaultStyle, this.mEmojiAsDefaultStyleExceptions);
        int end = charSequence.length();
        int currentOffset = 0;
        while (currentOffset < end) {
            int codePoint = Character.codePointAt(charSequence, currentOffset);
            if (sm.check(codePoint) != 2) {
                return null;
            }
            currentOffset += Character.charCount(codePoint);
        }
        if (sm.isInFlushableState()) {
            return sm.getCurrentMetadata();
        }
        return null;
    }

    /* access modifiers changed from: package-private */
    /* JADX WARNING: Removed duplicated region for block: B:22:0x0043 A[Catch:{ all -> 0x011b }] */
    /* JADX WARNING: Removed duplicated region for block: B:27:0x0061 A[Catch:{ all -> 0x011b }] */
    /* JADX WARNING: Removed duplicated region for block: B:71:0x0114  */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public java.lang.CharSequence process(java.lang.CharSequence r10, int r11, int r12, int r13, boolean r14) {
        /*
            r9 = this;
            boolean r0 = r10 instanceof androidx.emoji2.text.SpannableBuilder
            if (r0 == 0) goto L_0x000a
            r1 = r10
            androidx.emoji2.text.SpannableBuilder r1 = (androidx.emoji2.text.SpannableBuilder) r1
            r1.beginBatchEdit()
        L_0x000a:
            r1 = 0
            if (r0 != 0) goto L_0x002c
            boolean r2 = r10 instanceof android.text.Spannable     // Catch:{ all -> 0x011b }
            if (r2 == 0) goto L_0x0012
            goto L_0x002c
        L_0x0012:
            boolean r2 = r10 instanceof android.text.Spanned     // Catch:{ all -> 0x011b }
            if (r2 == 0) goto L_0x0030
            r2 = r10
            android.text.Spanned r2 = (android.text.Spanned) r2     // Catch:{ all -> 0x011b }
            int r3 = r11 + -1
            int r4 = r12 + 1
            java.lang.Class<androidx.emoji2.text.EmojiSpan> r5 = androidx.emoji2.text.EmojiSpan.class
            int r2 = r2.nextSpanTransition(r3, r4, r5)     // Catch:{ all -> 0x011b }
            if (r2 > r12) goto L_0x0030
            android.text.SpannableString r3 = new android.text.SpannableString     // Catch:{ all -> 0x011b }
            r3.<init>(r10)     // Catch:{ all -> 0x011b }
            r1 = r3
            goto L_0x0030
        L_0x002c:
            r2 = r10
            android.text.Spannable r2 = (android.text.Spannable) r2     // Catch:{ all -> 0x011b }
            r1 = r2
        L_0x0030:
            if (r1 == 0) goto L_0x005f
            java.lang.Class<androidx.emoji2.text.EmojiSpan> r2 = androidx.emoji2.text.EmojiSpan.class
            java.lang.Object[] r2 = r1.getSpans(r11, r12, r2)     // Catch:{ all -> 0x011b }
            androidx.emoji2.text.EmojiSpan[] r2 = (androidx.emoji2.text.EmojiSpan[]) r2     // Catch:{ all -> 0x011b }
            if (r2 == 0) goto L_0x005f
            int r3 = r2.length     // Catch:{ all -> 0x011b }
            if (r3 <= 0) goto L_0x005f
            int r3 = r2.length     // Catch:{ all -> 0x011b }
            r4 = 0
        L_0x0041:
            if (r4 >= r3) goto L_0x005f
            r5 = r2[r4]     // Catch:{ all -> 0x011b }
            int r6 = r1.getSpanStart(r5)     // Catch:{ all -> 0x011b }
            int r7 = r1.getSpanEnd(r5)     // Catch:{ all -> 0x011b }
            if (r6 == r12) goto L_0x0052
            r1.removeSpan(r5)     // Catch:{ all -> 0x011b }
        L_0x0052:
            int r8 = java.lang.Math.min(r6, r11)     // Catch:{ all -> 0x011b }
            r11 = r8
            int r8 = java.lang.Math.max(r7, r12)     // Catch:{ all -> 0x011b }
            r12 = r8
            int r4 = r4 + 1
            goto L_0x0041
        L_0x005f:
            if (r11 == r12) goto L_0x0111
            int r2 = r10.length()     // Catch:{ all -> 0x011b }
            if (r11 < r2) goto L_0x0069
            goto L_0x0111
        L_0x0069:
            r2 = 2147483647(0x7fffffff, float:NaN)
            if (r13 == r2) goto L_0x007f
            if (r1 == 0) goto L_0x007f
            r2 = 0
            int r3 = r1.length()     // Catch:{ all -> 0x011b }
            java.lang.Class<androidx.emoji2.text.EmojiSpan> r4 = androidx.emoji2.text.EmojiSpan.class
            java.lang.Object[] r2 = r1.getSpans(r2, r3, r4)     // Catch:{ all -> 0x011b }
            androidx.emoji2.text.EmojiSpan[] r2 = (androidx.emoji2.text.EmojiSpan[]) r2     // Catch:{ all -> 0x011b }
            int r2 = r2.length     // Catch:{ all -> 0x011b }
            int r13 = r13 - r2
        L_0x007f:
            r2 = 0
            androidx.emoji2.text.EmojiProcessor$ProcessorSm r3 = new androidx.emoji2.text.EmojiProcessor$ProcessorSm     // Catch:{ all -> 0x011b }
            androidx.emoji2.text.MetadataRepo r4 = r9.mMetadataRepo     // Catch:{ all -> 0x011b }
            androidx.emoji2.text.MetadataRepo$Node r4 = r4.getRootNode()     // Catch:{ all -> 0x011b }
            boolean r5 = r9.mUseEmojiAsDefaultStyle     // Catch:{ all -> 0x011b }
            int[] r6 = r9.mEmojiAsDefaultStyleExceptions     // Catch:{ all -> 0x011b }
            r3.<init>(r4, r5, r6)     // Catch:{ all -> 0x011b }
            r4 = r11
            int r5 = java.lang.Character.codePointAt(r10, r4)     // Catch:{ all -> 0x011b }
        L_0x0094:
            if (r4 >= r12) goto L_0x00de
            if (r2 >= r13) goto L_0x00de
            int r6 = r3.check(r5)     // Catch:{ all -> 0x011b }
            switch(r6) {
                case 1: goto L_0x00cc;
                case 2: goto L_0x00bf;
                case 3: goto L_0x00a0;
                default: goto L_0x009f;
            }     // Catch:{ all -> 0x011b }
        L_0x009f:
            goto L_0x00dd
        L_0x00a0:
            if (r14 != 0) goto L_0x00ac
            androidx.emoji2.text.EmojiMetadata r7 = r3.getFlushMetadata()     // Catch:{ all -> 0x011b }
            boolean r7 = r9.hasGlyph(r10, r11, r4, r7)     // Catch:{ all -> 0x011b }
            if (r7 != 0) goto L_0x00bd
        L_0x00ac:
            if (r1 != 0) goto L_0x00b4
            android.text.SpannableString r7 = new android.text.SpannableString     // Catch:{ all -> 0x011b }
            r7.<init>(r10)     // Catch:{ all -> 0x011b }
            r1 = r7
        L_0x00b4:
            androidx.emoji2.text.EmojiMetadata r7 = r3.getFlushMetadata()     // Catch:{ all -> 0x011b }
            r9.addEmoji(r1, r7, r11, r4)     // Catch:{ all -> 0x011b }
            int r2 = r2 + 1
        L_0x00bd:
            r11 = r4
            goto L_0x00dd
        L_0x00bf:
            int r7 = java.lang.Character.charCount(r5)     // Catch:{ all -> 0x011b }
            int r4 = r4 + r7
            if (r4 >= r12) goto L_0x00dd
            int r7 = java.lang.Character.codePointAt(r10, r4)     // Catch:{ all -> 0x011b }
            r5 = r7
            goto L_0x00dd
        L_0x00cc:
            int r7 = java.lang.Character.codePointAt(r10, r11)     // Catch:{ all -> 0x011b }
            int r7 = java.lang.Character.charCount(r7)     // Catch:{ all -> 0x011b }
            int r11 = r11 + r7
            r4 = r11
            if (r4 >= r12) goto L_0x00dd
            int r7 = java.lang.Character.codePointAt(r10, r4)     // Catch:{ all -> 0x011b }
            r5 = r7
        L_0x00dd:
            goto L_0x0094
        L_0x00de:
            boolean r6 = r3.isInFlushableState()     // Catch:{ all -> 0x011b }
            if (r6 == 0) goto L_0x0103
            if (r2 >= r13) goto L_0x0103
            if (r14 != 0) goto L_0x00f2
            androidx.emoji2.text.EmojiMetadata r6 = r3.getCurrentMetadata()     // Catch:{ all -> 0x011b }
            boolean r6 = r9.hasGlyph(r10, r11, r4, r6)     // Catch:{ all -> 0x011b }
            if (r6 != 0) goto L_0x0103
        L_0x00f2:
            if (r1 != 0) goto L_0x00fa
            android.text.SpannableString r6 = new android.text.SpannableString     // Catch:{ all -> 0x011b }
            r6.<init>(r10)     // Catch:{ all -> 0x011b }
            r1 = r6
        L_0x00fa:
            androidx.emoji2.text.EmojiMetadata r6 = r3.getCurrentMetadata()     // Catch:{ all -> 0x011b }
            r9.addEmoji(r1, r6, r11, r4)     // Catch:{ all -> 0x011b }
            int r2 = r2 + 1
        L_0x0103:
            if (r1 != 0) goto L_0x0107
            r6 = r10
            goto L_0x0108
        L_0x0107:
            r6 = r1
        L_0x0108:
            if (r0 == 0) goto L_0x0110
            r7 = r10
            androidx.emoji2.text.SpannableBuilder r7 = (androidx.emoji2.text.SpannableBuilder) r7
            r7.endBatchEdit()
        L_0x0110:
            return r6
        L_0x0111:
            if (r0 == 0) goto L_0x011a
            r2 = r10
            androidx.emoji2.text.SpannableBuilder r2 = (androidx.emoji2.text.SpannableBuilder) r2
            r2.endBatchEdit()
        L_0x011a:
            return r10
        L_0x011b:
            r1 = move-exception
            if (r0 == 0) goto L_0x0124
            r2 = r10
            androidx.emoji2.text.SpannableBuilder r2 = (androidx.emoji2.text.SpannableBuilder) r2
            r2.endBatchEdit()
        L_0x0124:
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.emoji2.text.EmojiProcessor.process(java.lang.CharSequence, int, int, int, boolean):java.lang.CharSequence");
    }

    static boolean handleOnKeyDown(Editable editable, int keyCode, KeyEvent event) {
        boolean handled;
        switch (keyCode) {
            case 67:
                handled = delete(editable, event, false);
                break;
            case 112:
                handled = delete(editable, event, true);
                break;
            default:
                handled = false;
                break;
        }
        if (!handled) {
            return false;
        }
        MetaKeyKeyListener.adjustMetaAfterKeypress(editable);
        return true;
    }

    private static boolean delete(Editable content, KeyEvent event, boolean forwardDelete) {
        EmojiSpan[] spans;
        if (hasModifiers(event)) {
            return false;
        }
        int start = Selection.getSelectionStart(content);
        int end = Selection.getSelectionEnd(content);
        if (!hasInvalidSelection(start, end) && (spans = (EmojiSpan[]) content.getSpans(start, end, EmojiSpan.class)) != null && spans.length > 0) {
            int length = spans.length;
            int index = 0;
            while (index < length) {
                EmojiSpan span = spans[index];
                int spanStart = content.getSpanStart(span);
                int spanEnd = content.getSpanEnd(span);
                if ((!forwardDelete || spanStart != start) && ((forwardDelete || spanEnd != start) && (start <= spanStart || start >= spanEnd))) {
                    index++;
                } else {
                    content.delete(spanStart, spanEnd);
                    return true;
                }
            }
        }
        return false;
    }

    static boolean handleDeleteSurroundingText(InputConnection inputConnection, Editable editable, int beforeLength, int afterLength, boolean inCodePoints) {
        int end;
        int start;
        if (editable == null || inputConnection == null || beforeLength < 0 || afterLength < 0) {
            return false;
        }
        int selectionStart = Selection.getSelectionStart(editable);
        int selectionEnd = Selection.getSelectionEnd(editable);
        if (hasInvalidSelection(selectionStart, selectionEnd)) {
            return false;
        }
        if (inCodePoints) {
            start = CodepointIndexFinder.findIndexBackward(editable, selectionStart, Math.max(beforeLength, 0));
            end = CodepointIndexFinder.findIndexForward(editable, selectionEnd, Math.max(afterLength, 0));
            if (start == -1 || end == -1) {
                return false;
            }
        } else {
            start = Math.max(selectionStart - beforeLength, 0);
            end = Math.min(selectionEnd + afterLength, editable.length());
        }
        EmojiSpan[] spans = (EmojiSpan[]) editable.getSpans(start, end, EmojiSpan.class);
        if (spans == null || spans.length <= 0) {
            return false;
        }
        for (EmojiSpan span : spans) {
            int spanStart = editable.getSpanStart(span);
            int spanEnd = editable.getSpanEnd(span);
            start = Math.min(spanStart, start);
            end = Math.max(spanEnd, end);
        }
        int start2 = Math.max(start, 0);
        int end2 = Math.min(end, editable.length());
        inputConnection.beginBatchEdit();
        editable.delete(start2, end2);
        inputConnection.endBatchEdit();
        return true;
    }

    private static boolean hasInvalidSelection(int start, int end) {
        return start == -1 || end == -1 || start != end;
    }

    private static boolean hasModifiers(KeyEvent event) {
        return !KeyEvent.metaStateHasNoModifiers(event.getMetaState());
    }

    private void addEmoji(Spannable spannable, EmojiMetadata metadata, int start, int end) {
        spannable.setSpan(this.mSpanFactory.createSpan(metadata), start, end, 33);
    }

    private boolean hasGlyph(CharSequence charSequence, int start, int end, EmojiMetadata metadata) {
        if (metadata.getHasGlyph() == 0) {
            metadata.setHasGlyph(this.mGlyphChecker.hasGlyph(charSequence, start, end, metadata.getSdkAdded()));
        }
        return metadata.getHasGlyph() == 2;
    }

    static final class ProcessorSm {
        private static final int STATE_DEFAULT = 1;
        private static final int STATE_WALKING = 2;
        private int mCurrentDepth;
        private MetadataRepo.Node mCurrentNode;
        private final int[] mEmojiAsDefaultStyleExceptions;
        private MetadataRepo.Node mFlushNode;
        private int mLastCodepoint;
        private final MetadataRepo.Node mRootNode;
        private int mState = 1;
        private final boolean mUseEmojiAsDefaultStyle;

        ProcessorSm(MetadataRepo.Node rootNode, boolean useEmojiAsDefaultStyle, int[] emojiAsDefaultStyleExceptions) {
            this.mRootNode = rootNode;
            this.mCurrentNode = rootNode;
            this.mUseEmojiAsDefaultStyle = useEmojiAsDefaultStyle;
            this.mEmojiAsDefaultStyleExceptions = emojiAsDefaultStyleExceptions;
        }

        /* access modifiers changed from: package-private */
        public int check(int codePoint) {
            int action;
            MetadataRepo.Node node = this.mCurrentNode.get(codePoint);
            switch (this.mState) {
                case 2:
                    if (node == null) {
                        if (isTextStyle(codePoint) == 0) {
                            if (isEmojiStyle(codePoint) == 0) {
                                if (this.mCurrentNode.getData() != null) {
                                    if (this.mCurrentDepth == 1) {
                                        if (!shouldUseEmojiPresentationStyleForSingleCodepoint()) {
                                            action = reset();
                                            break;
                                        } else {
                                            this.mFlushNode = this.mCurrentNode;
                                            action = 3;
                                            reset();
                                            break;
                                        }
                                    } else {
                                        this.mFlushNode = this.mCurrentNode;
                                        action = 3;
                                        reset();
                                        break;
                                    }
                                } else {
                                    action = reset();
                                    break;
                                }
                            } else {
                                action = 2;
                                break;
                            }
                        } else {
                            action = reset();
                            break;
                        }
                    } else {
                        this.mCurrentNode = node;
                        this.mCurrentDepth++;
                        action = 2;
                        break;
                    }
                default:
                    if (node != null) {
                        this.mState = 2;
                        this.mCurrentNode = node;
                        this.mCurrentDepth = 1;
                        action = 2;
                        break;
                    } else {
                        action = reset();
                        break;
                    }
            }
            this.mLastCodepoint = codePoint;
            return action;
        }

        private int reset() {
            this.mState = 1;
            this.mCurrentNode = this.mRootNode;
            this.mCurrentDepth = 0;
            return 1;
        }

        /* access modifiers changed from: package-private */
        public EmojiMetadata getFlushMetadata() {
            return this.mFlushNode.getData();
        }

        /* access modifiers changed from: package-private */
        public EmojiMetadata getCurrentMetadata() {
            return this.mCurrentNode.getData();
        }

        /* access modifiers changed from: package-private */
        public boolean isInFlushableState() {
            if (this.mState != 2 || this.mCurrentNode.getData() == null || (this.mCurrentDepth <= 1 && !shouldUseEmojiPresentationStyleForSingleCodepoint())) {
                return false;
            }
            return true;
        }

        private boolean shouldUseEmojiPresentationStyleForSingleCodepoint() {
            if (this.mCurrentNode.getData().isDefaultEmoji() || isEmojiStyle(this.mLastCodepoint)) {
                return true;
            }
            if (this.mUseEmojiAsDefaultStyle) {
                if (this.mEmojiAsDefaultStyleExceptions == null) {
                    return true;
                }
                if (Arrays.binarySearch(this.mEmojiAsDefaultStyleExceptions, this.mCurrentNode.getData().getCodepointAt(0)) < 0) {
                    return true;
                }
            }
            return false;
        }

        private static boolean isEmojiStyle(int codePoint) {
            return codePoint == 65039;
        }

        private static boolean isTextStyle(int codePoint) {
            return codePoint == 65038;
        }
    }

    private static final class CodepointIndexFinder {
        private static final int INVALID_INDEX = -1;

        private CodepointIndexFinder() {
        }

        static int findIndexBackward(CharSequence cs, int from, int numCodePoints) {
            int currentIndex = from;
            boolean waitingHighSurrogate = false;
            int length = cs.length();
            if (currentIndex < 0 || length < currentIndex || numCodePoints < 0) {
                return -1;
            }
            int remainingCodePoints = numCodePoints;
            while (remainingCodePoints != 0) {
                currentIndex--;
                if (currentIndex >= 0) {
                    char c = cs.charAt(currentIndex);
                    if (waitingHighSurrogate) {
                        if (!Character.isHighSurrogate(c)) {
                            return -1;
                        }
                        waitingHighSurrogate = false;
                        remainingCodePoints--;
                    } else if (!Character.isSurrogate(c)) {
                        remainingCodePoints--;
                    } else if (Character.isHighSurrogate(c)) {
                        return -1;
                    } else {
                        waitingHighSurrogate = true;
                    }
                } else if (waitingHighSurrogate) {
                    return -1;
                } else {
                    return 0;
                }
            }
            return currentIndex;
        }

        static int findIndexForward(CharSequence cs, int from, int numCodePoints) {
            int currentIndex = from;
            boolean waitingLowSurrogate = false;
            int length = cs.length();
            if (currentIndex < 0 || length < currentIndex || numCodePoints < 0) {
                return -1;
            }
            int remainingCodePoints = numCodePoints;
            while (remainingCodePoints != 0) {
                if (currentIndex < length) {
                    char c = cs.charAt(currentIndex);
                    if (waitingLowSurrogate) {
                        if (!Character.isLowSurrogate(c)) {
                            return -1;
                        }
                        remainingCodePoints--;
                        waitingLowSurrogate = false;
                        currentIndex++;
                    } else if (!Character.isSurrogate(c)) {
                        remainingCodePoints--;
                        currentIndex++;
                    } else if (Character.isLowSurrogate(c)) {
                        return -1;
                    } else {
                        waitingLowSurrogate = true;
                        currentIndex++;
                    }
                } else if (waitingLowSurrogate) {
                    return -1;
                } else {
                    return length;
                }
            }
            return currentIndex;
        }
    }

    public static class DefaultGlyphChecker implements EmojiCompat.GlyphChecker {
        private static final int PAINT_TEXT_SIZE = 10;
        private static final ThreadLocal<StringBuilder> sStringBuilder = new ThreadLocal<>();
        private final TextPaint mTextPaint;

        DefaultGlyphChecker() {
            TextPaint textPaint = new TextPaint();
            this.mTextPaint = textPaint;
            textPaint.setTextSize(10.0f);
        }

        public boolean hasGlyph(CharSequence charSequence, int start, int end, int sdkAdded) {
            if (Build.VERSION.SDK_INT < 23 && sdkAdded > Build.VERSION.SDK_INT) {
                return false;
            }
            StringBuilder builder = getStringBuilder();
            builder.setLength(0);
            while (start < end) {
                builder.append(charSequence.charAt(start));
                start++;
            }
            return PaintCompat.hasGlyph(this.mTextPaint, builder.toString());
        }

        private static StringBuilder getStringBuilder() {
            ThreadLocal<StringBuilder> threadLocal = sStringBuilder;
            if (threadLocal.get() == null) {
                threadLocal.set(new StringBuilder());
            }
            return threadLocal.get();
        }
    }
}
