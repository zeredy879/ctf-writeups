package com.google.android.material.textfield;

import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Configuration;
import android.graphics.Canvas;
import android.graphics.PorterDuff;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Parcel;
import android.os.Parcelable;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.util.AttributeSet;
import android.util.Log;
import android.util.SparseArray;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewStructure;
import android.widget.AutoCompleteTextView;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.appcompat.content.res.AppCompatResources;
import androidx.appcompat.widget.AppCompatDrawableManager;
import androidx.appcompat.widget.AppCompatTextView;
import androidx.appcompat.widget.DrawableUtils;
import androidx.core.content.ContextCompat;
import androidx.core.graphics.drawable.DrawableCompat;
import androidx.core.text.BidiFormatter;
import androidx.core.view.AccessibilityDelegateCompat;
import androidx.core.view.MarginLayoutParamsCompat;
import androidx.core.view.ViewCompat;
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
import androidx.core.widget.TextViewCompat;
import androidx.customview.view.AbsSavedState;
import androidx.transition.Fade;
import androidx.transition.TransitionManager;
import com.google.android.material.C0105R;
import com.google.android.material.animation.AnimationUtils;
import com.google.android.material.color.MaterialColors;
import com.google.android.material.internal.CheckableImageButton;
import com.google.android.material.internal.CollapsingTextHelper;
import com.google.android.material.internal.DescendantOffsetUtils;
import com.google.android.material.internal.ViewUtils;
import com.google.android.material.resources.MaterialResources;
import com.google.android.material.shape.MaterialShapeDrawable;
import com.google.android.material.shape.ShapeAppearanceModel;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.Iterator;
import java.util.LinkedHashSet;

public class TextInputLayout extends LinearLayout {
    public static final int BOX_BACKGROUND_FILLED = 1;
    public static final int BOX_BACKGROUND_NONE = 0;
    public static final int BOX_BACKGROUND_OUTLINE = 2;
    private static final int DEF_STYLE_RES = C0105R.style.Widget_Design_TextInputLayout;
    public static final int END_ICON_CLEAR_TEXT = 2;
    public static final int END_ICON_CUSTOM = -1;
    public static final int END_ICON_DROPDOWN_MENU = 3;
    public static final int END_ICON_NONE = 0;
    public static final int END_ICON_PASSWORD_TOGGLE = 1;
    private static final int INVALID_MAX_LENGTH = -1;
    private static final int LABEL_SCALE_ANIMATION_DURATION = 167;
    private static final String LOG_TAG = "TextInputLayout";
    private static final int NO_WIDTH = -1;
    private static final long PLACEHOLDER_FADE_DURATION = 87;
    private static final long PLACEHOLDER_START_DELAY = 67;
    private ValueAnimator animator;
    private boolean areCornerRadiiRtl;
    private MaterialShapeDrawable boxBackground;
    private int boxBackgroundColor;
    private int boxBackgroundMode;
    private int boxCollapsedPaddingTopPx;
    private final int boxLabelCutoutPaddingPx;
    private int boxStrokeColor;
    private int boxStrokeWidthDefaultPx;
    private int boxStrokeWidthFocusedPx;
    private int boxStrokeWidthPx;
    private MaterialShapeDrawable boxUnderlineDefault;
    private MaterialShapeDrawable boxUnderlineFocused;
    final CollapsingTextHelper collapsingTextHelper;
    boolean counterEnabled;
    private int counterMaxLength;
    private int counterOverflowTextAppearance;
    private ColorStateList counterOverflowTextColor;
    private boolean counterOverflowed;
    private int counterTextAppearance;
    private ColorStateList counterTextColor;
    private TextView counterView;
    private int defaultFilledBackgroundColor;
    private ColorStateList defaultHintTextColor;
    private int defaultStrokeColor;
    private int disabledColor;
    private int disabledFilledBackgroundColor;
    EditText editText;
    private final LinkedHashSet<OnEditTextAttachedListener> editTextAttachedListeners;
    private Drawable endDummyDrawable;
    private int endDummyDrawableWidth;
    private final LinkedHashSet<OnEndIconChangedListener> endIconChangedListeners;
    private final SparseArray<EndIconDelegate> endIconDelegates;
    private final FrameLayout endIconFrame;
    private int endIconMode;
    private View.OnLongClickListener endIconOnLongClickListener;
    private ColorStateList endIconTintList;
    private PorterDuff.Mode endIconTintMode;
    /* access modifiers changed from: private */
    public final CheckableImageButton endIconView;
    private final LinearLayout endLayout;
    private View.OnLongClickListener errorIconOnLongClickListener;
    private ColorStateList errorIconTintList;
    private PorterDuff.Mode errorIconTintMode;
    private final CheckableImageButton errorIconView;
    private boolean expandedHintEnabled;
    private int focusedFilledBackgroundColor;
    private int focusedStrokeColor;
    private ColorStateList focusedTextColor;
    private CharSequence hint;
    private boolean hintAnimationEnabled;
    private boolean hintEnabled;
    private boolean hintExpanded;
    private int hoveredFilledBackgroundColor;
    private int hoveredStrokeColor;
    private boolean inDrawableStateChanged;
    /* access modifiers changed from: private */
    public final IndicatorViewController indicatorViewController;
    private final FrameLayout inputFrame;
    private boolean isProvidingHint;
    private int maxEms;
    private int maxWidth;
    private int minEms;
    private int minWidth;
    private Drawable originalEditTextEndDrawable;
    private CharSequence originalHint;
    /* access modifiers changed from: private */
    public boolean placeholderEnabled;
    private Fade placeholderFadeIn;
    private Fade placeholderFadeOut;
    private CharSequence placeholderText;
    private int placeholderTextAppearance;
    private ColorStateList placeholderTextColor;
    private TextView placeholderTextView;
    /* access modifiers changed from: private */
    public boolean restoringSavedState;
    private ShapeAppearanceModel shapeAppearanceModel;
    private Drawable startDummyDrawable;
    private int startDummyDrawableWidth;
    /* access modifiers changed from: private */
    public final StartCompoundLayout startLayout;
    private ColorStateList strokeErrorColor;
    private CharSequence suffixText;
    private final TextView suffixTextView;
    private final Rect tmpBoundsRect;
    private final Rect tmpRect;
    private final RectF tmpRectF;
    private Typeface typeface;

    @Retention(RetentionPolicy.SOURCE)
    public @interface BoxBackgroundMode {
    }

    @Retention(RetentionPolicy.SOURCE)
    public @interface EndIconMode {
    }

    public interface OnEditTextAttachedListener {
        void onEditTextAttached(TextInputLayout textInputLayout);
    }

    public interface OnEndIconChangedListener {
        void onEndIconChanged(TextInputLayout textInputLayout, int i);
    }

    public TextInputLayout(Context context) {
        this(context, (AttributeSet) null);
    }

    public TextInputLayout(Context context, AttributeSet attrs) {
        this(context, attrs, C0105R.attr.textInputStyle);
    }

    /* JADX WARNING: Illegal instructions before constructor call */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public TextInputLayout(android.content.Context r38, android.util.AttributeSet r39, int r40) {
        /*
            r37 = this;
            r0 = r37
            r7 = r39
            r8 = r40
            int r9 = DEF_STYLE_RES
            r1 = r38
            android.content.Context r2 = com.google.android.material.theme.overlay.MaterialThemeOverlay.wrap(r1, r7, r8, r9)
            r0.<init>(r2, r7, r8)
            r10 = -1
            r0.minEms = r10
            r0.maxEms = r10
            r0.minWidth = r10
            r0.maxWidth = r10
            com.google.android.material.textfield.IndicatorViewController r2 = new com.google.android.material.textfield.IndicatorViewController
            r2.<init>(r0)
            r0.indicatorViewController = r2
            android.graphics.Rect r2 = new android.graphics.Rect
            r2.<init>()
            r0.tmpRect = r2
            android.graphics.Rect r2 = new android.graphics.Rect
            r2.<init>()
            r0.tmpBoundsRect = r2
            android.graphics.RectF r2 = new android.graphics.RectF
            r2.<init>()
            r0.tmpRectF = r2
            java.util.LinkedHashSet r2 = new java.util.LinkedHashSet
            r2.<init>()
            r0.editTextAttachedListeners = r2
            r11 = 0
            r0.endIconMode = r11
            android.util.SparseArray r12 = new android.util.SparseArray
            r12.<init>()
            r0.endIconDelegates = r12
            java.util.LinkedHashSet r2 = new java.util.LinkedHashSet
            r2.<init>()
            r0.endIconChangedListeners = r2
            com.google.android.material.internal.CollapsingTextHelper r2 = new com.google.android.material.internal.CollapsingTextHelper
            r2.<init>(r0)
            r0.collapsingTextHelper = r2
            android.content.Context r13 = r37.getContext()
            r14 = 1
            r0.setOrientation(r14)
            r0.setWillNotDraw(r11)
            r0.setAddStatesFromChildren(r14)
            android.widget.FrameLayout r15 = new android.widget.FrameLayout
            r15.<init>(r13)
            r0.inputFrame = r15
            android.widget.FrameLayout r6 = new android.widget.FrameLayout
            r6.<init>(r13)
            r0.endIconFrame = r6
            android.widget.LinearLayout r5 = new android.widget.LinearLayout
            r5.<init>(r13)
            r0.endLayout = r5
            androidx.appcompat.widget.AppCompatTextView r4 = new androidx.appcompat.widget.AppCompatTextView
            r4.<init>(r13)
            r0.suffixTextView = r4
            r1 = 8
            r5.setVisibility(r1)
            r6.setVisibility(r1)
            r4.setVisibility(r1)
            android.view.LayoutInflater r3 = android.view.LayoutInflater.from(r13)
            int r1 = com.google.android.material.C0105R.layout.design_text_input_end_icon
            android.view.View r1 = r3.inflate(r1, r5, r11)
            com.google.android.material.internal.CheckableImageButton r1 = (com.google.android.material.internal.CheckableImageButton) r1
            r0.errorIconView = r1
            int r10 = com.google.android.material.C0105R.layout.design_text_input_end_icon
            android.view.View r10 = r3.inflate(r10, r6, r11)
            com.google.android.material.internal.CheckableImageButton r10 = (com.google.android.material.internal.CheckableImageButton) r10
            r0.endIconView = r10
            r15.setAddStatesFromChildren(r14)
            r5.setOrientation(r11)
            android.widget.FrameLayout$LayoutParams r14 = new android.widget.FrameLayout$LayoutParams
            r11 = -2
            r16 = r1
            r1 = 8388613(0x800005, float:1.175495E-38)
            r17 = r3
            r3 = -1
            r14.<init>(r11, r3, r1)
            r5.setLayoutParams(r14)
            android.widget.FrameLayout$LayoutParams r1 = new android.widget.FrameLayout$LayoutParams
            r1.<init>(r11, r3)
            r6.setLayoutParams(r1)
            android.animation.TimeInterpolator r1 = com.google.android.material.animation.AnimationUtils.LINEAR_INTERPOLATOR
            r2.setTextSizeInterpolator(r1)
            android.animation.TimeInterpolator r1 = com.google.android.material.animation.AnimationUtils.LINEAR_INTERPOLATOR
            r2.setPositionInterpolator(r1)
            r1 = 8388659(0x800033, float:1.1755015E-38)
            r2.setCollapsedTextGravity(r1)
            int[] r3 = com.google.android.material.C0105R.styleable.TextInputLayout
            r1 = 5
            int[] r14 = new int[r1]
            int r1 = com.google.android.material.C0105R.styleable.TextInputLayout_counterTextAppearance
            r2 = 0
            r14[r2] = r1
            int r1 = com.google.android.material.C0105R.styleable.TextInputLayout_counterOverflowTextAppearance
            r2 = 1
            r14[r2] = r1
            int r1 = com.google.android.material.C0105R.styleable.TextInputLayout_errorTextAppearance
            r2 = 2
            r14[r2] = r1
            int r1 = com.google.android.material.C0105R.styleable.TextInputLayout_helperTextTextAppearance
            r11 = 3
            r14[r11] = r1
            int r1 = com.google.android.material.C0105R.styleable.TextInputLayout_hintTextAppearance
            r18 = 4
            r14[r18] = r1
            r11 = r16
            r1 = r13
            r16 = r15
            r15 = 2
            r2 = r39
            r19 = r4
            r4 = r40
            r20 = r5
            r5 = r9
            r21 = r6
            r6 = r14
            androidx.appcompat.widget.TintTypedArray r1 = com.google.android.material.internal.ThemeEnforcement.obtainTintedStyledAttributes(r1, r2, r3, r4, r5, r6)
            com.google.android.material.textfield.StartCompoundLayout r2 = new com.google.android.material.textfield.StartCompoundLayout
            r2.<init>(r0, r1)
            r0.startLayout = r2
            int r3 = com.google.android.material.C0105R.styleable.TextInputLayout_hintEnabled
            r4 = 1
            boolean r3 = r1.getBoolean(r3, r4)
            r0.hintEnabled = r3
            int r3 = com.google.android.material.C0105R.styleable.TextInputLayout_android_hint
            java.lang.CharSequence r3 = r1.getText(r3)
            r0.setHint((java.lang.CharSequence) r3)
            int r3 = com.google.android.material.C0105R.styleable.TextInputLayout_hintAnimationEnabled
            boolean r3 = r1.getBoolean(r3, r4)
            r0.hintAnimationEnabled = r3
            int r3 = com.google.android.material.C0105R.styleable.TextInputLayout_expandedHintEnabled
            boolean r3 = r1.getBoolean(r3, r4)
            r0.expandedHintEnabled = r3
            int r3 = com.google.android.material.C0105R.styleable.TextInputLayout_android_minEms
            boolean r3 = r1.hasValue(r3)
            if (r3 == 0) goto L_0x0142
            int r3 = com.google.android.material.C0105R.styleable.TextInputLayout_android_minEms
            r4 = -1
            int r3 = r1.getInt(r3, r4)
            r0.setMinEms(r3)
            goto L_0x0154
        L_0x0142:
            r4 = -1
            int r3 = com.google.android.material.C0105R.styleable.TextInputLayout_android_minWidth
            boolean r3 = r1.hasValue(r3)
            if (r3 == 0) goto L_0x0154
            int r3 = com.google.android.material.C0105R.styleable.TextInputLayout_android_minWidth
            int r3 = r1.getDimensionPixelSize(r3, r4)
            r0.setMinWidth(r3)
        L_0x0154:
            int r3 = com.google.android.material.C0105R.styleable.TextInputLayout_android_maxEms
            boolean r3 = r1.hasValue(r3)
            if (r3 == 0) goto L_0x0166
            int r3 = com.google.android.material.C0105R.styleable.TextInputLayout_android_maxEms
            int r3 = r1.getInt(r3, r4)
            r0.setMaxEms(r3)
            goto L_0x0177
        L_0x0166:
            int r3 = com.google.android.material.C0105R.styleable.TextInputLayout_android_maxWidth
            boolean r3 = r1.hasValue(r3)
            if (r3 == 0) goto L_0x0177
            int r3 = com.google.android.material.C0105R.styleable.TextInputLayout_android_maxWidth
            int r3 = r1.getDimensionPixelSize(r3, r4)
            r0.setMaxWidth(r3)
        L_0x0177:
            com.google.android.material.shape.ShapeAppearanceModel$Builder r3 = com.google.android.material.shape.ShapeAppearanceModel.builder((android.content.Context) r13, (android.util.AttributeSet) r7, (int) r8, (int) r9)
            com.google.android.material.shape.ShapeAppearanceModel r3 = r3.build()
            r0.shapeAppearanceModel = r3
            android.content.res.Resources r3 = r13.getResources()
            int r4 = com.google.android.material.C0105R.dimen.mtrl_textinput_box_label_cutout_padding
            int r3 = r3.getDimensionPixelOffset(r4)
            r0.boxLabelCutoutPaddingPx = r3
            int r3 = com.google.android.material.C0105R.styleable.TextInputLayout_boxCollapsedPaddingTop
            r4 = 0
            int r3 = r1.getDimensionPixelOffset(r3, r4)
            r0.boxCollapsedPaddingTopPx = r3
            int r3 = com.google.android.material.C0105R.styleable.TextInputLayout_boxStrokeWidth
            android.content.res.Resources r4 = r13.getResources()
            int r5 = com.google.android.material.C0105R.dimen.mtrl_textinput_box_stroke_width_default
            int r4 = r4.getDimensionPixelSize(r5)
            int r3 = r1.getDimensionPixelSize(r3, r4)
            r0.boxStrokeWidthDefaultPx = r3
            int r3 = com.google.android.material.C0105R.styleable.TextInputLayout_boxStrokeWidthFocused
            android.content.res.Resources r4 = r13.getResources()
            int r5 = com.google.android.material.C0105R.dimen.mtrl_textinput_box_stroke_width_focused
            int r4 = r4.getDimensionPixelSize(r5)
            int r3 = r1.getDimensionPixelSize(r3, r4)
            r0.boxStrokeWidthFocusedPx = r3
            int r3 = r0.boxStrokeWidthDefaultPx
            r0.boxStrokeWidthPx = r3
            int r3 = com.google.android.material.C0105R.styleable.TextInputLayout_boxCornerRadiusTopStart
            r4 = -1082130432(0xffffffffbf800000, float:-1.0)
            float r3 = r1.getDimension(r3, r4)
            int r5 = com.google.android.material.C0105R.styleable.TextInputLayout_boxCornerRadiusTopEnd
            float r5 = r1.getDimension(r5, r4)
            int r6 = com.google.android.material.C0105R.styleable.TextInputLayout_boxCornerRadiusBottomEnd
            float r6 = r1.getDimension(r6, r4)
            int r9 = com.google.android.material.C0105R.styleable.TextInputLayout_boxCornerRadiusBottomStart
            float r4 = r1.getDimension(r9, r4)
            com.google.android.material.shape.ShapeAppearanceModel r9 = r0.shapeAppearanceModel
            com.google.android.material.shape.ShapeAppearanceModel$Builder r9 = r9.toBuilder()
            r14 = 0
            int r22 = (r3 > r14 ? 1 : (r3 == r14 ? 0 : -1))
            if (r22 < 0) goto L_0x01e8
            r9.setTopLeftCornerSize((float) r3)
        L_0x01e8:
            int r22 = (r5 > r14 ? 1 : (r5 == r14 ? 0 : -1))
            if (r22 < 0) goto L_0x01ef
            r9.setTopRightCornerSize((float) r5)
        L_0x01ef:
            int r22 = (r6 > r14 ? 1 : (r6 == r14 ? 0 : -1))
            if (r22 < 0) goto L_0x01f6
            r9.setBottomRightCornerSize((float) r6)
        L_0x01f6:
            int r14 = (r4 > r14 ? 1 : (r4 == r14 ? 0 : -1))
            if (r14 < 0) goto L_0x01fd
            r9.setBottomLeftCornerSize((float) r4)
        L_0x01fd:
            com.google.android.material.shape.ShapeAppearanceModel r14 = r9.build()
            r0.shapeAppearanceModel = r14
            int r14 = com.google.android.material.C0105R.styleable.TextInputLayout_boxBackgroundColor
            android.content.res.ColorStateList r14 = com.google.android.material.resources.MaterialResources.getColorStateList((android.content.Context) r13, (androidx.appcompat.widget.TintTypedArray) r1, (int) r14)
            if (r14 == 0) goto L_0x0278
            int r15 = r14.getDefaultColor()
            r0.defaultFilledBackgroundColor = r15
            r0.boxBackgroundColor = r15
            boolean r15 = r14.isStateful()
            r23 = -16842910(0xfffffffffefeff62, float:-1.6947497E38)
            if (r15 == 0) goto L_0x024a
            r24 = r3
            r15 = 1
            int[] r3 = new int[r15]
            r15 = 0
            r3[r15] = r23
            r15 = -1
            int r3 = r14.getColorForState(r3, r15)
            r0.disabledFilledBackgroundColor = r3
            r3 = 2
            int[] r15 = new int[r3]
            r15 = {16842908, 16842910} // fill-array
            r3 = -1
            int r15 = r14.getColorForState(r15, r3)
            r0.focusedFilledBackgroundColor = r15
            r15 = 2
            int[] r3 = new int[r15]
            r3 = {16843623, 16842910} // fill-array
            r15 = -1
            int r3 = r14.getColorForState(r3, r15)
            r0.hoveredFilledBackgroundColor = r3
            r25 = r4
            r23 = r5
            goto L_0x0289
        L_0x024a:
            r24 = r3
            int r3 = r0.defaultFilledBackgroundColor
            r0.focusedFilledBackgroundColor = r3
            int r3 = com.google.android.material.C0105R.C0106color.mtrl_filled_background_color
            android.content.res.ColorStateList r3 = androidx.appcompat.content.res.AppCompatResources.getColorStateList(r13, r3)
            r25 = r4
            r15 = 1
            int[] r4 = new int[r15]
            r15 = 0
            r4[r15] = r23
            r15 = -1
            int r4 = r3.getColorForState(r4, r15)
            r0.disabledFilledBackgroundColor = r4
            r4 = 1
            int[] r15 = new int[r4]
            r4 = 16843623(0x1010367, float:2.3696E-38)
            r23 = r5
            r5 = 0
            r15[r5] = r4
            r4 = -1
            int r15 = r3.getColorForState(r15, r4)
            r0.hoveredFilledBackgroundColor = r15
            goto L_0x0289
        L_0x0278:
            r24 = r3
            r25 = r4
            r23 = r5
            r5 = 0
            r0.boxBackgroundColor = r5
            r0.defaultFilledBackgroundColor = r5
            r0.disabledFilledBackgroundColor = r5
            r0.focusedFilledBackgroundColor = r5
            r0.hoveredFilledBackgroundColor = r5
        L_0x0289:
            int r3 = com.google.android.material.C0105R.styleable.TextInputLayout_android_textColorHint
            boolean r3 = r1.hasValue(r3)
            if (r3 == 0) goto L_0x029b
            int r3 = com.google.android.material.C0105R.styleable.TextInputLayout_android_textColorHint
            android.content.res.ColorStateList r3 = r1.getColorStateList(r3)
            r0.focusedTextColor = r3
            r0.defaultHintTextColor = r3
        L_0x029b:
            int r3 = com.google.android.material.C0105R.styleable.TextInputLayout_boxStrokeColor
            android.content.res.ColorStateList r3 = com.google.android.material.resources.MaterialResources.getColorStateList((android.content.Context) r13, (androidx.appcompat.widget.TintTypedArray) r1, (int) r3)
            int r4 = com.google.android.material.C0105R.styleable.TextInputLayout_boxStrokeColor
            r5 = 0
            int r4 = r1.getColor(r4, r5)
            r0.focusedStrokeColor = r4
            int r4 = com.google.android.material.C0105R.C0106color.mtrl_textinput_default_box_stroke_color
            int r4 = androidx.core.content.ContextCompat.getColor(r13, r4)
            r0.defaultStrokeColor = r4
            int r4 = com.google.android.material.C0105R.C0106color.mtrl_textinput_disabled_color
            int r4 = androidx.core.content.ContextCompat.getColor(r13, r4)
            r0.disabledColor = r4
            int r4 = com.google.android.material.C0105R.C0106color.mtrl_textinput_hovered_box_stroke_color
            int r4 = androidx.core.content.ContextCompat.getColor(r13, r4)
            r0.hoveredStrokeColor = r4
            if (r3 == 0) goto L_0x02c7
            r0.setBoxStrokeColorStateList(r3)
        L_0x02c7:
            int r4 = com.google.android.material.C0105R.styleable.TextInputLayout_boxStrokeErrorColor
            boolean r4 = r1.hasValue(r4)
            if (r4 == 0) goto L_0x02d8
            int r4 = com.google.android.material.C0105R.styleable.TextInputLayout_boxStrokeErrorColor
            android.content.res.ColorStateList r4 = com.google.android.material.resources.MaterialResources.getColorStateList((android.content.Context) r13, (androidx.appcompat.widget.TintTypedArray) r1, (int) r4)
            r0.setBoxStrokeErrorColor(r4)
        L_0x02d8:
            int r4 = com.google.android.material.C0105R.styleable.TextInputLayout_hintTextAppearance
            r5 = -1
            int r4 = r1.getResourceId(r4, r5)
            if (r4 == r5) goto L_0x02ec
            int r5 = com.google.android.material.C0105R.styleable.TextInputLayout_hintTextAppearance
            r15 = 0
            int r5 = r1.getResourceId(r5, r15)
            r0.setHintTextAppearance(r5)
            goto L_0x02ed
        L_0x02ec:
            r15 = 0
        L_0x02ed:
            int r5 = com.google.android.material.C0105R.styleable.TextInputLayout_errorTextAppearance
            int r5 = r1.getResourceId(r5, r15)
            int r15 = com.google.android.material.C0105R.styleable.TextInputLayout_errorContentDescription
            java.lang.CharSequence r15 = r1.getText(r15)
            r26 = r3
            int r3 = com.google.android.material.C0105R.styleable.TextInputLayout_errorEnabled
            r27 = r4
            r4 = 0
            boolean r3 = r1.getBoolean(r3, r4)
            int r4 = com.google.android.material.C0105R.C0108id.text_input_error_icon
            r11.setId(r4)
            boolean r4 = com.google.android.material.resources.MaterialResources.isFontScaleAtLeast1_3(r13)
            if (r4 == 0) goto L_0x031d
            android.view.ViewGroup$LayoutParams r4 = r11.getLayoutParams()
            android.view.ViewGroup$MarginLayoutParams r4 = (android.view.ViewGroup.MarginLayoutParams) r4
            r28 = r6
            r6 = 0
            androidx.core.view.MarginLayoutParamsCompat.setMarginStart(r4, r6)
            goto L_0x031f
        L_0x031d:
            r28 = r6
        L_0x031f:
            int r4 = com.google.android.material.C0105R.styleable.TextInputLayout_errorIconTint
            boolean r4 = r1.hasValue(r4)
            if (r4 == 0) goto L_0x032f
            int r4 = com.google.android.material.C0105R.styleable.TextInputLayout_errorIconTint
            android.content.res.ColorStateList r4 = com.google.android.material.resources.MaterialResources.getColorStateList((android.content.Context) r13, (androidx.appcompat.widget.TintTypedArray) r1, (int) r4)
            r0.errorIconTintList = r4
        L_0x032f:
            int r4 = com.google.android.material.C0105R.styleable.TextInputLayout_errorIconTintMode
            boolean r4 = r1.hasValue(r4)
            if (r4 == 0) goto L_0x0345
            int r4 = com.google.android.material.C0105R.styleable.TextInputLayout_errorIconTintMode
            r6 = -1
            int r4 = r1.getInt(r4, r6)
            r6 = 0
            android.graphics.PorterDuff$Mode r4 = com.google.android.material.internal.ViewUtils.parseTintMode(r4, r6)
            r0.errorIconTintMode = r4
        L_0x0345:
            int r4 = com.google.android.material.C0105R.styleable.TextInputLayout_errorIconDrawable
            boolean r4 = r1.hasValue(r4)
            if (r4 == 0) goto L_0x0356
            int r4 = com.google.android.material.C0105R.styleable.TextInputLayout_errorIconDrawable
            android.graphics.drawable.Drawable r4 = r1.getDrawable(r4)
            r0.setErrorIconDrawable((android.graphics.drawable.Drawable) r4)
        L_0x0356:
            android.content.res.Resources r4 = r37.getResources()
            int r6 = com.google.android.material.C0105R.string.error_icon_content_description
            java.lang.CharSequence r4 = r4.getText(r6)
            r11.setContentDescription(r4)
            r4 = 2
            androidx.core.view.ViewCompat.setImportantForAccessibility(r11, r4)
            r4 = 0
            r11.setClickable(r4)
            r11.setPressable(r4)
            r11.setFocusable(r4)
            int r6 = com.google.android.material.C0105R.styleable.TextInputLayout_helperTextTextAppearance
            int r6 = r1.getResourceId(r6, r4)
            int r7 = com.google.android.material.C0105R.styleable.TextInputLayout_helperTextEnabled
            boolean r7 = r1.getBoolean(r7, r4)
            int r4 = com.google.android.material.C0105R.styleable.TextInputLayout_helperText
            java.lang.CharSequence r4 = r1.getText(r4)
            int r8 = com.google.android.material.C0105R.styleable.TextInputLayout_placeholderTextAppearance
            r29 = r9
            r9 = 0
            int r8 = r1.getResourceId(r8, r9)
            int r9 = com.google.android.material.C0105R.styleable.TextInputLayout_placeholderText
            java.lang.CharSequence r9 = r1.getText(r9)
            r30 = r14
            int r14 = com.google.android.material.C0105R.styleable.TextInputLayout_suffixTextAppearance
            r31 = r4
            r4 = 0
            int r14 = r1.getResourceId(r14, r4)
            int r4 = com.google.android.material.C0105R.styleable.TextInputLayout_suffixText
            java.lang.CharSequence r4 = r1.getText(r4)
            r32 = r4
            int r4 = com.google.android.material.C0105R.styleable.TextInputLayout_counterEnabled
            r33 = r3
            r3 = 0
            boolean r4 = r1.getBoolean(r4, r3)
            int r3 = com.google.android.material.C0105R.styleable.TextInputLayout_counterMaxLength
            r34 = r4
            r4 = -1
            int r3 = r1.getInt(r3, r4)
            r0.setCounterMaxLength(r3)
            int r3 = com.google.android.material.C0105R.styleable.TextInputLayout_counterTextAppearance
            r4 = 0
            int r3 = r1.getResourceId(r3, r4)
            r0.counterTextAppearance = r3
            int r3 = com.google.android.material.C0105R.styleable.TextInputLayout_counterOverflowTextAppearance
            int r3 = r1.getResourceId(r3, r4)
            r0.counterOverflowTextAppearance = r3
            int r3 = com.google.android.material.C0105R.styleable.TextInputLayout_boxBackgroundMode
            int r3 = r1.getInt(r3, r4)
            r0.setBoxBackgroundMode(r3)
            boolean r3 = com.google.android.material.resources.MaterialResources.isFontScaleAtLeast1_3(r13)
            if (r3 == 0) goto L_0x03e5
            android.view.ViewGroup$LayoutParams r3 = r10.getLayoutParams()
            android.view.ViewGroup$MarginLayoutParams r3 = (android.view.ViewGroup.MarginLayoutParams) r3
            androidx.core.view.MarginLayoutParamsCompat.setMarginStart(r3, r4)
        L_0x03e5:
            int r3 = com.google.android.material.C0105R.styleable.TextInputLayout_endIconDrawable
            int r3 = r1.getResourceId(r3, r4)
            com.google.android.material.textfield.CustomEndIconDelegate r4 = new com.google.android.material.textfield.CustomEndIconDelegate
            r4.<init>(r0, r3)
            r35 = r7
            r7 = -1
            r12.append(r7, r4)
            com.google.android.material.textfield.NoEndIconDelegate r4 = new com.google.android.material.textfield.NoEndIconDelegate
            r4.<init>(r0)
            r7 = 0
            r12.append(r7, r4)
            com.google.android.material.textfield.PasswordToggleEndIconDelegate r4 = new com.google.android.material.textfield.PasswordToggleEndIconDelegate
            if (r3 != 0) goto L_0x040c
            r36 = r2
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_passwordToggleDrawable
            int r2 = r1.getResourceId(r2, r7)
            goto L_0x040f
        L_0x040c:
            r36 = r2
            r2 = r3
        L_0x040f:
            r4.<init>(r0, r2)
            r2 = 1
            r12.append(r2, r4)
            com.google.android.material.textfield.ClearTextEndIconDelegate r2 = new com.google.android.material.textfield.ClearTextEndIconDelegate
            r2.<init>(r0, r3)
            r4 = 2
            r12.append(r4, r2)
            com.google.android.material.textfield.DropdownMenuEndIconDelegate r2 = new com.google.android.material.textfield.DropdownMenuEndIconDelegate
            r2.<init>(r0, r3)
            r4 = 3
            r12.append(r4, r2)
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_passwordToggleEnabled
            boolean r2 = r1.hasValue(r2)
            if (r2 != 0) goto L_0x0456
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_endIconTint
            boolean r2 = r1.hasValue(r2)
            if (r2 == 0) goto L_0x0440
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_endIconTint
            android.content.res.ColorStateList r2 = com.google.android.material.resources.MaterialResources.getColorStateList((android.content.Context) r13, (androidx.appcompat.widget.TintTypedArray) r1, (int) r2)
            r0.endIconTintList = r2
        L_0x0440:
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_endIconTintMode
            boolean r2 = r1.hasValue(r2)
            if (r2 == 0) goto L_0x0456
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_endIconTintMode
            r4 = -1
            int r2 = r1.getInt(r2, r4)
            r4 = 0
            android.graphics.PorterDuff$Mode r2 = com.google.android.material.internal.ViewUtils.parseTintMode(r2, r4)
            r0.endIconTintMode = r2
        L_0x0456:
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_endIconMode
            boolean r2 = r1.hasValue(r2)
            if (r2 == 0) goto L_0x0484
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_endIconMode
            r4 = 0
            int r2 = r1.getInt(r2, r4)
            r0.setEndIconMode(r2)
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_endIconContentDescription
            boolean r2 = r1.hasValue(r2)
            if (r2 == 0) goto L_0x0479
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_endIconContentDescription
            java.lang.CharSequence r2 = r1.getText(r2)
            r0.setEndIconContentDescription((java.lang.CharSequence) r2)
        L_0x0479:
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_endIconCheckable
            r4 = 1
            boolean r2 = r1.getBoolean(r2, r4)
            r0.setEndIconCheckable(r2)
            goto L_0x04c5
        L_0x0484:
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_passwordToggleEnabled
            boolean r2 = r1.hasValue(r2)
            if (r2 == 0) goto L_0x04c5
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_passwordToggleTint
            boolean r2 = r1.hasValue(r2)
            if (r2 == 0) goto L_0x049c
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_passwordToggleTint
            android.content.res.ColorStateList r2 = com.google.android.material.resources.MaterialResources.getColorStateList((android.content.Context) r13, (androidx.appcompat.widget.TintTypedArray) r1, (int) r2)
            r0.endIconTintList = r2
        L_0x049c:
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_passwordToggleTintMode
            boolean r2 = r1.hasValue(r2)
            if (r2 == 0) goto L_0x04b2
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_passwordToggleTintMode
            r4 = -1
            int r2 = r1.getInt(r2, r4)
            r4 = 0
            android.graphics.PorterDuff$Mode r2 = com.google.android.material.internal.ViewUtils.parseTintMode(r2, r4)
            r0.endIconTintMode = r2
        L_0x04b2:
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_passwordToggleEnabled
            r4 = 0
            boolean r2 = r1.getBoolean(r2, r4)
            r0.setEndIconMode(r2)
            int r4 = com.google.android.material.C0105R.styleable.TextInputLayout_passwordToggleContentDescription
            java.lang.CharSequence r4 = r1.getText(r4)
            r0.setEndIconContentDescription((java.lang.CharSequence) r4)
        L_0x04c5:
            int r2 = com.google.android.material.C0105R.C0108id.textinput_suffix_text
            r4 = r19
            r4.setId(r2)
            android.widget.FrameLayout$LayoutParams r2 = new android.widget.FrameLayout$LayoutParams
            r7 = 80
            r12 = -2
            r2.<init>(r12, r12, r7)
            r4.setLayoutParams(r2)
            r2 = 1
            androidx.core.view.ViewCompat.setAccessibilityLiveRegion(r4, r2)
            r0.setErrorContentDescription(r15)
            int r2 = r0.counterOverflowTextAppearance
            r0.setCounterOverflowTextAppearance(r2)
            r0.setHelperTextTextAppearance(r6)
            r0.setErrorTextAppearance(r5)
            int r2 = r0.counterTextAppearance
            r0.setCounterTextAppearance(r2)
            r0.setPlaceholderText(r9)
            r0.setPlaceholderTextAppearance(r8)
            r0.setSuffixTextAppearance(r14)
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_errorTextColor
            boolean r2 = r1.hasValue(r2)
            if (r2 == 0) goto L_0x0508
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_errorTextColor
            android.content.res.ColorStateList r2 = r1.getColorStateList(r2)
            r0.setErrorTextColor(r2)
        L_0x0508:
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_helperTextTextColor
            boolean r2 = r1.hasValue(r2)
            if (r2 == 0) goto L_0x0519
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_helperTextTextColor
            android.content.res.ColorStateList r2 = r1.getColorStateList(r2)
            r0.setHelperTextColor(r2)
        L_0x0519:
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_hintTextColor
            boolean r2 = r1.hasValue(r2)
            if (r2 == 0) goto L_0x052a
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_hintTextColor
            android.content.res.ColorStateList r2 = r1.getColorStateList(r2)
            r0.setHintTextColor(r2)
        L_0x052a:
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_counterTextColor
            boolean r2 = r1.hasValue(r2)
            if (r2 == 0) goto L_0x053b
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_counterTextColor
            android.content.res.ColorStateList r2 = r1.getColorStateList(r2)
            r0.setCounterTextColor(r2)
        L_0x053b:
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_counterOverflowTextColor
            boolean r2 = r1.hasValue(r2)
            if (r2 == 0) goto L_0x054c
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_counterOverflowTextColor
            android.content.res.ColorStateList r2 = r1.getColorStateList(r2)
            r0.setCounterOverflowTextColor(r2)
        L_0x054c:
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_placeholderTextColor
            boolean r2 = r1.hasValue(r2)
            if (r2 == 0) goto L_0x055d
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_placeholderTextColor
            android.content.res.ColorStateList r2 = r1.getColorStateList(r2)
            r0.setPlaceholderTextColor(r2)
        L_0x055d:
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_suffixTextColor
            boolean r2 = r1.hasValue(r2)
            if (r2 == 0) goto L_0x056e
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_suffixTextColor
            android.content.res.ColorStateList r2 = r1.getColorStateList(r2)
            r0.setSuffixTextColor(r2)
        L_0x056e:
            int r2 = com.google.android.material.C0105R.styleable.TextInputLayout_android_enabled
            r7 = 1
            boolean r2 = r1.getBoolean(r2, r7)
            r0.setEnabled(r2)
            r1.recycle()
            r2 = 2
            androidx.core.view.ViewCompat.setImportantForAccessibility(r0, r2)
            int r2 = android.os.Build.VERSION.SDK_INT
            r12 = 26
            if (r2 < r12) goto L_0x0588
            androidx.core.view.ViewCompat.setImportantForAutofill(r0, r7)
        L_0x0588:
            r2 = r21
            r2.addView(r10)
            r7 = r20
            r7.addView(r4)
            r7.addView(r11)
            r7.addView(r2)
            r2 = r16
            r4 = r36
            r2.addView(r4)
            r2.addView(r7)
            r0.addView(r2)
            r2 = r35
            r0.setHelperTextEnabled(r2)
            r4 = r33
            r0.setErrorEnabled(r4)
            r7 = r34
            r0.setCounterEnabled(r7)
            r10 = r31
            r0.setHelperText(r10)
            r11 = r32
            r0.setSuffixText(r11)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.textfield.TextInputLayout.<init>(android.content.Context, android.util.AttributeSet, int):void");
    }

    public void addView(View child, int index, ViewGroup.LayoutParams params) {
        if (child instanceof EditText) {
            FrameLayout.LayoutParams flp = new FrameLayout.LayoutParams(params);
            flp.gravity = (flp.gravity & -113) | 16;
            this.inputFrame.addView(child, flp);
            this.inputFrame.setLayoutParams(params);
            updateInputLayoutMargins();
            setEditText((EditText) child);
            return;
        }
        super.addView(child, index, params);
    }

    /* access modifiers changed from: package-private */
    public MaterialShapeDrawable getBoxBackground() {
        int i = this.boxBackgroundMode;
        if (i == 1 || i == 2) {
            return this.boxBackground;
        }
        throw new IllegalStateException();
    }

    public void setBoxBackgroundMode(int boxBackgroundMode2) {
        if (boxBackgroundMode2 != this.boxBackgroundMode) {
            this.boxBackgroundMode = boxBackgroundMode2;
            if (this.editText != null) {
                onApplyBoxBackgroundMode();
            }
        }
    }

    public int getBoxBackgroundMode() {
        return this.boxBackgroundMode;
    }

    private void onApplyBoxBackgroundMode() {
        assignBoxBackgroundByMode();
        setEditTextBoxBackground();
        updateTextInputBoxState();
        updateBoxCollapsedPaddingTop();
        adjustFilledEditTextPaddingForLargeFont();
        if (this.boxBackgroundMode != 0) {
            updateInputLayoutMargins();
        }
    }

    private void assignBoxBackgroundByMode() {
        switch (this.boxBackgroundMode) {
            case 0:
                this.boxBackground = null;
                this.boxUnderlineDefault = null;
                this.boxUnderlineFocused = null;
                return;
            case 1:
                this.boxBackground = new MaterialShapeDrawable(this.shapeAppearanceModel);
                this.boxUnderlineDefault = new MaterialShapeDrawable();
                this.boxUnderlineFocused = new MaterialShapeDrawable();
                return;
            case 2:
                if (!this.hintEnabled || (this.boxBackground instanceof CutoutDrawable)) {
                    this.boxBackground = new MaterialShapeDrawable(this.shapeAppearanceModel);
                } else {
                    this.boxBackground = new CutoutDrawable(this.shapeAppearanceModel);
                }
                this.boxUnderlineDefault = null;
                this.boxUnderlineFocused = null;
                return;
            default:
                throw new IllegalArgumentException(this.boxBackgroundMode + " is illegal; only @BoxBackgroundMode constants are supported.");
        }
    }

    private void setEditTextBoxBackground() {
        if (shouldUseEditTextBackgroundForBoxBackground()) {
            ViewCompat.setBackground(this.editText, this.boxBackground);
        }
    }

    private boolean shouldUseEditTextBackgroundForBoxBackground() {
        EditText editText2 = this.editText;
        return (editText2 == null || this.boxBackground == null || editText2.getBackground() != null || this.boxBackgroundMode == 0) ? false : true;
    }

    private void updateBoxCollapsedPaddingTop() {
        if (this.boxBackgroundMode != 1) {
            return;
        }
        if (MaterialResources.isFontScaleAtLeast2_0(getContext())) {
            this.boxCollapsedPaddingTopPx = getResources().getDimensionPixelSize(C0105R.dimen.material_font_2_0_box_collapsed_padding_top);
        } else if (MaterialResources.isFontScaleAtLeast1_3(getContext())) {
            this.boxCollapsedPaddingTopPx = getResources().getDimensionPixelSize(C0105R.dimen.material_font_1_3_box_collapsed_padding_top);
        }
    }

    private void adjustFilledEditTextPaddingForLargeFont() {
        if (this.editText != null && this.boxBackgroundMode == 1) {
            if (MaterialResources.isFontScaleAtLeast2_0(getContext())) {
                EditText editText2 = this.editText;
                ViewCompat.setPaddingRelative(editText2, ViewCompat.getPaddingStart(editText2), getResources().getDimensionPixelSize(C0105R.dimen.material_filled_edittext_font_2_0_padding_top), ViewCompat.getPaddingEnd(this.editText), getResources().getDimensionPixelSize(C0105R.dimen.material_filled_edittext_font_2_0_padding_bottom));
            } else if (MaterialResources.isFontScaleAtLeast1_3(getContext())) {
                EditText editText3 = this.editText;
                ViewCompat.setPaddingRelative(editText3, ViewCompat.getPaddingStart(editText3), getResources().getDimensionPixelSize(C0105R.dimen.material_filled_edittext_font_1_3_padding_top), ViewCompat.getPaddingEnd(this.editText), getResources().getDimensionPixelSize(C0105R.dimen.material_filled_edittext_font_1_3_padding_bottom));
            }
        }
    }

    public void setBoxCollapsedPaddingTop(int boxCollapsedPaddingTop) {
        this.boxCollapsedPaddingTopPx = boxCollapsedPaddingTop;
    }

    public int getBoxCollapsedPaddingTop() {
        return this.boxCollapsedPaddingTopPx;
    }

    public void setBoxStrokeWidthResource(int boxStrokeWidthResId) {
        setBoxStrokeWidth(getResources().getDimensionPixelSize(boxStrokeWidthResId));
    }

    public void setBoxStrokeWidth(int boxStrokeWidth) {
        this.boxStrokeWidthDefaultPx = boxStrokeWidth;
        updateTextInputBoxState();
    }

    public int getBoxStrokeWidth() {
        return this.boxStrokeWidthDefaultPx;
    }

    public void setBoxStrokeWidthFocusedResource(int boxStrokeWidthFocusedResId) {
        setBoxStrokeWidthFocused(getResources().getDimensionPixelSize(boxStrokeWidthFocusedResId));
    }

    public void setBoxStrokeWidthFocused(int boxStrokeWidthFocused) {
        this.boxStrokeWidthFocusedPx = boxStrokeWidthFocused;
        updateTextInputBoxState();
    }

    public int getBoxStrokeWidthFocused() {
        return this.boxStrokeWidthFocusedPx;
    }

    public void setBoxStrokeColor(int boxStrokeColor2) {
        if (this.focusedStrokeColor != boxStrokeColor2) {
            this.focusedStrokeColor = boxStrokeColor2;
            updateTextInputBoxState();
        }
    }

    public int getBoxStrokeColor() {
        return this.focusedStrokeColor;
    }

    public void setBoxStrokeColorStateList(ColorStateList boxStrokeColorStateList) {
        if (boxStrokeColorStateList.isStateful()) {
            this.defaultStrokeColor = boxStrokeColorStateList.getDefaultColor();
            this.disabledColor = boxStrokeColorStateList.getColorForState(new int[]{-16842910}, -1);
            this.hoveredStrokeColor = boxStrokeColorStateList.getColorForState(new int[]{16843623, 16842910}, -1);
            this.focusedStrokeColor = boxStrokeColorStateList.getColorForState(new int[]{16842908, 16842910}, -1);
        } else if (this.focusedStrokeColor != boxStrokeColorStateList.getDefaultColor()) {
            this.focusedStrokeColor = boxStrokeColorStateList.getDefaultColor();
        }
        updateTextInputBoxState();
    }

    public void setBoxStrokeErrorColor(ColorStateList strokeErrorColor2) {
        if (this.strokeErrorColor != strokeErrorColor2) {
            this.strokeErrorColor = strokeErrorColor2;
            updateTextInputBoxState();
        }
    }

    public ColorStateList getBoxStrokeErrorColor() {
        return this.strokeErrorColor;
    }

    public void setBoxBackgroundColorResource(int boxBackgroundColorId) {
        setBoxBackgroundColor(ContextCompat.getColor(getContext(), boxBackgroundColorId));
    }

    public void setBoxBackgroundColor(int boxBackgroundColor2) {
        if (this.boxBackgroundColor != boxBackgroundColor2) {
            this.boxBackgroundColor = boxBackgroundColor2;
            this.defaultFilledBackgroundColor = boxBackgroundColor2;
            this.focusedFilledBackgroundColor = boxBackgroundColor2;
            this.hoveredFilledBackgroundColor = boxBackgroundColor2;
            applyBoxAttributes();
        }
    }

    public void setBoxBackgroundColorStateList(ColorStateList boxBackgroundColorStateList) {
        int defaultColor = boxBackgroundColorStateList.getDefaultColor();
        this.defaultFilledBackgroundColor = defaultColor;
        this.boxBackgroundColor = defaultColor;
        this.disabledFilledBackgroundColor = boxBackgroundColorStateList.getColorForState(new int[]{-16842910}, -1);
        this.focusedFilledBackgroundColor = boxBackgroundColorStateList.getColorForState(new int[]{16842908, 16842910}, -1);
        this.hoveredFilledBackgroundColor = boxBackgroundColorStateList.getColorForState(new int[]{16843623, 16842910}, -1);
        applyBoxAttributes();
    }

    public int getBoxBackgroundColor() {
        return this.boxBackgroundColor;
    }

    public void setBoxCornerRadiiResources(int boxCornerRadiusTopStartId, int boxCornerRadiusTopEndId, int boxCornerRadiusBottomEndId, int boxCornerRadiusBottomStartId) {
        setBoxCornerRadii(getContext().getResources().getDimension(boxCornerRadiusTopStartId), getContext().getResources().getDimension(boxCornerRadiusTopEndId), getContext().getResources().getDimension(boxCornerRadiusBottomStartId), getContext().getResources().getDimension(boxCornerRadiusBottomEndId));
    }

    public void setBoxCornerRadii(float boxCornerRadiusTopStart, float boxCornerRadiusTopEnd, float boxCornerRadiusBottomStart, float boxCornerRadiusBottomEnd) {
        boolean isLayoutRtl = ViewUtils.isLayoutRtl(this);
        this.areCornerRadiiRtl = isLayoutRtl;
        float boxCornerRadiusTopLeft = isLayoutRtl ? boxCornerRadiusTopEnd : boxCornerRadiusTopStart;
        float boxCornerRadiusTopRight = isLayoutRtl ? boxCornerRadiusTopStart : boxCornerRadiusTopEnd;
        float boxCornerRadiusBottomLeft = isLayoutRtl ? boxCornerRadiusBottomEnd : boxCornerRadiusBottomStart;
        float boxCornerRadiusBottomRight = isLayoutRtl ? boxCornerRadiusBottomStart : boxCornerRadiusBottomEnd;
        MaterialShapeDrawable materialShapeDrawable = this.boxBackground;
        if (materialShapeDrawable == null || materialShapeDrawable.getTopLeftCornerResolvedSize() != boxCornerRadiusTopLeft || this.boxBackground.getTopRightCornerResolvedSize() != boxCornerRadiusTopRight || this.boxBackground.getBottomLeftCornerResolvedSize() != boxCornerRadiusBottomLeft || this.boxBackground.getBottomRightCornerResolvedSize() != boxCornerRadiusBottomRight) {
            this.shapeAppearanceModel = this.shapeAppearanceModel.toBuilder().setTopLeftCornerSize(boxCornerRadiusTopLeft).setTopRightCornerSize(boxCornerRadiusTopRight).setBottomLeftCornerSize(boxCornerRadiusBottomLeft).setBottomRightCornerSize(boxCornerRadiusBottomRight).build();
            applyBoxAttributes();
        }
    }

    public float getBoxCornerRadiusTopStart() {
        if (ViewUtils.isLayoutRtl(this)) {
            return this.shapeAppearanceModel.getTopRightCornerSize().getCornerSize(this.tmpRectF);
        }
        return this.shapeAppearanceModel.getTopLeftCornerSize().getCornerSize(this.tmpRectF);
    }

    public float getBoxCornerRadiusTopEnd() {
        if (ViewUtils.isLayoutRtl(this)) {
            return this.shapeAppearanceModel.getTopLeftCornerSize().getCornerSize(this.tmpRectF);
        }
        return this.shapeAppearanceModel.getTopRightCornerSize().getCornerSize(this.tmpRectF);
    }

    public float getBoxCornerRadiusBottomEnd() {
        if (ViewUtils.isLayoutRtl(this)) {
            return this.shapeAppearanceModel.getBottomLeftCornerSize().getCornerSize(this.tmpRectF);
        }
        return this.shapeAppearanceModel.getBottomRightCornerSize().getCornerSize(this.tmpRectF);
    }

    public float getBoxCornerRadiusBottomStart() {
        if (ViewUtils.isLayoutRtl(this)) {
            return this.shapeAppearanceModel.getBottomRightCornerSize().getCornerSize(this.tmpRectF);
        }
        return this.shapeAppearanceModel.getBottomLeftCornerSize().getCornerSize(this.tmpRectF);
    }

    public void setTypeface(Typeface typeface2) {
        if (typeface2 != this.typeface) {
            this.typeface = typeface2;
            this.collapsingTextHelper.setTypefaces(typeface2);
            this.indicatorViewController.setTypefaces(typeface2);
            TextView textView = this.counterView;
            if (textView != null) {
                textView.setTypeface(typeface2);
            }
        }
    }

    public Typeface getTypeface() {
        return this.typeface;
    }

    public void dispatchProvideAutofillStructure(ViewStructure structure, int flags) {
        EditText editText2 = this.editText;
        if (editText2 == null) {
            super.dispatchProvideAutofillStructure(structure, flags);
        } else if (this.originalHint != null) {
            boolean wasProvidingHint = this.isProvidingHint;
            this.isProvidingHint = false;
            CharSequence hint2 = editText2.getHint();
            this.editText.setHint(this.originalHint);
            try {
                super.dispatchProvideAutofillStructure(structure, flags);
            } finally {
                this.editText.setHint(hint2);
                this.isProvidingHint = wasProvidingHint;
            }
        } else {
            structure.setAutofillId(getAutofillId());
            onProvideAutofillStructure(structure, flags);
            onProvideAutofillVirtualStructure(structure, flags);
            structure.setChildCount(this.inputFrame.getChildCount());
            for (int i = 0; i < this.inputFrame.getChildCount(); i++) {
                View child = this.inputFrame.getChildAt(i);
                ViewStructure childStructure = structure.newChild(i);
                child.dispatchProvideAutofillStructure(childStructure, flags);
                if (child == this.editText) {
                    childStructure.setHint(getHint());
                }
            }
        }
    }

    private void setEditText(EditText editText2) {
        if (this.editText == null) {
            if (this.endIconMode != 3 && !(editText2 instanceof TextInputEditText)) {
                Log.i(LOG_TAG, "EditText added is not a TextInputEditText. Please switch to using that class instead.");
            }
            this.editText = editText2;
            int i = this.minEms;
            if (i != -1) {
                setMinEms(i);
            } else {
                setMinWidth(this.minWidth);
            }
            int i2 = this.maxEms;
            if (i2 != -1) {
                setMaxEms(i2);
            } else {
                setMaxWidth(this.maxWidth);
            }
            onApplyBoxBackgroundMode();
            setTextInputAccessibilityDelegate(new AccessibilityDelegate(this));
            this.collapsingTextHelper.setTypefaces(this.editText.getTypeface());
            this.collapsingTextHelper.setExpandedTextSize(this.editText.getTextSize());
            if (Build.VERSION.SDK_INT >= 21) {
                this.collapsingTextHelper.setExpandedLetterSpacing(this.editText.getLetterSpacing());
            }
            int editTextGravity = this.editText.getGravity();
            this.collapsingTextHelper.setCollapsedTextGravity((editTextGravity & -113) | 48);
            this.collapsingTextHelper.setExpandedTextGravity(editTextGravity);
            this.editText.addTextChangedListener(new TextWatcher() {
                public void afterTextChanged(Editable s) {
                    TextInputLayout textInputLayout = TextInputLayout.this;
                    textInputLayout.updateLabelState(!textInputLayout.restoringSavedState);
                    if (TextInputLayout.this.counterEnabled) {
                        TextInputLayout.this.updateCounter(s.length());
                    }
                    if (TextInputLayout.this.placeholderEnabled) {
                        TextInputLayout.this.updatePlaceholderText(s.length());
                    }
                }

                public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                }

                public void onTextChanged(CharSequence s, int start, int before, int count) {
                }
            });
            if (this.defaultHintTextColor == null) {
                this.defaultHintTextColor = this.editText.getHintTextColors();
            }
            if (this.hintEnabled) {
                if (TextUtils.isEmpty(this.hint)) {
                    CharSequence hint2 = this.editText.getHint();
                    this.originalHint = hint2;
                    setHint(hint2);
                    this.editText.setHint((CharSequence) null);
                }
                this.isProvidingHint = true;
            }
            if (this.counterView != null) {
                updateCounter(this.editText.getText().length());
            }
            updateEditTextBackground();
            this.indicatorViewController.adjustIndicatorPadding();
            this.startLayout.bringToFront();
            this.endLayout.bringToFront();
            this.endIconFrame.bringToFront();
            this.errorIconView.bringToFront();
            dispatchOnEditTextAttached();
            updateSuffixTextViewPadding();
            if (!isEnabled()) {
                editText2.setEnabled(false);
            }
            updateLabelState(false, true);
            return;
        }
        throw new IllegalArgumentException("We already have an EditText, can only have one");
    }

    private void updateInputLayoutMargins() {
        if (this.boxBackgroundMode != 1) {
            LinearLayout.LayoutParams lp = (LinearLayout.LayoutParams) this.inputFrame.getLayoutParams();
            int newTopMargin = calculateLabelMarginTop();
            if (newTopMargin != lp.topMargin) {
                lp.topMargin = newTopMargin;
                this.inputFrame.requestLayout();
            }
        }
    }

    public int getBaseline() {
        EditText editText2 = this.editText;
        if (editText2 != null) {
            return editText2.getBaseline() + getPaddingTop() + calculateLabelMarginTop();
        }
        return super.getBaseline();
    }

    /* access modifiers changed from: package-private */
    public void updateLabelState(boolean animate) {
        updateLabelState(animate, false);
    }

    private void updateLabelState(boolean animate, boolean force) {
        ColorStateList colorStateList;
        TextView textView;
        int disabledHintColor;
        boolean isEnabled = isEnabled();
        EditText editText2 = this.editText;
        boolean hasText = editText2 != null && !TextUtils.isEmpty(editText2.getText());
        EditText editText3 = this.editText;
        boolean hasFocus = editText3 != null && editText3.hasFocus();
        boolean errorShouldBeShown = this.indicatorViewController.errorShouldBeShown();
        ColorStateList colorStateList2 = this.defaultHintTextColor;
        if (colorStateList2 != null) {
            this.collapsingTextHelper.setCollapsedTextColor(colorStateList2);
            this.collapsingTextHelper.setExpandedTextColor(this.defaultHintTextColor);
        }
        if (!isEnabled) {
            ColorStateList colorStateList3 = this.defaultHintTextColor;
            if (colorStateList3 != null) {
                disabledHintColor = colorStateList3.getColorForState(new int[]{-16842910}, this.disabledColor);
            } else {
                disabledHintColor = this.disabledColor;
            }
            this.collapsingTextHelper.setCollapsedTextColor(ColorStateList.valueOf(disabledHintColor));
            this.collapsingTextHelper.setExpandedTextColor(ColorStateList.valueOf(disabledHintColor));
        } else if (errorShouldBeShown) {
            this.collapsingTextHelper.setCollapsedTextColor(this.indicatorViewController.getErrorViewTextColors());
        } else if (this.counterOverflowed && (textView = this.counterView) != null) {
            this.collapsingTextHelper.setCollapsedTextColor(textView.getTextColors());
        } else if (hasFocus && (colorStateList = this.focusedTextColor) != null) {
            this.collapsingTextHelper.setCollapsedTextColor(colorStateList);
        }
        if (hasText || !this.expandedHintEnabled || (isEnabled() && hasFocus)) {
            if (force || this.hintExpanded) {
                collapseHint(animate);
            }
        } else if (force || !this.hintExpanded) {
            expandHint(animate);
        }
    }

    public EditText getEditText() {
        return this.editText;
    }

    public void setMinEms(int minEms2) {
        this.minEms = minEms2;
        EditText editText2 = this.editText;
        if (editText2 != null && minEms2 != -1) {
            editText2.setMinEms(minEms2);
        }
    }

    public int getMinEms() {
        return this.minEms;
    }

    public void setMaxEms(int maxEms2) {
        this.maxEms = maxEms2;
        EditText editText2 = this.editText;
        if (editText2 != null && maxEms2 != -1) {
            editText2.setMaxEms(maxEms2);
        }
    }

    public int getMaxEms() {
        return this.maxEms;
    }

    public void setMinWidth(int minWidth2) {
        this.minWidth = minWidth2;
        EditText editText2 = this.editText;
        if (editText2 != null && minWidth2 != -1) {
            editText2.setMinWidth(minWidth2);
        }
    }

    public void setMinWidthResource(int minWidthId) {
        setMinWidth(getContext().getResources().getDimensionPixelSize(minWidthId));
    }

    public int getMinWidth() {
        return this.minWidth;
    }

    public void setMaxWidth(int maxWidth2) {
        this.maxWidth = maxWidth2;
        EditText editText2 = this.editText;
        if (editText2 != null && maxWidth2 != -1) {
            editText2.setMaxWidth(maxWidth2);
        }
    }

    public void setMaxWidthResource(int maxWidthId) {
        setMaxWidth(getContext().getResources().getDimensionPixelSize(maxWidthId));
    }

    public int getMaxWidth() {
        return this.maxWidth;
    }

    public void setHint(CharSequence hint2) {
        if (this.hintEnabled) {
            setHintInternal(hint2);
            sendAccessibilityEvent(2048);
        }
    }

    public void setHint(int textHintId) {
        setHint(textHintId != 0 ? getResources().getText(textHintId) : null);
    }

    private void setHintInternal(CharSequence hint2) {
        if (!TextUtils.equals(hint2, this.hint)) {
            this.hint = hint2;
            this.collapsingTextHelper.setText(hint2);
            if (!this.hintExpanded) {
                openCutout();
            }
        }
    }

    public CharSequence getHint() {
        if (this.hintEnabled) {
            return this.hint;
        }
        return null;
    }

    public void setHintEnabled(boolean enabled) {
        if (enabled != this.hintEnabled) {
            this.hintEnabled = enabled;
            if (!enabled) {
                this.isProvidingHint = false;
                if (!TextUtils.isEmpty(this.hint) && TextUtils.isEmpty(this.editText.getHint())) {
                    this.editText.setHint(this.hint);
                }
                setHintInternal((CharSequence) null);
            } else {
                CharSequence editTextHint = this.editText.getHint();
                if (!TextUtils.isEmpty(editTextHint)) {
                    if (TextUtils.isEmpty(this.hint)) {
                        setHint(editTextHint);
                    }
                    this.editText.setHint((CharSequence) null);
                }
                this.isProvidingHint = true;
            }
            if (this.editText != null) {
                updateInputLayoutMargins();
            }
        }
    }

    public boolean isHintEnabled() {
        return this.hintEnabled;
    }

    public boolean isProvidingHint() {
        return this.isProvidingHint;
    }

    public void setHintTextAppearance(int resId) {
        this.collapsingTextHelper.setCollapsedTextAppearance(resId);
        this.focusedTextColor = this.collapsingTextHelper.getCollapsedTextColor();
        if (this.editText != null) {
            updateLabelState(false);
            updateInputLayoutMargins();
        }
    }

    public void setHintTextColor(ColorStateList hintTextColor) {
        if (this.focusedTextColor != hintTextColor) {
            if (this.defaultHintTextColor == null) {
                this.collapsingTextHelper.setCollapsedTextColor(hintTextColor);
            }
            this.focusedTextColor = hintTextColor;
            if (this.editText != null) {
                updateLabelState(false);
            }
        }
    }

    public ColorStateList getHintTextColor() {
        return this.focusedTextColor;
    }

    public void setDefaultHintTextColor(ColorStateList textColor) {
        this.defaultHintTextColor = textColor;
        this.focusedTextColor = textColor;
        if (this.editText != null) {
            updateLabelState(false);
        }
    }

    public ColorStateList getDefaultHintTextColor() {
        return this.defaultHintTextColor;
    }

    public void setErrorEnabled(boolean enabled) {
        this.indicatorViewController.setErrorEnabled(enabled);
    }

    public void setErrorTextAppearance(int errorTextAppearance) {
        this.indicatorViewController.setErrorTextAppearance(errorTextAppearance);
    }

    public void setErrorTextColor(ColorStateList errorTextColor) {
        this.indicatorViewController.setErrorViewTextColor(errorTextColor);
    }

    public int getErrorCurrentTextColors() {
        return this.indicatorViewController.getErrorViewCurrentTextColor();
    }

    public void setHelperTextTextAppearance(int helperTextTextAppearance) {
        this.indicatorViewController.setHelperTextAppearance(helperTextTextAppearance);
    }

    public void setHelperTextColor(ColorStateList helperTextColor) {
        this.indicatorViewController.setHelperTextViewTextColor(helperTextColor);
    }

    public boolean isErrorEnabled() {
        return this.indicatorViewController.isErrorEnabled();
    }

    public void setHelperTextEnabled(boolean enabled) {
        this.indicatorViewController.setHelperTextEnabled(enabled);
    }

    public void setHelperText(CharSequence helperText) {
        if (!TextUtils.isEmpty(helperText)) {
            if (!isHelperTextEnabled()) {
                setHelperTextEnabled(true);
            }
            this.indicatorViewController.showHelper(helperText);
        } else if (isHelperTextEnabled()) {
            setHelperTextEnabled(false);
        }
    }

    public boolean isHelperTextEnabled() {
        return this.indicatorViewController.isHelperTextEnabled();
    }

    public int getHelperTextCurrentTextColor() {
        return this.indicatorViewController.getHelperTextViewCurrentTextColor();
    }

    public void setErrorContentDescription(CharSequence errorContentDecription) {
        this.indicatorViewController.setErrorContentDescription(errorContentDecription);
    }

    public CharSequence getErrorContentDescription() {
        return this.indicatorViewController.getErrorContentDescription();
    }

    public void setError(CharSequence errorText) {
        if (!this.indicatorViewController.isErrorEnabled()) {
            if (!TextUtils.isEmpty(errorText)) {
                setErrorEnabled(true);
            } else {
                return;
            }
        }
        if (!TextUtils.isEmpty(errorText)) {
            this.indicatorViewController.showError(errorText);
        } else {
            this.indicatorViewController.hideError();
        }
    }

    public void setErrorIconDrawable(int resId) {
        setErrorIconDrawable(resId != 0 ? AppCompatResources.getDrawable(getContext(), resId) : null);
        refreshErrorIconDrawableState();
    }

    public void setErrorIconDrawable(Drawable errorIconDrawable) {
        this.errorIconView.setImageDrawable(errorIconDrawable);
        updateErrorIconVisibility();
        IconHelper.applyIconTint(this, this.errorIconView, this.errorIconTintList, this.errorIconTintMode);
    }

    public Drawable getErrorIconDrawable() {
        return this.errorIconView.getDrawable();
    }

    public void setErrorIconTintList(ColorStateList errorIconTintList2) {
        if (this.errorIconTintList != errorIconTintList2) {
            this.errorIconTintList = errorIconTintList2;
            IconHelper.applyIconTint(this, this.errorIconView, errorIconTintList2, this.errorIconTintMode);
        }
    }

    public void setErrorIconTintMode(PorterDuff.Mode errorIconTintMode2) {
        if (this.errorIconTintMode != errorIconTintMode2) {
            this.errorIconTintMode = errorIconTintMode2;
            IconHelper.applyIconTint(this, this.errorIconView, this.errorIconTintList, errorIconTintMode2);
        }
    }

    public void setCounterEnabled(boolean enabled) {
        if (this.counterEnabled != enabled) {
            if (enabled) {
                AppCompatTextView appCompatTextView = new AppCompatTextView(getContext());
                this.counterView = appCompatTextView;
                appCompatTextView.setId(C0105R.C0108id.textinput_counter);
                Typeface typeface2 = this.typeface;
                if (typeface2 != null) {
                    this.counterView.setTypeface(typeface2);
                }
                this.counterView.setMaxLines(1);
                this.indicatorViewController.addIndicator(this.counterView, 2);
                MarginLayoutParamsCompat.setMarginStart((ViewGroup.MarginLayoutParams) this.counterView.getLayoutParams(), getResources().getDimensionPixelOffset(C0105R.dimen.mtrl_textinput_counter_margin_start));
                updateCounterTextAppearanceAndColor();
                updateCounter();
            } else {
                this.indicatorViewController.removeIndicator(this.counterView, 2);
                this.counterView = null;
            }
            this.counterEnabled = enabled;
        }
    }

    public void setCounterTextAppearance(int counterTextAppearance2) {
        if (this.counterTextAppearance != counterTextAppearance2) {
            this.counterTextAppearance = counterTextAppearance2;
            updateCounterTextAppearanceAndColor();
        }
    }

    public void setCounterTextColor(ColorStateList counterTextColor2) {
        if (this.counterTextColor != counterTextColor2) {
            this.counterTextColor = counterTextColor2;
            updateCounterTextAppearanceAndColor();
        }
    }

    public ColorStateList getCounterTextColor() {
        return this.counterTextColor;
    }

    public void setCounterOverflowTextAppearance(int counterOverflowTextAppearance2) {
        if (this.counterOverflowTextAppearance != counterOverflowTextAppearance2) {
            this.counterOverflowTextAppearance = counterOverflowTextAppearance2;
            updateCounterTextAppearanceAndColor();
        }
    }

    public void setCounterOverflowTextColor(ColorStateList counterOverflowTextColor2) {
        if (this.counterOverflowTextColor != counterOverflowTextColor2) {
            this.counterOverflowTextColor = counterOverflowTextColor2;
            updateCounterTextAppearanceAndColor();
        }
    }

    public ColorStateList getCounterOverflowTextColor() {
        return this.counterTextColor;
    }

    public boolean isCounterEnabled() {
        return this.counterEnabled;
    }

    public void setCounterMaxLength(int maxLength) {
        if (this.counterMaxLength != maxLength) {
            if (maxLength > 0) {
                this.counterMaxLength = maxLength;
            } else {
                this.counterMaxLength = -1;
            }
            if (this.counterEnabled) {
                updateCounter();
            }
        }
    }

    private void updateCounter() {
        if (this.counterView != null) {
            EditText editText2 = this.editText;
            updateCounter(editText2 == null ? 0 : editText2.getText().length());
        }
    }

    /* access modifiers changed from: package-private */
    public void updateCounter(int length) {
        boolean wasCounterOverflowed = this.counterOverflowed;
        int i = this.counterMaxLength;
        if (i == -1) {
            this.counterView.setText(String.valueOf(length));
            this.counterView.setContentDescription((CharSequence) null);
            this.counterOverflowed = false;
        } else {
            this.counterOverflowed = length > i;
            updateCounterContentDescription(getContext(), this.counterView, length, this.counterMaxLength, this.counterOverflowed);
            if (wasCounterOverflowed != this.counterOverflowed) {
                updateCounterTextAppearanceAndColor();
            }
            this.counterView.setText(BidiFormatter.getInstance().unicodeWrap(getContext().getString(C0105R.string.character_counter_pattern, new Object[]{Integer.valueOf(length), Integer.valueOf(this.counterMaxLength)})));
        }
        if (this.editText != null && wasCounterOverflowed != this.counterOverflowed) {
            updateLabelState(false);
            updateTextInputBoxState();
            updateEditTextBackground();
        }
    }

    private static void updateCounterContentDescription(Context context, TextView counterView2, int length, int counterMaxLength2, boolean counterOverflowed2) {
        int i;
        if (counterOverflowed2) {
            i = C0105R.string.character_counter_overflowed_content_description;
        } else {
            i = C0105R.string.character_counter_content_description;
        }
        counterView2.setContentDescription(context.getString(i, new Object[]{Integer.valueOf(length), Integer.valueOf(counterMaxLength2)}));
    }

    public void setPlaceholderText(CharSequence placeholderText2) {
        if (this.placeholderTextView == null) {
            AppCompatTextView appCompatTextView = new AppCompatTextView(getContext());
            this.placeholderTextView = appCompatTextView;
            appCompatTextView.setId(C0105R.C0108id.textinput_placeholder);
            ViewCompat.setImportantForAccessibility(this.placeholderTextView, 2);
            Fade createPlaceholderFadeTransition = createPlaceholderFadeTransition();
            this.placeholderFadeIn = createPlaceholderFadeTransition;
            createPlaceholderFadeTransition.setStartDelay(PLACEHOLDER_START_DELAY);
            this.placeholderFadeOut = createPlaceholderFadeTransition();
            setPlaceholderTextAppearance(this.placeholderTextAppearance);
            setPlaceholderTextColor(this.placeholderTextColor);
        }
        if (TextUtils.isEmpty(placeholderText2)) {
            setPlaceholderTextEnabled(false);
        } else {
            if (!this.placeholderEnabled) {
                setPlaceholderTextEnabled(true);
            }
            this.placeholderText = placeholderText2;
        }
        updatePlaceholderText();
    }

    public CharSequence getPlaceholderText() {
        if (this.placeholderEnabled) {
            return this.placeholderText;
        }
        return null;
    }

    private void setPlaceholderTextEnabled(boolean placeholderEnabled2) {
        if (this.placeholderEnabled != placeholderEnabled2) {
            if (placeholderEnabled2) {
                addPlaceholderTextView();
            } else {
                removePlaceholderTextView();
                this.placeholderTextView = null;
            }
            this.placeholderEnabled = placeholderEnabled2;
        }
    }

    private Fade createPlaceholderFadeTransition() {
        Fade placeholderFadeTransition = new Fade();
        placeholderFadeTransition.setDuration(PLACEHOLDER_FADE_DURATION);
        placeholderFadeTransition.setInterpolator(AnimationUtils.LINEAR_INTERPOLATOR);
        return placeholderFadeTransition;
    }

    private void updatePlaceholderText() {
        EditText editText2 = this.editText;
        updatePlaceholderText(editText2 == null ? 0 : editText2.getText().length());
    }

    /* access modifiers changed from: private */
    public void updatePlaceholderText(int inputTextLength) {
        if (inputTextLength != 0 || this.hintExpanded) {
            hidePlaceholderText();
        } else {
            showPlaceholderText();
        }
    }

    private void showPlaceholderText() {
        if (this.placeholderTextView != null && this.placeholderEnabled && !TextUtils.isEmpty(this.placeholderText)) {
            this.placeholderTextView.setText(this.placeholderText);
            TransitionManager.beginDelayedTransition(this.inputFrame, this.placeholderFadeIn);
            this.placeholderTextView.setVisibility(0);
            this.placeholderTextView.bringToFront();
            if (Build.VERSION.SDK_INT >= 16) {
                announceForAccessibility(this.placeholderText);
            }
        }
    }

    private void hidePlaceholderText() {
        TextView textView = this.placeholderTextView;
        if (textView != null && this.placeholderEnabled) {
            textView.setText((CharSequence) null);
            TransitionManager.beginDelayedTransition(this.inputFrame, this.placeholderFadeOut);
            this.placeholderTextView.setVisibility(4);
        }
    }

    private void addPlaceholderTextView() {
        TextView textView = this.placeholderTextView;
        if (textView != null) {
            this.inputFrame.addView(textView);
            this.placeholderTextView.setVisibility(0);
        }
    }

    private void removePlaceholderTextView() {
        TextView textView = this.placeholderTextView;
        if (textView != null) {
            textView.setVisibility(8);
        }
    }

    public void setPlaceholderTextColor(ColorStateList placeholderTextColor2) {
        if (this.placeholderTextColor != placeholderTextColor2) {
            this.placeholderTextColor = placeholderTextColor2;
            TextView textView = this.placeholderTextView;
            if (textView != null && placeholderTextColor2 != null) {
                textView.setTextColor(placeholderTextColor2);
            }
        }
    }

    public ColorStateList getPlaceholderTextColor() {
        return this.placeholderTextColor;
    }

    public void setPlaceholderTextAppearance(int placeholderTextAppearance2) {
        this.placeholderTextAppearance = placeholderTextAppearance2;
        TextView textView = this.placeholderTextView;
        if (textView != null) {
            TextViewCompat.setTextAppearance(textView, placeholderTextAppearance2);
        }
    }

    public int getPlaceholderTextAppearance() {
        return this.placeholderTextAppearance;
    }

    public void setPrefixText(CharSequence prefixText) {
        this.startLayout.setPrefixText(prefixText);
    }

    public CharSequence getPrefixText() {
        return this.startLayout.getPrefixText();
    }

    public TextView getPrefixTextView() {
        return this.startLayout.getPrefixTextView();
    }

    public void setPrefixTextColor(ColorStateList prefixTextColor) {
        this.startLayout.setPrefixTextColor(prefixTextColor);
    }

    public ColorStateList getPrefixTextColor() {
        return this.startLayout.getPrefixTextColor();
    }

    public void setPrefixTextAppearance(int prefixTextAppearance) {
        this.startLayout.setPrefixTextAppearance(prefixTextAppearance);
    }

    public void setSuffixText(CharSequence suffixText2) {
        this.suffixText = TextUtils.isEmpty(suffixText2) ? null : suffixText2;
        this.suffixTextView.setText(suffixText2);
        updateSuffixTextVisibility();
    }

    public CharSequence getSuffixText() {
        return this.suffixText;
    }

    public TextView getSuffixTextView() {
        return this.suffixTextView;
    }

    private void updateSuffixTextVisibility() {
        int oldVisibility = this.suffixTextView.getVisibility();
        boolean z = false;
        int newVisibility = (this.suffixText == null || isHintExpanded()) ? 8 : 0;
        if (oldVisibility != newVisibility) {
            EndIconDelegate endIconDelegate = getEndIconDelegate();
            if (newVisibility == 0) {
                z = true;
            }
            endIconDelegate.onSuffixVisibilityChanged(z);
        }
        updateEndLayoutVisibility();
        this.suffixTextView.setVisibility(newVisibility);
        updateDummyDrawables();
    }

    public void setSuffixTextColor(ColorStateList suffixTextColor) {
        this.suffixTextView.setTextColor(suffixTextColor);
    }

    public ColorStateList getSuffixTextColor() {
        return this.suffixTextView.getTextColors();
    }

    public void setSuffixTextAppearance(int suffixTextAppearance) {
        TextViewCompat.setTextAppearance(this.suffixTextView, suffixTextAppearance);
    }

    private void updateSuffixTextViewPadding() {
        if (this.editText != null) {
            ViewCompat.setPaddingRelative(this.suffixTextView, getContext().getResources().getDimensionPixelSize(C0105R.dimen.material_input_text_to_prefix_suffix_padding), this.editText.getPaddingTop(), (isEndIconVisible() || isErrorIconVisible()) ? 0 : ViewCompat.getPaddingEnd(this.editText), this.editText.getPaddingBottom());
        }
    }

    public void setEnabled(boolean enabled) {
        recursiveSetEnabled(this, enabled);
        super.setEnabled(enabled);
    }

    private static void recursiveSetEnabled(ViewGroup vg, boolean enabled) {
        int count = vg.getChildCount();
        for (int i = 0; i < count; i++) {
            View child = vg.getChildAt(i);
            child.setEnabled(enabled);
            if (child instanceof ViewGroup) {
                recursiveSetEnabled((ViewGroup) child, enabled);
            }
        }
    }

    public int getCounterMaxLength() {
        return this.counterMaxLength;
    }

    /* access modifiers changed from: package-private */
    public CharSequence getCounterOverflowDescription() {
        TextView textView;
        if (!this.counterEnabled || !this.counterOverflowed || (textView = this.counterView) == null) {
            return null;
        }
        return textView.getContentDescription();
    }

    private void updateCounterTextAppearanceAndColor() {
        ColorStateList colorStateList;
        ColorStateList colorStateList2;
        TextView textView = this.counterView;
        if (textView != null) {
            setTextAppearanceCompatWithErrorFallback(textView, this.counterOverflowed ? this.counterOverflowTextAppearance : this.counterTextAppearance);
            if (!this.counterOverflowed && (colorStateList2 = this.counterTextColor) != null) {
                this.counterView.setTextColor(colorStateList2);
            }
            if (this.counterOverflowed && (colorStateList = this.counterOverflowTextColor) != null) {
                this.counterView.setTextColor(colorStateList);
            }
        }
    }

    /* access modifiers changed from: package-private */
    public void setTextAppearanceCompatWithErrorFallback(TextView textView, int textAppearance) {
        boolean useDefaultColor = false;
        try {
            TextViewCompat.setTextAppearance(textView, textAppearance);
            if (Build.VERSION.SDK_INT >= 23 && textView.getTextColors().getDefaultColor() == -65281) {
                useDefaultColor = true;
            }
        } catch (Exception e) {
            useDefaultColor = true;
        }
        if (useDefaultColor) {
            TextViewCompat.setTextAppearance(textView, C0105R.style.TextAppearance_AppCompat_Caption);
            textView.setTextColor(ContextCompat.getColor(getContext(), C0105R.C0106color.design_error));
        }
    }

    private int calculateLabelMarginTop() {
        if (!this.hintEnabled) {
            return 0;
        }
        switch (this.boxBackgroundMode) {
            case 0:
                return (int) this.collapsingTextHelper.getCollapsedTextHeight();
            case 2:
                return (int) (this.collapsingTextHelper.getCollapsedTextHeight() / 2.0f);
            default:
                return 0;
        }
    }

    private Rect calculateCollapsedTextBounds(Rect rect) {
        if (this.editText != null) {
            Rect bounds = this.tmpBoundsRect;
            boolean isRtl = ViewUtils.isLayoutRtl(this);
            bounds.bottom = rect.bottom;
            switch (this.boxBackgroundMode) {
                case 1:
                    bounds.left = getLabelLeftBoundAlightWithPrefix(rect.left, isRtl);
                    bounds.top = rect.top + this.boxCollapsedPaddingTopPx;
                    bounds.right = getLabelRightBoundAlignedWithSuffix(rect.right, isRtl);
                    return bounds;
                case 2:
                    bounds.left = rect.left + this.editText.getPaddingLeft();
                    bounds.top = rect.top - calculateLabelMarginTop();
                    bounds.right = rect.right - this.editText.getPaddingRight();
                    return bounds;
                default:
                    bounds.left = getLabelLeftBoundAlightWithPrefix(rect.left, isRtl);
                    bounds.top = getPaddingTop();
                    bounds.right = getLabelRightBoundAlignedWithSuffix(rect.right, isRtl);
                    return bounds;
            }
        } else {
            throw new IllegalStateException();
        }
    }

    private int getLabelLeftBoundAlightWithPrefix(int rectLeft, boolean isRtl) {
        int left = this.editText.getCompoundPaddingLeft() + rectLeft;
        if (getPrefixText() == null || isRtl) {
            return left;
        }
        return (left - getPrefixTextView().getMeasuredWidth()) + getPrefixTextView().getPaddingLeft();
    }

    private int getLabelRightBoundAlignedWithSuffix(int rectRight, boolean isRtl) {
        int right = rectRight - this.editText.getCompoundPaddingRight();
        if (getPrefixText() == null || !isRtl) {
            return right;
        }
        return right + (getPrefixTextView().getMeasuredWidth() - getPrefixTextView().getPaddingRight());
    }

    private Rect calculateExpandedTextBounds(Rect rect) {
        if (this.editText != null) {
            Rect bounds = this.tmpBoundsRect;
            float labelHeight = this.collapsingTextHelper.getExpandedTextHeight();
            bounds.left = rect.left + this.editText.getCompoundPaddingLeft();
            bounds.top = calculateExpandedLabelTop(rect, labelHeight);
            bounds.right = rect.right - this.editText.getCompoundPaddingRight();
            bounds.bottom = calculateExpandedLabelBottom(rect, bounds, labelHeight);
            return bounds;
        }
        throw new IllegalStateException();
    }

    private int calculateExpandedLabelTop(Rect rect, float labelHeight) {
        if (isSingleLineFilledTextField()) {
            return (int) (((float) rect.centerY()) - (labelHeight / 2.0f));
        }
        return rect.top + this.editText.getCompoundPaddingTop();
    }

    private int calculateExpandedLabelBottom(Rect rect, Rect bounds, float labelHeight) {
        if (isSingleLineFilledTextField()) {
            return (int) (((float) bounds.top) + labelHeight);
        }
        return rect.bottom - this.editText.getCompoundPaddingBottom();
    }

    private boolean isSingleLineFilledTextField() {
        if (this.boxBackgroundMode != 1 || (Build.VERSION.SDK_INT >= 16 && this.editText.getMinLines() > 1)) {
            return false;
        }
        return true;
    }

    private int calculateBoxBackgroundColor() {
        int backgroundColor = this.boxBackgroundColor;
        if (this.boxBackgroundMode == 1) {
            return MaterialColors.layer(MaterialColors.getColor((View) this, C0105R.attr.colorSurface, 0), this.boxBackgroundColor);
        }
        return backgroundColor;
    }

    private void applyBoxAttributes() {
        MaterialShapeDrawable materialShapeDrawable = this.boxBackground;
        if (materialShapeDrawable != null) {
            ShapeAppearanceModel shapeAppearanceModel2 = materialShapeDrawable.getShapeAppearanceModel();
            ShapeAppearanceModel shapeAppearanceModel3 = this.shapeAppearanceModel;
            if (shapeAppearanceModel2 != shapeAppearanceModel3) {
                this.boxBackground.setShapeAppearanceModel(shapeAppearanceModel3);
                updateDropdownMenuBackground();
            }
            if (canDrawOutlineStroke()) {
                this.boxBackground.setStroke((float) this.boxStrokeWidthPx, this.boxStrokeColor);
            }
            int calculateBoxBackgroundColor = calculateBoxBackgroundColor();
            this.boxBackgroundColor = calculateBoxBackgroundColor;
            this.boxBackground.setFillColor(ColorStateList.valueOf(calculateBoxBackgroundColor));
            if (this.endIconMode == 3) {
                this.editText.getBackground().invalidateSelf();
            }
            applyBoxUnderlineAttributes();
            invalidate();
        }
    }

    private void applyBoxUnderlineAttributes() {
        ColorStateList colorStateList;
        if (this.boxUnderlineDefault != null && this.boxUnderlineFocused != null) {
            if (canDrawStroke()) {
                MaterialShapeDrawable materialShapeDrawable = this.boxUnderlineDefault;
                if (this.editText.isFocused()) {
                    colorStateList = ColorStateList.valueOf(this.defaultStrokeColor);
                } else {
                    colorStateList = ColorStateList.valueOf(this.boxStrokeColor);
                }
                materialShapeDrawable.setFillColor(colorStateList);
                this.boxUnderlineFocused.setFillColor(ColorStateList.valueOf(this.boxStrokeColor));
            }
            invalidate();
        }
    }

    private boolean canDrawOutlineStroke() {
        return this.boxBackgroundMode == 2 && canDrawStroke();
    }

    private boolean canDrawStroke() {
        return this.boxStrokeWidthPx > -1 && this.boxStrokeColor != 0;
    }

    private void updateDropdownMenuBackground() {
        if (this.endIconMode == 3 && this.boxBackgroundMode == 2) {
            ((DropdownMenuEndIconDelegate) this.endIconDelegates.get(3)).updateOutlinedRippleEffect((AutoCompleteTextView) this.editText);
        }
    }

    /* access modifiers changed from: package-private */
    public void updateEditTextBackground() {
        Drawable editTextBackground;
        TextView textView;
        EditText editText2 = this.editText;
        if (editText2 != null && this.boxBackgroundMode == 0 && (editTextBackground = editText2.getBackground()) != null) {
            if (DrawableUtils.canSafelyMutateDrawable(editTextBackground)) {
                editTextBackground = editTextBackground.mutate();
            }
            if (this.indicatorViewController.errorShouldBeShown()) {
                editTextBackground.setColorFilter(AppCompatDrawableManager.getPorterDuffColorFilter(this.indicatorViewController.getErrorViewCurrentTextColor(), PorterDuff.Mode.SRC_IN));
            } else if (!this.counterOverflowed || (textView = this.counterView) == null) {
                DrawableCompat.clearColorFilter(editTextBackground);
                this.editText.refreshDrawableState();
            } else {
                editTextBackground.setColorFilter(AppCompatDrawableManager.getPorterDuffColorFilter(textView.getCurrentTextColor(), PorterDuff.Mode.SRC_IN));
            }
        }
    }

    static class SavedState extends AbsSavedState {
        public static final Parcelable.Creator<SavedState> CREATOR = new Parcelable.ClassLoaderCreator<SavedState>() {
            public SavedState createFromParcel(Parcel in, ClassLoader loader) {
                return new SavedState(in, loader);
            }

            public SavedState createFromParcel(Parcel in) {
                return new SavedState(in, (ClassLoader) null);
            }

            public SavedState[] newArray(int size) {
                return new SavedState[size];
            }
        };
        CharSequence error;
        CharSequence helperText;
        CharSequence hintText;
        boolean isEndIconChecked;
        CharSequence placeholderText;

        SavedState(Parcelable superState) {
            super(superState);
        }

        SavedState(Parcel source, ClassLoader loader) {
            super(source, loader);
            this.error = (CharSequence) TextUtils.CHAR_SEQUENCE_CREATOR.createFromParcel(source);
            this.isEndIconChecked = source.readInt() != 1 ? false : true;
            this.hintText = (CharSequence) TextUtils.CHAR_SEQUENCE_CREATOR.createFromParcel(source);
            this.helperText = (CharSequence) TextUtils.CHAR_SEQUENCE_CREATOR.createFromParcel(source);
            this.placeholderText = (CharSequence) TextUtils.CHAR_SEQUENCE_CREATOR.createFromParcel(source);
        }

        public void writeToParcel(Parcel dest, int flags) {
            super.writeToParcel(dest, flags);
            TextUtils.writeToParcel(this.error, dest, flags);
            dest.writeInt(this.isEndIconChecked ? 1 : 0);
            TextUtils.writeToParcel(this.hintText, dest, flags);
            TextUtils.writeToParcel(this.helperText, dest, flags);
            TextUtils.writeToParcel(this.placeholderText, dest, flags);
        }

        public String toString() {
            return "TextInputLayout.SavedState{" + Integer.toHexString(System.identityHashCode(this)) + " error=" + this.error + " hint=" + this.hintText + " helperText=" + this.helperText + " placeholderText=" + this.placeholderText + "}";
        }
    }

    public Parcelable onSaveInstanceState() {
        SavedState ss = new SavedState(super.onSaveInstanceState());
        if (this.indicatorViewController.errorShouldBeShown()) {
            ss.error = getError();
        }
        ss.isEndIconChecked = hasEndIcon() && this.endIconView.isChecked();
        ss.hintText = getHint();
        ss.helperText = getHelperText();
        ss.placeholderText = getPlaceholderText();
        return ss;
    }

    /* access modifiers changed from: protected */
    public void onRestoreInstanceState(Parcelable state) {
        if (!(state instanceof SavedState)) {
            super.onRestoreInstanceState(state);
            return;
        }
        SavedState ss = (SavedState) state;
        super.onRestoreInstanceState(ss.getSuperState());
        setError(ss.error);
        if (ss.isEndIconChecked) {
            this.endIconView.post(new Runnable() {
                public void run() {
                    TextInputLayout.this.endIconView.performClick();
                    TextInputLayout.this.endIconView.jumpDrawablesToCurrentState();
                }
            });
        }
        setHint(ss.hintText);
        setHelperText(ss.helperText);
        setPlaceholderText(ss.placeholderText);
        requestLayout();
    }

    /* access modifiers changed from: protected */
    public void dispatchRestoreInstanceState(SparseArray<Parcelable> container) {
        this.restoringSavedState = true;
        super.dispatchRestoreInstanceState(container);
        this.restoringSavedState = false;
    }

    public CharSequence getError() {
        if (this.indicatorViewController.isErrorEnabled()) {
            return this.indicatorViewController.getErrorText();
        }
        return null;
    }

    public CharSequence getHelperText() {
        if (this.indicatorViewController.isHelperTextEnabled()) {
            return this.indicatorViewController.getHelperText();
        }
        return null;
    }

    public boolean isHintAnimationEnabled() {
        return this.hintAnimationEnabled;
    }

    public void setHintAnimationEnabled(boolean enabled) {
        this.hintAnimationEnabled = enabled;
    }

    public boolean isExpandedHintEnabled() {
        return this.expandedHintEnabled;
    }

    public void setExpandedHintEnabled(boolean enabled) {
        if (this.expandedHintEnabled != enabled) {
            this.expandedHintEnabled = enabled;
            updateLabelState(false);
        }
    }

    public void onRtlPropertiesChanged(int layoutDirection) {
        super.onRtlPropertiesChanged(layoutDirection);
        boolean shouldCornersBeRtl = false;
        boolean isLayoutDirectionRtl = layoutDirection == 1;
        boolean z = this.areCornerRadiiRtl;
        if (isLayoutDirectionRtl != z) {
            if (isLayoutDirectionRtl && !z) {
                shouldCornersBeRtl = true;
            }
            float boxCornerRadiusTopLeft = this.shapeAppearanceModel.getTopLeftCornerSize().getCornerSize(this.tmpRectF);
            float boxCornerRadiusTopRight = this.shapeAppearanceModel.getTopRightCornerSize().getCornerSize(this.tmpRectF);
            float boxCornerRadiusBottomLeft = this.shapeAppearanceModel.getBottomLeftCornerSize().getCornerSize(this.tmpRectF);
            float boxCornerRadiusBottomRight = this.shapeAppearanceModel.getBottomRightCornerSize().getCornerSize(this.tmpRectF);
            setBoxCornerRadii(shouldCornersBeRtl ? boxCornerRadiusTopLeft : boxCornerRadiusTopRight, shouldCornersBeRtl ? boxCornerRadiusTopRight : boxCornerRadiusTopLeft, shouldCornersBeRtl ? boxCornerRadiusBottomLeft : boxCornerRadiusBottomRight, shouldCornersBeRtl ? boxCornerRadiusBottomRight : boxCornerRadiusBottomLeft);
        }
    }

    /* access modifiers changed from: protected */
    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
        boolean updatedHeight = updateEditTextHeightBasedOnIcon();
        boolean updatedIcon = updateDummyDrawables();
        if (updatedHeight || updatedIcon) {
            this.editText.post(new Runnable() {
                public void run() {
                    TextInputLayout.this.editText.requestLayout();
                }
            });
        }
        updatePlaceholderMeasurementsBasedOnEditText();
        updateSuffixTextViewPadding();
    }

    private boolean updateEditTextHeightBasedOnIcon() {
        int maxIconHeight;
        if (this.editText == null || this.editText.getMeasuredHeight() >= (maxIconHeight = Math.max(this.endLayout.getMeasuredHeight(), this.startLayout.getMeasuredHeight()))) {
            return false;
        }
        this.editText.setMinimumHeight(maxIconHeight);
        return true;
    }

    private void updatePlaceholderMeasurementsBasedOnEditText() {
        EditText editText2;
        if (this.placeholderTextView != null && (editText2 = this.editText) != null) {
            this.placeholderTextView.setGravity(editText2.getGravity());
            this.placeholderTextView.setPadding(this.editText.getCompoundPaddingLeft(), this.editText.getCompoundPaddingTop(), this.editText.getCompoundPaddingRight(), this.editText.getCompoundPaddingBottom());
        }
    }

    public void setStartIconDrawable(int resId) {
        setStartIconDrawable(resId != 0 ? AppCompatResources.getDrawable(getContext(), resId) : null);
    }

    public void setStartIconDrawable(Drawable startIconDrawable) {
        this.startLayout.setStartIconDrawable(startIconDrawable);
    }

    public Drawable getStartIconDrawable() {
        return this.startLayout.getStartIconDrawable();
    }

    public void setStartIconOnClickListener(View.OnClickListener startIconOnClickListener) {
        this.startLayout.setStartIconOnClickListener(startIconOnClickListener);
    }

    public void setStartIconOnLongClickListener(View.OnLongClickListener startIconOnLongClickListener) {
        this.startLayout.setStartIconOnLongClickListener(startIconOnLongClickListener);
    }

    public void setStartIconVisible(boolean visible) {
        this.startLayout.setStartIconVisible(visible);
    }

    public boolean isStartIconVisible() {
        return this.startLayout.isStartIconVisible();
    }

    public void refreshStartIconDrawableState() {
        this.startLayout.refreshStartIconDrawableState();
    }

    public void setStartIconCheckable(boolean startIconCheckable) {
        this.startLayout.setStartIconCheckable(startIconCheckable);
    }

    public boolean isStartIconCheckable() {
        return this.startLayout.isStartIconCheckable();
    }

    public void setStartIconContentDescription(int resId) {
        setStartIconContentDescription(resId != 0 ? getResources().getText(resId) : null);
    }

    public void setStartIconContentDescription(CharSequence startIconContentDescription) {
        this.startLayout.setStartIconContentDescription(startIconContentDescription);
    }

    public CharSequence getStartIconContentDescription() {
        return this.startLayout.getStartIconContentDescription();
    }

    public void setStartIconTintList(ColorStateList startIconTintList) {
        this.startLayout.setStartIconTintList(startIconTintList);
    }

    public void setStartIconTintMode(PorterDuff.Mode startIconTintMode) {
        this.startLayout.setStartIconTintMode(startIconTintMode);
    }

    public void setEndIconMode(int endIconMode2) {
        if (this.endIconMode != endIconMode2) {
            int previousEndIconMode = this.endIconMode;
            this.endIconMode = endIconMode2;
            dispatchOnEndIconChanged(previousEndIconMode);
            setEndIconVisible(endIconMode2 != 0);
            if (getEndIconDelegate().isBoxBackgroundModeSupported(this.boxBackgroundMode)) {
                getEndIconDelegate().initialize();
                IconHelper.applyIconTint(this, this.endIconView, this.endIconTintList, this.endIconTintMode);
                return;
            }
            throw new IllegalStateException("The current box background mode " + this.boxBackgroundMode + " is not supported by the end icon mode " + endIconMode2);
        }
    }

    public int getEndIconMode() {
        return this.endIconMode;
    }

    public void setEndIconOnClickListener(View.OnClickListener endIconOnClickListener) {
        setIconOnClickListener(this.endIconView, endIconOnClickListener, this.endIconOnLongClickListener);
    }

    public void setErrorIconOnClickListener(View.OnClickListener errorIconOnClickListener) {
        setIconOnClickListener(this.errorIconView, errorIconOnClickListener, this.errorIconOnLongClickListener);
    }

    public void setEndIconOnLongClickListener(View.OnLongClickListener endIconOnLongClickListener2) {
        this.endIconOnLongClickListener = endIconOnLongClickListener2;
        setIconOnLongClickListener(this.endIconView, endIconOnLongClickListener2);
    }

    public void setErrorIconOnLongClickListener(View.OnLongClickListener errorIconOnLongClickListener2) {
        this.errorIconOnLongClickListener = errorIconOnLongClickListener2;
        setIconOnLongClickListener(this.errorIconView, errorIconOnLongClickListener2);
    }

    public void refreshErrorIconDrawableState() {
        IconHelper.refreshIconDrawableState(this, this.errorIconView, this.errorIconTintList);
    }

    public void setEndIconVisible(boolean visible) {
        if (isEndIconVisible() != visible) {
            this.endIconView.setVisibility(visible ? 0 : 8);
            updateEndLayoutVisibility();
            updateSuffixTextViewPadding();
            updateDummyDrawables();
        }
    }

    public boolean isEndIconVisible() {
        return this.endIconFrame.getVisibility() == 0 && this.endIconView.getVisibility() == 0;
    }

    public void setEndIconActivated(boolean endIconActivated) {
        this.endIconView.setActivated(endIconActivated);
    }

    public void refreshEndIconDrawableState() {
        IconHelper.refreshIconDrawableState(this, this.endIconView, this.endIconTintList);
    }

    public void setEndIconCheckable(boolean endIconCheckable) {
        this.endIconView.setCheckable(endIconCheckable);
    }

    public boolean isEndIconCheckable() {
        return this.endIconView.isCheckable();
    }

    public void setEndIconDrawable(int resId) {
        setEndIconDrawable(resId != 0 ? AppCompatResources.getDrawable(getContext(), resId) : null);
    }

    public void setEndIconDrawable(Drawable endIconDrawable) {
        this.endIconView.setImageDrawable(endIconDrawable);
        if (endIconDrawable != null) {
            IconHelper.applyIconTint(this, this.endIconView, this.endIconTintList, this.endIconTintMode);
            refreshEndIconDrawableState();
        }
    }

    public Drawable getEndIconDrawable() {
        return this.endIconView.getDrawable();
    }

    public void setEndIconContentDescription(int resId) {
        setEndIconContentDescription(resId != 0 ? getResources().getText(resId) : null);
    }

    public void setEndIconContentDescription(CharSequence endIconContentDescription) {
        if (getEndIconContentDescription() != endIconContentDescription) {
            this.endIconView.setContentDescription(endIconContentDescription);
        }
    }

    public CharSequence getEndIconContentDescription() {
        return this.endIconView.getContentDescription();
    }

    public void setEndIconTintList(ColorStateList endIconTintList2) {
        if (this.endIconTintList != endIconTintList2) {
            this.endIconTintList = endIconTintList2;
            IconHelper.applyIconTint(this, this.endIconView, endIconTintList2, this.endIconTintMode);
        }
    }

    public void setEndIconTintMode(PorterDuff.Mode endIconTintMode2) {
        if (this.endIconTintMode != endIconTintMode2) {
            this.endIconTintMode = endIconTintMode2;
            IconHelper.applyIconTint(this, this.endIconView, this.endIconTintList, endIconTintMode2);
        }
    }

    public void addOnEndIconChangedListener(OnEndIconChangedListener listener) {
        this.endIconChangedListeners.add(listener);
    }

    public void removeOnEndIconChangedListener(OnEndIconChangedListener listener) {
        this.endIconChangedListeners.remove(listener);
    }

    public void clearOnEndIconChangedListeners() {
        this.endIconChangedListeners.clear();
    }

    public void addOnEditTextAttachedListener(OnEditTextAttachedListener listener) {
        this.editTextAttachedListeners.add(listener);
        if (this.editText != null) {
            listener.onEditTextAttached(this);
        }
    }

    public void removeOnEditTextAttachedListener(OnEditTextAttachedListener listener) {
        this.editTextAttachedListeners.remove(listener);
    }

    public void clearOnEditTextAttachedListeners() {
        this.editTextAttachedListeners.clear();
    }

    @Deprecated
    public void setPasswordVisibilityToggleDrawable(int resId) {
        setPasswordVisibilityToggleDrawable(resId != 0 ? AppCompatResources.getDrawable(getContext(), resId) : null);
    }

    @Deprecated
    public void setPasswordVisibilityToggleDrawable(Drawable icon) {
        this.endIconView.setImageDrawable(icon);
    }

    @Deprecated
    public void setPasswordVisibilityToggleContentDescription(int resId) {
        setPasswordVisibilityToggleContentDescription(resId != 0 ? getResources().getText(resId) : null);
    }

    @Deprecated
    public void setPasswordVisibilityToggleContentDescription(CharSequence description) {
        this.endIconView.setContentDescription(description);
    }

    @Deprecated
    public Drawable getPasswordVisibilityToggleDrawable() {
        return this.endIconView.getDrawable();
    }

    @Deprecated
    public CharSequence getPasswordVisibilityToggleContentDescription() {
        return this.endIconView.getContentDescription();
    }

    @Deprecated
    public boolean isPasswordVisibilityToggleEnabled() {
        return this.endIconMode == 1;
    }

    @Deprecated
    public void setPasswordVisibilityToggleEnabled(boolean enabled) {
        if (enabled && this.endIconMode != 1) {
            setEndIconMode(1);
        } else if (!enabled) {
            setEndIconMode(0);
        }
    }

    @Deprecated
    public void setPasswordVisibilityToggleTintList(ColorStateList tintList) {
        this.endIconTintList = tintList;
        IconHelper.applyIconTint(this, this.endIconView, tintList, this.endIconTintMode);
    }

    @Deprecated
    public void setPasswordVisibilityToggleTintMode(PorterDuff.Mode mode) {
        this.endIconTintMode = mode;
        IconHelper.applyIconTint(this, this.endIconView, this.endIconTintList, mode);
    }

    @Deprecated
    public void passwordVisibilityToggleRequested(boolean shouldSkipAnimations) {
        if (this.endIconMode == 1) {
            this.endIconView.performClick();
            if (shouldSkipAnimations) {
                this.endIconView.jumpDrawablesToCurrentState();
            }
        }
    }

    public void setTextInputAccessibilityDelegate(AccessibilityDelegate delegate) {
        EditText editText2 = this.editText;
        if (editText2 != null) {
            ViewCompat.setAccessibilityDelegate(editText2, delegate);
        }
    }

    private void updateEndLayoutVisibility() {
        int i = 8;
        this.endIconFrame.setVisibility((this.endIconView.getVisibility() != 0 || isErrorIconVisible()) ? 8 : 0);
        boolean shouldBeVisible = isEndIconVisible() || isErrorIconVisible() || ((this.suffixText == null || isHintExpanded()) ? 8 : 0) == 0;
        LinearLayout linearLayout = this.endLayout;
        if (shouldBeVisible) {
            i = 0;
        }
        linearLayout.setVisibility(i);
    }

    /* access modifiers changed from: package-private */
    public CheckableImageButton getEndIconView() {
        return this.endIconView;
    }

    private EndIconDelegate getEndIconDelegate() {
        EndIconDelegate endIconDelegate = this.endIconDelegates.get(this.endIconMode);
        return endIconDelegate != null ? endIconDelegate : this.endIconDelegates.get(0);
    }

    private void dispatchOnEditTextAttached() {
        Iterator it = this.editTextAttachedListeners.iterator();
        while (it.hasNext()) {
            ((OnEditTextAttachedListener) it.next()).onEditTextAttached(this);
        }
    }

    private boolean hasEndIcon() {
        return this.endIconMode != 0;
    }

    private void dispatchOnEndIconChanged(int previousIcon) {
        Iterator it = this.endIconChangedListeners.iterator();
        while (it.hasNext()) {
            ((OnEndIconChangedListener) it.next()).onEndIconChanged(this, previousIcon);
        }
    }

    private void tintEndIconOnError(boolean tintEndIconOnError) {
        if (!tintEndIconOnError || getEndIconDrawable() == null) {
            IconHelper.applyIconTint(this, this.endIconView, this.endIconTintList, this.endIconTintMode);
            return;
        }
        Drawable endIconDrawable = DrawableCompat.wrap(getEndIconDrawable()).mutate();
        DrawableCompat.setTint(endIconDrawable, this.indicatorViewController.getErrorViewCurrentTextColor());
        this.endIconView.setImageDrawable(endIconDrawable);
    }

    /* access modifiers changed from: package-private */
    public boolean updateDummyDrawables() {
        if (this.editText == null) {
            return false;
        }
        boolean updatedIcon = false;
        if (shouldUpdateStartDummyDrawable()) {
            int right = this.startLayout.getMeasuredWidth() - this.editText.getPaddingLeft();
            if (this.startDummyDrawable == null || this.startDummyDrawableWidth != right) {
                ColorDrawable colorDrawable = new ColorDrawable();
                this.startDummyDrawable = colorDrawable;
                this.startDummyDrawableWidth = right;
                colorDrawable.setBounds(0, 0, right, 1);
            }
            Drawable[] compounds = TextViewCompat.getCompoundDrawablesRelative(this.editText);
            Drawable drawable = compounds[0];
            Drawable drawable2 = this.startDummyDrawable;
            if (drawable != drawable2) {
                TextViewCompat.setCompoundDrawablesRelative(this.editText, drawable2, compounds[1], compounds[2], compounds[3]);
                updatedIcon = true;
            }
        } else if (this.startDummyDrawable != null) {
            Drawable[] compounds2 = TextViewCompat.getCompoundDrawablesRelative(this.editText);
            TextViewCompat.setCompoundDrawablesRelative(this.editText, (Drawable) null, compounds2[1], compounds2[2], compounds2[3]);
            this.startDummyDrawable = null;
            updatedIcon = true;
        }
        if (shouldUpdateEndDummyDrawable()) {
            int right2 = this.suffixTextView.getMeasuredWidth() - this.editText.getPaddingRight();
            View iconView = getEndIconToUpdateDummyDrawable();
            if (iconView != null) {
                right2 = iconView.getMeasuredWidth() + right2 + MarginLayoutParamsCompat.getMarginStart((ViewGroup.MarginLayoutParams) iconView.getLayoutParams());
            }
            Drawable[] compounds3 = TextViewCompat.getCompoundDrawablesRelative(this.editText);
            Drawable drawable3 = this.endDummyDrawable;
            if (drawable3 == null || this.endDummyDrawableWidth == right2) {
                if (drawable3 == null) {
                    ColorDrawable colorDrawable2 = new ColorDrawable();
                    this.endDummyDrawable = colorDrawable2;
                    this.endDummyDrawableWidth = right2;
                    colorDrawable2.setBounds(0, 0, right2, 1);
                }
                Drawable drawable4 = compounds3[2];
                Drawable drawable5 = this.endDummyDrawable;
                if (drawable4 == drawable5) {
                    return updatedIcon;
                }
                this.originalEditTextEndDrawable = compounds3[2];
                TextViewCompat.setCompoundDrawablesRelative(this.editText, compounds3[0], compounds3[1], drawable5, compounds3[3]);
                return true;
            }
            this.endDummyDrawableWidth = right2;
            drawable3.setBounds(0, 0, right2, 1);
            TextViewCompat.setCompoundDrawablesRelative(this.editText, compounds3[0], compounds3[1], this.endDummyDrawable, compounds3[3]);
            return true;
        } else if (this.endDummyDrawable == null) {
            return updatedIcon;
        } else {
            Drawable[] compounds4 = TextViewCompat.getCompoundDrawablesRelative(this.editText);
            if (compounds4[2] == this.endDummyDrawable) {
                TextViewCompat.setCompoundDrawablesRelative(this.editText, compounds4[0], compounds4[1], this.originalEditTextEndDrawable, compounds4[3]);
                updatedIcon = true;
            }
            this.endDummyDrawable = null;
            return updatedIcon;
        }
    }

    private boolean shouldUpdateStartDummyDrawable() {
        return (getStartIconDrawable() != null || (getPrefixText() != null && getPrefixTextView().getVisibility() == 0)) && this.startLayout.getMeasuredWidth() > 0;
    }

    private boolean shouldUpdateEndDummyDrawable() {
        return (this.errorIconView.getVisibility() == 0 || ((hasEndIcon() && isEndIconVisible()) || this.suffixText != null)) && this.endLayout.getMeasuredWidth() > 0;
    }

    private CheckableImageButton getEndIconToUpdateDummyDrawable() {
        if (this.errorIconView.getVisibility() == 0) {
            return this.errorIconView;
        }
        if (!hasEndIcon() || !isEndIconVisible()) {
            return null;
        }
        return this.endIconView;
    }

    private static void setIconOnClickListener(CheckableImageButton iconView, View.OnClickListener onClickListener, View.OnLongClickListener onLongClickListener) {
        iconView.setOnClickListener(onClickListener);
        setIconClickable(iconView, onLongClickListener);
    }

    private static void setIconOnLongClickListener(CheckableImageButton iconView, View.OnLongClickListener onLongClickListener) {
        iconView.setOnLongClickListener(onLongClickListener);
        setIconClickable(iconView, onLongClickListener);
    }

    private static void setIconClickable(CheckableImageButton iconView, View.OnLongClickListener onLongClickListener) {
        boolean iconClickable = ViewCompat.hasOnClickListeners(iconView);
        boolean iconFocusable = false;
        int i = 1;
        boolean iconLongClickable = onLongClickListener != null;
        if (iconClickable || iconLongClickable) {
            iconFocusable = true;
        }
        iconView.setFocusable(iconFocusable);
        iconView.setClickable(iconClickable);
        iconView.setPressable(iconClickable);
        iconView.setLongClickable(iconLongClickable);
        if (!iconFocusable) {
            i = 2;
        }
        ViewCompat.setImportantForAccessibility(iconView, i);
    }

    /* access modifiers changed from: protected */
    public void onLayout(boolean changed, int left, int top, int right, int bottom) {
        super.onLayout(changed, left, top, right, bottom);
        EditText editText2 = this.editText;
        if (editText2 != null) {
            Rect rect = this.tmpRect;
            DescendantOffsetUtils.getDescendantRect(this, editText2, rect);
            updateBoxUnderlineBounds(rect);
            if (this.hintEnabled) {
                this.collapsingTextHelper.setExpandedTextSize(this.editText.getTextSize());
                int editTextGravity = this.editText.getGravity();
                this.collapsingTextHelper.setCollapsedTextGravity((editTextGravity & -113) | 48);
                this.collapsingTextHelper.setExpandedTextGravity(editTextGravity);
                this.collapsingTextHelper.setCollapsedBounds(calculateCollapsedTextBounds(rect));
                this.collapsingTextHelper.setExpandedBounds(calculateExpandedTextBounds(rect));
                this.collapsingTextHelper.recalculate();
                if (cutoutEnabled() && !this.hintExpanded) {
                    openCutout();
                }
            }
        }
    }

    private void updateBoxUnderlineBounds(Rect bounds) {
        if (this.boxUnderlineDefault != null) {
            this.boxUnderlineDefault.setBounds(bounds.left, bounds.bottom - this.boxStrokeWidthDefaultPx, bounds.right, bounds.bottom);
        }
        if (this.boxUnderlineFocused != null) {
            this.boxUnderlineFocused.setBounds(bounds.left, bounds.bottom - this.boxStrokeWidthFocusedPx, bounds.right, bounds.bottom);
        }
    }

    public void draw(Canvas canvas) {
        super.draw(canvas);
        drawHint(canvas);
        drawBoxUnderline(canvas);
    }

    /* access modifiers changed from: protected */
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        this.collapsingTextHelper.maybeUpdateFontWeightAdjustment(newConfig);
    }

    private void drawHint(Canvas canvas) {
        if (this.hintEnabled) {
            this.collapsingTextHelper.draw(canvas);
        }
    }

    private void drawBoxUnderline(Canvas canvas) {
        MaterialShapeDrawable materialShapeDrawable;
        if (this.boxUnderlineFocused != null && (materialShapeDrawable = this.boxUnderlineDefault) != null) {
            materialShapeDrawable.draw(canvas);
            if (this.editText.isFocused()) {
                Rect focusedUnderlineBounds = this.boxUnderlineFocused.getBounds();
                Rect defaultUnderlineBounds = this.boxUnderlineDefault.getBounds();
                float hintExpansionFraction = this.collapsingTextHelper.getExpansionFraction();
                int midpointX = defaultUnderlineBounds.centerX();
                focusedUnderlineBounds.left = AnimationUtils.lerp(midpointX, defaultUnderlineBounds.left, hintExpansionFraction);
                focusedUnderlineBounds.right = AnimationUtils.lerp(midpointX, defaultUnderlineBounds.right, hintExpansionFraction);
                this.boxUnderlineFocused.draw(canvas);
            }
        }
    }

    private void collapseHint(boolean animate) {
        ValueAnimator valueAnimator = this.animator;
        if (valueAnimator != null && valueAnimator.isRunning()) {
            this.animator.cancel();
        }
        if (!animate || !this.hintAnimationEnabled) {
            this.collapsingTextHelper.setExpansionFraction(1.0f);
        } else {
            animateToExpansionFraction(1.0f);
        }
        this.hintExpanded = false;
        if (cutoutEnabled()) {
            openCutout();
        }
        updatePlaceholderText();
        this.startLayout.onHintStateChanged(false);
        updateSuffixTextVisibility();
    }

    private boolean cutoutEnabled() {
        return this.hintEnabled && !TextUtils.isEmpty(this.hint) && (this.boxBackground instanceof CutoutDrawable);
    }

    private void openCutout() {
        if (cutoutEnabled()) {
            RectF cutoutBounds = this.tmpRectF;
            this.collapsingTextHelper.getCollapsedTextActualBounds(cutoutBounds, this.editText.getWidth(), this.editText.getGravity());
            applyCutoutPadding(cutoutBounds);
            cutoutBounds.offset((float) (-getPaddingLeft()), (((float) (-getPaddingTop())) - (cutoutBounds.height() / 2.0f)) + ((float) this.boxStrokeWidthPx));
            ((CutoutDrawable) this.boxBackground).setCutout(cutoutBounds);
        }
    }

    private void recalculateCutout() {
        if (cutoutEnabled() && !this.hintExpanded) {
            closeCutout();
            openCutout();
        }
    }

    private void closeCutout() {
        if (cutoutEnabled()) {
            ((CutoutDrawable) this.boxBackground).removeCutout();
        }
    }

    private void applyCutoutPadding(RectF cutoutBounds) {
        cutoutBounds.left -= (float) this.boxLabelCutoutPaddingPx;
        cutoutBounds.right += (float) this.boxLabelCutoutPaddingPx;
    }

    /* access modifiers changed from: package-private */
    public boolean cutoutIsOpen() {
        return cutoutEnabled() && ((CutoutDrawable) this.boxBackground).hasCutout();
    }

    /* access modifiers changed from: protected */
    public void drawableStateChanged() {
        if (!this.inDrawableStateChanged) {
            boolean z = true;
            this.inDrawableStateChanged = true;
            super.drawableStateChanged();
            int[] state = getDrawableState();
            boolean changed = false;
            CollapsingTextHelper collapsingTextHelper2 = this.collapsingTextHelper;
            if (collapsingTextHelper2 != null) {
                changed = false | collapsingTextHelper2.setState(state);
            }
            if (this.editText != null) {
                if (!ViewCompat.isLaidOut(this) || !isEnabled()) {
                    z = false;
                }
                updateLabelState(z);
            }
            updateEditTextBackground();
            updateTextInputBoxState();
            if (changed) {
                invalidate();
            }
            this.inDrawableStateChanged = false;
        }
    }

    /* access modifiers changed from: package-private */
    /* JADX WARNING: Code restructure failed: missing block: B:6:0x0012, code lost:
        r0 = r5.editText;
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public void updateTextInputBoxState() {
        /*
            r5 = this;
            com.google.android.material.shape.MaterialShapeDrawable r0 = r5.boxBackground
            if (r0 == 0) goto L_0x00e3
            int r0 = r5.boxBackgroundMode
            if (r0 != 0) goto L_0x000a
            goto L_0x00e3
        L_0x000a:
            boolean r0 = r5.isFocused()
            r1 = 0
            r2 = 1
            if (r0 != 0) goto L_0x001f
            android.widget.EditText r0 = r5.editText
            if (r0 == 0) goto L_0x001d
            boolean r0 = r0.hasFocus()
            if (r0 == 0) goto L_0x001d
            goto L_0x001f
        L_0x001d:
            r0 = 0
            goto L_0x0020
        L_0x001f:
            r0 = 1
        L_0x0020:
            boolean r3 = r5.isHovered()
            if (r3 != 0) goto L_0x0030
            android.widget.EditText r3 = r5.editText
            if (r3 == 0) goto L_0x0031
            boolean r3 = r3.isHovered()
            if (r3 == 0) goto L_0x0031
        L_0x0030:
            r1 = 1
        L_0x0031:
            boolean r3 = r5.isEnabled()
            if (r3 != 0) goto L_0x003c
            int r3 = r5.disabledColor
            r5.boxStrokeColor = r3
            goto L_0x007e
        L_0x003c:
            com.google.android.material.textfield.IndicatorViewController r3 = r5.indicatorViewController
            boolean r3 = r3.errorShouldBeShown()
            if (r3 == 0) goto L_0x0055
            android.content.res.ColorStateList r3 = r5.strokeErrorColor
            if (r3 == 0) goto L_0x004c
            r5.updateStrokeErrorColor(r0, r1)
            goto L_0x007e
        L_0x004c:
            com.google.android.material.textfield.IndicatorViewController r3 = r5.indicatorViewController
            int r3 = r3.getErrorViewCurrentTextColor()
            r5.boxStrokeColor = r3
            goto L_0x007e
        L_0x0055:
            boolean r3 = r5.counterOverflowed
            if (r3 == 0) goto L_0x006c
            android.widget.TextView r3 = r5.counterView
            if (r3 == 0) goto L_0x006c
            android.content.res.ColorStateList r4 = r5.strokeErrorColor
            if (r4 == 0) goto L_0x0065
            r5.updateStrokeErrorColor(r0, r1)
            goto L_0x007e
        L_0x0065:
            int r3 = r3.getCurrentTextColor()
            r5.boxStrokeColor = r3
            goto L_0x007e
        L_0x006c:
            if (r0 == 0) goto L_0x0073
            int r3 = r5.focusedStrokeColor
            r5.boxStrokeColor = r3
            goto L_0x007e
        L_0x0073:
            if (r1 == 0) goto L_0x007a
            int r3 = r5.hoveredStrokeColor
            r5.boxStrokeColor = r3
            goto L_0x007e
        L_0x007a:
            int r3 = r5.defaultStrokeColor
            r5.boxStrokeColor = r3
        L_0x007e:
            r5.updateErrorIconVisibility()
            r5.refreshErrorIconDrawableState()
            r5.refreshStartIconDrawableState()
            r5.refreshEndIconDrawableState()
            com.google.android.material.textfield.EndIconDelegate r3 = r5.getEndIconDelegate()
            boolean r3 = r3.shouldTintIconOnError()
            if (r3 == 0) goto L_0x009d
            com.google.android.material.textfield.IndicatorViewController r3 = r5.indicatorViewController
            boolean r3 = r3.errorShouldBeShown()
            r5.tintEndIconOnError(r3)
        L_0x009d:
            int r3 = r5.boxBackgroundMode
            r4 = 2
            if (r3 != r4) goto L_0x00bc
            int r3 = r5.boxStrokeWidthPx
            if (r0 == 0) goto L_0x00b1
            boolean r4 = r5.isEnabled()
            if (r4 == 0) goto L_0x00b1
            int r4 = r5.boxStrokeWidthFocusedPx
            r5.boxStrokeWidthPx = r4
            goto L_0x00b5
        L_0x00b1:
            int r4 = r5.boxStrokeWidthDefaultPx
            r5.boxStrokeWidthPx = r4
        L_0x00b5:
            int r4 = r5.boxStrokeWidthPx
            if (r4 == r3) goto L_0x00bc
            r5.recalculateCutout()
        L_0x00bc:
            int r3 = r5.boxBackgroundMode
            if (r3 != r2) goto L_0x00df
            boolean r2 = r5.isEnabled()
            if (r2 != 0) goto L_0x00cb
            int r2 = r5.disabledFilledBackgroundColor
            r5.boxBackgroundColor = r2
            goto L_0x00df
        L_0x00cb:
            if (r1 == 0) goto L_0x00d4
            if (r0 != 0) goto L_0x00d4
            int r2 = r5.hoveredFilledBackgroundColor
            r5.boxBackgroundColor = r2
            goto L_0x00df
        L_0x00d4:
            if (r0 == 0) goto L_0x00db
            int r2 = r5.focusedFilledBackgroundColor
            r5.boxBackgroundColor = r2
            goto L_0x00df
        L_0x00db:
            int r2 = r5.defaultFilledBackgroundColor
            r5.boxBackgroundColor = r2
        L_0x00df:
            r5.applyBoxAttributes()
            return
        L_0x00e3:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.textfield.TextInputLayout.updateTextInputBoxState():void");
    }

    private void updateStrokeErrorColor(boolean hasFocus, boolean isHovered) {
        int defaultStrokeErrorColor = this.strokeErrorColor.getDefaultColor();
        int hoveredStrokeErrorColor = this.strokeErrorColor.getColorForState(new int[]{16843623, 16842910}, defaultStrokeErrorColor);
        int focusedStrokeErrorColor = this.strokeErrorColor.getColorForState(new int[]{16843518, 16842910}, defaultStrokeErrorColor);
        if (hasFocus) {
            this.boxStrokeColor = focusedStrokeErrorColor;
        } else if (isHovered) {
            this.boxStrokeColor = hoveredStrokeErrorColor;
        } else {
            this.boxStrokeColor = defaultStrokeErrorColor;
        }
    }

    private void updateErrorIconVisibility() {
        int i = 0;
        boolean visible = getErrorIconDrawable() != null && this.indicatorViewController.isErrorEnabled() && this.indicatorViewController.errorShouldBeShown();
        CheckableImageButton checkableImageButton = this.errorIconView;
        if (!visible) {
            i = 8;
        }
        checkableImageButton.setVisibility(i);
        updateEndLayoutVisibility();
        updateSuffixTextViewPadding();
        if (!hasEndIcon()) {
            updateDummyDrawables();
        }
    }

    private boolean isErrorIconVisible() {
        return this.errorIconView.getVisibility() == 0;
    }

    private void expandHint(boolean animate) {
        ValueAnimator valueAnimator = this.animator;
        if (valueAnimator != null && valueAnimator.isRunning()) {
            this.animator.cancel();
        }
        if (!animate || !this.hintAnimationEnabled) {
            this.collapsingTextHelper.setExpansionFraction(0.0f);
        } else {
            animateToExpansionFraction(0.0f);
        }
        if (cutoutEnabled() && ((CutoutDrawable) this.boxBackground).hasCutout()) {
            closeCutout();
        }
        this.hintExpanded = true;
        hidePlaceholderText();
        this.startLayout.onHintStateChanged(true);
        updateSuffixTextVisibility();
    }

    /* access modifiers changed from: package-private */
    public void animateToExpansionFraction(float target) {
        if (this.collapsingTextHelper.getExpansionFraction() != target) {
            if (this.animator == null) {
                ValueAnimator valueAnimator = new ValueAnimator();
                this.animator = valueAnimator;
                valueAnimator.setInterpolator(AnimationUtils.FAST_OUT_SLOW_IN_INTERPOLATOR);
                this.animator.setDuration(167);
                this.animator.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() {
                    public void onAnimationUpdate(ValueAnimator animator) {
                        TextInputLayout.this.collapsingTextHelper.setExpansionFraction(((Float) animator.getAnimatedValue()).floatValue());
                    }
                });
            }
            this.animator.setFloatValues(new float[]{this.collapsingTextHelper.getExpansionFraction(), target});
            this.animator.start();
        }
    }

    /* access modifiers changed from: package-private */
    public final boolean isHintExpanded() {
        return this.hintExpanded;
    }

    /* access modifiers changed from: package-private */
    public final boolean isHelperTextDisplayed() {
        return this.indicatorViewController.helperTextIsDisplayed();
    }

    /* access modifiers changed from: package-private */
    public final int getHintCurrentCollapsedTextColor() {
        return this.collapsingTextHelper.getCurrentCollapsedTextColor();
    }

    /* access modifiers changed from: package-private */
    public final float getHintCollapsedTextHeight() {
        return this.collapsingTextHelper.getCollapsedTextHeight();
    }

    /* access modifiers changed from: package-private */
    public final int getErrorTextCurrentColor() {
        return this.indicatorViewController.getErrorViewCurrentTextColor();
    }

    public static class AccessibilityDelegate extends AccessibilityDelegateCompat {
        private final TextInputLayout layout;

        public AccessibilityDelegate(TextInputLayout layout2) {
            this.layout = layout2;
        }

        public void onInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfoCompat info) {
            String hint;
            View helperTextView;
            String text;
            AccessibilityNodeInfoCompat accessibilityNodeInfoCompat = info;
            super.onInitializeAccessibilityNodeInfo(host, info);
            EditText editText = this.layout.getEditText();
            CharSequence inputText = editText != null ? editText.getText() : null;
            CharSequence hintText = this.layout.getHint();
            CharSequence errorText = this.layout.getError();
            CharSequence placeholderText = this.layout.getPlaceholderText();
            int maxCharLimit = this.layout.getCounterMaxLength();
            CharSequence counterOverflowDesc = this.layout.getCounterOverflowDescription();
            boolean showingText = !TextUtils.isEmpty(inputText);
            boolean hasHint = !TextUtils.isEmpty(hintText);
            boolean isHintCollapsed = !this.layout.isHintExpanded();
            boolean showingError = !TextUtils.isEmpty(errorText);
            boolean contentInvalid = showingError || !TextUtils.isEmpty(counterOverflowDesc);
            String hint2 = hasHint ? hintText.toString() : "";
            this.layout.startLayout.setupAccessibilityNodeInfo(accessibilityNodeInfoCompat);
            if (showingText) {
                accessibilityNodeInfoCompat.setText(inputText);
                hint = hint2;
                EditText editText2 = editText;
            } else if (!TextUtils.isEmpty(hint2)) {
                hint = hint2;
                accessibilityNodeInfoCompat.setText(hint);
                if (!isHintCollapsed || placeholderText == null) {
                } else {
                    EditText editText3 = editText;
                    accessibilityNodeInfoCompat.setText(hint + ", " + placeholderText);
                }
            } else {
                hint = hint2;
                EditText editText4 = editText;
                if (placeholderText != null) {
                    accessibilityNodeInfoCompat.setText(placeholderText);
                }
            }
            if (!TextUtils.isEmpty(hint)) {
                CharSequence charSequence = hintText;
                if (Build.VERSION.SDK_INT >= 26) {
                    accessibilityNodeInfoCompat.setHintText(hint);
                } else {
                    if (showingText) {
                        text = inputText + ", " + hint;
                    } else {
                        text = hint;
                    }
                    accessibilityNodeInfoCompat.setText(text);
                }
                accessibilityNodeInfoCompat.setShowingHintText(!showingText);
            }
            accessibilityNodeInfoCompat.setMaxTextLength((inputText == null || inputText.length() != maxCharLimit) ? -1 : maxCharLimit);
            if (contentInvalid) {
                accessibilityNodeInfoCompat.setError(showingError ? errorText : counterOverflowDesc);
            }
            if (Build.VERSION.SDK_INT >= 17 && (helperTextView = this.layout.indicatorViewController.getHelperTextView()) != null) {
                accessibilityNodeInfoCompat.setLabelFor(helperTextView);
            }
        }
    }
}
