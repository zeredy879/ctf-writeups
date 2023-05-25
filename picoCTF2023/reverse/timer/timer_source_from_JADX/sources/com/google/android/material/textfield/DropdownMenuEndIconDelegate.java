package com.google.android.material.textfield;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ValueAnimator;
import android.content.res.ColorStateList;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.LayerDrawable;
import android.graphics.drawable.RippleDrawable;
import android.graphics.drawable.StateListDrawable;
import android.os.Build;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.MotionEvent;
import android.view.View;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityManager;
import android.widget.AutoCompleteTextView;
import android.widget.EditText;
import android.widget.Spinner;
import androidx.core.view.ViewCompat;
import androidx.core.view.accessibility.AccessibilityManagerCompat;
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
import com.google.android.material.C0105R;
import com.google.android.material.animation.AnimationUtils;
import com.google.android.material.color.MaterialColors;
import com.google.android.material.internal.TextWatcherAdapter;
import com.google.android.material.shape.MaterialShapeDrawable;
import com.google.android.material.shape.ShapeAppearanceModel;
import com.google.android.material.textfield.TextInputLayout;

class DropdownMenuEndIconDelegate extends EndIconDelegate {
    private static final int ANIMATION_FADE_IN_DURATION = 67;
    private static final int ANIMATION_FADE_OUT_DURATION = 50;
    /* access modifiers changed from: private */
    public static final boolean IS_LOLLIPOP = (Build.VERSION.SDK_INT >= 21);
    /* access modifiers changed from: private */
    public final TextInputLayout.AccessibilityDelegate accessibilityDelegate = new TextInputLayout.AccessibilityDelegate(this.textInputLayout) {
        public void onInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfoCompat info) {
            super.onInitializeAccessibilityNodeInfo(host, info);
            if (!DropdownMenuEndIconDelegate.isEditable(DropdownMenuEndIconDelegate.this.textInputLayout.getEditText())) {
                info.setClassName(Spinner.class.getName());
            }
            if (info.isShowingHintText()) {
                info.setHintText((CharSequence) null);
            }
        }

        public void onPopulateAccessibilityEvent(View host, AccessibilityEvent event) {
            super.onPopulateAccessibilityEvent(host, event);
            AutoCompleteTextView editText = DropdownMenuEndIconDelegate.castAutoCompleteTextViewOrThrow(DropdownMenuEndIconDelegate.this.textInputLayout.getEditText());
            if (event.getEventType() == 1 && DropdownMenuEndIconDelegate.this.accessibilityManager.isEnabled() && !DropdownMenuEndIconDelegate.isEditable(DropdownMenuEndIconDelegate.this.textInputLayout.getEditText())) {
                DropdownMenuEndIconDelegate.this.showHideDropdown(editText);
                DropdownMenuEndIconDelegate.this.updateDropdownPopupDirty();
            }
        }
    };
    /* access modifiers changed from: private */
    public AccessibilityManager accessibilityManager;
    private final TextInputLayout.OnEditTextAttachedListener dropdownMenuOnEditTextAttachedListener = new TextInputLayout.OnEditTextAttachedListener() {
        public void onEditTextAttached(TextInputLayout textInputLayout) {
            AutoCompleteTextView autoCompleteTextView = DropdownMenuEndIconDelegate.castAutoCompleteTextViewOrThrow(textInputLayout.getEditText());
            DropdownMenuEndIconDelegate.this.setPopupBackground(autoCompleteTextView);
            DropdownMenuEndIconDelegate.this.addRippleEffect(autoCompleteTextView);
            DropdownMenuEndIconDelegate.this.setUpDropdownShowHideBehavior(autoCompleteTextView);
            autoCompleteTextView.setThreshold(0);
            autoCompleteTextView.removeTextChangedListener(DropdownMenuEndIconDelegate.this.exposedDropdownEndIconTextWatcher);
            autoCompleteTextView.addTextChangedListener(DropdownMenuEndIconDelegate.this.exposedDropdownEndIconTextWatcher);
            textInputLayout.setEndIconCheckable(true);
            textInputLayout.setErrorIconDrawable((Drawable) null);
            if (!DropdownMenuEndIconDelegate.isEditable(autoCompleteTextView) && DropdownMenuEndIconDelegate.this.accessibilityManager.isTouchExplorationEnabled()) {
                ViewCompat.setImportantForAccessibility(DropdownMenuEndIconDelegate.this.endIconView, 2);
            }
            textInputLayout.setTextInputAccessibilityDelegate(DropdownMenuEndIconDelegate.this.accessibilityDelegate);
            textInputLayout.setEndIconVisible(true);
        }
    };
    private long dropdownPopupActivatedAt = Long.MAX_VALUE;
    /* access modifiers changed from: private */
    public boolean dropdownPopupDirty = false;
    private final TextInputLayout.OnEndIconChangedListener endIconChangedListener = new TextInputLayout.OnEndIconChangedListener() {
        public void onEndIconChanged(TextInputLayout textInputLayout, int previousIcon) {
            final AutoCompleteTextView editText = (AutoCompleteTextView) textInputLayout.getEditText();
            if (editText != null && previousIcon == 3) {
                editText.post(new Runnable() {
                    public void run() {
                        editText.removeTextChangedListener(DropdownMenuEndIconDelegate.this.exposedDropdownEndIconTextWatcher);
                    }
                });
                if (editText.getOnFocusChangeListener() == DropdownMenuEndIconDelegate.this.onFocusChangeListener) {
                    editText.setOnFocusChangeListener((View.OnFocusChangeListener) null);
                }
                editText.setOnTouchListener((View.OnTouchListener) null);
                if (DropdownMenuEndIconDelegate.IS_LOLLIPOP) {
                    editText.setOnDismissListener((AutoCompleteTextView.OnDismissListener) null);
                }
            }
            if (previousIcon == 3) {
                textInputLayout.removeOnAttachStateChangeListener(DropdownMenuEndIconDelegate.this.onAttachStateChangeListener);
                DropdownMenuEndIconDelegate.this.removeTouchExplorationStateChangeListenerIfNeeded();
            }
        }
    };
    /* access modifiers changed from: private */
    public final TextWatcher exposedDropdownEndIconTextWatcher = new TextWatcherAdapter() {
        public void afterTextChanged(Editable s) {
            final AutoCompleteTextView editText = DropdownMenuEndIconDelegate.castAutoCompleteTextViewOrThrow(DropdownMenuEndIconDelegate.this.textInputLayout.getEditText());
            if (DropdownMenuEndIconDelegate.this.accessibilityManager.isTouchExplorationEnabled() && DropdownMenuEndIconDelegate.isEditable(editText) && !DropdownMenuEndIconDelegate.this.endIconView.hasFocus()) {
                editText.dismissDropDown();
            }
            editText.post(new Runnable() {
                public void run() {
                    boolean isPopupShowing = editText.isPopupShowing();
                    DropdownMenuEndIconDelegate.this.setEndIconChecked(isPopupShowing);
                    boolean unused = DropdownMenuEndIconDelegate.this.dropdownPopupDirty = isPopupShowing;
                }
            });
        }
    };
    /* access modifiers changed from: private */
    public ValueAnimator fadeInAnim;
    private ValueAnimator fadeOutAnim;
    private StateListDrawable filledPopupBackground;
    /* access modifiers changed from: private */
    public boolean isEndIconChecked = false;
    /* access modifiers changed from: private */
    public final View.OnAttachStateChangeListener onAttachStateChangeListener = new View.OnAttachStateChangeListener() {
        public void onViewAttachedToWindow(View ignored) {
            DropdownMenuEndIconDelegate.this.addTouchExplorationStateChangeListenerIfNeeded();
        }

        public void onViewDetachedFromWindow(View ignored) {
            DropdownMenuEndIconDelegate.this.removeTouchExplorationStateChangeListenerIfNeeded();
        }
    };
    /* access modifiers changed from: private */
    public final View.OnFocusChangeListener onFocusChangeListener = new View.OnFocusChangeListener() {
        public void onFocusChange(View v, boolean hasFocus) {
            DropdownMenuEndIconDelegate.this.textInputLayout.setEndIconActivated(hasFocus);
            if (!hasFocus) {
                DropdownMenuEndIconDelegate.this.setEndIconChecked(false);
                boolean unused = DropdownMenuEndIconDelegate.this.dropdownPopupDirty = false;
            }
        }
    };
    private MaterialShapeDrawable outlinedPopupBackground;
    private final AccessibilityManagerCompat.TouchExplorationStateChangeListener touchExplorationStateChangeListener = new AccessibilityManagerCompat.TouchExplorationStateChangeListener() {
        public void onTouchExplorationStateChanged(boolean enabled) {
            AutoCompleteTextView autoCompleteTextView;
            if (DropdownMenuEndIconDelegate.this.textInputLayout != null && (autoCompleteTextView = (AutoCompleteTextView) DropdownMenuEndIconDelegate.this.textInputLayout.getEditText()) != null && !DropdownMenuEndIconDelegate.isEditable(autoCompleteTextView)) {
                ViewCompat.setImportantForAccessibility(DropdownMenuEndIconDelegate.this.endIconView, enabled ? 2 : 1);
            }
        }
    };

    DropdownMenuEndIconDelegate(TextInputLayout textInputLayout, int customEndIcon) {
        super(textInputLayout, customEndIcon);
    }

    /* access modifiers changed from: package-private */
    public void initialize() {
        int drawableResId;
        float popupCornerRadius = (float) this.context.getResources().getDimensionPixelOffset(C0105R.dimen.mtrl_shape_corner_size_small_component);
        float exposedDropdownPopupElevation = (float) this.context.getResources().getDimensionPixelOffset(C0105R.dimen.mtrl_exposed_dropdown_menu_popup_elevation);
        int exposedDropdownPopupVerticalPadding = this.context.getResources().getDimensionPixelOffset(C0105R.dimen.mtrl_exposed_dropdown_menu_popup_vertical_padding);
        MaterialShapeDrawable roundedCornersPopupBackground = getPopUpMaterialShapeDrawable(popupCornerRadius, popupCornerRadius, exposedDropdownPopupElevation, exposedDropdownPopupVerticalPadding);
        MaterialShapeDrawable roundedBottomCornersPopupBackground = getPopUpMaterialShapeDrawable(0.0f, popupCornerRadius, exposedDropdownPopupElevation, exposedDropdownPopupVerticalPadding);
        this.outlinedPopupBackground = roundedCornersPopupBackground;
        StateListDrawable stateListDrawable = new StateListDrawable();
        this.filledPopupBackground = stateListDrawable;
        stateListDrawable.addState(new int[]{16842922}, roundedCornersPopupBackground);
        this.filledPopupBackground.addState(new int[0], roundedBottomCornersPopupBackground);
        if (this.customEndIcon == 0) {
            drawableResId = IS_LOLLIPOP ? C0105R.C0107drawable.mtrl_dropdown_arrow : C0105R.C0107drawable.mtrl_ic_arrow_drop_down;
        } else {
            drawableResId = this.customEndIcon;
        }
        this.textInputLayout.setEndIconDrawable(drawableResId);
        this.textInputLayout.setEndIconContentDescription(this.textInputLayout.getResources().getText(C0105R.string.exposed_dropdown_menu_content_description));
        this.textInputLayout.setEndIconOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                DropdownMenuEndIconDelegate.this.showHideDropdown((AutoCompleteTextView) DropdownMenuEndIconDelegate.this.textInputLayout.getEditText());
            }
        });
        this.textInputLayout.addOnEditTextAttachedListener(this.dropdownMenuOnEditTextAttachedListener);
        this.textInputLayout.addOnEndIconChangedListener(this.endIconChangedListener);
        initAnimators();
        this.accessibilityManager = (AccessibilityManager) this.context.getSystemService("accessibility");
        this.textInputLayout.addOnAttachStateChangeListener(this.onAttachStateChangeListener);
        addTouchExplorationStateChangeListenerIfNeeded();
    }

    /* access modifiers changed from: package-private */
    public boolean shouldTintIconOnError() {
        return true;
    }

    /* access modifiers changed from: package-private */
    public boolean isBoxBackgroundModeSupported(int boxBackgroundMode) {
        return boxBackgroundMode != 0;
    }

    /* access modifiers changed from: private */
    public void showHideDropdown(AutoCompleteTextView editText) {
        if (editText != null) {
            if (isDropdownPopupActive()) {
                this.dropdownPopupDirty = false;
            }
            if (!this.dropdownPopupDirty) {
                if (IS_LOLLIPOP) {
                    setEndIconChecked(!this.isEndIconChecked);
                } else {
                    this.isEndIconChecked = !this.isEndIconChecked;
                    this.endIconView.toggle();
                }
                if (this.isEndIconChecked) {
                    editText.requestFocus();
                    editText.showDropDown();
                    return;
                }
                editText.dismissDropDown();
                return;
            }
            this.dropdownPopupDirty = false;
        }
    }

    /* access modifiers changed from: private */
    public void setPopupBackground(AutoCompleteTextView editText) {
        if (IS_LOLLIPOP) {
            int boxBackgroundMode = this.textInputLayout.getBoxBackgroundMode();
            if (boxBackgroundMode == 2) {
                editText.setDropDownBackgroundDrawable(this.outlinedPopupBackground);
            } else if (boxBackgroundMode == 1) {
                editText.setDropDownBackgroundDrawable(this.filledPopupBackground);
            }
        }
    }

    /* access modifiers changed from: package-private */
    public void updateOutlinedRippleEffect(AutoCompleteTextView editText) {
        if (!isEditable(editText) && this.textInputLayout.getBoxBackgroundMode() == 2 && (editText.getBackground() instanceof LayerDrawable)) {
            addRippleEffect(editText);
        }
    }

    /* access modifiers changed from: private */
    public void addRippleEffect(AutoCompleteTextView editText) {
        if (!isEditable(editText)) {
            int boxBackgroundMode = this.textInputLayout.getBoxBackgroundMode();
            MaterialShapeDrawable boxBackground = this.textInputLayout.getBoxBackground();
            int rippleColor = MaterialColors.getColor(editText, C0105R.attr.colorControlHighlight);
            int[][] states = {new int[]{16842919}, new int[0]};
            if (boxBackgroundMode == 2) {
                addRippleEffectOnOutlinedLayout(editText, rippleColor, states, boxBackground);
            } else if (boxBackgroundMode == 1) {
                addRippleEffectOnFilledLayout(editText, rippleColor, states, boxBackground);
            }
        }
    }

    private void addRippleEffectOnOutlinedLayout(AutoCompleteTextView editText, int rippleColor, int[][] states, MaterialShapeDrawable boxBackground) {
        LayerDrawable editTextBackground;
        int surfaceColor = MaterialColors.getColor(editText, C0105R.attr.colorSurface);
        MaterialShapeDrawable rippleBackground = new MaterialShapeDrawable(boxBackground.getShapeAppearanceModel());
        int pressedBackgroundColor = MaterialColors.layer(rippleColor, surfaceColor, 0.1f);
        rippleBackground.setFillColor(new ColorStateList(states, new int[]{pressedBackgroundColor, 0}));
        if (IS_LOLLIPOP) {
            rippleBackground.setTint(surfaceColor);
            ColorStateList rippleColorStateList = new ColorStateList(states, new int[]{pressedBackgroundColor, surfaceColor});
            MaterialShapeDrawable mask = new MaterialShapeDrawable(boxBackground.getShapeAppearanceModel());
            mask.setTint(-1);
            editTextBackground = new LayerDrawable(new Drawable[]{new RippleDrawable(rippleColorStateList, rippleBackground, mask), boxBackground});
        } else {
            editTextBackground = new LayerDrawable(new Drawable[]{rippleBackground, boxBackground});
        }
        ViewCompat.setBackground(editText, editTextBackground);
    }

    private void addRippleEffectOnFilledLayout(AutoCompleteTextView editText, int rippleColor, int[][] states, MaterialShapeDrawable boxBackground) {
        int boxBackgroundColor = this.textInputLayout.getBoxBackgroundColor();
        int[] colors = {MaterialColors.layer(rippleColor, boxBackgroundColor, 0.1f), boxBackgroundColor};
        if (IS_LOLLIPOP) {
            ViewCompat.setBackground(editText, new RippleDrawable(new ColorStateList(states, colors), boxBackground, boxBackground));
            return;
        }
        MaterialShapeDrawable rippleBackground = new MaterialShapeDrawable(boxBackground.getShapeAppearanceModel());
        rippleBackground.setFillColor(new ColorStateList(states, colors));
        LayerDrawable editTextBackground = new LayerDrawable(new Drawable[]{boxBackground, rippleBackground});
        int start = ViewCompat.getPaddingStart(editText);
        int top = editText.getPaddingTop();
        int end = ViewCompat.getPaddingEnd(editText);
        int bottom = editText.getPaddingBottom();
        ViewCompat.setBackground(editText, editTextBackground);
        ViewCompat.setPaddingRelative(editText, start, top, end, bottom);
    }

    /* access modifiers changed from: private */
    public void setUpDropdownShowHideBehavior(final AutoCompleteTextView editText) {
        editText.setOnTouchListener(new View.OnTouchListener() {
            public boolean onTouch(View v, MotionEvent event) {
                if (event.getAction() == 1) {
                    if (DropdownMenuEndIconDelegate.this.isDropdownPopupActive()) {
                        boolean unused = DropdownMenuEndIconDelegate.this.dropdownPopupDirty = false;
                    }
                    DropdownMenuEndIconDelegate.this.showHideDropdown(editText);
                    DropdownMenuEndIconDelegate.this.updateDropdownPopupDirty();
                }
                return false;
            }
        });
        editText.setOnFocusChangeListener(this.onFocusChangeListener);
        if (IS_LOLLIPOP) {
            editText.setOnDismissListener(new AutoCompleteTextView.OnDismissListener() {
                public void onDismiss() {
                    DropdownMenuEndIconDelegate.this.updateDropdownPopupDirty();
                    DropdownMenuEndIconDelegate.this.setEndIconChecked(false);
                }
            });
        }
    }

    private MaterialShapeDrawable getPopUpMaterialShapeDrawable(float topCornerRadius, float bottomCornerRadius, float elevation, int verticalPadding) {
        ShapeAppearanceModel shapeAppearanceModel = ShapeAppearanceModel.builder().setTopLeftCornerSize(topCornerRadius).setTopRightCornerSize(topCornerRadius).setBottomLeftCornerSize(bottomCornerRadius).setBottomRightCornerSize(bottomCornerRadius).build();
        MaterialShapeDrawable popupDrawable = MaterialShapeDrawable.createWithElevationOverlay(this.context, elevation);
        popupDrawable.setShapeAppearanceModel(shapeAppearanceModel);
        popupDrawable.setPadding(0, verticalPadding, 0, verticalPadding);
        return popupDrawable;
    }

    /* access modifiers changed from: private */
    public boolean isDropdownPopupActive() {
        long activeFor = System.currentTimeMillis() - this.dropdownPopupActivatedAt;
        return activeFor < 0 || activeFor > 300;
    }

    /* access modifiers changed from: private */
    public static AutoCompleteTextView castAutoCompleteTextViewOrThrow(EditText editText) {
        if (editText instanceof AutoCompleteTextView) {
            return (AutoCompleteTextView) editText;
        }
        throw new RuntimeException("EditText needs to be an AutoCompleteTextView if an Exposed Dropdown Menu is being used.");
    }

    /* access modifiers changed from: private */
    public void updateDropdownPopupDirty() {
        this.dropdownPopupDirty = true;
        this.dropdownPopupActivatedAt = System.currentTimeMillis();
    }

    /* access modifiers changed from: private */
    public static boolean isEditable(EditText editText) {
        return editText.getKeyListener() != null;
    }

    /* access modifiers changed from: private */
    public void setEndIconChecked(boolean checked) {
        if (this.isEndIconChecked != checked) {
            this.isEndIconChecked = checked;
            this.fadeInAnim.cancel();
            this.fadeOutAnim.start();
        }
    }

    private void initAnimators() {
        this.fadeInAnim = getAlphaAnimator(67, 0.0f, 1.0f);
        ValueAnimator alphaAnimator = getAlphaAnimator(50, 1.0f, 0.0f);
        this.fadeOutAnim = alphaAnimator;
        alphaAnimator.addListener(new AnimatorListenerAdapter() {
            public void onAnimationEnd(Animator animation) {
                DropdownMenuEndIconDelegate.this.endIconView.setChecked(DropdownMenuEndIconDelegate.this.isEndIconChecked);
                DropdownMenuEndIconDelegate.this.fadeInAnim.start();
            }
        });
    }

    private ValueAnimator getAlphaAnimator(int duration, float... values) {
        ValueAnimator animator = ValueAnimator.ofFloat(values);
        animator.setInterpolator(AnimationUtils.LINEAR_INTERPOLATOR);
        animator.setDuration((long) duration);
        animator.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() {
            public void onAnimationUpdate(ValueAnimator animation) {
                DropdownMenuEndIconDelegate.this.endIconView.setAlpha(((Float) animation.getAnimatedValue()).floatValue());
            }
        });
        return animator;
    }

    /* access modifiers changed from: private */
    public void addTouchExplorationStateChangeListenerIfNeeded() {
        if (this.accessibilityManager != null && this.textInputLayout != null && ViewCompat.isAttachedToWindow(this.textInputLayout)) {
            AccessibilityManagerCompat.addTouchExplorationStateChangeListener(this.accessibilityManager, this.touchExplorationStateChangeListener);
        }
    }

    /* access modifiers changed from: private */
    public void removeTouchExplorationStateChangeListenerIfNeeded() {
        AccessibilityManager accessibilityManager2 = this.accessibilityManager;
        if (accessibilityManager2 != null) {
            AccessibilityManagerCompat.removeTouchExplorationStateChangeListener(accessibilityManager2, this.touchExplorationStateChangeListener);
        }
    }
}
