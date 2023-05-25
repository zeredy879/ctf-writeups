package com.google.android.material.textfield;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ValueAnimator;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.EditText;
import com.google.android.material.C0105R;
import com.google.android.material.animation.AnimationUtils;
import com.google.android.material.textfield.TextInputLayout;

class ClearTextEndIconDelegate extends EndIconDelegate {
    private static final int ANIMATION_FADE_DURATION = 100;
    private static final int ANIMATION_SCALE_DURATION = 150;
    private static final float ANIMATION_SCALE_FROM_VALUE = 0.8f;
    /* access modifiers changed from: private */
    public final TextWatcher clearTextEndIconTextWatcher = new TextWatcher() {
        public void beforeTextChanged(CharSequence s, int start, int count, int after) {
        }

        public void onTextChanged(CharSequence s, int start, int before, int count) {
        }

        public void afterTextChanged(Editable s) {
            if (ClearTextEndIconDelegate.this.textInputLayout.getSuffixText() == null) {
                ClearTextEndIconDelegate clearTextEndIconDelegate = ClearTextEndIconDelegate.this;
                clearTextEndIconDelegate.animateIcon(clearTextEndIconDelegate.shouldBeVisible());
            }
        }
    };
    private final TextInputLayout.OnEditTextAttachedListener clearTextOnEditTextAttachedListener = new TextInputLayout.OnEditTextAttachedListener() {
        public void onEditTextAttached(TextInputLayout textInputLayout) {
            EditText editText = textInputLayout.getEditText();
            textInputLayout.setEndIconVisible(ClearTextEndIconDelegate.this.shouldBeVisible());
            editText.setOnFocusChangeListener(ClearTextEndIconDelegate.this.onFocusChangeListener);
            ClearTextEndIconDelegate.this.endIconView.setOnFocusChangeListener(ClearTextEndIconDelegate.this.onFocusChangeListener);
            editText.removeTextChangedListener(ClearTextEndIconDelegate.this.clearTextEndIconTextWatcher);
            editText.addTextChangedListener(ClearTextEndIconDelegate.this.clearTextEndIconTextWatcher);
        }
    };
    private final TextInputLayout.OnEndIconChangedListener endIconChangedListener = new TextInputLayout.OnEndIconChangedListener() {
        public void onEndIconChanged(TextInputLayout textInputLayout, int previousIcon) {
            final EditText editText = textInputLayout.getEditText();
            if (editText != null && previousIcon == 2) {
                editText.post(new Runnable() {
                    public void run() {
                        editText.removeTextChangedListener(ClearTextEndIconDelegate.this.clearTextEndIconTextWatcher);
                        ClearTextEndIconDelegate.this.animateIcon(true);
                    }
                });
                if (editText.getOnFocusChangeListener() == ClearTextEndIconDelegate.this.onFocusChangeListener) {
                    editText.setOnFocusChangeListener((View.OnFocusChangeListener) null);
                }
                if (ClearTextEndIconDelegate.this.endIconView.getOnFocusChangeListener() == ClearTextEndIconDelegate.this.onFocusChangeListener) {
                    ClearTextEndIconDelegate.this.endIconView.setOnFocusChangeListener((View.OnFocusChangeListener) null);
                }
            }
        }
    };
    private AnimatorSet iconInAnim;
    private ValueAnimator iconOutAnim;
    /* access modifiers changed from: private */
    public final View.OnFocusChangeListener onFocusChangeListener = new View.OnFocusChangeListener() {
        public void onFocusChange(View v, boolean hasFocus) {
            ClearTextEndIconDelegate clearTextEndIconDelegate = ClearTextEndIconDelegate.this;
            clearTextEndIconDelegate.animateIcon(clearTextEndIconDelegate.shouldBeVisible());
        }
    };

    ClearTextEndIconDelegate(TextInputLayout textInputLayout, int customEndIcon) {
        super(textInputLayout, customEndIcon);
    }

    /* access modifiers changed from: package-private */
    public void initialize() {
        this.textInputLayout.setEndIconDrawable(this.customEndIcon == 0 ? C0105R.C0107drawable.mtrl_ic_cancel : this.customEndIcon);
        this.textInputLayout.setEndIconContentDescription(this.textInputLayout.getResources().getText(C0105R.string.clear_text_end_icon_content_description));
        this.textInputLayout.setEndIconCheckable(false);
        this.textInputLayout.setEndIconOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                Editable text = ClearTextEndIconDelegate.this.textInputLayout.getEditText().getText();
                if (text != null) {
                    text.clear();
                }
                ClearTextEndIconDelegate.this.textInputLayout.refreshEndIconDrawableState();
            }
        });
        this.textInputLayout.addOnEditTextAttachedListener(this.clearTextOnEditTextAttachedListener);
        this.textInputLayout.addOnEndIconChangedListener(this.endIconChangedListener);
        initAnimators();
    }

    /* access modifiers changed from: package-private */
    public void onSuffixVisibilityChanged(boolean visible) {
        if (this.textInputLayout.getSuffixText() != null) {
            animateIcon(visible);
        }
    }

    /* access modifiers changed from: private */
    public void animateIcon(boolean show) {
        boolean shouldSkipAnimation = this.textInputLayout.isEndIconVisible() == show;
        if (show && !this.iconInAnim.isRunning()) {
            this.iconOutAnim.cancel();
            this.iconInAnim.start();
            if (shouldSkipAnimation) {
                this.iconInAnim.end();
            }
        } else if (!show) {
            this.iconInAnim.cancel();
            this.iconOutAnim.start();
            if (shouldSkipAnimation) {
                this.iconOutAnim.end();
            }
        }
    }

    private void initAnimators() {
        ValueAnimator scaleAnimator = getScaleAnimator();
        ValueAnimator fadeAnimator = getAlphaAnimator(0.0f, 1.0f);
        AnimatorSet animatorSet = new AnimatorSet();
        this.iconInAnim = animatorSet;
        animatorSet.playTogether(new Animator[]{scaleAnimator, fadeAnimator});
        this.iconInAnim.addListener(new AnimatorListenerAdapter() {
            public void onAnimationStart(Animator animation) {
                ClearTextEndIconDelegate.this.textInputLayout.setEndIconVisible(true);
            }
        });
        ValueAnimator alphaAnimator = getAlphaAnimator(1.0f, 0.0f);
        this.iconOutAnim = alphaAnimator;
        alphaAnimator.addListener(new AnimatorListenerAdapter() {
            public void onAnimationEnd(Animator animation) {
                ClearTextEndIconDelegate.this.textInputLayout.setEndIconVisible(false);
            }
        });
    }

    private ValueAnimator getAlphaAnimator(float... values) {
        ValueAnimator animator = ValueAnimator.ofFloat(values);
        animator.setInterpolator(AnimationUtils.LINEAR_INTERPOLATOR);
        animator.setDuration(100);
        animator.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() {
            public void onAnimationUpdate(ValueAnimator animation) {
                ClearTextEndIconDelegate.this.endIconView.setAlpha(((Float) animation.getAnimatedValue()).floatValue());
            }
        });
        return animator;
    }

    private ValueAnimator getScaleAnimator() {
        ValueAnimator animator = ValueAnimator.ofFloat(new float[]{ANIMATION_SCALE_FROM_VALUE, 1.0f});
        animator.setInterpolator(AnimationUtils.LINEAR_OUT_SLOW_IN_INTERPOLATOR);
        animator.setDuration(150);
        animator.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() {
            public void onAnimationUpdate(ValueAnimator animation) {
                float scale = ((Float) animation.getAnimatedValue()).floatValue();
                ClearTextEndIconDelegate.this.endIconView.setScaleX(scale);
                ClearTextEndIconDelegate.this.endIconView.setScaleY(scale);
            }
        });
        return animator;
    }

    /* access modifiers changed from: private */
    public boolean shouldBeVisible() {
        EditText editText = this.textInputLayout.getEditText();
        return editText != null && (editText.hasFocus() || this.endIconView.hasFocus()) && editText.getText().length() > 0;
    }
}
