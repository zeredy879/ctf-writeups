package com.google.android.material.behavior;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.TimeInterpolator;
import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewPropertyAnimator;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import com.google.android.material.animation.AnimationUtils;

public class HideBottomViewOnScrollBehavior<V extends View> extends CoordinatorLayout.Behavior<V> {
    protected static final int ENTER_ANIMATION_DURATION = 225;
    protected static final int EXIT_ANIMATION_DURATION = 175;
    private static final int STATE_SCROLLED_DOWN = 1;
    private static final int STATE_SCROLLED_UP = 2;
    private int additionalHiddenOffsetY = 0;
    /* access modifiers changed from: private */
    public ViewPropertyAnimator currentAnimator;
    private int currentState = 2;
    private int height = 0;

    public HideBottomViewOnScrollBehavior() {
    }

    public HideBottomViewOnScrollBehavior(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    public boolean onLayoutChild(CoordinatorLayout parent, V child, int layoutDirection) {
        this.height = child.getMeasuredHeight() + ((ViewGroup.MarginLayoutParams) child.getLayoutParams()).bottomMargin;
        return super.onLayoutChild(parent, child, layoutDirection);
    }

    public void setAdditionalHiddenOffsetY(V child, int offset) {
        this.additionalHiddenOffsetY = offset;
        if (this.currentState == 1) {
            child.setTranslationY((float) (this.height + offset));
        }
    }

    public boolean onStartNestedScroll(CoordinatorLayout coordinatorLayout, V v, View directTargetChild, View target, int nestedScrollAxes, int type) {
        return nestedScrollAxes == 2;
    }

    public void onNestedScroll(CoordinatorLayout coordinatorLayout, V child, View target, int dxConsumed, int dyConsumed, int dxUnconsumed, int dyUnconsumed, int type, int[] consumed) {
        if (dyConsumed > 0) {
            slideDown(child);
        } else if (dyConsumed < 0) {
            slideUp(child);
        }
    }

    public boolean isScrolledUp() {
        return this.currentState == 2;
    }

    public void slideUp(V child) {
        slideUp(child, true);
    }

    public void slideUp(V child, boolean animate) {
        if (!isScrolledUp()) {
            ViewPropertyAnimator viewPropertyAnimator = this.currentAnimator;
            if (viewPropertyAnimator != null) {
                viewPropertyAnimator.cancel();
                child.clearAnimation();
            }
            this.currentState = 2;
            if (animate) {
                animateChildTo(child, 0, 225, AnimationUtils.LINEAR_OUT_SLOW_IN_INTERPOLATOR);
                return;
            }
            child.setTranslationY((float) 0);
        }
    }

    public boolean isScrolledDown() {
        return this.currentState == 1;
    }

    public void slideDown(V child) {
        slideDown(child, true);
    }

    public void slideDown(V child, boolean animate) {
        if (!isScrolledDown()) {
            ViewPropertyAnimator viewPropertyAnimator = this.currentAnimator;
            if (viewPropertyAnimator != null) {
                viewPropertyAnimator.cancel();
                child.clearAnimation();
            }
            this.currentState = 1;
            int targetTranslationY = this.height + this.additionalHiddenOffsetY;
            if (animate) {
                animateChildTo(child, targetTranslationY, 175, AnimationUtils.FAST_OUT_LINEAR_IN_INTERPOLATOR);
                return;
            }
            child.setTranslationY((float) targetTranslationY);
        }
    }

    private void animateChildTo(V child, int targetY, long duration, TimeInterpolator interpolator) {
        this.currentAnimator = child.animate().translationY((float) targetY).setInterpolator(interpolator).setDuration(duration).setListener(new AnimatorListenerAdapter() {
            public void onAnimationEnd(Animator animation) {
                ViewPropertyAnimator unused = HideBottomViewOnScrollBehavior.this.currentAnimator = null;
            }
        });
    }
}
