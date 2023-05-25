package com.google.android.material.timepicker;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.util.Pair;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewConfiguration;
import androidx.core.view.ViewCompat;
import com.google.android.material.C0105R;
import java.util.ArrayList;
import java.util.List;

class ClockHandView extends View {
    private static final int ANIMATION_DURATION = 200;
    private boolean animatingOnTouchUp;
    private final float centerDotRadius;
    private boolean changedDuringTouch;
    private int circleRadius;
    private double degRad;
    private float downX;
    private float downY;
    private boolean isInTapRegion;
    private final List<OnRotateListener> listeners;
    private OnActionUpListener onActionUpListener;
    private float originalDeg;
    private final Paint paint;
    private ValueAnimator rotationAnimator;
    private int scaledTouchSlop;
    private final RectF selectorBox;
    private final int selectorRadius;
    private final int selectorStrokeWidth;

    public interface OnActionUpListener {
        void onActionUp(float f, boolean z);
    }

    public interface OnRotateListener {
        void onRotate(float f, boolean z);
    }

    public ClockHandView(Context context) {
        this(context, (AttributeSet) null);
    }

    public ClockHandView(Context context, AttributeSet attrs) {
        this(context, attrs, C0105R.attr.materialClockStyle);
    }

    public ClockHandView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.listeners = new ArrayList();
        Paint paint2 = new Paint();
        this.paint = paint2;
        this.selectorBox = new RectF();
        TypedArray a = context.obtainStyledAttributes(attrs, C0105R.styleable.ClockHandView, defStyleAttr, C0105R.style.Widget_MaterialComponents_TimePicker_Clock);
        this.circleRadius = a.getDimensionPixelSize(C0105R.styleable.ClockHandView_materialCircleRadius, 0);
        this.selectorRadius = a.getDimensionPixelSize(C0105R.styleable.ClockHandView_selectorSize, 0);
        Resources res = getResources();
        this.selectorStrokeWidth = res.getDimensionPixelSize(C0105R.dimen.material_clock_hand_stroke_width);
        this.centerDotRadius = (float) res.getDimensionPixelSize(C0105R.dimen.material_clock_hand_center_dot_radius);
        int selectorColor = a.getColor(C0105R.styleable.ClockHandView_clockHandColor, 0);
        paint2.setAntiAlias(true);
        paint2.setColor(selectorColor);
        setHandRotation(0.0f);
        this.scaledTouchSlop = ViewConfiguration.get(context).getScaledTouchSlop();
        ViewCompat.setImportantForAccessibility(this, 2);
        a.recycle();
    }

    /* access modifiers changed from: protected */
    public void onLayout(boolean changed, int left, int top, int right, int bottom) {
        super.onLayout(changed, left, top, right, bottom);
        setHandRotation(getHandRotation());
    }

    public void setHandRotation(float degrees) {
        setHandRotation(degrees, false);
    }

    public void setHandRotation(float degrees, boolean animate) {
        ValueAnimator valueAnimator = this.rotationAnimator;
        if (valueAnimator != null) {
            valueAnimator.cancel();
        }
        if (!animate) {
            setHandRotationInternal(degrees, false);
            return;
        }
        Pair<Float, Float> animationValues = getValuesForAnimation(degrees);
        ValueAnimator ofFloat = ValueAnimator.ofFloat(new float[]{((Float) animationValues.first).floatValue(), ((Float) animationValues.second).floatValue()});
        this.rotationAnimator = ofFloat;
        ofFloat.setDuration(200);
        this.rotationAnimator.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() {
            public void onAnimationUpdate(ValueAnimator animation) {
                ClockHandView.this.setHandRotationInternal(((Float) animation.getAnimatedValue()).floatValue(), true);
            }
        });
        this.rotationAnimator.addListener(new AnimatorListenerAdapter() {
            public void onAnimationCancel(Animator animation) {
                animation.end();
            }
        });
        this.rotationAnimator.start();
    }

    private Pair<Float, Float> getValuesForAnimation(float degrees) {
        float currentDegrees = getHandRotation();
        if (Math.abs(currentDegrees - degrees) > 180.0f) {
            if (currentDegrees > 180.0f && degrees < 180.0f) {
                degrees += 360.0f;
            }
            if (currentDegrees < 180.0f && degrees > 180.0f) {
                currentDegrees += 360.0f;
            }
        }
        return new Pair<>(Float.valueOf(currentDegrees), Float.valueOf(degrees));
    }

    /* access modifiers changed from: private */
    public void setHandRotationInternal(float degrees, boolean animate) {
        float degrees2 = degrees % 360.0f;
        this.originalDeg = degrees2;
        this.degRad = Math.toRadians((double) (degrees2 - 90.0f));
        float selCenterX = ((float) (getWidth() / 2)) + (((float) this.circleRadius) * ((float) Math.cos(this.degRad)));
        float selCenterY = ((float) (getHeight() / 2)) + (((float) this.circleRadius) * ((float) Math.sin(this.degRad)));
        RectF rectF = this.selectorBox;
        int i = this.selectorRadius;
        rectF.set(selCenterX - ((float) i), selCenterY - ((float) i), ((float) i) + selCenterX, ((float) i) + selCenterY);
        for (OnRotateListener listener : this.listeners) {
            listener.onRotate(degrees2, animate);
        }
        invalidate();
    }

    public void setAnimateOnTouchUp(boolean animating) {
        this.animatingOnTouchUp = animating;
    }

    public void addOnRotateListener(OnRotateListener listener) {
        this.listeners.add(listener);
    }

    public void setOnActionUpListener(OnActionUpListener listener) {
        this.onActionUpListener = listener;
    }

    public float getHandRotation() {
        return this.originalDeg;
    }

    /* access modifiers changed from: protected */
    public void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        drawSelector(canvas);
    }

    private void drawSelector(Canvas canvas) {
        Canvas canvas2 = canvas;
        int yCenter = getHeight() / 2;
        int xCenter = getWidth() / 2;
        float selCenterX = ((float) xCenter) + (((float) this.circleRadius) * ((float) Math.cos(this.degRad)));
        float selCenterY = ((float) yCenter) + (((float) this.circleRadius) * ((float) Math.sin(this.degRad)));
        this.paint.setStrokeWidth(0.0f);
        canvas2.drawCircle(selCenterX, selCenterY, (float) this.selectorRadius, this.paint);
        double sin = Math.sin(this.degRad);
        double cos = Math.cos(this.degRad);
        float lineLength = (float) (this.circleRadius - this.selectorRadius);
        float linePointX = (float) (((int) (((double) lineLength) * cos)) + xCenter);
        this.paint.setStrokeWidth((float) this.selectorStrokeWidth);
        Canvas canvas3 = canvas;
        float linePointY = (float) (((int) (((double) lineLength) * sin)) + yCenter);
        float f = linePointX;
        float f2 = lineLength;
        canvas3.drawLine((float) xCenter, (float) yCenter, linePointX, linePointY, this.paint);
        canvas2.drawCircle((float) xCenter, (float) yCenter, this.centerDotRadius, this.paint);
    }

    public RectF getCurrentSelectorBox() {
        return this.selectorBox;
    }

    public int getSelectorRadius() {
        return this.selectorRadius;
    }

    public void setCircleRadius(int circleRadius2) {
        this.circleRadius = circleRadius2;
        invalidate();
    }

    public boolean onTouchEvent(MotionEvent event) {
        OnActionUpListener onActionUpListener2;
        int action = event.getActionMasked();
        boolean forceSelection = false;
        boolean actionDown = false;
        boolean actionUp = false;
        float x = event.getX();
        float y = event.getY();
        boolean z = false;
        switch (action) {
            case 0:
                this.downX = x;
                this.downY = y;
                this.isInTapRegion = true;
                this.changedDuringTouch = false;
                actionDown = true;
                break;
            case 1:
            case 2:
                int deltaX = (int) (x - this.downX);
                int deltaY = (int) (y - this.downY);
                this.isInTapRegion = (deltaX * deltaX) + (deltaY * deltaY) > this.scaledTouchSlop;
                if (this.changedDuringTouch) {
                    forceSelection = true;
                }
                if (action == 1) {
                    z = true;
                }
                actionUp = z;
                break;
        }
        boolean handleTouchInput = handleTouchInput(x, y, forceSelection, actionDown, actionUp) | this.changedDuringTouch;
        this.changedDuringTouch = handleTouchInput;
        if (handleTouchInput && actionUp && (onActionUpListener2 = this.onActionUpListener) != null) {
            onActionUpListener2.onActionUp((float) getDegreesFromXY(x, y), this.isInTapRegion);
        }
        return true;
    }

    private boolean handleTouchInput(float x, float y, boolean forceSelection, boolean touchDown, boolean actionUp) {
        int degrees = getDegreesFromXY(x, y);
        boolean z = false;
        boolean valueChanged = getHandRotation() != ((float) degrees);
        if (touchDown && valueChanged) {
            return true;
        }
        if (!valueChanged && !forceSelection) {
            return false;
        }
        float f = (float) degrees;
        if (actionUp && this.animatingOnTouchUp) {
            z = true;
        }
        setHandRotation(f, z);
        return true;
    }

    private int getDegreesFromXY(float x, float y) {
        int degrees = ((int) Math.toDegrees(Math.atan2((double) (y - ((float) (getHeight() / 2))), (double) (x - ((float) (getWidth() / 2)))))) + 90;
        if (degrees < 0) {
            return degrees + 360;
        }
        return degrees;
    }
}
