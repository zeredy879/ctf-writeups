package com.google.android.material.shape;

import android.graphics.RectF;
import java.util.Arrays;

public final class RelativeCornerSize implements CornerSize {
    private final float percent;

    public RelativeCornerSize(float percent2) {
        this.percent = percent2;
    }

    public float getRelativePercent() {
        return this.percent;
    }

    public float getCornerSize(RectF bounds) {
        return this.percent * bounds.height();
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if ((o instanceof RelativeCornerSize) && this.percent == ((RelativeCornerSize) o).percent) {
            return true;
        }
        return false;
    }

    public int hashCode() {
        return Arrays.hashCode(new Object[]{Float.valueOf(this.percent)});
    }
}
