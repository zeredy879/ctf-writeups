package com.google.android.material.motion;

import android.animation.TimeInterpolator;
import android.content.Context;
import android.util.TypedValue;
import androidx.core.graphics.PathParser;
import androidx.core.view.animation.PathInterpolatorCompat;
import com.google.android.material.resources.MaterialAttributes;

public class MotionUtils {
    private static final String EASING_TYPE_CUBIC_BEZIER = "cubic-bezier";
    private static final String EASING_TYPE_FORMAT_END = ")";
    private static final String EASING_TYPE_FORMAT_START = "(";
    private static final String EASING_TYPE_PATH = "path";

    private MotionUtils() {
    }

    public static int resolveThemeDuration(Context context, int attrResId, int defaultDuration) {
        return MaterialAttributes.resolveInteger(context, attrResId, defaultDuration);
    }

    public static TimeInterpolator resolveThemeInterpolator(Context context, int attrResId, TimeInterpolator defaultInterpolator) {
        TypedValue easingValue = new TypedValue();
        if (!context.getTheme().resolveAttribute(attrResId, easingValue, true)) {
            return defaultInterpolator;
        }
        if (easingValue.type == 3) {
            String easingString = String.valueOf(easingValue.string);
            if (isEasingType(easingString, EASING_TYPE_CUBIC_BEZIER)) {
                String[] controlPoints = getEasingContent(easingString, EASING_TYPE_CUBIC_BEZIER).split(",");
                if (controlPoints.length == 4) {
                    return PathInterpolatorCompat.create(getControlPoint(controlPoints, 0), getControlPoint(controlPoints, 1), getControlPoint(controlPoints, 2), getControlPoint(controlPoints, 3));
                }
                throw new IllegalArgumentException("Motion easing theme attribute must have 4 control points if using bezier curve format; instead got: " + controlPoints.length);
            } else if (isEasingType(easingString, EASING_TYPE_PATH)) {
                return PathInterpolatorCompat.create(PathParser.createPathFromPathData(getEasingContent(easingString, EASING_TYPE_PATH)));
            } else {
                throw new IllegalArgumentException("Invalid motion easing type: " + easingString);
            }
        } else {
            throw new IllegalArgumentException("Motion easing theme attribute must be a string");
        }
    }

    private static boolean isEasingType(String easingString, String easingType) {
        StringBuilder sb = new StringBuilder();
        sb.append(easingType);
        sb.append(EASING_TYPE_FORMAT_START);
        return easingString.startsWith(sb.toString()) && easingString.endsWith(EASING_TYPE_FORMAT_END);
    }

    private static String getEasingContent(String easingString, String easingType) {
        return easingString.substring(easingType.length() + EASING_TYPE_FORMAT_START.length(), easingString.length() - EASING_TYPE_FORMAT_END.length());
    }

    private static float getControlPoint(String[] controlPoints, int index) {
        float controlPoint = Float.parseFloat(controlPoints[index]);
        if (controlPoint >= 0.0f && controlPoint <= 1.0f) {
            return controlPoint;
        }
        throw new IllegalArgumentException("Motion easing control point value must be between 0 and 1; instead got: " + controlPoint);
    }
}
