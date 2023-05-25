package com.google.android.material.textfield;

import android.content.res.ColorStateList;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.view.View;
import androidx.core.graphics.drawable.DrawableCompat;
import androidx.core.view.ViewCompat;
import com.google.android.material.internal.CheckableImageButton;
import java.util.Arrays;

class IconHelper {
    private IconHelper() {
    }

    static void setIconOnClickListener(CheckableImageButton iconView, View.OnClickListener onClickListener, View.OnLongClickListener onLongClickListener) {
        iconView.setOnClickListener(onClickListener);
        setIconClickable(iconView, onLongClickListener);
    }

    static void setIconOnLongClickListener(CheckableImageButton iconView, View.OnLongClickListener onLongClickListener) {
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

    static void applyIconTint(TextInputLayout textInputLayout, CheckableImageButton iconView, ColorStateList iconTintList, PorterDuff.Mode iconTintMode) {
        Drawable icon = iconView.getDrawable();
        if (icon != null) {
            icon = DrawableCompat.wrap(icon).mutate();
            if (iconTintList == null || !iconTintList.isStateful()) {
                DrawableCompat.setTintList(icon, iconTintList);
            } else {
                DrawableCompat.setTintList(icon, ColorStateList.valueOf(iconTintList.getColorForState(mergeIconState(textInputLayout, iconView), iconTintList.getDefaultColor())));
            }
            if (iconTintMode != null) {
                DrawableCompat.setTintMode(icon, iconTintMode);
            }
        }
        if (iconView.getDrawable() != icon) {
            iconView.setImageDrawable(icon);
        }
    }

    static void refreshIconDrawableState(TextInputLayout textInputLayout, CheckableImageButton iconView, ColorStateList colorStateList) {
        Drawable icon = iconView.getDrawable();
        if (iconView.getDrawable() != null && colorStateList != null && colorStateList.isStateful()) {
            int color = colorStateList.getColorForState(mergeIconState(textInputLayout, iconView), colorStateList.getDefaultColor());
            Drawable icon2 = DrawableCompat.wrap(icon).mutate();
            DrawableCompat.setTintList(icon2, ColorStateList.valueOf(color));
            iconView.setImageDrawable(icon2);
        }
    }

    private static int[] mergeIconState(TextInputLayout textInputLayout, CheckableImageButton iconView) {
        int[] textInputStates = textInputLayout.getDrawableState();
        int[] iconStates = iconView.getDrawableState();
        int index = textInputStates.length;
        int[] states = Arrays.copyOf(textInputStates, textInputStates.length + iconStates.length);
        System.arraycopy(iconStates, 0, states, index, iconStates.length);
        return states;
    }
}
