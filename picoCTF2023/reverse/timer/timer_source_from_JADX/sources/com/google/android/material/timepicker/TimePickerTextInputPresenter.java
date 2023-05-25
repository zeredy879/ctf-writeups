package com.google.android.material.timepicker;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.appcompat.content.res.AppCompatResources;
import androidx.core.content.ContextCompat;
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
import com.google.android.material.C0105R;
import com.google.android.material.button.MaterialButtonToggleGroup;
import com.google.android.material.color.MaterialColors;
import com.google.android.material.internal.TextWatcherAdapter;
import com.google.android.material.timepicker.TimePickerView;
import java.lang.reflect.Field;
import java.util.Locale;

class TimePickerTextInputPresenter implements TimePickerView.OnSelectionChange, TimePickerPresenter {
    private final TimePickerTextInputKeyController controller;
    private final EditText hourEditText;
    private final ChipTextInputComboView hourTextInput;
    private final TextWatcher hourTextWatcher = new TextWatcherAdapter() {
        public void afterTextChanged(Editable s) {
            try {
                if (TextUtils.isEmpty(s)) {
                    TimePickerTextInputPresenter.this.time.setHour(0);
                    return;
                }
                TimePickerTextInputPresenter.this.time.setHour(Integer.parseInt(s.toString()));
            } catch (NumberFormatException e) {
            }
        }
    };
    private final EditText minuteEditText;
    private final ChipTextInputComboView minuteTextInput;
    private final TextWatcher minuteTextWatcher = new TextWatcherAdapter() {
        public void afterTextChanged(Editable s) {
            try {
                if (TextUtils.isEmpty(s)) {
                    TimePickerTextInputPresenter.this.time.setMinute(0);
                    return;
                }
                TimePickerTextInputPresenter.this.time.setMinute(Integer.parseInt(s.toString()));
            } catch (NumberFormatException e) {
            }
        }
    };
    /* access modifiers changed from: private */
    public final TimeModel time;
    private final LinearLayout timePickerView;
    private MaterialButtonToggleGroup toggle;

    public TimePickerTextInputPresenter(LinearLayout timePickerView2, final TimeModel time2) {
        this.timePickerView = timePickerView2;
        this.time = time2;
        Resources res = timePickerView2.getResources();
        ChipTextInputComboView chipTextInputComboView = (ChipTextInputComboView) timePickerView2.findViewById(C0105R.C0108id.material_minute_text_input);
        this.minuteTextInput = chipTextInputComboView;
        ChipTextInputComboView chipTextInputComboView2 = (ChipTextInputComboView) timePickerView2.findViewById(C0105R.C0108id.material_hour_text_input);
        this.hourTextInput = chipTextInputComboView2;
        ((TextView) chipTextInputComboView.findViewById(C0105R.C0108id.material_label)).setText(res.getString(C0105R.string.material_timepicker_minute));
        ((TextView) chipTextInputComboView2.findViewById(C0105R.C0108id.material_label)).setText(res.getString(C0105R.string.material_timepicker_hour));
        chipTextInputComboView.setTag(C0105R.C0108id.selection_type, 12);
        chipTextInputComboView2.setTag(C0105R.C0108id.selection_type, 10);
        if (time2.format == 0) {
            setupPeriodToggle();
        }
        View.OnClickListener onClickListener = new View.OnClickListener() {
            public void onClick(View v) {
                TimePickerTextInputPresenter.this.onSelectionChanged(((Integer) v.getTag(C0105R.C0108id.selection_type)).intValue());
            }
        };
        chipTextInputComboView2.setOnClickListener(onClickListener);
        chipTextInputComboView.setOnClickListener(onClickListener);
        chipTextInputComboView2.addInputFilter(time2.getHourInputValidator());
        chipTextInputComboView.addInputFilter(time2.getMinuteInputValidator());
        EditText editText = chipTextInputComboView2.getTextInput().getEditText();
        this.hourEditText = editText;
        EditText editText2 = chipTextInputComboView.getTextInput().getEditText();
        this.minuteEditText = editText2;
        if (Build.VERSION.SDK_INT < 21) {
            int primaryColor = MaterialColors.getColor(timePickerView2, C0105R.attr.colorPrimary);
            setCursorDrawableColor(editText, primaryColor);
            setCursorDrawableColor(editText2, primaryColor);
        }
        this.controller = new TimePickerTextInputKeyController(chipTextInputComboView2, chipTextInputComboView, time2);
        chipTextInputComboView2.setChipDelegate(new ClickActionDelegate(timePickerView2.getContext(), C0105R.string.material_hour_selection) {
            public void onInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfoCompat info) {
                super.onInitializeAccessibilityNodeInfo(host, info);
                info.setContentDescription(host.getResources().getString(C0105R.string.material_hour_suffix, new Object[]{String.valueOf(time2.getHourForDisplay())}));
            }
        });
        chipTextInputComboView.setChipDelegate(new ClickActionDelegate(timePickerView2.getContext(), C0105R.string.material_minute_selection) {
            public void onInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfoCompat info) {
                super.onInitializeAccessibilityNodeInfo(host, info);
                info.setContentDescription(host.getResources().getString(C0105R.string.material_minute_suffix, new Object[]{String.valueOf(time2.minute)}));
            }
        });
        initialize();
    }

    public void initialize() {
        addTextWatchers();
        setTime(this.time);
        this.controller.bind();
    }

    private void addTextWatchers() {
        this.hourEditText.addTextChangedListener(this.hourTextWatcher);
        this.minuteEditText.addTextChangedListener(this.minuteTextWatcher);
    }

    private void removeTextWatchers() {
        this.hourEditText.removeTextChangedListener(this.hourTextWatcher);
        this.minuteEditText.removeTextChangedListener(this.minuteTextWatcher);
    }

    private void setTime(TimeModel time2) {
        removeTextWatchers();
        Locale current = this.timePickerView.getResources().getConfiguration().locale;
        String minuteFormatted = String.format(current, TimeModel.ZERO_LEADING_NUMBER_FORMAT, new Object[]{Integer.valueOf(time2.minute)});
        String hourFormatted = String.format(current, TimeModel.ZERO_LEADING_NUMBER_FORMAT, new Object[]{Integer.valueOf(time2.getHourForDisplay())});
        this.minuteTextInput.setText(minuteFormatted);
        this.hourTextInput.setText(hourFormatted);
        addTextWatchers();
        updateSelection();
    }

    private void setupPeriodToggle() {
        MaterialButtonToggleGroup materialButtonToggleGroup = (MaterialButtonToggleGroup) this.timePickerView.findViewById(C0105R.C0108id.material_clock_period_toggle);
        this.toggle = materialButtonToggleGroup;
        materialButtonToggleGroup.addOnButtonCheckedListener(new MaterialButtonToggleGroup.OnButtonCheckedListener() {
            public void onButtonChecked(MaterialButtonToggleGroup group, int checkedId, boolean isChecked) {
                TimePickerTextInputPresenter.this.time.setPeriod(checkedId == C0105R.C0108id.material_clock_period_pm_button ? 1 : 0);
            }
        });
        this.toggle.setVisibility(0);
        updateSelection();
    }

    private void updateSelection() {
        int i;
        MaterialButtonToggleGroup materialButtonToggleGroup = this.toggle;
        if (materialButtonToggleGroup != null) {
            if (this.time.period == 0) {
                i = C0105R.C0108id.material_clock_period_am_button;
            } else {
                i = C0105R.C0108id.material_clock_period_pm_button;
            }
            materialButtonToggleGroup.check(i);
        }
    }

    public void onSelectionChanged(int selection) {
        this.time.selection = selection;
        boolean z = true;
        this.minuteTextInput.setChecked(selection == 12);
        ChipTextInputComboView chipTextInputComboView = this.hourTextInput;
        if (selection != 10) {
            z = false;
        }
        chipTextInputComboView.setChecked(z);
        updateSelection();
    }

    public void show() {
        this.timePickerView.setVisibility(0);
    }

    public void hide() {
        View currentFocus = this.timePickerView.getFocusedChild();
        if (currentFocus == null) {
            this.timePickerView.setVisibility(8);
            return;
        }
        InputMethodManager imm = (InputMethodManager) ContextCompat.getSystemService(this.timePickerView.getContext(), InputMethodManager.class);
        if (imm != null) {
            imm.hideSoftInputFromWindow(currentFocus.getWindowToken(), 0);
        }
        this.timePickerView.setVisibility(8);
    }

    public void invalidate() {
        setTime(this.time);
    }

    private static void setCursorDrawableColor(EditText view, int color) {
        try {
            Context context = view.getContext();
            Field cursorDrawableResField = TextView.class.getDeclaredField("mCursorDrawableRes");
            cursorDrawableResField.setAccessible(true);
            int cursorDrawableResId = cursorDrawableResField.getInt(view);
            Field editorField = TextView.class.getDeclaredField("mEditor");
            editorField.setAccessible(true);
            Object editor = editorField.get(view);
            Field cursorDrawableField = editor.getClass().getDeclaredField("mCursorDrawable");
            cursorDrawableField.setAccessible(true);
            Drawable drawable = AppCompatResources.getDrawable(context, cursorDrawableResId);
            drawable.setColorFilter(color, PorterDuff.Mode.SRC_IN);
            cursorDrawableField.set(editor, new Drawable[]{drawable, drawable});
        } catch (Throwable th) {
        }
    }

    public void resetChecked() {
        boolean z = true;
        this.minuteTextInput.setChecked(this.time.selection == 12);
        ChipTextInputComboView chipTextInputComboView = this.hourTextInput;
        if (this.time.selection != 10) {
            z = false;
        }
        chipTextInputComboView.setChecked(z);
    }

    public void clearCheck() {
        this.minuteTextInput.setChecked(false);
        this.hourTextInput.setChecked(false);
    }
}
