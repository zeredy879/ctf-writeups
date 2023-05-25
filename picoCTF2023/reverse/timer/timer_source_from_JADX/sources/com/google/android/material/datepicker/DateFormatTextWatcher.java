package com.google.android.material.datepicker;

import android.content.Context;
import android.text.TextUtils;
import android.view.View;
import com.google.android.material.C0105R;
import com.google.android.material.internal.TextWatcherAdapter;
import com.google.android.material.textfield.TextInputLayout;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.Date;

abstract class DateFormatTextWatcher extends TextWatcherAdapter {
    private static final int VALIDATION_DELAY = 1000;
    private final CalendarConstraints constraints;
    /* access modifiers changed from: private */
    public final DateFormat dateFormat;
    /* access modifiers changed from: private */
    public final String outOfRange;
    private final Runnable setErrorCallback;
    private Runnable setRangeErrorCallback;
    /* access modifiers changed from: private */
    public final TextInputLayout textInputLayout;

    /* access modifiers changed from: package-private */
    public abstract void onValidDate(Long l);

    DateFormatTextWatcher(final String formatHint, DateFormat dateFormat2, TextInputLayout textInputLayout2, CalendarConstraints constraints2) {
        this.dateFormat = dateFormat2;
        this.textInputLayout = textInputLayout2;
        this.constraints = constraints2;
        this.outOfRange = textInputLayout2.getContext().getString(C0105R.string.mtrl_picker_out_of_range);
        this.setErrorCallback = new Runnable() {
            public void run() {
                TextInputLayout textLayout = DateFormatTextWatcher.this.textInputLayout;
                DateFormat df = DateFormatTextWatcher.this.dateFormat;
                Context context = textLayout.getContext();
                String invalidFormat = context.getString(C0105R.string.mtrl_picker_invalid_format);
                String useLine = String.format(context.getString(C0105R.string.mtrl_picker_invalid_format_use), new Object[]{formatHint});
                String exampleLine = String.format(context.getString(C0105R.string.mtrl_picker_invalid_format_example), new Object[]{df.format(new Date(UtcDates.getTodayCalendar().getTimeInMillis()))});
                textLayout.setError(invalidFormat + "\n" + useLine + "\n" + exampleLine);
                DateFormatTextWatcher.this.onInvalidDate();
            }
        };
    }

    /* access modifiers changed from: package-private */
    public void onInvalidDate() {
    }

    public void onTextChanged(CharSequence s, int start, int before, int count) {
        this.textInputLayout.removeCallbacks(this.setErrorCallback);
        this.textInputLayout.removeCallbacks(this.setRangeErrorCallback);
        this.textInputLayout.setError((CharSequence) null);
        onValidDate((Long) null);
        if (!TextUtils.isEmpty(s)) {
            try {
                Date date = this.dateFormat.parse(s.toString());
                this.textInputLayout.setError((CharSequence) null);
                long milliseconds = date.getTime();
                if (!this.constraints.getDateValidator().isValid(milliseconds) || !this.constraints.isWithinBounds(milliseconds)) {
                    Runnable createRangeErrorCallback = createRangeErrorCallback(milliseconds);
                    this.setRangeErrorCallback = createRangeErrorCallback;
                    runValidation(this.textInputLayout, createRangeErrorCallback);
                    return;
                }
                onValidDate(Long.valueOf(date.getTime()));
            } catch (ParseException e) {
                runValidation(this.textInputLayout, this.setErrorCallback);
            }
        }
    }

    private Runnable createRangeErrorCallback(final long milliseconds) {
        return new Runnable() {
            public void run() {
                DateFormatTextWatcher.this.textInputLayout.setError(String.format(DateFormatTextWatcher.this.outOfRange, new Object[]{DateStrings.getDateString(milliseconds)}));
                DateFormatTextWatcher.this.onInvalidDate();
            }
        };
    }

    public void runValidation(View view, Runnable validation) {
        view.postDelayed(validation, 1000);
    }
}
