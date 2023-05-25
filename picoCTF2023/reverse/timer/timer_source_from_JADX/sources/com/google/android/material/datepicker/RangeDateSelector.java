package com.google.android.material.datepicker;

import android.content.Context;
import android.content.res.Resources;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.DisplayMetrics;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import androidx.core.util.Pair;
import androidx.core.util.Preconditions;
import com.google.android.material.C0105R;
import com.google.android.material.internal.ManufacturerUtils;
import com.google.android.material.internal.ViewUtils;
import com.google.android.material.resources.MaterialAttributes;
import com.google.android.material.textfield.TextInputLayout;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;

public class RangeDateSelector implements DateSelector<Pair<Long, Long>> {
    public static final Parcelable.Creator<RangeDateSelector> CREATOR = new Parcelable.Creator<RangeDateSelector>() {
        public RangeDateSelector createFromParcel(Parcel source) {
            RangeDateSelector rangeDateSelector = new RangeDateSelector();
            Long unused = rangeDateSelector.selectedStartItem = (Long) source.readValue(Long.class.getClassLoader());
            Long unused2 = rangeDateSelector.selectedEndItem = (Long) source.readValue(Long.class.getClassLoader());
            return rangeDateSelector;
        }

        public RangeDateSelector[] newArray(int size) {
            return new RangeDateSelector[size];
        }
    };
    private final String invalidRangeEndError = " ";
    private String invalidRangeStartError;
    /* access modifiers changed from: private */
    public Long proposedTextEnd = null;
    /* access modifiers changed from: private */
    public Long proposedTextStart = null;
    /* access modifiers changed from: private */
    public Long selectedEndItem = null;
    /* access modifiers changed from: private */
    public Long selectedStartItem = null;

    public void select(long selection) {
        Long l = this.selectedStartItem;
        if (l == null) {
            this.selectedStartItem = Long.valueOf(selection);
        } else if (this.selectedEndItem != null || !isValidRange(l.longValue(), selection)) {
            this.selectedEndItem = null;
            this.selectedStartItem = Long.valueOf(selection);
        } else {
            this.selectedEndItem = Long.valueOf(selection);
        }
    }

    public boolean isSelectionComplete() {
        Long l = this.selectedStartItem;
        return (l == null || this.selectedEndItem == null || !isValidRange(l.longValue(), this.selectedEndItem.longValue())) ? false : true;
    }

    public void setSelection(Pair<Long, Long> selection) {
        if (!(selection.first == null || selection.second == null)) {
            Preconditions.checkArgument(isValidRange(((Long) selection.first).longValue(), ((Long) selection.second).longValue()));
        }
        Long l = null;
        this.selectedStartItem = selection.first == null ? null : Long.valueOf(UtcDates.canonicalYearMonthDay(((Long) selection.first).longValue()));
        if (selection.second != null) {
            l = Long.valueOf(UtcDates.canonicalYearMonthDay(((Long) selection.second).longValue()));
        }
        this.selectedEndItem = l;
    }

    public Pair<Long, Long> getSelection() {
        return new Pair<>(this.selectedStartItem, this.selectedEndItem);
    }

    public Collection<Pair<Long, Long>> getSelectedRanges() {
        if (this.selectedStartItem == null || this.selectedEndItem == null) {
            return new ArrayList();
        }
        ArrayList<Pair<Long, Long>> ranges = new ArrayList<>();
        ranges.add(new Pair<>(this.selectedStartItem, this.selectedEndItem));
        return ranges;
    }

    public Collection<Long> getSelectedDays() {
        ArrayList<Long> selections = new ArrayList<>();
        Long l = this.selectedStartItem;
        if (l != null) {
            selections.add(l);
        }
        Long l2 = this.selectedEndItem;
        if (l2 != null) {
            selections.add(l2);
        }
        return selections;
    }

    public int getDefaultThemeResId(Context context) {
        int defaultThemeAttr;
        Resources res = context.getResources();
        DisplayMetrics display = res.getDisplayMetrics();
        if (Math.min(display.widthPixels, display.heightPixels) > res.getDimensionPixelSize(C0105R.dimen.mtrl_calendar_maximum_default_fullscreen_minor_axis)) {
            defaultThemeAttr = C0105R.attr.materialCalendarTheme;
        } else {
            defaultThemeAttr = C0105R.attr.materialCalendarFullscreenTheme;
        }
        return MaterialAttributes.resolveOrThrow(context, defaultThemeAttr, MaterialDatePicker.class.getCanonicalName());
    }

    public String getSelectionDisplayString(Context context) {
        Resources res = context.getResources();
        Long l = this.selectedStartItem;
        if (l == null && this.selectedEndItem == null) {
            return res.getString(C0105R.string.mtrl_picker_range_header_unselected);
        }
        Long l2 = this.selectedEndItem;
        if (l2 == null) {
            return res.getString(C0105R.string.mtrl_picker_range_header_only_start_selected, new Object[]{DateStrings.getDateString(this.selectedStartItem.longValue())});
        } else if (l == null) {
            return res.getString(C0105R.string.mtrl_picker_range_header_only_end_selected, new Object[]{DateStrings.getDateString(this.selectedEndItem.longValue())});
        } else {
            Pair<String, String> dateRangeStrings = DateStrings.getDateRangeString(l, l2);
            return res.getString(C0105R.string.mtrl_picker_range_header_selected, new Object[]{dateRangeStrings.first, dateRangeStrings.second});
        }
    }

    public int getDefaultTitleResId() {
        return C0105R.string.mtrl_picker_range_header_title;
    }

    public View onCreateTextInputView(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle, CalendarConstraints constraints, OnSelectionChangedListener<Pair<Long, Long>> listener) {
        View root = layoutInflater.inflate(C0105R.layout.mtrl_picker_text_input_date_range, viewGroup, false);
        TextInputLayout startTextInput = (TextInputLayout) root.findViewById(C0105R.C0108id.mtrl_picker_text_input_range_start);
        TextInputLayout endTextInput = (TextInputLayout) root.findViewById(C0105R.C0108id.mtrl_picker_text_input_range_end);
        EditText startEditText = startTextInput.getEditText();
        EditText endEditText = endTextInput.getEditText();
        if (ManufacturerUtils.isDateInputKeyboardMissingSeparatorCharacters()) {
            startEditText.setInputType(17);
            endEditText.setInputType(17);
        }
        this.invalidRangeStartError = root.getResources().getString(C0105R.string.mtrl_picker_invalid_range);
        SimpleDateFormat format = UtcDates.getTextInputFormat();
        Long l = this.selectedStartItem;
        if (l != null) {
            startEditText.setText(format.format(l));
            this.proposedTextStart = this.selectedStartItem;
        }
        Long l2 = this.selectedEndItem;
        if (l2 != null) {
            endEditText.setText(format.format(l2));
            this.proposedTextEnd = this.selectedEndItem;
        }
        String formatHint = UtcDates.getTextInputHint(root.getResources(), format);
        startTextInput.setPlaceholderText(formatHint);
        endTextInput.setPlaceholderText(formatHint);
        C06891 r9 = r0;
        CalendarConstraints calendarConstraints = constraints;
        String formatHint2 = formatHint;
        final TextInputLayout textInputLayout = startTextInput;
        SimpleDateFormat format2 = format;
        final TextInputLayout textInputLayout2 = endTextInput;
        EditText endEditText2 = endEditText;
        final OnSelectionChangedListener<Pair<Long, Long>> onSelectionChangedListener = listener;
        C06891 r0 = new DateFormatTextWatcher(formatHint, format, startTextInput, calendarConstraints) {
            /* access modifiers changed from: package-private */
            public void onValidDate(Long day) {
                Long unused = RangeDateSelector.this.proposedTextStart = day;
                RangeDateSelector.this.updateIfValidTextProposal(textInputLayout, textInputLayout2, onSelectionChangedListener);
            }

            /* access modifiers changed from: package-private */
            public void onInvalidDate() {
                Long unused = RangeDateSelector.this.proposedTextStart = null;
                RangeDateSelector.this.updateIfValidTextProposal(textInputLayout, textInputLayout2, onSelectionChangedListener);
            }
        };
        startEditText.addTextChangedListener(r9);
        endEditText2.addTextChangedListener(new DateFormatTextWatcher(formatHint2, format2, endTextInput, calendarConstraints) {
            /* access modifiers changed from: package-private */
            public void onValidDate(Long day) {
                Long unused = RangeDateSelector.this.proposedTextEnd = day;
                RangeDateSelector.this.updateIfValidTextProposal(textInputLayout, textInputLayout2, onSelectionChangedListener);
            }

            /* access modifiers changed from: package-private */
            public void onInvalidDate() {
                Long unused = RangeDateSelector.this.proposedTextEnd = null;
                RangeDateSelector.this.updateIfValidTextProposal(textInputLayout, textInputLayout2, onSelectionChangedListener);
            }
        });
        ViewUtils.requestFocusAndShowKeyboard(startEditText);
        return root;
    }

    private boolean isValidRange(long start, long end) {
        return start <= end;
    }

    /* access modifiers changed from: private */
    public void updateIfValidTextProposal(TextInputLayout startTextInput, TextInputLayout endTextInput, OnSelectionChangedListener<Pair<Long, Long>> listener) {
        Long l = this.proposedTextStart;
        if (l == null || this.proposedTextEnd == null) {
            clearInvalidRange(startTextInput, endTextInput);
            listener.onIncompleteSelectionChanged();
        } else if (isValidRange(l.longValue(), this.proposedTextEnd.longValue())) {
            this.selectedStartItem = this.proposedTextStart;
            this.selectedEndItem = this.proposedTextEnd;
            listener.onSelectionChanged(getSelection());
        } else {
            setInvalidRange(startTextInput, endTextInput);
            listener.onIncompleteSelectionChanged();
        }
    }

    private void clearInvalidRange(TextInputLayout start, TextInputLayout end) {
        if (start.getError() != null && this.invalidRangeStartError.contentEquals(start.getError())) {
            start.setError((CharSequence) null);
        }
        if (end.getError() != null && " ".contentEquals(end.getError())) {
            end.setError((CharSequence) null);
        }
    }

    private void setInvalidRange(TextInputLayout start, TextInputLayout end) {
        start.setError(this.invalidRangeStartError);
        end.setError(" ");
    }

    public int describeContents() {
        return 0;
    }

    public void writeToParcel(Parcel dest, int flags) {
        dest.writeValue(this.selectedStartItem);
        dest.writeValue(this.selectedEndItem);
    }
}
