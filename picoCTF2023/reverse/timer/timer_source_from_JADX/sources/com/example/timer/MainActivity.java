package com.example.timer;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata(mo14702d1 = {"\u00008\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002J\u0012\u0010\u001b\u001a\u00020\u001c2\b\u0010\u001d\u001a\u0004\u0018\u00010\u001eH\u0014J\u0010\u0010\u001f\u001a\u00020\u001c2\u0006\u0010 \u001a\u00020!H\u0002R\u001a\u0010\u0003\u001a\u00020\u0004X.¢\u0006\u000e\n\u0000\u001a\u0004\b\u0005\u0010\u0006\"\u0004\b\u0007\u0010\bR\u001a\u0010\t\u001a\u00020\u0004X.¢\u0006\u000e\n\u0000\u001a\u0004\b\n\u0010\u0006\"\u0004\b\u000b\u0010\bR\u001a\u0010\f\u001a\u00020\rX.¢\u0006\u000e\n\u0000\u001a\u0004\b\u000e\u0010\u000f\"\u0004\b\u0010\u0010\u0011R\u001a\u0010\u0012\u001a\u00020\u0004X.¢\u0006\u000e\n\u0000\u001a\u0004\b\u0013\u0010\u0006\"\u0004\b\u0014\u0010\bR\u001a\u0010\u0015\u001a\u00020\u0016X.¢\u0006\u000e\n\u0000\u001a\u0004\b\u0017\u0010\u0018\"\u0004\b\u0019\u0010\u001a¨\u0006\""}, mo14703d2 = {"Lcom/example/timer/MainActivity;", "Landroidx/appcompat/app/AppCompatActivity;", "()V", "hours", "Landroid/widget/EditText;", "getHours", "()Landroid/widget/EditText;", "setHours", "(Landroid/widget/EditText;)V", "minutes", "getMinutes", "setMinutes", "playbtn", "Landroid/widget/Button;", "getPlaybtn", "()Landroid/widget/Button;", "setPlaybtn", "(Landroid/widget/Button;)V", "seconds", "getSeconds", "setSeconds", "textView", "Landroid/widget/TextView;", "getTextView", "()Landroid/widget/TextView;", "setTextView", "(Landroid/widget/TextView;)V", "onCreate", "", "savedInstanceState", "Landroid/os/Bundle;", "startCountingDown", "starttime", "", "app_debug"}, mo14704k = 1, mo14705mv = {1, 6, 0}, mo14707xi = 48)
/* compiled from: MainActivity.kt */
public final class MainActivity extends AppCompatActivity {
    public EditText hours;
    public EditText minutes;
    public Button playbtn;
    public EditText seconds;
    public TextView textView;

    public final TextView getTextView() {
        TextView textView2 = this.textView;
        if (textView2 != null) {
            return textView2;
        }
        Intrinsics.throwUninitializedPropertyAccessException("textView");
        return null;
    }

    public final void setTextView(TextView textView2) {
        Intrinsics.checkNotNullParameter(textView2, "<set-?>");
        this.textView = textView2;
    }

    public final Button getPlaybtn() {
        Button button = this.playbtn;
        if (button != null) {
            return button;
        }
        Intrinsics.throwUninitializedPropertyAccessException("playbtn");
        return null;
    }

    public final void setPlaybtn(Button button) {
        Intrinsics.checkNotNullParameter(button, "<set-?>");
        this.playbtn = button;
    }

    public final EditText getSeconds() {
        EditText editText = this.seconds;
        if (editText != null) {
            return editText;
        }
        Intrinsics.throwUninitializedPropertyAccessException("seconds");
        return null;
    }

    public final void setSeconds(EditText editText) {
        Intrinsics.checkNotNullParameter(editText, "<set-?>");
        this.seconds = editText;
    }

    public final EditText getMinutes() {
        EditText editText = this.minutes;
        if (editText != null) {
            return editText;
        }
        Intrinsics.throwUninitializedPropertyAccessException("minutes");
        return null;
    }

    public final void setMinutes(EditText editText) {
        Intrinsics.checkNotNullParameter(editText, "<set-?>");
        this.minutes = editText;
    }

    public final EditText getHours() {
        EditText editText = this.hours;
        if (editText != null) {
            return editText;
        }
        Intrinsics.throwUninitializedPropertyAccessException("hours");
        return null;
    }

    public final void setHours(EditText editText) {
        Intrinsics.checkNotNullParameter(editText, "<set-?>");
        this.hours = editText;
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView((int) C0099R.layout.activity_main);
        View findViewById = findViewById(C0099R.C0102id.textView);
        Intrinsics.checkNotNullExpressionValue(findViewById, "findViewById(R.id.textView)");
        setTextView((TextView) findViewById);
        View findViewById2 = findViewById(C0099R.C0102id.play_btn);
        Intrinsics.checkNotNullExpressionValue(findViewById2, "findViewById(R.id.play_btn)");
        setPlaybtn((Button) findViewById2);
        View findViewById3 = findViewById(C0099R.C0102id.seconds_edt_txt);
        Intrinsics.checkNotNullExpressionValue(findViewById3, "findViewById(R.id.seconds_edt_txt)");
        setSeconds((EditText) findViewById3);
        View findViewById4 = findViewById(C0099R.C0102id.min_edt_txt);
        Intrinsics.checkNotNullExpressionValue(findViewById4, "findViewById(R.id.min_edt_txt)");
        setMinutes((EditText) findViewById4);
        View findViewById5 = findViewById(C0099R.C0102id.hours_edt_txt);
        Intrinsics.checkNotNullExpressionValue(findViewById5, "findViewById(R.id.hours_edt_txt)");
        setHours((EditText) findViewById5);
        getMinutes().setText("0");
        getSeconds().setText("0");
        getHours().setText("0");
        getPlaybtn().setOnClickListener(new MainActivity$$ExternalSyntheticLambda0(this));
    }

    /* access modifiers changed from: private */
    /* renamed from: onCreate$lambda-0  reason: not valid java name */
    public static final void m62onCreate$lambda0(MainActivity this$0, View it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.startCountingDown(((Integer.parseInt(this$0.getHours().getText().toString()) * 3600) + (Integer.parseInt(this$0.getMinutes().getText().toString()) * 60) + Integer.parseInt(this$0.getSeconds().getText().toString())) * 1000);
    }

    private final void startCountingDown(int starttime) {
        new MainActivity$startCountingDown$1(this, (long) starttime).start();
    }
}
