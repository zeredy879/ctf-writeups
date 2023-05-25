package com.example.timer;

import android.os.CountDownTimer;
import android.widget.TextView;
import kotlin.Metadata;

@Metadata(mo14702d1 = {"\u0000\u0019\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\t\n\u0000*\u0001\u0000\b\n\u0018\u00002\u00020\u0001J\b\u0010\u0002\u001a\u00020\u0003H\u0016J\u0010\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u0006H\u0016¨\u0006\u0007"}, mo14703d2 = {"com/example/timer/MainActivity$startCountingDown$1", "Landroid/os/CountDownTimer;", "onFinish", "", "onTick", "millisUntilFinished", "", "app_debug"}, mo14704k = 1, mo14705mv = {1, 6, 0}, mo14707xi = 48)
/* compiled from: MainActivity.kt */
public final class MainActivity$startCountingDown$1 extends CountDownTimer {
    final /* synthetic */ MainActivity this$0;

    /* JADX INFO: super call moved to the top of the method (can break code semantics) */
    MainActivity$startCountingDown$1(MainActivity $receiver, long $super_call_param$1) {
        super($super_call_param$1, 1000);
        this.this$0 = $receiver;
    }

    public void onTick(long millisUntilFinished) {
        long seconds_remaining = millisUntilFinished / ((long) 1000);
        if (seconds_remaining < 60) {
            this.this$0.getSeconds().setText(String.valueOf(seconds_remaining));
            this.this$0.getMinutes().setText("0");
            this.this$0.getHours().setText("0");
        }
        if (seconds_remaining > 60 && seconds_remaining < 3600) {
            this.this$0.getSeconds().setText(String.valueOf(seconds_remaining % ((long) 60)));
            this.this$0.getMinutes().setText(String.valueOf(((int) seconds_remaining) / 60));
            this.this$0.getHours().setText("0");
        }
        if (seconds_remaining >= 3600) {
            long j = (long) 3600;
            long sec_remaining = seconds_remaining % j;
            int minutes_remaining = ((int) sec_remaining) / 60;
            this.this$0.getSeconds().setText(String.valueOf(sec_remaining % ((long) 60)));
            this.this$0.getMinutes().setText(String.valueOf(minutes_remaining));
            this.this$0.getHours().setText(String.valueOf(seconds_remaining / j));
        }
        TextView textView = this.this$0.getTextView();
        textView.setText("seconds remaining: " + seconds_remaining);
    }

    public void onFinish() {
        this.this$0.getTextView().setText("done!");
    }
}
