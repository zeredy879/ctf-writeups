package androidx.core.location;

import android.location.GnssStatus;
import androidx.core.location.LocationManagerCompat;
import java.util.concurrent.Executor;

/* renamed from: androidx.core.location.LocationManagerCompat$PreRGnssStatusTransport$$ExternalSyntheticLambda3 */
/* compiled from: D8$$SyntheticClass */
public final /* synthetic */ class C0310xcc169349 implements Runnable {
    public final /* synthetic */ LocationManagerCompat.PreRGnssStatusTransport f$0;
    public final /* synthetic */ Executor f$1;
    public final /* synthetic */ GnssStatus f$2;

    public /* synthetic */ C0310xcc169349(LocationManagerCompat.PreRGnssStatusTransport preRGnssStatusTransport, Executor executor, GnssStatus gnssStatus) {
        this.f$0 = preRGnssStatusTransport;
        this.f$1 = executor;
        this.f$2 = gnssStatus;
    }

    public final void run() {
        this.f$0.mo6191xdecf6cdb(this.f$1, this.f$2);
    }
}
