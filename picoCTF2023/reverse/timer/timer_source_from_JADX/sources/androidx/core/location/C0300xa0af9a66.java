package androidx.core.location;

import android.location.Location;
import androidx.core.location.LocationManagerCompat;

/* renamed from: androidx.core.location.LocationManagerCompat$LocationListenerTransport$$ExternalSyntheticLambda1 */
/* compiled from: D8$$SyntheticClass */
public final /* synthetic */ class C0300xa0af9a66 implements Runnable {
    public final /* synthetic */ LocationManagerCompat.LocationListenerTransport f$0;
    public final /* synthetic */ LocationListenerCompat f$1;
    public final /* synthetic */ Location f$2;

    public /* synthetic */ C0300xa0af9a66(LocationManagerCompat.LocationListenerTransport locationListenerTransport, LocationListenerCompat locationListenerCompat, Location location) {
        this.f$0 = locationListenerTransport;
        this.f$1 = locationListenerCompat;
        this.f$2 = location;
    }

    public final void run() {
        this.f$0.mo6177xad6a74fb(this.f$1, this.f$2);
    }
}
