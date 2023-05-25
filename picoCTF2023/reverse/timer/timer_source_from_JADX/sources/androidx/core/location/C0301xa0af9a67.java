package androidx.core.location;

import androidx.core.location.LocationManagerCompat;

/* renamed from: androidx.core.location.LocationManagerCompat$LocationListenerTransport$$ExternalSyntheticLambda2 */
/* compiled from: D8$$SyntheticClass */
public final /* synthetic */ class C0301xa0af9a67 implements Runnable {
    public final /* synthetic */ LocationManagerCompat.LocationListenerTransport f$0;
    public final /* synthetic */ LocationListenerCompat f$1;
    public final /* synthetic */ String f$2;

    public /* synthetic */ C0301xa0af9a67(LocationManagerCompat.LocationListenerTransport locationListenerTransport, LocationListenerCompat locationListenerCompat, String str) {
        this.f$0 = locationListenerTransport;
        this.f$1 = locationListenerCompat;
        this.f$2 = str;
    }

    public final void run() {
        this.f$0.mo6179x48c02650(this.f$1, this.f$2);
    }
}
