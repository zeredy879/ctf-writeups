package androidx.core.location;

import androidx.core.location.LocationManagerCompat;
import java.util.List;

/* renamed from: androidx.core.location.LocationManagerCompat$LocationListenerTransport$$ExternalSyntheticLambda5 */
/* compiled from: D8$$SyntheticClass */
public final /* synthetic */ class C0304xa0af9a6a implements Runnable {
    public final /* synthetic */ LocationManagerCompat.LocationListenerTransport f$0;
    public final /* synthetic */ LocationListenerCompat f$1;
    public final /* synthetic */ List f$2;

    public /* synthetic */ C0304xa0af9a6a(LocationManagerCompat.LocationListenerTransport locationListenerTransport, LocationListenerCompat locationListenerCompat, List list) {
        this.f$0 = locationListenerTransport;
        this.f$1 = locationListenerCompat;
        this.f$2 = list;
    }

    public final void run() {
        this.f$0.mo6178x2fb529da(this.f$1, this.f$2);
    }
}
