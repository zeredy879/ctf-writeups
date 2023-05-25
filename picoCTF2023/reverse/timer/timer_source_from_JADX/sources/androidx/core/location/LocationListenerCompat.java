package androidx.core.location;

import android.location.LocationListener;
import android.os.Bundle;

public interface LocationListenerCompat extends LocationListener {
    void onProviderDisabled(String str);

    void onProviderEnabled(String str);

    void onStatusChanged(String str, int i, Bundle bundle);

    /* renamed from: androidx.core.location.LocationListenerCompat$-CC  reason: invalid class name */
    public final /* synthetic */ class CC {
        public static void $default$onStatusChanged(LocationListenerCompat _this, String provider, int status, Bundle extras) {
        }

        public static void $default$onProviderEnabled(LocationListenerCompat _this, String provider) {
        }

        public static void $default$onProviderDisabled(LocationListenerCompat _this, String provider) {
        }
    }
}
