package androidx.core.location;

import android.location.GnssStatus;
import android.os.Build;
import androidx.core.util.Preconditions;

class GnssStatusWrapper extends GnssStatusCompat {
    private final GnssStatus mWrapped;

    GnssStatusWrapper(GnssStatus gnssStatus) {
        this.mWrapped = (GnssStatus) Preconditions.checkNotNull(gnssStatus);
    }

    public int getSatelliteCount() {
        return this.mWrapped.getSatelliteCount();
    }

    public int getConstellationType(int satelliteIndex) {
        return this.mWrapped.getConstellationType(satelliteIndex);
    }

    public int getSvid(int satelliteIndex) {
        return this.mWrapped.getSvid(satelliteIndex);
    }

    public float getCn0DbHz(int satelliteIndex) {
        return this.mWrapped.getCn0DbHz(satelliteIndex);
    }

    public float getElevationDegrees(int satelliteIndex) {
        return this.mWrapped.getElevationDegrees(satelliteIndex);
    }

    public float getAzimuthDegrees(int satelliteIndex) {
        return this.mWrapped.getAzimuthDegrees(satelliteIndex);
    }

    public boolean hasEphemerisData(int satelliteIndex) {
        return this.mWrapped.hasEphemerisData(satelliteIndex);
    }

    public boolean hasAlmanacData(int satelliteIndex) {
        return this.mWrapped.hasAlmanacData(satelliteIndex);
    }

    public boolean usedInFix(int satelliteIndex) {
        return this.mWrapped.usedInFix(satelliteIndex);
    }

    public boolean hasCarrierFrequencyHz(int satelliteIndex) {
        if (Build.VERSION.SDK_INT >= 26) {
            return this.mWrapped.hasCarrierFrequencyHz(satelliteIndex);
        }
        return false;
    }

    public float getCarrierFrequencyHz(int satelliteIndex) {
        if (Build.VERSION.SDK_INT >= 26) {
            return this.mWrapped.getCarrierFrequencyHz(satelliteIndex);
        }
        throw new UnsupportedOperationException();
    }

    public boolean hasBasebandCn0DbHz(int satelliteIndex) {
        if (Build.VERSION.SDK_INT >= 30) {
            return this.mWrapped.hasBasebandCn0DbHz(satelliteIndex);
        }
        return false;
    }

    public float getBasebandCn0DbHz(int satelliteIndex) {
        if (Build.VERSION.SDK_INT >= 30) {
            return this.mWrapped.getBasebandCn0DbHz(satelliteIndex);
        }
        throw new UnsupportedOperationException();
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof GnssStatusWrapper)) {
            return false;
        }
        return this.mWrapped.equals(((GnssStatusWrapper) o).mWrapped);
    }

    public int hashCode() {
        return this.mWrapped.hashCode();
    }
}
