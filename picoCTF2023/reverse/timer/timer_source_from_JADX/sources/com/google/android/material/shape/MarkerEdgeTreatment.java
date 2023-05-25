package com.google.android.material.shape;

public final class MarkerEdgeTreatment extends EdgeTreatment {
    private final float radius;

    public MarkerEdgeTreatment(float radius2) {
        this.radius = radius2 - 0.001f;
    }

    public void getEdgePath(float length, float center, float interpolation, ShapePath shapePath) {
        float side = (float) ((((double) this.radius) * Math.sqrt(2.0d)) / 2.0d);
        float side2 = (float) Math.sqrt(Math.pow((double) this.radius, 2.0d) - Math.pow((double) side, 2.0d));
        shapePath.reset(center - side, ((float) (-((((double) this.radius) * Math.sqrt(2.0d)) - ((double) this.radius)))) + side2);
        shapePath.lineTo(center, (float) (-((((double) this.radius) * Math.sqrt(2.0d)) - ((double) this.radius))));
        shapePath.lineTo(center + side, ((float) (-((((double) this.radius) * Math.sqrt(2.0d)) - ((double) this.radius)))) + side2);
    }

    /* access modifiers changed from: package-private */
    public boolean forceIntersection() {
        return true;
    }
}
