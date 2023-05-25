package com.google.android.material.color;

final class ViewingConditions {
    public static final ViewingConditions DEFAULT = make(ColorUtils.whitePointD65(), (float) ((((double) ColorUtils.yFromLstar(50.0f)) * 63.66197723675813d) / 100.0d), 50.0f, 2.0f, false);

    /* renamed from: aw */
    private final float f159aw;

    /* renamed from: c */
    private final float f160c;

    /* renamed from: fl */
    private final float f161fl;
    private final float flRoot;

    /* renamed from: n */
    private final float f162n;
    private final float nbb;

    /* renamed from: nc */
    private final float f163nc;
    private final float ncb;
    private final float[] rgbD;

    /* renamed from: z */
    private final float f164z;

    public float getAw() {
        return this.f159aw;
    }

    public float getN() {
        return this.f162n;
    }

    public float getNbb() {
        return this.nbb;
    }

    /* access modifiers changed from: package-private */
    public float getNcb() {
        return this.ncb;
    }

    /* access modifiers changed from: package-private */
    public float getC() {
        return this.f160c;
    }

    /* access modifiers changed from: package-private */
    public float getNc() {
        return this.f163nc;
    }

    public float[] getRgbD() {
        return this.rgbD;
    }

    /* access modifiers changed from: package-private */
    public float getFl() {
        return this.f161fl;
    }

    public float getFlRoot() {
        return this.flRoot;
    }

    /* access modifiers changed from: package-private */
    public float getZ() {
        return this.f164z;
    }

    static ViewingConditions make(float[] whitePoint, float adaptingLuminance, float backgroundLstar, float surround, boolean discountingIlluminant) {
        float c;
        float d;
        float f = adaptingLuminance;
        float[][] matrix = Cam16.XYZ_TO_CAM16RGB;
        float[] xyz = whitePoint;
        float rW = (xyz[0] * matrix[0][0]) + (xyz[1] * matrix[0][1]) + (xyz[2] * matrix[0][2]);
        float gW = (xyz[0] * matrix[1][0]) + (xyz[1] * matrix[1][1]) + (xyz[2] * matrix[1][2]);
        float bW = (xyz[0] * matrix[2][0]) + (xyz[1] * matrix[2][1]) + (xyz[2] * matrix[2][2]);
        float f2 = (surround / 10.0f) + 0.8f;
        if (((double) f2) >= 0.9d) {
            c = MathUtils.lerp(0.59f, 0.69f, (f2 - 0.9f) * 10.0f);
        } else {
            c = MathUtils.lerp(0.525f, 0.59f, (f2 - 0.8f) * 10.0f);
        }
        if (discountingIlluminant) {
            d = 1.0f;
        } else {
            d = (1.0f - (((float) Math.exp((double) (((-f) - 42.0f) / 92.0f))) * 0.2777778f)) * f2;
        }
        float d2 = ((double) d) > 1.0d ? 1.0f : ((double) d) < 0.0d ? 0.0f : d;
        float[] rgbD2 = {(((100.0f / rW) * d2) + 1.0f) - d2, (((100.0f / gW) * d2) + 1.0f) - d2, (((100.0f / bW) * d2) + 1.0f) - d2};
        float k = 1.0f / ((5.0f * f) + 1.0f);
        float k4 = k * k * k * k;
        float k4F = 1.0f - k4;
        float gW2 = gW;
        float fl = (k4 * f) + (0.1f * k4F * k4F * ((float) Math.cbrt(((double) f) * 5.0d)));
        float n = ColorUtils.yFromLstar(backgroundLstar) / whitePoint[1];
        float z = ((float) Math.sqrt((double) n)) + 1.48f;
        float fl2 = fl;
        float nbb2 = 0.725f / ((float) Math.pow((double) n, 0.2d));
        float ncb2 = nbb2;
        float f3 = rW;
        float[] rgbAFactors = {(float) Math.pow(((double) ((rgbD2[0] * fl2) * rW)) / 100.0d, 0.42d), (float) Math.pow(((double) ((rgbD2[1] * fl2) * gW2)) / 100.0d, 0.42d), (float) Math.pow(((double) ((rgbD2[2] * fl2) * bW)) / 100.0d, 0.42d)};
        float[] rgbA = {(rgbAFactors[0] * 400.0f) / (rgbAFactors[0] + 27.13f), (rgbAFactors[1] * 400.0f) / (rgbAFactors[1] + 27.13f), (rgbAFactors[2] * 400.0f) / (rgbAFactors[2] + 27.13f)};
        float fl3 = fl2;
        float[][] fArr = matrix;
        return new ViewingConditions(n, ((rgbA[0] * 2.0f) + rgbA[1] + (rgbA[2] * 0.05f)) * nbb2, nbb2, ncb2, c, f2, rgbD2, fl3, (float) Math.pow((double) fl3, 0.25d), z);
    }

    private ViewingConditions(float n, float aw, float nbb2, float ncb2, float c, float nc, float[] rgbD2, float fl, float flRoot2, float z) {
        this.f162n = n;
        this.f159aw = aw;
        this.nbb = nbb2;
        this.ncb = ncb2;
        this.f160c = c;
        this.f163nc = nc;
        this.rgbD = rgbD2;
        this.f161fl = fl;
        this.flRoot = flRoot2;
        this.f164z = z;
    }
}
