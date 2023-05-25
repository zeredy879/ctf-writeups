package com.google.android.material.color;

final class Cam16 {
    static final float[][] CAM16RGB_TO_XYZ = {new float[]{1.8620678f, -1.0112547f, 0.14918678f}, new float[]{0.38752654f, 0.62144744f, -0.00897398f}, new float[]{-0.0158415f, -0.03412294f, 1.0499644f}};
    static final float[][] XYZ_TO_CAM16RGB = {new float[]{0.401288f, 0.650173f, -0.051461f}, new float[]{-0.250268f, 1.204414f, 0.045854f}, new float[]{-0.002079f, 0.048952f, 0.953127f}};
    private final float astar;
    private final float bstar;
    private final float chroma;
    private final float hue;

    /* renamed from: j */
    private final float f154j;
    private final float jstar;

    /* renamed from: m */
    private final float f155m;

    /* renamed from: q */
    private final float f156q;

    /* renamed from: s */
    private final float f157s;

    /* access modifiers changed from: package-private */
    public float distance(Cam16 other) {
        float dJ = getJStar() - other.getJStar();
        float dA = getAStar() - other.getAStar();
        float dB = getBStar() - other.getBStar();
        return (float) (Math.pow(Math.sqrt((double) ((dJ * dJ) + (dA * dA) + (dB * dB))), 0.63d) * 1.41d);
    }

    public float getHue() {
        return this.hue;
    }

    public float getChroma() {
        return this.chroma;
    }

    public float getJ() {
        return this.f154j;
    }

    public float getQ() {
        return this.f156q;
    }

    public float getM() {
        return this.f155m;
    }

    public float getS() {
        return this.f157s;
    }

    public float getJStar() {
        return this.jstar;
    }

    public float getAStar() {
        return this.astar;
    }

    public float getBStar() {
        return this.bstar;
    }

    private Cam16(float hue2, float chroma2, float j, float q, float m, float s, float jstar2, float astar2, float bstar2) {
        this.hue = hue2;
        this.chroma = chroma2;
        this.f154j = j;
        this.f156q = q;
        this.f155m = m;
        this.f157s = s;
        this.jstar = jstar2;
        this.astar = astar2;
        this.bstar = bstar2;
    }

    public static Cam16 fromInt(int argb) {
        return fromIntInViewingConditions(argb, ViewingConditions.DEFAULT);
    }

    static Cam16 fromIntInViewingConditions(int argb, ViewingConditions viewingConditions) {
        float f;
        int i = argb;
        int red = (16711680 & i) >> 16;
        int green = (65280 & i) >> 8;
        int blue = i & 255;
        float redL = ColorUtils.linearized(((float) red) / 255.0f) * 100.0f;
        float greenL = ColorUtils.linearized(((float) green) / 255.0f) * 100.0f;
        float blueL = ColorUtils.linearized(((float) blue) / 255.0f) * 100.0f;
        float x = (0.41233894f * redL) + (0.35762063f * greenL) + (0.18051042f * blueL);
        float y = (0.2126f * redL) + (0.7152f * greenL) + (0.0722f * blueL);
        float z = (0.01932141f * redL) + (0.11916382f * greenL) + (0.9503448f * blueL);
        float[][] matrix = XYZ_TO_CAM16RGB;
        float rT = (matrix[0][0] * x) + (matrix[0][1] * y) + (matrix[0][2] * z);
        float gT = (matrix[1][0] * x) + (matrix[1][1] * y) + (matrix[1][2] * z);
        float bT = (matrix[2][0] * x) + (matrix[2][1] * y) + (matrix[2][2] * z);
        float rD = viewingConditions.getRgbD()[0] * rT;
        float gD = viewingConditions.getRgbD()[1] * gT;
        float bD = viewingConditions.getRgbD()[2] * bT;
        int i2 = red;
        int green2 = green;
        int i3 = blue;
        float rAF = (float) Math.pow(((double) (viewingConditions.getFl() * Math.abs(rD))) / 100.0d, 0.42d);
        float f2 = redL;
        float f3 = blueL;
        float gAF = (float) Math.pow(((double) (viewingConditions.getFl() * Math.abs(gD))) / 100.0d, 0.42d);
        float bAF = (float) Math.pow(((double) (viewingConditions.getFl() * Math.abs(bD))) / 100.0d, 0.42d);
        float rA = ((Math.signum(rD) * 400.0f) * rAF) / (rAF + 27.13f);
        float gA = ((Math.signum(gD) * 400.0f) * gAF) / (gAF + 27.13f);
        float bA = ((Math.signum(bD) * 400.0f) * bAF) / (27.13f + bAF);
        float f4 = rAF;
        float f5 = gAF;
        int i4 = green2;
        float f6 = greenL;
        float a = ((float) (((((double) rA) * 11.0d) + (((double) gA) * -12.0d)) + ((double) bA))) / 11.0f;
        float f7 = bAF;
        float b = ((float) (((double) (rA + gA)) - (((double) bA) * 2.0d))) / 9.0f;
        float u = (((rA * 20.0f) + (gA * 20.0f)) + (21.0f * bA)) / 20.0f;
        float p2 = (((40.0f * rA) + (gA * 20.0f)) + bA) / 20.0f;
        float f8 = rA;
        float f9 = bA;
        float f10 = gA;
        float atan2 = (float) Math.atan2((double) b, (double) a);
        float atanDegrees = (atan2 * 180.0f) / 3.1415927f;
        if (atanDegrees < 0.0f) {
            f = atanDegrees + 360.0f;
        } else {
            f = atanDegrees >= 360.0f ? atanDegrees - 360.0f : atanDegrees;
        }
        float hue2 = f;
        float f11 = atan2;
        float hue3 = hue2;
        float hueRadians = (hue3 * 3.1415927f) / 180.0f;
        float ac = viewingConditions.getNbb() * p2;
        float f12 = atanDegrees;
        float f13 = ac;
        float f14 = p2;
        float f15 = x;
        float j = ((float) Math.pow((double) (ac / viewingConditions.getAw()), (double) (viewingConditions.getC() * viewingConditions.getZ()))) * 100.0f;
        float f16 = y;
        float q = (4.0f / viewingConditions.getC()) * ((float) Math.sqrt((double) (j / 100.0f))) * (viewingConditions.getAw() + 4.0f) * viewingConditions.getFlRoot();
        float huePrime = ((double) hue3) < 20.14d ? hue3 + 360.0f : hue3;
        float eHue = ((float) (Math.cos(Math.toRadians((double) huePrime) + 2.0d) + 3.8d)) * 0.25f;
        float p1 = 3846.1538f * eHue * viewingConditions.getNc() * viewingConditions.getNcb();
        float f17 = z;
        float[][] fArr = matrix;
        float f18 = rD;
        float f19 = rT;
        float t = (((float) Math.hypot((double) a, (double) b)) * p1) / (0.305f + u);
        float f20 = a;
        float f21 = b;
        float f22 = huePrime;
        float u2 = u;
        float alpha = ((float) Math.pow(1.64d - Math.pow(0.29d, (double) viewingConditions.getN()), 0.73d)) * ((float) Math.pow((double) t, 0.9d));
        float c = ((float) Math.sqrt(((double) j) / 100.0d)) * alpha;
        float m = viewingConditions.getFlRoot() * c;
        float jstar2 = (1.7f * j) / ((0.007f * j) + 1.0f);
        float f23 = alpha;
        float f24 = u2;
        float mstar = ((float) Math.log1p((double) (m * 0.0228f))) * 43.85965f;
        float f25 = eHue;
        float f26 = p1;
        float f27 = t;
        return new Cam16(hue3, c, j, q, m, ((float) Math.sqrt((double) ((viewingConditions.getC() * alpha) / (viewingConditions.getAw() + 4.0f)))) * 50.0f, jstar2, ((float) Math.cos((double) hueRadians)) * mstar, ((float) Math.sin((double) hueRadians)) * mstar);
    }

    static Cam16 fromJch(float j, float c, float h) {
        return fromJchInViewingConditions(j, c, h, ViewingConditions.DEFAULT);
    }

    private static Cam16 fromJchInViewingConditions(float j, float c, float h, ViewingConditions viewingConditions) {
        float f = j;
        float q = (4.0f / viewingConditions.getC()) * ((float) Math.sqrt(((double) f) / 100.0d)) * (viewingConditions.getAw() + 4.0f) * viewingConditions.getFlRoot();
        float m = c * viewingConditions.getFlRoot();
        float s = ((float) Math.sqrt((double) ((viewingConditions.getC() * (c / ((float) Math.sqrt(((double) f) / 100.0d)))) / (viewingConditions.getAw() + 4.0f)))) * 50.0f;
        float hueRadians = (3.1415927f * h) / 180.0f;
        float jstar2 = (1.7f * f) / ((0.007f * f) + 1.0f);
        float mstar = ((float) Math.log1p(((double) m) * 0.0228d)) * 43.85965f;
        return new Cam16(h, c, j, q, m, s, jstar2, mstar * ((float) Math.cos((double) hueRadians)), mstar * ((float) Math.sin((double) hueRadians)));
    }

    public static Cam16 fromUcs(float jstar2, float astar2, float bstar2) {
        return fromUcsInViewingConditions(jstar2, astar2, bstar2, ViewingConditions.DEFAULT);
    }

    public static Cam16 fromUcsInViewingConditions(float jstar2, float astar2, float bstar2, ViewingConditions viewingConditions) {
        double c = (Math.expm1(Math.hypot((double) astar2, (double) bstar2) * 0.02280000038444996d) / 0.02280000038444996d) / ((double) viewingConditions.getFlRoot());
        double h = Math.atan2((double) bstar2, (double) astar2) * 57.29577951308232d;
        if (h < 0.0d) {
            h += 360.0d;
        }
        return fromJchInViewingConditions(jstar2 / (1.0f - ((jstar2 - 100.0f) * 0.007f)), (float) c, (float) h, viewingConditions);
    }

    public int getInt() {
        return viewed(ViewingConditions.DEFAULT);
    }

    /* access modifiers changed from: package-private */
    public int viewed(ViewingConditions viewingConditions) {
        float alpha;
        if (((double) getChroma()) == 0.0d || ((double) getJ()) == 0.0d) {
            alpha = 0.0f;
        } else {
            alpha = getChroma() / ((float) Math.sqrt(((double) getJ()) / 100.0d));
        }
        float t = (float) Math.pow(((double) alpha) / Math.pow(1.64d - Math.pow(0.29d, (double) viewingConditions.getN()), 0.73d), 1.1111111111111112d);
        float hRad = (getHue() * 3.1415927f) / 180.0f;
        float eHue = ((float) (Math.cos(((double) hRad) + 2.0d) + 3.8d)) * 0.25f;
        float ac = viewingConditions.getAw() * ((float) Math.pow(((double) getJ()) / 100.0d, (1.0d / ((double) viewingConditions.getC())) / ((double) viewingConditions.getZ())));
        float p1 = 3846.1538f * eHue * viewingConditions.getNc() * viewingConditions.getNcb();
        float p2 = ac / viewingConditions.getNbb();
        float hSin = (float) Math.sin((double) hRad);
        float hCos = (float) Math.cos((double) hRad);
        float gamma = (((0.305f + p2) * 23.0f) * t) / (((23.0f * p1) + ((11.0f * t) * hCos)) + ((108.0f * t) * hSin));
        float a = gamma * hCos;
        float b = gamma * hSin;
        float rA = (((p2 * 460.0f) + (451.0f * a)) + (288.0f * b)) / 1403.0f;
        float gA = (((p2 * 460.0f) - (891.0f * a)) - (261.0f * b)) / 1403.0f;
        float bA = (((460.0f * p2) - (220.0f * a)) - (6300.0f * b)) / 1403.0f;
        float f = alpha;
        float f2 = t;
        float rCBase = (float) Math.max(0.0d, (((double) Math.abs(rA)) * 27.13d) / (400.0d - ((double) Math.abs(rA))));
        float f3 = p1;
        float f4 = p2;
        float rC = Math.signum(rA) * (100.0f / viewingConditions.getFl()) * ((float) Math.pow((double) rCBase, 2.380952380952381d));
        float f5 = ac;
        float f6 = eHue;
        float gC = Math.signum(gA) * (100.0f / viewingConditions.getFl()) * ((float) Math.pow((double) ((float) Math.max(0.0d, (((double) Math.abs(gA)) * 27.13d) / (400.0d - ((double) Math.abs(gA))))), 2.380952380952381d));
        float bCBase = (float) Math.max(0.0d, (((double) Math.abs(bA)) * 27.13d) / (400.0d - ((double) Math.abs(bA))));
        float f7 = hRad;
        float f8 = bCBase;
        float bC = Math.signum(bA) * (100.0f / viewingConditions.getFl()) * ((float) Math.pow((double) bCBase, 2.380952380952381d));
        float rF = rC / viewingConditions.getRgbD()[0];
        float gF = gC / viewingConditions.getRgbD()[1];
        float bF = bC / viewingConditions.getRgbD()[2];
        float[][] matrix = CAM16RGB_TO_XYZ;
        float f9 = rCBase;
        return ColorUtils.intFromXyzComponents((matrix[0][0] * rF) + (matrix[0][1] * gF) + (matrix[0][2] * bF), (matrix[1][0] * rF) + (matrix[1][1] * gF) + (matrix[1][2] * bF), (matrix[2][0] * rF) + (matrix[2][1] * gF) + (matrix[2][2] * bF));
    }
}
