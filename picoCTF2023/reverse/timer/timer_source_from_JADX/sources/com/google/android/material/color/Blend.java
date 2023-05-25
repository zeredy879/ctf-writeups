package com.google.android.material.color;

final class Blend {
    private static final float HARMONIZE_MAX_DEGREES = 15.0f;
    private static final float HARMONIZE_PERCENTAGE = 0.5f;

    private Blend() {
    }

    public static int harmonize(int designColor, int sourceColor) {
        Hct fromHct = Hct.fromInt(designColor);
        Hct toHct = Hct.fromInt(sourceColor);
        return Hct.from(MathUtils.sanitizeDegrees(fromHct.getHue() + (rotationDirection(fromHct.getHue(), toHct.getHue()) * Math.min(0.5f * MathUtils.differenceDegrees(fromHct.getHue(), toHct.getHue()), HARMONIZE_MAX_DEGREES))), fromHct.getChroma(), fromHct.getTone()).toInt();
    }

    public static int blendHctHue(int from, int to, float amount) {
        return Hct.from(Cam16.fromInt(blendCam16Ucs(from, to, amount)).getHue(), Cam16.fromInt(from).getChroma(), ColorUtils.lstarFromInt(from)).toInt();
    }

    public static int blendCam16Ucs(int from, int to, float amount) {
        Cam16 fromCam = Cam16.fromInt(from);
        Cam16 toCam = Cam16.fromInt(to);
        float aJ = fromCam.getJStar();
        float aA = fromCam.getAStar();
        float aB = fromCam.getBStar();
        return Cam16.fromUcs(((toCam.getJStar() - aJ) * amount) + aJ, ((toCam.getAStar() - aA) * amount) + aA, ((toCam.getBStar() - aB) * amount) + aB).getInt();
    }

    private static float rotationDirection(float from, float to) {
        float a = to - from;
        float b = (to - from) + 360.0f;
        float c = (to - from) - 360.0f;
        float aAbs = Math.abs(a);
        float bAbs = Math.abs(b);
        float cAbs = Math.abs(c);
        if (aAbs > bAbs || aAbs > cAbs) {
            if (bAbs > aAbs || bAbs > cAbs) {
                if (((double) c) >= 0.0d) {
                    return 1.0f;
                }
                return -1.0f;
            } else if (((double) b) >= 0.0d) {
                return 1.0f;
            } else {
                return -1.0f;
            }
        } else if (((double) a) >= 0.0d) {
            return 1.0f;
        } else {
            return -1.0f;
        }
    }
}
