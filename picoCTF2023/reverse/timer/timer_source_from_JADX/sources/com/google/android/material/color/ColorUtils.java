package com.google.android.material.color;

import androidx.core.view.ViewCompat;
import java.util.Arrays;

final class ColorUtils {
    private static final float[] WHITE_POINT_D65 = {95.047f, 100.0f, 108.883f};

    private ColorUtils() {
    }

    public static final float[] whitePointD65() {
        return Arrays.copyOf(WHITE_POINT_D65, 3);
    }

    public static int redFromInt(int argb) {
        return (16711680 & argb) >> 16;
    }

    public static int greenFromInt(int argb) {
        return (65280 & argb) >> 8;
    }

    public static int blueFromInt(int argb) {
        return argb & 255;
    }

    public static float lstarFromInt(int argb) {
        return (float) labFromInt(argb)[0];
    }

    public static String hexFromInt(int argb) {
        int red = redFromInt(argb);
        int blue = blueFromInt(argb);
        return String.format("#%02x%02x%02x", new Object[]{Integer.valueOf(red), Integer.valueOf(greenFromInt(argb)), Integer.valueOf(blue)});
    }

    public static float[] xyzFromInt(int argb) {
        float r = linearized(((float) redFromInt(argb)) / 255.0f) * 100.0f;
        float g = linearized(((float) greenFromInt(argb)) / 255.0f) * 100.0f;
        float b = linearized(((float) blueFromInt(argb)) / 255.0f) * 100.0f;
        return new float[]{(0.41233894f * r) + (0.35762063f * g) + (0.18051042f * b), (0.2126f * r) + (0.7152f * g) + (0.0722f * b), (0.01932141f * r) + (0.11916382f * g) + (0.9503448f * b)};
    }

    public static int intFromRgb(int r, int g, int b) {
        return (((((r & 255) << 16) | ViewCompat.MEASURED_STATE_MASK) | ((g & 255) << 8)) | (b & 255)) >>> 0;
    }

    public static double[] labFromInt(int argb) {
        double fy;
        double fx;
        double d;
        double fz;
        float[] xyz = xyzFromInt(argb);
        float f = xyz[1];
        float[] fArr = WHITE_POINT_D65;
        double yNormalized = (double) (f / fArr[1]);
        if (yNormalized > 0.008856451679035631d) {
            fy = Math.cbrt(yNormalized);
        } else {
            fy = ((yNormalized * 903.2962962962963d) + 16.0d) / 116.0d;
        }
        float[] fArr2 = fArr;
        double xNormalized = (double) (xyz[0] / fArr[0]);
        if (xNormalized > 0.008856451679035631d) {
            fx = Math.cbrt(xNormalized);
        } else {
            fx = ((xNormalized * 903.2962962962963d) + 16.0d) / 116.0d;
        }
        double zNormalized = (double) (xyz[2] / fArr2[2]);
        if (zNormalized > 0.008856451679035631d) {
            fz = Math.cbrt(zNormalized);
            d = 116.0d;
        } else {
            d = 116.0d;
            fz = ((903.2962962962963d * zNormalized) + 16.0d) / 116.0d;
        }
        return new double[]{(d * fy) - 16.0d, (fx - fy) * 500.0d, (fy - fz) * 200.0d};
    }

    public static int intFromLab(double l, double a, double b) {
        double fy = (l + 16.0d) / 116.0d;
        double fx = (a / 500.0d) + fy;
        double fz = fy - (b / 200.0d);
        double fx3 = fx * fx * fx;
        double xNormalized = fx3 > 0.008856451679035631d ? fx3 : ((fx * 116.0d) - 16.0d) / 903.2962962962963d;
        double yNormalized = l > 8.0d ? fy * fy * fy : l / 903.2962962962963d;
        double fz3 = fz * fz * fz;
        double zNormalized = fz3 > 0.008856451679035631d ? fz3 : ((116.0d * fz) - 16.0d) / 903.2962962962963d;
        float[] fArr = WHITE_POINT_D65;
        double x = ((double) fArr[0]) * xNormalized;
        double d = x;
        return intFromXyzComponents((float) x, (float) (((double) fArr[1]) * yNormalized), (float) (((double) fArr[2]) * zNormalized));
    }

    public static int intFromXyzComponents(float x, float y, float z) {
        float x2 = x / 100.0f;
        float y2 = y / 100.0f;
        float z2 = z / 100.0f;
        return intFromRgb(Math.max(Math.min(255, Math.round(delinearized((3.2406f * x2) + (-1.5372f * y2) + (-0.4986f * z2)) * 255.0f)), 0), Math.max(Math.min(255, Math.round(delinearized((-0.9689f * x2) + (1.8758f * y2) + (0.0415f * z2)) * 255.0f)), 0), Math.max(Math.min(255, Math.round(255.0f * delinearized((0.0557f * x2) + (-0.204f * y2) + (1.057f * z2)))), 0));
    }

    public static int intFromXyz(float[] xyz) {
        return intFromXyzComponents(xyz[0], xyz[1], xyz[2]);
    }

    public static int intFromLstar(float lstar) {
        float fy = (lstar + 16.0f) / 116.0f;
        float fz = fy;
        float fx = fy;
        boolean cubeExceedEpsilon = (fy * fy) * fy > 0.008856452f;
        float y = (lstar > 8.0f ? 1 : (lstar == 8.0f ? 0 : -1)) > 0 ? fy * fy * fy : lstar / 903.2963f;
        float x = cubeExceedEpsilon ? fx * fx * fx : ((fx * 116.0f) - 16.0f) / 903.2963f;
        float z = cubeExceedEpsilon ? fz * fz * fz : ((116.0f * fx) - 16.0f) / 903.2963f;
        float[] fArr = WHITE_POINT_D65;
        return intFromXyz(new float[]{fArr[0] * x, fArr[1] * y, fArr[2] * z});
    }

    public static float yFromLstar(float lstar) {
        if (lstar > 8.0f) {
            return ((float) Math.pow((((double) lstar) + 16.0d) / 116.0d, 3.0d)) * 100.0f;
        }
        return (lstar / 903.2963f) * 100.0f;
    }

    public static float linearized(float rgb) {
        if (rgb <= 0.04045f) {
            return rgb / 12.92f;
        }
        return (float) Math.pow((double) ((0.055f + rgb) / 1.055f), 2.4000000953674316d);
    }

    public static float delinearized(float rgb) {
        if (rgb <= 0.0031308f) {
            return 12.92f * rgb;
        }
        return (((float) Math.pow((double) rgb, 0.4166666567325592d)) * 1.055f) - 0.055f;
    }
}
