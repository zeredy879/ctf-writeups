package androidx.constraintlayout.core.motion.utils;

import java.io.PrintStream;
import java.lang.reflect.Array;
import java.util.Arrays;

public class StepCurve extends Easing {
    private static final boolean DEBUG = false;
    MonotonicCurveFit mCurveFit;

    StepCurve(String configString) {
        this.str = configString;
        double[] values = new double[(this.str.length() / 2)];
        int start = configString.indexOf(40) + 1;
        int off1 = configString.indexOf(44, start);
        int count = 0;
        while (off1 != -1) {
            int count2 = count + 1;
            values[count] = Double.parseDouble(configString.substring(start, off1).trim());
            int i = off1 + 1;
            start = i;
            off1 = configString.indexOf(44, i);
            count = count2;
        }
        values[count] = Double.parseDouble(configString.substring(start, configString.indexOf(41, start)).trim());
        this.mCurveFit = genSpline(Arrays.copyOf(values, count + 1));
    }

    private static MonotonicCurveFit genSpline(String str) {
        String[] sp = str.split("\\s+");
        double[] values = new double[sp.length];
        for (int i = 0; i < values.length; i++) {
            values[i] = Double.parseDouble(sp[i]);
        }
        return genSpline(values);
    }

    private static MonotonicCurveFit genSpline(double[] values) {
        double[] dArr = values;
        int length = (dArr.length * 3) - 2;
        int len = dArr.length - 1;
        double gap = 1.0d / ((double) len);
        int[] iArr = new int[2];
        iArr[1] = 1;
        iArr[0] = length;
        double[][] points = (double[][]) Array.newInstance(double.class, iArr);
        double[] time = new double[length];
        for (int i = 0; i < dArr.length; i++) {
            double v = dArr[i];
            points[i + len][0] = v;
            time[i + len] = ((double) i) * gap;
            if (i > 0) {
                points[(len * 2) + i][0] = v + 1.0d;
                time[(len * 2) + i] = (((double) i) * gap) + 1.0d;
                points[i - 1][0] = (v - 1.0d) - gap;
                time[i - 1] = ((((double) i) * gap) - 4.0d) - gap;
            }
        }
        MonotonicCurveFit ms = new MonotonicCurveFit(time, points);
        PrintStream printStream = System.out;
        printStream.println(" 0 " + ms.getPos(0.0d, 0));
        PrintStream printStream2 = System.out;
        printStream2.println(" 1 " + ms.getPos(1.0d, 0));
        return ms;
    }

    public double getDiff(double x) {
        return this.mCurveFit.getSlope(x, 0);
    }

    public double get(double x) {
        return this.mCurveFit.getPos(x, 0);
    }
}
