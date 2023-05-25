package androidx.constraintlayout.motion.utils;

import android.os.Build;
import android.util.Log;
import android.util.SparseArray;
import android.view.View;
import androidx.constraintlayout.core.motion.utils.CurveFit;
import androidx.constraintlayout.core.motion.utils.KeyCache;
import androidx.constraintlayout.core.motion.utils.TimeCycleSplineSet;
import androidx.constraintlayout.motion.widget.MotionLayout;
import androidx.constraintlayout.widget.ConstraintAttribute;
import java.lang.reflect.Array;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public abstract class ViewTimeCycle extends TimeCycleSplineSet {
    private static final String TAG = "ViewTimeCycle";

    public abstract boolean setProperty(View view, float f, long j, KeyCache keyCache);

    public float get(float pos, long time, View view, KeyCache cache) {
        long j = time;
        View view2 = view;
        KeyCache keyCache = cache;
        this.mCurveFit.getPos((double) pos, this.mCache);
        float period = this.mCache[1];
        if (period == 0.0f) {
            this.mContinue = false;
            return this.mCache[2];
        }
        if (Float.isNaN(this.last_cycle)) {
            this.last_cycle = keyCache.getFloatValue(view2, this.mType, 0);
            if (Float.isNaN(this.last_cycle)) {
                this.last_cycle = 0.0f;
            }
        }
        this.last_cycle = (float) ((((double) this.last_cycle) + ((((double) (j - this.last_time)) * 1.0E-9d) * ((double) period))) % 1.0d);
        keyCache.setFloatValue(view2, this.mType, 0, this.last_cycle);
        this.last_time = j;
        float v = this.mCache[0];
        float value = (v * calcWave(this.last_cycle)) + this.mCache[2];
        this.mContinue = (v == 0.0f && period == 0.0f) ? false : true;
        return value;
    }

    public static ViewTimeCycle makeCustomSpline(String str, SparseArray<ConstraintAttribute> attrList) {
        return new CustomSet(str, attrList);
    }

    /* JADX WARNING: Can't fix incorrect switch cases order */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public static androidx.constraintlayout.motion.utils.ViewTimeCycle makeSpline(java.lang.String r1, long r2) {
        /*
            int r0 = r1.hashCode()
            switch(r0) {
                case -1249320806: goto L_0x007d;
                case -1249320805: goto L_0x0073;
                case -1225497657: goto L_0x0068;
                case -1225497656: goto L_0x005d;
                case -1225497655: goto L_0x0052;
                case -1001078227: goto L_0x0047;
                case -908189618: goto L_0x003d;
                case -908189617: goto L_0x0033;
                case -40300674: goto L_0x0029;
                case -4379043: goto L_0x001f;
                case 37232917: goto L_0x0014;
                case 92909918: goto L_0x0009;
                default: goto L_0x0007;
            }
        L_0x0007:
            goto L_0x0087
        L_0x0009:
            java.lang.String r0 = "alpha"
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L_0x0007
            r0 = 0
            goto L_0x0088
        L_0x0014:
            java.lang.String r0 = "transitionPathRotate"
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L_0x0007
            r0 = 5
            goto L_0x0088
        L_0x001f:
            java.lang.String r0 = "elevation"
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L_0x0007
            r0 = 1
            goto L_0x0088
        L_0x0029:
            java.lang.String r0 = "rotation"
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L_0x0007
            r0 = 2
            goto L_0x0088
        L_0x0033:
            java.lang.String r0 = "scaleY"
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L_0x0007
            r0 = 7
            goto L_0x0088
        L_0x003d:
            java.lang.String r0 = "scaleX"
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L_0x0007
            r0 = 6
            goto L_0x0088
        L_0x0047:
            java.lang.String r0 = "progress"
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L_0x0007
            r0 = 11
            goto L_0x0088
        L_0x0052:
            java.lang.String r0 = "translationZ"
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L_0x0007
            r0 = 10
            goto L_0x0088
        L_0x005d:
            java.lang.String r0 = "translationY"
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L_0x0007
            r0 = 9
            goto L_0x0088
        L_0x0068:
            java.lang.String r0 = "translationX"
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L_0x0007
            r0 = 8
            goto L_0x0088
        L_0x0073:
            java.lang.String r0 = "rotationY"
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L_0x0007
            r0 = 4
            goto L_0x0088
        L_0x007d:
            java.lang.String r0 = "rotationX"
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L_0x0007
            r0 = 3
            goto L_0x0088
        L_0x0087:
            r0 = -1
        L_0x0088:
            switch(r0) {
                case 0: goto L_0x00cf;
                case 1: goto L_0x00c9;
                case 2: goto L_0x00c3;
                case 3: goto L_0x00bd;
                case 4: goto L_0x00b7;
                case 5: goto L_0x00b1;
                case 6: goto L_0x00ab;
                case 7: goto L_0x00a5;
                case 8: goto L_0x009f;
                case 9: goto L_0x0099;
                case 10: goto L_0x0093;
                case 11: goto L_0x008d;
                default: goto L_0x008b;
            }
        L_0x008b:
            r0 = 0
            return r0
        L_0x008d:
            androidx.constraintlayout.motion.utils.ViewTimeCycle$ProgressSet r0 = new androidx.constraintlayout.motion.utils.ViewTimeCycle$ProgressSet
            r0.<init>()
            goto L_0x00d5
        L_0x0093:
            androidx.constraintlayout.motion.utils.ViewTimeCycle$TranslationZset r0 = new androidx.constraintlayout.motion.utils.ViewTimeCycle$TranslationZset
            r0.<init>()
            goto L_0x00d5
        L_0x0099:
            androidx.constraintlayout.motion.utils.ViewTimeCycle$TranslationYset r0 = new androidx.constraintlayout.motion.utils.ViewTimeCycle$TranslationYset
            r0.<init>()
            goto L_0x00d5
        L_0x009f:
            androidx.constraintlayout.motion.utils.ViewTimeCycle$TranslationXset r0 = new androidx.constraintlayout.motion.utils.ViewTimeCycle$TranslationXset
            r0.<init>()
            goto L_0x00d5
        L_0x00a5:
            androidx.constraintlayout.motion.utils.ViewTimeCycle$ScaleYset r0 = new androidx.constraintlayout.motion.utils.ViewTimeCycle$ScaleYset
            r0.<init>()
            goto L_0x00d5
        L_0x00ab:
            androidx.constraintlayout.motion.utils.ViewTimeCycle$ScaleXset r0 = new androidx.constraintlayout.motion.utils.ViewTimeCycle$ScaleXset
            r0.<init>()
            goto L_0x00d5
        L_0x00b1:
            androidx.constraintlayout.motion.utils.ViewTimeCycle$PathRotate r0 = new androidx.constraintlayout.motion.utils.ViewTimeCycle$PathRotate
            r0.<init>()
            goto L_0x00d5
        L_0x00b7:
            androidx.constraintlayout.motion.utils.ViewTimeCycle$RotationYset r0 = new androidx.constraintlayout.motion.utils.ViewTimeCycle$RotationYset
            r0.<init>()
            goto L_0x00d5
        L_0x00bd:
            androidx.constraintlayout.motion.utils.ViewTimeCycle$RotationXset r0 = new androidx.constraintlayout.motion.utils.ViewTimeCycle$RotationXset
            r0.<init>()
            goto L_0x00d5
        L_0x00c3:
            androidx.constraintlayout.motion.utils.ViewTimeCycle$RotationSet r0 = new androidx.constraintlayout.motion.utils.ViewTimeCycle$RotationSet
            r0.<init>()
            goto L_0x00d5
        L_0x00c9:
            androidx.constraintlayout.motion.utils.ViewTimeCycle$ElevationSet r0 = new androidx.constraintlayout.motion.utils.ViewTimeCycle$ElevationSet
            r0.<init>()
            goto L_0x00d5
        L_0x00cf:
            androidx.constraintlayout.motion.utils.ViewTimeCycle$AlphaSet r0 = new androidx.constraintlayout.motion.utils.ViewTimeCycle$AlphaSet
            r0.<init>()
        L_0x00d5:
            r0.setStartTime(r2)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.motion.utils.ViewTimeCycle.makeSpline(java.lang.String, long):androidx.constraintlayout.motion.utils.ViewTimeCycle");
    }

    static class ElevationSet extends ViewTimeCycle {
        ElevationSet() {
        }

        public boolean setProperty(View view, float t, long time, KeyCache cache) {
            if (Build.VERSION.SDK_INT >= 21) {
                view.setElevation(get(t, time, view, cache));
            }
            return this.mContinue;
        }
    }

    static class AlphaSet extends ViewTimeCycle {
        AlphaSet() {
        }

        public boolean setProperty(View view, float t, long time, KeyCache cache) {
            view.setAlpha(get(t, time, view, cache));
            return this.mContinue;
        }
    }

    static class RotationSet extends ViewTimeCycle {
        RotationSet() {
        }

        public boolean setProperty(View view, float t, long time, KeyCache cache) {
            view.setRotation(get(t, time, view, cache));
            return this.mContinue;
        }
    }

    static class RotationXset extends ViewTimeCycle {
        RotationXset() {
        }

        public boolean setProperty(View view, float t, long time, KeyCache cache) {
            view.setRotationX(get(t, time, view, cache));
            return this.mContinue;
        }
    }

    static class RotationYset extends ViewTimeCycle {
        RotationYset() {
        }

        public boolean setProperty(View view, float t, long time, KeyCache cache) {
            view.setRotationY(get(t, time, view, cache));
            return this.mContinue;
        }
    }

    public static class PathRotate extends ViewTimeCycle {
        public boolean setProperty(View view, float t, long time, KeyCache cache) {
            return this.mContinue;
        }

        public boolean setPathRotate(View view, KeyCache cache, float t, long time, double dx, double dy) {
            view.setRotation(get(t, time, view, cache) + ((float) Math.toDegrees(Math.atan2(dy, dx))));
            return this.mContinue;
        }
    }

    static class ScaleXset extends ViewTimeCycle {
        ScaleXset() {
        }

        public boolean setProperty(View view, float t, long time, KeyCache cache) {
            view.setScaleX(get(t, time, view, cache));
            return this.mContinue;
        }
    }

    static class ScaleYset extends ViewTimeCycle {
        ScaleYset() {
        }

        public boolean setProperty(View view, float t, long time, KeyCache cache) {
            view.setScaleY(get(t, time, view, cache));
            return this.mContinue;
        }
    }

    static class TranslationXset extends ViewTimeCycle {
        TranslationXset() {
        }

        public boolean setProperty(View view, float t, long time, KeyCache cache) {
            view.setTranslationX(get(t, time, view, cache));
            return this.mContinue;
        }
    }

    static class TranslationYset extends ViewTimeCycle {
        TranslationYset() {
        }

        public boolean setProperty(View view, float t, long time, KeyCache cache) {
            view.setTranslationY(get(t, time, view, cache));
            return this.mContinue;
        }
    }

    static class TranslationZset extends ViewTimeCycle {
        TranslationZset() {
        }

        public boolean setProperty(View view, float t, long time, KeyCache cache) {
            if (Build.VERSION.SDK_INT >= 21) {
                view.setTranslationZ(get(t, time, view, cache));
            }
            return this.mContinue;
        }
    }

    public static class CustomSet extends ViewTimeCycle {
        String mAttributeName;
        float[] mCache;
        SparseArray<ConstraintAttribute> mConstraintAttributeList;
        float[] mTempValues;
        SparseArray<float[]> mWaveProperties = new SparseArray<>();

        public CustomSet(String attribute, SparseArray<ConstraintAttribute> attrList) {
            this.mAttributeName = attribute.split(",")[1];
            this.mConstraintAttributeList = attrList;
        }

        public void setup(int curveType) {
            int size = this.mConstraintAttributeList.size();
            int dimensionality = this.mConstraintAttributeList.valueAt(0).numberOfInterpolatedValues();
            double[] time = new double[size];
            this.mTempValues = new float[(dimensionality + 2)];
            this.mCache = new float[dimensionality];
            int[] iArr = new int[2];
            iArr[1] = dimensionality + 2;
            iArr[0] = size;
            double[][] values = (double[][]) Array.newInstance(double.class, iArr);
            for (int i = 0; i < size; i++) {
                int key = this.mConstraintAttributeList.keyAt(i);
                float[] waveProp = this.mWaveProperties.valueAt(i);
                time[i] = ((double) key) * 0.01d;
                this.mConstraintAttributeList.valueAt(i).getValuesToInterpolate(this.mTempValues);
                int k = 0;
                while (true) {
                    float[] fArr = this.mTempValues;
                    if (k >= fArr.length) {
                        break;
                    }
                    values[i][k] = (double) fArr[k];
                    k++;
                }
                values[i][dimensionality] = (double) waveProp[0];
                values[i][dimensionality + 1] = (double) waveProp[1];
            }
            this.mCurveFit = CurveFit.get(curveType, time, values);
        }

        public void setPoint(int position, float value, float period, int shape, float offset) {
            throw new RuntimeException("don't call for custom attribute call setPoint(pos, ConstraintAttribute,...)");
        }

        public void setPoint(int position, ConstraintAttribute value, float period, int shape, float offset) {
            this.mConstraintAttributeList.append(position, value);
            this.mWaveProperties.append(position, new float[]{period, offset});
            this.mWaveShape = Math.max(this.mWaveShape, shape);
        }

        public boolean setProperty(View view, float t, long time, KeyCache cache) {
            View view2 = view;
            long j = time;
            this.mCurveFit.getPos((double) t, this.mTempValues);
            float[] fArr = this.mTempValues;
            float period = fArr[fArr.length - 2];
            float offset = fArr[fArr.length - 1];
            long delta_time = j - this.last_time;
            if (Float.isNaN(this.last_cycle)) {
                this.last_cycle = cache.getFloatValue(view2, this.mAttributeName, 0);
                if (Float.isNaN(this.last_cycle)) {
                    this.last_cycle = 0.0f;
                }
            } else {
                KeyCache keyCache = cache;
            }
            this.last_cycle = (float) ((((double) this.last_cycle) + ((((double) delta_time) * 1.0E-9d) * ((double) period))) % 1.0d);
            this.last_time = j;
            float wave = calcWave(this.last_cycle);
            this.mContinue = false;
            for (int i = 0; i < this.mCache.length; i++) {
                this.mContinue |= ((double) this.mTempValues[i]) != 0.0d;
                this.mCache[i] = (this.mTempValues[i] * wave) + offset;
            }
            CustomSupport.setInterpolatedValue(this.mConstraintAttributeList.valueAt(0), view2, this.mCache);
            if (period != 0.0f) {
                this.mContinue = true;
            }
            return this.mContinue;
        }
    }

    static class ProgressSet extends ViewTimeCycle {
        boolean mNoMethod = false;

        ProgressSet() {
        }

        public boolean setProperty(View view, float t, long time, KeyCache cache) {
            Method method;
            View view2 = view;
            if (view2 instanceof MotionLayout) {
                ((MotionLayout) view2).setProgress(get(t, time, view, cache));
            } else if (this.mNoMethod) {
                return false;
            } else {
                try {
                    method = view.getClass().getMethod("setProgress", new Class[]{Float.TYPE});
                } catch (NoSuchMethodException e) {
                    this.mNoMethod = true;
                    method = null;
                }
                if (method != null) {
                    try {
                        method.invoke(view, new Object[]{Float.valueOf(get(t, time, view, cache))});
                    } catch (IllegalAccessException e2) {
                        Log.e(ViewTimeCycle.TAG, "unable to setProgress", e2);
                    } catch (InvocationTargetException e3) {
                        Log.e(ViewTimeCycle.TAG, "unable to setProgress", e3);
                    }
                }
            }
            return this.mContinue;
        }
    }
}
