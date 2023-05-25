package androidx.constraintlayout.motion.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.os.Build;
import android.util.AttributeSet;
import android.util.Log;
import android.util.SparseIntArray;
import androidx.constraintlayout.core.motion.utils.SplineSet;
import androidx.constraintlayout.core.motion.utils.TypedValues;
import androidx.constraintlayout.motion.utils.ViewOscillator;
import androidx.constraintlayout.motion.utils.ViewSpline;
import androidx.constraintlayout.widget.C0015R;
import androidx.constraintlayout.widget.ConstraintAttribute;
import java.util.HashMap;
import java.util.HashSet;

public class KeyCycle extends Key {
    public static final int KEY_TYPE = 4;
    static final String NAME = "KeyCycle";
    public static final int SHAPE_BOUNCE = 6;
    public static final int SHAPE_COS_WAVE = 5;
    public static final int SHAPE_REVERSE_SAW_WAVE = 4;
    public static final int SHAPE_SAW_WAVE = 3;
    public static final int SHAPE_SIN_WAVE = 0;
    public static final int SHAPE_SQUARE_WAVE = 1;
    public static final int SHAPE_TRIANGLE_WAVE = 2;
    private static final String TAG = "KeyCycle";
    public static final String WAVE_OFFSET = "waveOffset";
    public static final String WAVE_PERIOD = "wavePeriod";
    public static final String WAVE_PHASE = "wavePhase";
    public static final String WAVE_SHAPE = "waveShape";
    /* access modifiers changed from: private */
    public float mAlpha = Float.NaN;
    /* access modifiers changed from: private */
    public int mCurveFit = 0;
    /* access modifiers changed from: private */
    public String mCustomWaveShape = null;
    /* access modifiers changed from: private */
    public float mElevation = Float.NaN;
    /* access modifiers changed from: private */
    public float mProgress = Float.NaN;
    /* access modifiers changed from: private */
    public float mRotation = Float.NaN;
    /* access modifiers changed from: private */
    public float mRotationX = Float.NaN;
    /* access modifiers changed from: private */
    public float mRotationY = Float.NaN;
    /* access modifiers changed from: private */
    public float mScaleX = Float.NaN;
    /* access modifiers changed from: private */
    public float mScaleY = Float.NaN;
    /* access modifiers changed from: private */
    public String mTransitionEasing = null;
    /* access modifiers changed from: private */
    public float mTransitionPathRotate = Float.NaN;
    /* access modifiers changed from: private */
    public float mTranslationX = Float.NaN;
    /* access modifiers changed from: private */
    public float mTranslationY = Float.NaN;
    /* access modifiers changed from: private */
    public float mTranslationZ = Float.NaN;
    /* access modifiers changed from: private */
    public float mWaveOffset = 0.0f;
    /* access modifiers changed from: private */
    public float mWavePeriod = Float.NaN;
    /* access modifiers changed from: private */
    public float mWavePhase = 0.0f;
    /* access modifiers changed from: private */
    public int mWaveShape = -1;
    /* access modifiers changed from: private */
    public int mWaveVariesBy = -1;

    public KeyCycle() {
        this.mType = 4;
        this.mCustomConstraints = new HashMap();
    }

    public void load(Context context, AttributeSet attrs) {
        Loader.read(this, context.obtainStyledAttributes(attrs, C0015R.styleable.KeyCycle));
    }

    public void getAttributeNames(HashSet<String> attributes) {
        if (!Float.isNaN(this.mAlpha)) {
            attributes.add("alpha");
        }
        if (!Float.isNaN(this.mElevation)) {
            attributes.add("elevation");
        }
        if (!Float.isNaN(this.mRotation)) {
            attributes.add(Key.ROTATION);
        }
        if (!Float.isNaN(this.mRotationX)) {
            attributes.add("rotationX");
        }
        if (!Float.isNaN(this.mRotationY)) {
            attributes.add("rotationY");
        }
        if (!Float.isNaN(this.mScaleX)) {
            attributes.add("scaleX");
        }
        if (!Float.isNaN(this.mScaleY)) {
            attributes.add("scaleY");
        }
        if (!Float.isNaN(this.mTransitionPathRotate)) {
            attributes.add("transitionPathRotate");
        }
        if (!Float.isNaN(this.mTranslationX)) {
            attributes.add("translationX");
        }
        if (!Float.isNaN(this.mTranslationY)) {
            attributes.add("translationY");
        }
        if (!Float.isNaN(this.mTranslationZ)) {
            attributes.add("translationZ");
        }
        if (this.mCustomConstraints.size() > 0) {
            for (String s : this.mCustomConstraints.keySet()) {
                attributes.add("CUSTOM," + s);
            }
        }
    }

    public void addCycleValues(HashMap<String, ViewOscillator> oscSet) {
        ViewOscillator osc;
        ViewOscillator osc2;
        HashMap<String, ViewOscillator> hashMap = oscSet;
        for (String key : oscSet.keySet()) {
            if (key.startsWith("CUSTOM")) {
                ConstraintAttribute cValue = (ConstraintAttribute) this.mCustomConstraints.get(key.substring("CUSTOM".length() + 1));
                if (!(cValue == null || cValue.getType() != ConstraintAttribute.AttributeType.FLOAT_TYPE || (osc2 = hashMap.get(key)) == null)) {
                    osc2.setPoint(this.mFramePosition, this.mWaveShape, this.mCustomWaveShape, this.mWaveVariesBy, this.mWavePeriod, this.mWaveOffset, this.mWavePhase, cValue.getValueToInterpolate(), cValue);
                }
            } else {
                float value = getValue(key);
                if (!Float.isNaN(value) && (osc = hashMap.get(key)) != null) {
                    osc.setPoint(this.mFramePosition, this.mWaveShape, this.mCustomWaveShape, this.mWaveVariesBy, this.mWavePeriod, this.mWaveOffset, this.mWavePhase, value);
                }
            }
        }
    }

    /* JADX WARNING: Can't fix incorrect switch cases order */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public float getValue(java.lang.String r3) {
        /*
            r2 = this;
            int r0 = r3.hashCode()
            switch(r0) {
                case -1249320806: goto L_0x0095;
                case -1249320805: goto L_0x008b;
                case -1225497657: goto L_0x0080;
                case -1225497656: goto L_0x0075;
                case -1225497655: goto L_0x006a;
                case -1001078227: goto L_0x005f;
                case -908189618: goto L_0x0055;
                case -908189617: goto L_0x004b;
                case -40300674: goto L_0x0041;
                case -4379043: goto L_0x0037;
                case 37232917: goto L_0x002c;
                case 92909918: goto L_0x0021;
                case 156108012: goto L_0x0015;
                case 1530034690: goto L_0x0009;
                default: goto L_0x0007;
            }
        L_0x0007:
            goto L_0x009f
        L_0x0009:
            java.lang.String r0 = "wavePhase"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0007
            r0 = 12
            goto L_0x00a0
        L_0x0015:
            java.lang.String r0 = "waveOffset"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0007
            r0 = 11
            goto L_0x00a0
        L_0x0021:
            java.lang.String r0 = "alpha"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0007
            r0 = 0
            goto L_0x00a0
        L_0x002c:
            java.lang.String r0 = "transitionPathRotate"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0007
            r0 = 5
            goto L_0x00a0
        L_0x0037:
            java.lang.String r0 = "elevation"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0007
            r0 = 1
            goto L_0x00a0
        L_0x0041:
            java.lang.String r0 = "rotation"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0007
            r0 = 2
            goto L_0x00a0
        L_0x004b:
            java.lang.String r0 = "scaleY"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0007
            r0 = 7
            goto L_0x00a0
        L_0x0055:
            java.lang.String r0 = "scaleX"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0007
            r0 = 6
            goto L_0x00a0
        L_0x005f:
            java.lang.String r0 = "progress"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0007
            r0 = 13
            goto L_0x00a0
        L_0x006a:
            java.lang.String r0 = "translationZ"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0007
            r0 = 10
            goto L_0x00a0
        L_0x0075:
            java.lang.String r0 = "translationY"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0007
            r0 = 9
            goto L_0x00a0
        L_0x0080:
            java.lang.String r0 = "translationX"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0007
            r0 = 8
            goto L_0x00a0
        L_0x008b:
            java.lang.String r0 = "rotationY"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0007
            r0 = 4
            goto L_0x00a0
        L_0x0095:
            java.lang.String r0 = "rotationX"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0007
            r0 = 3
            goto L_0x00a0
        L_0x009f:
            r0 = -1
        L_0x00a0:
            switch(r0) {
                case 0: goto L_0x00e9;
                case 1: goto L_0x00e6;
                case 2: goto L_0x00e3;
                case 3: goto L_0x00e0;
                case 4: goto L_0x00dd;
                case 5: goto L_0x00da;
                case 6: goto L_0x00d7;
                case 7: goto L_0x00d4;
                case 8: goto L_0x00d1;
                case 9: goto L_0x00ce;
                case 10: goto L_0x00cb;
                case 11: goto L_0x00c8;
                case 12: goto L_0x00c5;
                case 13: goto L_0x00c2;
                default: goto L_0x00a3;
            }
        L_0x00a3:
            java.lang.String r0 = "CUSTOM"
            boolean r0 = r3.startsWith(r0)
            if (r0 != 0) goto L_0x00ec
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            java.lang.String r1 = "  UNKNOWN  "
            r0.append(r1)
            r0.append(r3)
            java.lang.String r0 = r0.toString()
            java.lang.String r1 = "WARNING! KeyCycle"
            android.util.Log.v(r1, r0)
            goto L_0x00ec
        L_0x00c2:
            float r0 = r2.mProgress
            return r0
        L_0x00c5:
            float r0 = r2.mWavePhase
            return r0
        L_0x00c8:
            float r0 = r2.mWaveOffset
            return r0
        L_0x00cb:
            float r0 = r2.mTranslationZ
            return r0
        L_0x00ce:
            float r0 = r2.mTranslationY
            return r0
        L_0x00d1:
            float r0 = r2.mTranslationX
            return r0
        L_0x00d4:
            float r0 = r2.mScaleY
            return r0
        L_0x00d7:
            float r0 = r2.mScaleX
            return r0
        L_0x00da:
            float r0 = r2.mTransitionPathRotate
            return r0
        L_0x00dd:
            float r0 = r2.mRotationY
            return r0
        L_0x00e0:
            float r0 = r2.mRotationX
            return r0
        L_0x00e3:
            float r0 = r2.mRotation
            return r0
        L_0x00e6:
            float r0 = r2.mElevation
            return r0
        L_0x00e9:
            float r0 = r2.mAlpha
            return r0
        L_0x00ec:
            r0 = 2143289344(0x7fc00000, float:NaN)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.motion.widget.KeyCycle.getValue(java.lang.String):float");
    }

    public void addValues(HashMap<String, ViewSpline> splines) {
        Debug.logStack(TypedValues.CycleType.NAME, "add " + splines.size() + " values", 2);
        for (String s : splines.keySet()) {
            SplineSet splineSet = splines.get(s);
            if (splineSet != null) {
                char c = 65535;
                switch (s.hashCode()) {
                    case -1249320806:
                        if (s.equals("rotationX")) {
                            c = 3;
                            break;
                        }
                        break;
                    case -1249320805:
                        if (s.equals("rotationY")) {
                            c = 4;
                            break;
                        }
                        break;
                    case -1225497657:
                        if (s.equals("translationX")) {
                            c = 8;
                            break;
                        }
                        break;
                    case -1225497656:
                        if (s.equals("translationY")) {
                            c = 9;
                            break;
                        }
                        break;
                    case -1225497655:
                        if (s.equals("translationZ")) {
                            c = 10;
                            break;
                        }
                        break;
                    case -1001078227:
                        if (s.equals("progress")) {
                            c = 13;
                            break;
                        }
                        break;
                    case -908189618:
                        if (s.equals("scaleX")) {
                            c = 6;
                            break;
                        }
                        break;
                    case -908189617:
                        if (s.equals("scaleY")) {
                            c = 7;
                            break;
                        }
                        break;
                    case -40300674:
                        if (s.equals(Key.ROTATION)) {
                            c = 2;
                            break;
                        }
                        break;
                    case -4379043:
                        if (s.equals("elevation")) {
                            c = 1;
                            break;
                        }
                        break;
                    case 37232917:
                        if (s.equals("transitionPathRotate")) {
                            c = 5;
                            break;
                        }
                        break;
                    case 92909918:
                        if (s.equals("alpha")) {
                            c = 0;
                            break;
                        }
                        break;
                    case 156108012:
                        if (s.equals("waveOffset")) {
                            c = 11;
                            break;
                        }
                        break;
                    case 1530034690:
                        if (s.equals("wavePhase")) {
                            c = 12;
                            break;
                        }
                        break;
                }
                switch (c) {
                    case 0:
                        splineSet.setPoint(this.mFramePosition, this.mAlpha);
                        break;
                    case 1:
                        splineSet.setPoint(this.mFramePosition, this.mElevation);
                        break;
                    case 2:
                        splineSet.setPoint(this.mFramePosition, this.mRotation);
                        break;
                    case 3:
                        splineSet.setPoint(this.mFramePosition, this.mRotationX);
                        break;
                    case 4:
                        splineSet.setPoint(this.mFramePosition, this.mRotationY);
                        break;
                    case 5:
                        splineSet.setPoint(this.mFramePosition, this.mTransitionPathRotate);
                        break;
                    case 6:
                        splineSet.setPoint(this.mFramePosition, this.mScaleX);
                        break;
                    case 7:
                        splineSet.setPoint(this.mFramePosition, this.mScaleY);
                        break;
                    case 8:
                        splineSet.setPoint(this.mFramePosition, this.mTranslationX);
                        break;
                    case 9:
                        splineSet.setPoint(this.mFramePosition, this.mTranslationY);
                        break;
                    case 10:
                        splineSet.setPoint(this.mFramePosition, this.mTranslationZ);
                        break;
                    case 11:
                        splineSet.setPoint(this.mFramePosition, this.mWaveOffset);
                        break;
                    case 12:
                        splineSet.setPoint(this.mFramePosition, this.mWavePhase);
                        break;
                    case 13:
                        splineSet.setPoint(this.mFramePosition, this.mProgress);
                        break;
                    default:
                        if (s.startsWith("CUSTOM")) {
                            break;
                        } else {
                            Log.v("WARNING KeyCycle", "  UNKNOWN  " + s);
                            break;
                        }
                }
            }
        }
    }

    private static class Loader {
        private static final int ANDROID_ALPHA = 9;
        private static final int ANDROID_ELEVATION = 10;
        private static final int ANDROID_ROTATION = 11;
        private static final int ANDROID_ROTATION_X = 12;
        private static final int ANDROID_ROTATION_Y = 13;
        private static final int ANDROID_SCALE_X = 15;
        private static final int ANDROID_SCALE_Y = 16;
        private static final int ANDROID_TRANSLATION_X = 17;
        private static final int ANDROID_TRANSLATION_Y = 18;
        private static final int ANDROID_TRANSLATION_Z = 19;
        private static final int CURVE_FIT = 4;
        private static final int FRAME_POSITION = 2;
        private static final int PROGRESS = 20;
        private static final int TARGET_ID = 1;
        private static final int TRANSITION_EASING = 3;
        private static final int TRANSITION_PATH_ROTATE = 14;
        private static final int WAVE_OFFSET = 7;
        private static final int WAVE_PERIOD = 6;
        private static final int WAVE_PHASE = 21;
        private static final int WAVE_SHAPE = 5;
        private static final int WAVE_VARIES_BY = 8;
        private static SparseIntArray mAttrMap;

        private Loader() {
        }

        static {
            SparseIntArray sparseIntArray = new SparseIntArray();
            mAttrMap = sparseIntArray;
            sparseIntArray.append(C0015R.styleable.KeyCycle_motionTarget, 1);
            mAttrMap.append(C0015R.styleable.KeyCycle_framePosition, 2);
            mAttrMap.append(C0015R.styleable.KeyCycle_transitionEasing, 3);
            mAttrMap.append(C0015R.styleable.KeyCycle_curveFit, 4);
            mAttrMap.append(C0015R.styleable.KeyCycle_waveShape, 5);
            mAttrMap.append(C0015R.styleable.KeyCycle_wavePeriod, 6);
            mAttrMap.append(C0015R.styleable.KeyCycle_waveOffset, 7);
            mAttrMap.append(C0015R.styleable.KeyCycle_waveVariesBy, 8);
            mAttrMap.append(C0015R.styleable.KeyCycle_android_alpha, 9);
            mAttrMap.append(C0015R.styleable.KeyCycle_android_elevation, 10);
            mAttrMap.append(C0015R.styleable.KeyCycle_android_rotation, 11);
            mAttrMap.append(C0015R.styleable.KeyCycle_android_rotationX, 12);
            mAttrMap.append(C0015R.styleable.KeyCycle_android_rotationY, 13);
            mAttrMap.append(C0015R.styleable.KeyCycle_transitionPathRotate, 14);
            mAttrMap.append(C0015R.styleable.KeyCycle_android_scaleX, 15);
            mAttrMap.append(C0015R.styleable.KeyCycle_android_scaleY, 16);
            mAttrMap.append(C0015R.styleable.KeyCycle_android_translationX, 17);
            mAttrMap.append(C0015R.styleable.KeyCycle_android_translationY, 18);
            mAttrMap.append(C0015R.styleable.KeyCycle_android_translationZ, 19);
            mAttrMap.append(C0015R.styleable.KeyCycle_motionProgress, 20);
            mAttrMap.append(C0015R.styleable.KeyCycle_wavePhase, 21);
        }

        /* access modifiers changed from: private */
        public static void read(KeyCycle c, TypedArray a) {
            int N = a.getIndexCount();
            for (int i = 0; i < N; i++) {
                int attr = a.getIndex(i);
                switch (mAttrMap.get(attr)) {
                    case 1:
                        if (!MotionLayout.IS_IN_EDIT_MODE) {
                            if (a.peekValue(attr).type != 3) {
                                c.mTargetId = a.getResourceId(attr, c.mTargetId);
                                break;
                            } else {
                                c.mTargetString = a.getString(attr);
                                break;
                            }
                        } else {
                            c.mTargetId = a.getResourceId(attr, c.mTargetId);
                            if (c.mTargetId != -1) {
                                break;
                            } else {
                                c.mTargetString = a.getString(attr);
                                break;
                            }
                        }
                    case 2:
                        c.mFramePosition = a.getInt(attr, c.mFramePosition);
                        break;
                    case 3:
                        String unused = c.mTransitionEasing = a.getString(attr);
                        break;
                    case 4:
                        int unused2 = c.mCurveFit = a.getInteger(attr, c.mCurveFit);
                        break;
                    case 5:
                        if (a.peekValue(attr).type != 3) {
                            int unused3 = c.mWaveShape = a.getInt(attr, c.mWaveShape);
                            break;
                        } else {
                            String unused4 = c.mCustomWaveShape = a.getString(attr);
                            int unused5 = c.mWaveShape = 7;
                            break;
                        }
                    case 6:
                        float unused6 = c.mWavePeriod = a.getFloat(attr, c.mWavePeriod);
                        break;
                    case 7:
                        if (a.peekValue(attr).type != 5) {
                            float unused7 = c.mWaveOffset = a.getFloat(attr, c.mWaveOffset);
                            break;
                        } else {
                            float unused8 = c.mWaveOffset = a.getDimension(attr, c.mWaveOffset);
                            break;
                        }
                    case 8:
                        int unused9 = c.mWaveVariesBy = a.getInt(attr, c.mWaveVariesBy);
                        break;
                    case 9:
                        float unused10 = c.mAlpha = a.getFloat(attr, c.mAlpha);
                        break;
                    case 10:
                        float unused11 = c.mElevation = a.getDimension(attr, c.mElevation);
                        break;
                    case 11:
                        float unused12 = c.mRotation = a.getFloat(attr, c.mRotation);
                        break;
                    case 12:
                        float unused13 = c.mRotationX = a.getFloat(attr, c.mRotationX);
                        break;
                    case 13:
                        float unused14 = c.mRotationY = a.getFloat(attr, c.mRotationY);
                        break;
                    case 14:
                        float unused15 = c.mTransitionPathRotate = a.getFloat(attr, c.mTransitionPathRotate);
                        break;
                    case 15:
                        float unused16 = c.mScaleX = a.getFloat(attr, c.mScaleX);
                        break;
                    case 16:
                        float unused17 = c.mScaleY = a.getFloat(attr, c.mScaleY);
                        break;
                    case 17:
                        float unused18 = c.mTranslationX = a.getDimension(attr, c.mTranslationX);
                        break;
                    case 18:
                        float unused19 = c.mTranslationY = a.getDimension(attr, c.mTranslationY);
                        break;
                    case 19:
                        if (Build.VERSION.SDK_INT < 21) {
                            break;
                        } else {
                            float unused20 = c.mTranslationZ = a.getDimension(attr, c.mTranslationZ);
                            break;
                        }
                    case 20:
                        float unused21 = c.mProgress = a.getFloat(attr, c.mProgress);
                        break;
                    case 21:
                        float unused22 = c.mWavePhase = a.getFloat(attr, c.mWavePhase) / 360.0f;
                        break;
                    default:
                        Log.e(TypedValues.CycleType.NAME, "unused attribute 0x" + Integer.toHexString(attr) + "   " + mAttrMap.get(attr));
                        break;
                }
            }
        }
    }

    /* JADX WARNING: Can't fix incorrect switch cases order */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public void setValue(java.lang.String r3, java.lang.Object r4) {
        /*
            r2 = this;
            int r0 = r3.hashCode()
            r1 = 7
            switch(r0) {
                case -1913008125: goto L_0x00c6;
                case -1812823328: goto L_0x00bb;
                case -1249320806: goto L_0x00b1;
                case -1249320805: goto L_0x00a7;
                case -1225497657: goto L_0x009c;
                case -1225497656: goto L_0x0091;
                case -1225497655: goto L_0x0086;
                case -908189618: goto L_0x007c;
                case -908189617: goto L_0x0071;
                case -40300674: goto L_0x0067;
                case -4379043: goto L_0x005c;
                case 37232917: goto L_0x0050;
                case 92909918: goto L_0x0045;
                case 156108012: goto L_0x0039;
                case 184161818: goto L_0x002d;
                case 579057826: goto L_0x0022;
                case 1530034690: goto L_0x0016;
                case 1532805160: goto L_0x000a;
                default: goto L_0x0008;
            }
        L_0x0008:
            goto L_0x00d0
        L_0x000a:
            java.lang.String r0 = "waveShape"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0008
            r0 = 17
            goto L_0x00d1
        L_0x0016:
            java.lang.String r0 = "wavePhase"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0008
            r0 = 16
            goto L_0x00d1
        L_0x0022:
            java.lang.String r0 = "curveFit"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0008
            r0 = 1
            goto L_0x00d1
        L_0x002d:
            java.lang.String r0 = "wavePeriod"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0008
            r0 = 14
            goto L_0x00d1
        L_0x0039:
            java.lang.String r0 = "waveOffset"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0008
            r0 = 15
            goto L_0x00d1
        L_0x0045:
            java.lang.String r0 = "alpha"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0008
            r0 = 0
            goto L_0x00d1
        L_0x0050:
            java.lang.String r0 = "transitionPathRotate"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0008
            r0 = 10
            goto L_0x00d1
        L_0x005c:
            java.lang.String r0 = "elevation"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0008
            r0 = 2
            goto L_0x00d1
        L_0x0067:
            java.lang.String r0 = "rotation"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0008
            r0 = 4
            goto L_0x00d1
        L_0x0071:
            java.lang.String r0 = "scaleY"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0008
            r0 = 8
            goto L_0x00d1
        L_0x007c:
            java.lang.String r0 = "scaleX"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0008
            r0 = 7
            goto L_0x00d1
        L_0x0086:
            java.lang.String r0 = "translationZ"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0008
            r0 = 13
            goto L_0x00d1
        L_0x0091:
            java.lang.String r0 = "translationY"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0008
            r0 = 12
            goto L_0x00d1
        L_0x009c:
            java.lang.String r0 = "translationX"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0008
            r0 = 11
            goto L_0x00d1
        L_0x00a7:
            java.lang.String r0 = "rotationY"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0008
            r0 = 6
            goto L_0x00d1
        L_0x00b1:
            java.lang.String r0 = "rotationX"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0008
            r0 = 5
            goto L_0x00d1
        L_0x00bb:
            java.lang.String r0 = "transitionEasing"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0008
            r0 = 9
            goto L_0x00d1
        L_0x00c6:
            java.lang.String r0 = "motionProgress"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L_0x0008
            r0 = 3
            goto L_0x00d1
        L_0x00d0:
            r0 = -1
        L_0x00d1:
            switch(r0) {
                case 0: goto L_0x015e;
                case 1: goto L_0x0157;
                case 2: goto L_0x0150;
                case 3: goto L_0x0149;
                case 4: goto L_0x0142;
                case 5: goto L_0x013b;
                case 6: goto L_0x0134;
                case 7: goto L_0x012d;
                case 8: goto L_0x0126;
                case 9: goto L_0x011f;
                case 10: goto L_0x0118;
                case 11: goto L_0x0111;
                case 12: goto L_0x010a;
                case 13: goto L_0x0103;
                case 14: goto L_0x00fc;
                case 15: goto L_0x00f4;
                case 16: goto L_0x00ec;
                case 17: goto L_0x00d6;
                default: goto L_0x00d4;
            }
        L_0x00d4:
            goto L_0x0165
        L_0x00d6:
            boolean r0 = r4 instanceof java.lang.Integer
            if (r0 == 0) goto L_0x00e2
            int r0 = r2.toInt(r4)
            r2.mWaveShape = r0
            goto L_0x0165
        L_0x00e2:
            r2.mWaveShape = r1
            java.lang.String r0 = r4.toString()
            r2.mCustomWaveShape = r0
            goto L_0x0165
        L_0x00ec:
            float r0 = r2.toFloat(r4)
            r2.mWavePhase = r0
            goto L_0x0165
        L_0x00f4:
            float r0 = r2.toFloat(r4)
            r2.mWaveOffset = r0
            goto L_0x0165
        L_0x00fc:
            float r0 = r2.toFloat(r4)
            r2.mWavePeriod = r0
            goto L_0x0165
        L_0x0103:
            float r0 = r2.toFloat(r4)
            r2.mTranslationZ = r0
            goto L_0x0165
        L_0x010a:
            float r0 = r2.toFloat(r4)
            r2.mTranslationY = r0
            goto L_0x0165
        L_0x0111:
            float r0 = r2.toFloat(r4)
            r2.mTranslationX = r0
            goto L_0x0165
        L_0x0118:
            float r0 = r2.toFloat(r4)
            r2.mTransitionPathRotate = r0
            goto L_0x0165
        L_0x011f:
            java.lang.String r0 = r4.toString()
            r2.mTransitionEasing = r0
            goto L_0x0165
        L_0x0126:
            float r0 = r2.toFloat(r4)
            r2.mScaleY = r0
            goto L_0x0165
        L_0x012d:
            float r0 = r2.toFloat(r4)
            r2.mScaleX = r0
            goto L_0x0165
        L_0x0134:
            float r0 = r2.toFloat(r4)
            r2.mRotationY = r0
            goto L_0x0165
        L_0x013b:
            float r0 = r2.toFloat(r4)
            r2.mRotationX = r0
            goto L_0x0165
        L_0x0142:
            float r0 = r2.toFloat(r4)
            r2.mRotation = r0
            goto L_0x0165
        L_0x0149:
            float r0 = r2.toFloat(r4)
            r2.mProgress = r0
            goto L_0x0165
        L_0x0150:
            float r0 = r2.toFloat(r4)
            r2.mElevation = r0
            goto L_0x0165
        L_0x0157:
            int r0 = r2.toInt(r4)
            r2.mCurveFit = r0
            goto L_0x0165
        L_0x015e:
            float r0 = r2.toFloat(r4)
            r2.mAlpha = r0
        L_0x0165:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.motion.widget.KeyCycle.setValue(java.lang.String, java.lang.Object):void");
    }

    public Key copy(Key src) {
        super.copy(src);
        KeyCycle k = (KeyCycle) src;
        this.mTransitionEasing = k.mTransitionEasing;
        this.mCurveFit = k.mCurveFit;
        this.mWaveShape = k.mWaveShape;
        this.mCustomWaveShape = k.mCustomWaveShape;
        this.mWavePeriod = k.mWavePeriod;
        this.mWaveOffset = k.mWaveOffset;
        this.mWavePhase = k.mWavePhase;
        this.mProgress = k.mProgress;
        this.mWaveVariesBy = k.mWaveVariesBy;
        this.mAlpha = k.mAlpha;
        this.mElevation = k.mElevation;
        this.mRotation = k.mRotation;
        this.mTransitionPathRotate = k.mTransitionPathRotate;
        this.mRotationX = k.mRotationX;
        this.mRotationY = k.mRotationY;
        this.mScaleX = k.mScaleX;
        this.mScaleY = k.mScaleY;
        this.mTranslationX = k.mTranslationX;
        this.mTranslationY = k.mTranslationY;
        this.mTranslationZ = k.mTranslationZ;
        return this;
    }

    public Key clone() {
        return new KeyCycle().copy(this);
    }
}
