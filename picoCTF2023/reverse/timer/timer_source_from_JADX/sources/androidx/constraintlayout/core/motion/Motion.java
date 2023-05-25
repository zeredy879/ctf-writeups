package androidx.constraintlayout.core.motion;

import androidx.constraintlayout.core.motion.key.MotionKey;
import androidx.constraintlayout.core.motion.key.MotionKeyPosition;
import androidx.constraintlayout.core.motion.key.MotionKeyTrigger;
import androidx.constraintlayout.core.motion.utils.CurveFit;
import androidx.constraintlayout.core.motion.utils.DifferentialInterpolator;
import androidx.constraintlayout.core.motion.utils.Easing;
import androidx.constraintlayout.core.motion.utils.FloatRect;
import androidx.constraintlayout.core.motion.utils.KeyCache;
import androidx.constraintlayout.core.motion.utils.KeyCycleOscillator;
import androidx.constraintlayout.core.motion.utils.Rect;
import androidx.constraintlayout.core.motion.utils.SplineSet;
import androidx.constraintlayout.core.motion.utils.TimeCycleSplineSet;
import androidx.constraintlayout.core.motion.utils.TypedValues;
import androidx.constraintlayout.core.motion.utils.Utils;
import androidx.constraintlayout.core.motion.utils.VelocityMatrix;
import androidx.constraintlayout.core.motion.utils.ViewState;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;

public class Motion implements TypedValues {
    static final int BOUNCE = 4;
    private static final boolean DEBUG = false;
    public static final int DRAW_PATH_AS_CONFIGURED = 4;
    public static final int DRAW_PATH_BASIC = 1;
    public static final int DRAW_PATH_CARTESIAN = 3;
    public static final int DRAW_PATH_NONE = 0;
    public static final int DRAW_PATH_RECTANGLE = 5;
    public static final int DRAW_PATH_RELATIVE = 2;
    public static final int DRAW_PATH_SCREEN = 6;
    static final int EASE_IN = 1;
    static final int EASE_IN_OUT = 0;
    static final int EASE_OUT = 2;
    private static final boolean FAVOR_FIXED_SIZE_VIEWS = false;
    public static final int HORIZONTAL_PATH_X = 2;
    public static final int HORIZONTAL_PATH_Y = 3;
    private static final int INTERPOLATOR_REFERENCE_ID = -2;
    private static final int INTERPOLATOR_UNDEFINED = -3;
    static final int LINEAR = 3;
    static final int OVERSHOOT = 5;
    public static final int PATH_PERCENT = 0;
    public static final int PATH_PERPENDICULAR = 1;
    public static final int ROTATION_LEFT = 2;
    public static final int ROTATION_RIGHT = 1;
    private static final int SPLINE_STRING = -1;
    private static final String TAG = "MotionController";
    public static final int VERTICAL_PATH_X = 4;
    public static final int VERTICAL_PATH_Y = 5;
    private int MAX_DIMENSION = 4;
    String[] attributeTable;
    private CurveFit mArcSpline;
    private int[] mAttributeInterpolatorCount;
    private String[] mAttributeNames;
    private HashMap<String, SplineSet> mAttributesMap;
    String mConstraintTag;
    float mCurrentCenterX;
    float mCurrentCenterY;
    private int mCurveFitType = -1;
    private HashMap<String, KeyCycleOscillator> mCycleMap;
    private MotionPaths mEndMotionPath = new MotionPaths();
    private MotionConstrainedPoint mEndPoint = new MotionConstrainedPoint();
    int mId;
    private double[] mInterpolateData;
    private int[] mInterpolateVariables;
    private double[] mInterpolateVelocity;
    private ArrayList<MotionKey> mKeyList = new ArrayList<>();
    private MotionKeyTrigger[] mKeyTriggers;
    private ArrayList<MotionPaths> mMotionPaths = new ArrayList<>();
    float mMotionStagger = Float.NaN;
    private boolean mNoMovement = false;
    private int mPathMotionArc = -1;
    private DifferentialInterpolator mQuantizeMotionInterpolator = null;
    private float mQuantizeMotionPhase = Float.NaN;
    private int mQuantizeMotionSteps = -1;
    private CurveFit[] mSpline;
    float mStaggerOffset = 0.0f;
    float mStaggerScale = 1.0f;
    private MotionPaths mStartMotionPath = new MotionPaths();
    private MotionConstrainedPoint mStartPoint = new MotionConstrainedPoint();
    Rect mTempRect = new Rect();
    private HashMap<String, TimeCycleSplineSet> mTimeCycleAttributesMap;
    private int mTransformPivotTarget = -1;
    private MotionWidget mTransformPivotView = null;
    private float[] mValuesBuff = new float[4];
    private float[] mVelocity = new float[1];
    MotionWidget mView;

    public int getTransformPivotTarget() {
        return this.mTransformPivotTarget;
    }

    public void setTransformPivotTarget(int transformPivotTarget) {
        this.mTransformPivotTarget = transformPivotTarget;
        this.mTransformPivotView = null;
    }

    public MotionPaths getKeyFrame(int i) {
        return this.mMotionPaths.get(i);
    }

    public Motion(MotionWidget view) {
        setView(view);
    }

    public float getStartX() {
        return this.mStartMotionPath.f73x;
    }

    public float getStartY() {
        return this.mStartMotionPath.f74y;
    }

    public float getFinalX() {
        return this.mEndMotionPath.f73x;
    }

    public float getFinalY() {
        return this.mEndMotionPath.f74y;
    }

    public float getStartWidth() {
        return this.mStartMotionPath.width;
    }

    public float getStartHeight() {
        return this.mStartMotionPath.height;
    }

    public float getFinalWidth() {
        return this.mEndMotionPath.width;
    }

    public float getFinalHeight() {
        return this.mEndMotionPath.height;
    }

    public int getAnimateRelativeTo() {
        return this.mStartMotionPath.mAnimateRelativeTo;
    }

    public void setupRelative(Motion motionController) {
        this.mStartMotionPath.setupRelative(motionController, motionController.mStartMotionPath);
        this.mEndMotionPath.setupRelative(motionController, motionController.mEndMotionPath);
    }

    public float getCenterX() {
        return this.mCurrentCenterX;
    }

    public float getCenterY() {
        return this.mCurrentCenterY;
    }

    public void getCenter(double p, float[] pos, float[] vel) {
        double[] position = new double[4];
        double[] velocity = new double[4];
        int[] iArr = new int[4];
        this.mSpline[0].getPos(p, position);
        this.mSpline[0].getSlope(p, velocity);
        Arrays.fill(vel, 0.0f);
        this.mStartMotionPath.getCenter(p, this.mInterpolateVariables, position, pos, velocity, vel);
    }

    public void buildPath(float[] points, int pointCount) {
        float position;
        double p;
        Motion motion = this;
        int i = pointCount;
        float f = 1.0f;
        float mils = 1.0f / ((float) (i - 1));
        HashMap<String, SplineSet> hashMap = motion.mAttributesMap;
        KeyCycleOscillator keyCycleOscillator = null;
        SplineSet trans_x = hashMap == null ? null : hashMap.get("translationX");
        HashMap<String, SplineSet> hashMap2 = motion.mAttributesMap;
        SplineSet trans_y = hashMap2 == null ? null : hashMap2.get("translationY");
        HashMap<String, KeyCycleOscillator> hashMap3 = motion.mCycleMap;
        KeyCycleOscillator osc_x = hashMap3 == null ? null : hashMap3.get("translationX");
        HashMap<String, KeyCycleOscillator> hashMap4 = motion.mCycleMap;
        if (hashMap4 != null) {
            keyCycleOscillator = hashMap4.get("translationY");
        }
        KeyCycleOscillator osc_y = keyCycleOscillator;
        int i2 = 0;
        while (i2 < i) {
            float position2 = ((float) i2) * mils;
            float f2 = motion.mStaggerScale;
            if (f2 != f) {
                float f3 = motion.mStaggerOffset;
                if (position2 < f3) {
                    position2 = 0.0f;
                }
                if (position2 <= f3 || ((double) position2) >= 1.0d) {
                    position = position2;
                } else {
                    position = Math.min((position2 - f3) * f2, f);
                }
            } else {
                position = position2;
            }
            double p2 = (double) position;
            Easing easing = motion.mStartMotionPath.mKeyFrameEasing;
            Iterator<MotionPaths> it = motion.mMotionPaths.iterator();
            float start = 0.0f;
            Easing easing2 = easing;
            float end = Float.NaN;
            while (it.hasNext()) {
                MotionPaths frame = it.next();
                if (frame.mKeyFrameEasing != null) {
                    if (frame.time < position) {
                        easing2 = frame.mKeyFrameEasing;
                        start = frame.time;
                    } else if (Float.isNaN(end)) {
                        end = frame.time;
                    }
                }
            }
            if (easing2 != null) {
                if (Float.isNaN(end)) {
                    end = 1.0f;
                }
                double d = p2;
                float offset = (float) easing2.get((double) ((position - start) / (end - start)));
                float f4 = offset;
                float f5 = end;
                p = (double) (((end - start) * offset) + start);
            } else {
                float f6 = end;
                p = p2;
            }
            motion.mSpline[0].getPos(p, motion.mInterpolateData);
            CurveFit curveFit = motion.mArcSpline;
            if (curveFit != null) {
                double[] dArr = motion.mInterpolateData;
                if (dArr.length > 0) {
                    curveFit.getPos(p, dArr);
                }
            }
            double d2 = p;
            Easing easing3 = easing2;
            float position3 = position;
            motion.mStartMotionPath.getCenter(p, motion.mInterpolateVariables, motion.mInterpolateData, points, i2 * 2);
            if (osc_x != null) {
                int i3 = i2 * 2;
                points[i3] = points[i3] + osc_x.get(position3);
            } else if (trans_x != null) {
                int i4 = i2 * 2;
                points[i4] = points[i4] + trans_x.get(position3);
            }
            if (osc_y != null) {
                int i5 = (i2 * 2) + 1;
                points[i5] = points[i5] + osc_y.get(position3);
            } else if (trans_y != null) {
                int i6 = (i2 * 2) + 1;
                points[i6] = points[i6] + trans_y.get(position3);
            }
            i2++;
            f = 1.0f;
            motion = this;
        }
    }

    /* access modifiers changed from: package-private */
    public double[] getPos(double position) {
        this.mSpline[0].getPos(position, this.mInterpolateData);
        CurveFit curveFit = this.mArcSpline;
        if (curveFit != null) {
            double[] dArr = this.mInterpolateData;
            if (dArr.length > 0) {
                curveFit.getPos(position, dArr);
            }
        }
        return this.mInterpolateData;
    }

    /* access modifiers changed from: package-private */
    public void buildBounds(float[] bounds, int pointCount) {
        float mils;
        Motion motion = this;
        int i = pointCount;
        float f = 1.0f;
        float mils2 = 1.0f / ((float) (i - 1));
        HashMap<String, SplineSet> hashMap = motion.mAttributesMap;
        SplineSet trans_x = hashMap == null ? null : hashMap.get("translationX");
        HashMap<String, SplineSet> hashMap2 = motion.mAttributesMap;
        if (hashMap2 != null) {
            SplineSet splineSet = hashMap2.get("translationY");
        }
        HashMap<String, KeyCycleOscillator> hashMap3 = motion.mCycleMap;
        if (hashMap3 != null) {
            KeyCycleOscillator keyCycleOscillator = hashMap3.get("translationX");
        }
        HashMap<String, KeyCycleOscillator> hashMap4 = motion.mCycleMap;
        if (hashMap4 != null) {
            KeyCycleOscillator keyCycleOscillator2 = hashMap4.get("translationY");
        }
        int i2 = 0;
        while (i2 < i) {
            float position = ((float) i2) * mils2;
            float f2 = motion.mStaggerScale;
            if (f2 != f) {
                float f3 = motion.mStaggerOffset;
                if (position < f3) {
                    position = 0.0f;
                }
                if (position > f3 && ((double) position) < 1.0d) {
                    position = Math.min((position - f3) * f2, f);
                }
            }
            double p = (double) position;
            Easing easing = motion.mStartMotionPath.mKeyFrameEasing;
            float start = 0.0f;
            float end = Float.NaN;
            Iterator<MotionPaths> it = motion.mMotionPaths.iterator();
            while (it.hasNext()) {
                MotionPaths frame = it.next();
                if (frame.mKeyFrameEasing != null) {
                    if (frame.time < position) {
                        Easing easing2 = frame.mKeyFrameEasing;
                        start = frame.time;
                        easing = easing2;
                    } else if (Float.isNaN(end)) {
                        end = frame.time;
                    }
                }
                int i3 = pointCount;
            }
            if (easing != null) {
                if (Float.isNaN(end)) {
                    end = 1.0f;
                }
                mils = mils2;
                p = (double) (((end - start) * ((float) easing.get((double) ((position - start) / (end - start))))) + start);
            } else {
                mils = mils2;
            }
            motion.mSpline[0].getPos(p, motion.mInterpolateData);
            CurveFit curveFit = motion.mArcSpline;
            if (curveFit != null) {
                double[] dArr = motion.mInterpolateData;
                if (dArr.length > 0) {
                    curveFit.getPos(p, dArr);
                }
            }
            motion.mStartMotionPath.getBounds(motion.mInterpolateVariables, motion.mInterpolateData, bounds, i2 * 2);
            i2++;
            motion = this;
            i = pointCount;
            mils2 = mils;
            trans_x = trans_x;
            f = 1.0f;
        }
    }

    private float getPreCycleDistance() {
        double p;
        float offset;
        int pointCount = 100;
        float[] points = new float[2];
        float mils = 1.0f / ((float) (100 - 1));
        float sum = 0.0f;
        double x = 0.0d;
        double y = 0.0d;
        int i = 0;
        while (i < pointCount) {
            float position = ((float) i) * mils;
            double p2 = (double) position;
            Easing easing = this.mStartMotionPath.mKeyFrameEasing;
            int pointCount2 = pointCount;
            Iterator<MotionPaths> it = this.mMotionPaths.iterator();
            float start = 0.0f;
            Easing easing2 = easing;
            float end = Float.NaN;
            while (it.hasNext()) {
                MotionPaths frame = it.next();
                Iterator<MotionPaths> it2 = it;
                if (frame.mKeyFrameEasing != null) {
                    if (frame.time < position) {
                        Easing easing3 = frame.mKeyFrameEasing;
                        start = frame.time;
                        easing2 = easing3;
                    } else if (Float.isNaN(end)) {
                        end = frame.time;
                    }
                }
                it = it2;
            }
            if (easing2 != null) {
                if (Float.isNaN(end)) {
                    end = 1.0f;
                }
                double d = p2;
                offset = end;
                p = (double) (((end - start) * ((float) easing2.get((double) ((position - start) / (end - start))))) + start);
            } else {
                offset = end;
                p = p2;
            }
            this.mSpline[0].getPos(p, this.mInterpolateData);
            float f = offset;
            double d2 = p;
            Easing easing4 = easing2;
            float f2 = position;
            int i2 = i;
            this.mStartMotionPath.getCenter(p, this.mInterpolateVariables, this.mInterpolateData, points, 0);
            if (i2 > 0) {
                sum = (float) (((double) sum) + Math.hypot(y - ((double) points[1]), x - ((double) points[0])));
            }
            x = (double) points[0];
            y = (double) points[1];
            i = i2 + 1;
            pointCount = pointCount2;
        }
        return sum;
    }

    /* access modifiers changed from: package-private */
    public MotionKeyPosition getPositionKeyframe(int layoutWidth, int layoutHeight, float x, float y) {
        FloatRect start = new FloatRect();
        start.left = this.mStartMotionPath.f73x;
        start.top = this.mStartMotionPath.f74y;
        start.right = start.left + this.mStartMotionPath.width;
        start.bottom = start.top + this.mStartMotionPath.height;
        FloatRect end = new FloatRect();
        end.left = this.mEndMotionPath.f73x;
        end.top = this.mEndMotionPath.f74y;
        end.right = end.left + this.mEndMotionPath.width;
        end.bottom = end.top + this.mEndMotionPath.height;
        Iterator<MotionKey> it = this.mKeyList.iterator();
        while (it.hasNext()) {
            MotionKey key = it.next();
            if ((key instanceof MotionKeyPosition) && ((MotionKeyPosition) key).intersects(layoutWidth, layoutHeight, start, end, x, y)) {
                return (MotionKeyPosition) key;
            }
        }
        return null;
    }

    public int buildKeyFrames(float[] keyFrames, int[] mode, int[] pos) {
        if (keyFrames == null) {
            return 0;
        }
        int count = 0;
        double[] time = this.mSpline[0].getTimePoints();
        if (mode != null) {
            Iterator<MotionPaths> it = this.mMotionPaths.iterator();
            while (it.hasNext()) {
                mode[count] = it.next().mMode;
                count++;
            }
            count = 0;
        }
        if (pos != null) {
            Iterator<MotionPaths> it2 = this.mMotionPaths.iterator();
            while (it2.hasNext()) {
                pos[count] = (int) (it2.next().position * 100.0f);
                count++;
            }
            count = 0;
        }
        for (int i = 0; i < time.length; i++) {
            this.mSpline[0].getPos(time[i], this.mInterpolateData);
            this.mStartMotionPath.getCenter(time[i], this.mInterpolateVariables, this.mInterpolateData, keyFrames, count);
            count += 2;
        }
        return count / 2;
    }

    /* access modifiers changed from: package-private */
    public int buildKeyBounds(float[] keyBounds, int[] mode) {
        if (keyBounds == null) {
            return 0;
        }
        int count = 0;
        double[] time = this.mSpline[0].getTimePoints();
        if (mode != null) {
            Iterator<MotionPaths> it = this.mMotionPaths.iterator();
            while (it.hasNext()) {
                mode[count] = it.next().mMode;
                count++;
            }
            count = 0;
        }
        for (double pos : time) {
            this.mSpline[0].getPos(pos, this.mInterpolateData);
            this.mStartMotionPath.getBounds(this.mInterpolateVariables, this.mInterpolateData, keyBounds, count);
            count += 2;
        }
        return count / 2;
    }

    /* access modifiers changed from: package-private */
    public int getAttributeValues(String attributeType, float[] points, int pointCount) {
        float f = 1.0f / ((float) (pointCount - 1));
        SplineSet spline = this.mAttributesMap.get(attributeType);
        if (spline == null) {
            return -1;
        }
        for (int j = 0; j < points.length; j++) {
            points[j] = spline.get((float) (j / (points.length - 1)));
        }
        return points.length;
    }

    public void buildRect(float p, float[] path, int offset) {
        this.mSpline[0].getPos((double) getAdjustedPosition(p, (float[]) null), this.mInterpolateData);
        this.mStartMotionPath.getRect(this.mInterpolateVariables, this.mInterpolateData, path, offset);
    }

    /* access modifiers changed from: package-private */
    public void buildRectangles(float[] path, int pointCount) {
        float mils = 1.0f / ((float) (pointCount - 1));
        for (int i = 0; i < pointCount; i++) {
            this.mSpline[0].getPos((double) getAdjustedPosition(((float) i) * mils, (float[]) null), this.mInterpolateData);
            this.mStartMotionPath.getRect(this.mInterpolateVariables, this.mInterpolateData, path, i * 8);
        }
    }

    /* access modifiers changed from: package-private */
    public float getKeyFrameParameter(int type, float x, float y) {
        float dx = this.mEndMotionPath.f73x - this.mStartMotionPath.f73x;
        float dy = this.mEndMotionPath.f74y - this.mStartMotionPath.f74y;
        float startCenterX = this.mStartMotionPath.f73x + (this.mStartMotionPath.width / 2.0f);
        float startCenterY = this.mStartMotionPath.f74y + (this.mStartMotionPath.height / 2.0f);
        float hypotenuse = (float) Math.hypot((double) dx, (double) dy);
        if (((double) hypotenuse) < 1.0E-7d) {
            return Float.NaN;
        }
        float vx = x - startCenterX;
        float vy = y - startCenterY;
        if (((float) Math.hypot((double) vx, (double) vy)) == 0.0f) {
            return 0.0f;
        }
        float pathDistance = (vx * dx) + (vy * dy);
        switch (type) {
            case 0:
                return pathDistance / hypotenuse;
            case 1:
                return (float) Math.sqrt((double) ((hypotenuse * hypotenuse) - (pathDistance * pathDistance)));
            case 2:
                return vx / dx;
            case 3:
                return vy / dx;
            case 4:
                return vx / dy;
            case 5:
                return vy / dy;
            default:
                return 0.0f;
        }
    }

    private void insertKey(MotionPaths point) {
        MotionPaths redundant = null;
        Iterator<MotionPaths> it = this.mMotionPaths.iterator();
        while (it.hasNext()) {
            MotionPaths p = it.next();
            if (point.position == p.position) {
                redundant = p;
            }
        }
        if (redundant != null) {
            this.mMotionPaths.remove(redundant);
        }
        int pos = Collections.binarySearch(this.mMotionPaths, point);
        if (pos == 0) {
            Utils.loge(TAG, " KeyPath position \"" + point.position + "\" outside of range");
        }
        this.mMotionPaths.add((-pos) - 1, point);
    }

    /* access modifiers changed from: package-private */
    public void addKeys(ArrayList<MotionKey> list) {
        this.mKeyList.addAll(list);
    }

    public void addKey(MotionKey key) {
        this.mKeyList.add(key);
    }

    public void setPathMotionArc(int arc) {
        this.mPathMotionArc = arc;
    }

    /* JADX DEBUG: Multi-variable search result rejected for TypeSearchVarInfo{r9v24, resolved type: java.lang.Object} */
    /* JADX DEBUG: Multi-variable search result rejected for TypeSearchVarInfo{r8v19, resolved type: double[][]} */
    /* JADX WARNING: Multi-variable type inference failed */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public void setup(int r31, int r32, float r33, long r34) {
        /*
            r30 = this;
            r0 = r30
            r1 = r34
            java.lang.Class<double> r3 = double.class
            java.util.HashSet r4 = new java.util.HashSet
            r4.<init>()
            java.util.HashSet r5 = new java.util.HashSet
            r5.<init>()
            java.util.HashSet r6 = new java.util.HashSet
            r6.<init>()
            java.util.HashSet r7 = new java.util.HashSet
            r7.<init>()
            java.util.HashMap r8 = new java.util.HashMap
            r8.<init>()
            r9 = 0
            int r10 = r0.mPathMotionArc
            r11 = -1
            if (r10 == r11) goto L_0x0029
            androidx.constraintlayout.core.motion.MotionPaths r12 = r0.mStartMotionPath
            r12.mPathMotionArc = r10
        L_0x0029:
            androidx.constraintlayout.core.motion.MotionConstrainedPoint r10 = r0.mStartPoint
            androidx.constraintlayout.core.motion.MotionConstrainedPoint r12 = r0.mEndPoint
            r10.different(r12, r6)
            java.util.ArrayList<androidx.constraintlayout.core.motion.key.MotionKey> r10 = r0.mKeyList
            if (r10 == 0) goto L_0x00a1
            java.util.Iterator r10 = r10.iterator()
        L_0x0038:
            boolean r12 = r10.hasNext()
            if (r12 == 0) goto L_0x009e
            java.lang.Object r12 = r10.next()
            androidx.constraintlayout.core.motion.key.MotionKey r12 = (androidx.constraintlayout.core.motion.key.MotionKey) r12
            boolean r13 = r12 instanceof androidx.constraintlayout.core.motion.key.MotionKeyPosition
            if (r13 == 0) goto L_0x006f
            r13 = r12
            androidx.constraintlayout.core.motion.key.MotionKeyPosition r13 = (androidx.constraintlayout.core.motion.key.MotionKeyPosition) r13
            androidx.constraintlayout.core.motion.MotionPaths r15 = new androidx.constraintlayout.core.motion.MotionPaths
            androidx.constraintlayout.core.motion.MotionPaths r14 = r0.mStartMotionPath
            androidx.constraintlayout.core.motion.MotionPaths r11 = r0.mEndMotionPath
            r18 = r14
            r14 = r15
            r20 = r4
            r4 = r15
            r15 = r31
            r16 = r32
            r17 = r13
            r19 = r11
            r14.<init>(r15, r16, r17, r18, r19)
            r0.insertKey(r4)
            int r4 = r13.mCurveFit
            r11 = -1
            if (r4 == r11) goto L_0x006e
            int r4 = r13.mCurveFit
            r0.mCurveFitType = r4
        L_0x006e:
            goto L_0x009a
        L_0x006f:
            r20 = r4
            boolean r4 = r12 instanceof androidx.constraintlayout.core.motion.key.MotionKeyCycle
            if (r4 == 0) goto L_0x0079
            r12.getAttributeNames(r7)
            goto L_0x009a
        L_0x0079:
            boolean r4 = r12 instanceof androidx.constraintlayout.core.motion.key.MotionKeyTimeCycle
            if (r4 == 0) goto L_0x0081
            r12.getAttributeNames(r5)
            goto L_0x009a
        L_0x0081:
            boolean r4 = r12 instanceof androidx.constraintlayout.core.motion.key.MotionKeyTrigger
            if (r4 == 0) goto L_0x0094
            if (r9 != 0) goto L_0x008d
            java.util.ArrayList r4 = new java.util.ArrayList
            r4.<init>()
            r9 = r4
        L_0x008d:
            r4 = r12
            androidx.constraintlayout.core.motion.key.MotionKeyTrigger r4 = (androidx.constraintlayout.core.motion.key.MotionKeyTrigger) r4
            r9.add(r4)
            goto L_0x009a
        L_0x0094:
            r12.setInterpolation(r8)
            r12.getAttributeNames(r6)
        L_0x009a:
            r4 = r20
            r11 = -1
            goto L_0x0038
        L_0x009e:
            r20 = r4
            goto L_0x00a3
        L_0x00a1:
            r20 = r4
        L_0x00a3:
            r4 = 0
            if (r9 == 0) goto L_0x00b0
            androidx.constraintlayout.core.motion.key.MotionKeyTrigger[] r10 = new androidx.constraintlayout.core.motion.key.MotionKeyTrigger[r4]
            java.lang.Object[] r10 = r9.toArray(r10)
            androidx.constraintlayout.core.motion.key.MotionKeyTrigger[] r10 = (androidx.constraintlayout.core.motion.key.MotionKeyTrigger[]) r10
            r0.mKeyTriggers = r10
        L_0x00b0:
            boolean r10 = r6.isEmpty()
            java.lang.String r11 = ","
            java.lang.String r12 = "CUSTOM,"
            r13 = 1
            if (r10 != 0) goto L_0x01b3
            java.util.HashMap r10 = new java.util.HashMap
            r10.<init>()
            r0.mAttributesMap = r10
            java.util.Iterator r10 = r6.iterator()
        L_0x00c6:
            boolean r14 = r10.hasNext()
            if (r14 == 0) goto L_0x014b
            java.lang.Object r14 = r10.next()
            java.lang.String r14 = (java.lang.String) r14
            boolean r15 = r14.startsWith(r12)
            if (r15 == 0) goto L_0x012a
            androidx.constraintlayout.core.motion.utils.KeyFrameArray$CustomVar r15 = new androidx.constraintlayout.core.motion.utils.KeyFrameArray$CustomVar
            r15.<init>()
            java.lang.String[] r16 = r14.split(r11)
            r4 = r16[r13]
            java.util.ArrayList<androidx.constraintlayout.core.motion.key.MotionKey> r13 = r0.mKeyList
            java.util.Iterator r13 = r13.iterator()
        L_0x00e9:
            boolean r18 = r13.hasNext()
            if (r18 == 0) goto L_0x011f
            java.lang.Object r18 = r13.next()
            r19 = r9
            r9 = r18
            androidx.constraintlayout.core.motion.key.MotionKey r9 = (androidx.constraintlayout.core.motion.key.MotionKey) r9
            r18 = r10
            java.util.HashMap<java.lang.String, androidx.constraintlayout.core.motion.CustomVariable> r10 = r9.mCustom
            if (r10 != 0) goto L_0x0104
            r10 = r18
            r9 = r19
            goto L_0x00e9
        L_0x0104:
            java.util.HashMap<java.lang.String, androidx.constraintlayout.core.motion.CustomVariable> r10 = r9.mCustom
            java.lang.Object r10 = r10.get(r4)
            androidx.constraintlayout.core.motion.CustomVariable r10 = (androidx.constraintlayout.core.motion.CustomVariable) r10
            if (r10 == 0) goto L_0x0116
            r21 = r4
            int r4 = r9.mFramePosition
            r15.append(r4, r10)
            goto L_0x0118
        L_0x0116:
            r21 = r4
        L_0x0118:
            r10 = r18
            r9 = r19
            r4 = r21
            goto L_0x00e9
        L_0x011f:
            r21 = r4
            r19 = r9
            r18 = r10
            androidx.constraintlayout.core.motion.utils.SplineSet r4 = androidx.constraintlayout.core.motion.utils.SplineSet.makeCustomSplineSet(r14, r15)
            goto L_0x0132
        L_0x012a:
            r19 = r9
            r18 = r10
            androidx.constraintlayout.core.motion.utils.SplineSet r4 = androidx.constraintlayout.core.motion.utils.SplineSet.makeSpline(r14, r1)
        L_0x0132:
            if (r4 != 0) goto L_0x013b
            r10 = r18
            r9 = r19
            r4 = 0
            r13 = 1
            goto L_0x00c6
        L_0x013b:
            r4.setType(r14)
            java.util.HashMap<java.lang.String, androidx.constraintlayout.core.motion.utils.SplineSet> r9 = r0.mAttributesMap
            r9.put(r14, r4)
            r10 = r18
            r9 = r19
            r4 = 0
            r13 = 1
            goto L_0x00c6
        L_0x014b:
            r19 = r9
            java.util.ArrayList<androidx.constraintlayout.core.motion.key.MotionKey> r4 = r0.mKeyList
            if (r4 == 0) goto L_0x016b
            java.util.Iterator r4 = r4.iterator()
        L_0x0155:
            boolean r9 = r4.hasNext()
            if (r9 == 0) goto L_0x016b
            java.lang.Object r9 = r4.next()
            androidx.constraintlayout.core.motion.key.MotionKey r9 = (androidx.constraintlayout.core.motion.key.MotionKey) r9
            boolean r10 = r9 instanceof androidx.constraintlayout.core.motion.key.MotionKeyAttributes
            if (r10 == 0) goto L_0x016a
            java.util.HashMap<java.lang.String, androidx.constraintlayout.core.motion.utils.SplineSet> r10 = r0.mAttributesMap
            r9.addValues(r10)
        L_0x016a:
            goto L_0x0155
        L_0x016b:
            androidx.constraintlayout.core.motion.MotionConstrainedPoint r4 = r0.mStartPoint
            java.util.HashMap<java.lang.String, androidx.constraintlayout.core.motion.utils.SplineSet> r9 = r0.mAttributesMap
            r10 = 0
            r4.addValues(r9, r10)
            androidx.constraintlayout.core.motion.MotionConstrainedPoint r4 = r0.mEndPoint
            java.util.HashMap<java.lang.String, androidx.constraintlayout.core.motion.utils.SplineSet> r9 = r0.mAttributesMap
            r10 = 100
            r4.addValues(r9, r10)
            java.util.HashMap<java.lang.String, androidx.constraintlayout.core.motion.utils.SplineSet> r4 = r0.mAttributesMap
            java.util.Set r4 = r4.keySet()
            java.util.Iterator r4 = r4.iterator()
        L_0x0186:
            boolean r9 = r4.hasNext()
            if (r9 == 0) goto L_0x01b5
            java.lang.Object r9 = r4.next()
            java.lang.String r9 = (java.lang.String) r9
            r10 = 0
            boolean r13 = r8.containsKey(r9)
            if (r13 == 0) goto L_0x01a5
            java.lang.Object r13 = r8.get(r9)
            java.lang.Integer r13 = (java.lang.Integer) r13
            if (r13 == 0) goto L_0x01a5
            int r10 = r13.intValue()
        L_0x01a5:
            java.util.HashMap<java.lang.String, androidx.constraintlayout.core.motion.utils.SplineSet> r13 = r0.mAttributesMap
            java.lang.Object r13 = r13.get(r9)
            androidx.constraintlayout.core.motion.utils.SplineSet r13 = (androidx.constraintlayout.core.motion.utils.SplineSet) r13
            if (r13 == 0) goto L_0x01b2
            r13.setup(r10)
        L_0x01b2:
            goto L_0x0186
        L_0x01b3:
            r19 = r9
        L_0x01b5:
            boolean r4 = r5.isEmpty()
            if (r4 != 0) goto L_0x02a9
            java.util.HashMap<java.lang.String, androidx.constraintlayout.core.motion.utils.TimeCycleSplineSet> r4 = r0.mTimeCycleAttributesMap
            if (r4 != 0) goto L_0x01c6
            java.util.HashMap r4 = new java.util.HashMap
            r4.<init>()
            r0.mTimeCycleAttributesMap = r4
        L_0x01c6:
            java.util.Iterator r4 = r5.iterator()
        L_0x01ca:
            boolean r9 = r4.hasNext()
            if (r9 == 0) goto L_0x0253
            java.lang.Object r9 = r4.next()
            java.lang.String r9 = (java.lang.String) r9
            java.util.HashMap<java.lang.String, androidx.constraintlayout.core.motion.utils.TimeCycleSplineSet> r10 = r0.mTimeCycleAttributesMap
            boolean r10 = r10.containsKey(r9)
            if (r10 == 0) goto L_0x01df
            goto L_0x01ca
        L_0x01df:
            r10 = 0
            boolean r13 = r9.startsWith(r12)
            if (r13 == 0) goto L_0x0239
            androidx.constraintlayout.core.motion.utils.KeyFrameArray$CustomVar r13 = new androidx.constraintlayout.core.motion.utils.KeyFrameArray$CustomVar
            r13.<init>()
            java.lang.String[] r14 = r9.split(r11)
            r15 = 1
            r14 = r14[r15]
            java.util.ArrayList<androidx.constraintlayout.core.motion.key.MotionKey> r15 = r0.mKeyList
            java.util.Iterator r15 = r15.iterator()
        L_0x01f8:
            boolean r18 = r15.hasNext()
            if (r18 == 0) goto L_0x022e
            java.lang.Object r18 = r15.next()
            r21 = r4
            r4 = r18
            androidx.constraintlayout.core.motion.key.MotionKey r4 = (androidx.constraintlayout.core.motion.key.MotionKey) r4
            r18 = r5
            java.util.HashMap<java.lang.String, androidx.constraintlayout.core.motion.CustomVariable> r5 = r4.mCustom
            if (r5 != 0) goto L_0x0213
            r5 = r18
            r4 = r21
            goto L_0x01f8
        L_0x0213:
            java.util.HashMap<java.lang.String, androidx.constraintlayout.core.motion.CustomVariable> r5 = r4.mCustom
            java.lang.Object r5 = r5.get(r14)
            androidx.constraintlayout.core.motion.CustomVariable r5 = (androidx.constraintlayout.core.motion.CustomVariable) r5
            if (r5 == 0) goto L_0x0225
            r22 = r10
            int r10 = r4.mFramePosition
            r13.append(r10, r5)
            goto L_0x0227
        L_0x0225:
            r22 = r10
        L_0x0227:
            r5 = r18
            r4 = r21
            r10 = r22
            goto L_0x01f8
        L_0x022e:
            r21 = r4
            r18 = r5
            r22 = r10
            androidx.constraintlayout.core.motion.utils.SplineSet r4 = androidx.constraintlayout.core.motion.utils.SplineSet.makeCustomSplineSet(r9, r13)
            goto L_0x0243
        L_0x0239:
            r21 = r4
            r18 = r5
            r22 = r10
            androidx.constraintlayout.core.motion.utils.SplineSet r4 = androidx.constraintlayout.core.motion.utils.SplineSet.makeSpline(r9, r1)
        L_0x0243:
            if (r4 != 0) goto L_0x024a
            r5 = r18
            r4 = r21
            goto L_0x01ca
        L_0x024a:
            r4.setType(r9)
            r5 = r18
            r4 = r21
            goto L_0x01ca
        L_0x0253:
            r18 = r5
            java.util.ArrayList<androidx.constraintlayout.core.motion.key.MotionKey> r4 = r0.mKeyList
            if (r4 == 0) goto L_0x0276
            java.util.Iterator r4 = r4.iterator()
        L_0x025d:
            boolean r5 = r4.hasNext()
            if (r5 == 0) goto L_0x0276
            java.lang.Object r5 = r4.next()
            androidx.constraintlayout.core.motion.key.MotionKey r5 = (androidx.constraintlayout.core.motion.key.MotionKey) r5
            boolean r9 = r5 instanceof androidx.constraintlayout.core.motion.key.MotionKeyTimeCycle
            if (r9 == 0) goto L_0x0275
            r9 = r5
            androidx.constraintlayout.core.motion.key.MotionKeyTimeCycle r9 = (androidx.constraintlayout.core.motion.key.MotionKeyTimeCycle) r9
            java.util.HashMap<java.lang.String, androidx.constraintlayout.core.motion.utils.TimeCycleSplineSet> r10 = r0.mTimeCycleAttributesMap
            r9.addTimeValues(r10)
        L_0x0275:
            goto L_0x025d
        L_0x0276:
            java.util.HashMap<java.lang.String, androidx.constraintlayout.core.motion.utils.TimeCycleSplineSet> r4 = r0.mTimeCycleAttributesMap
            java.util.Set r4 = r4.keySet()
            java.util.Iterator r4 = r4.iterator()
        L_0x0280:
            boolean r5 = r4.hasNext()
            if (r5 == 0) goto L_0x02ab
            java.lang.Object r5 = r4.next()
            java.lang.String r5 = (java.lang.String) r5
            r9 = 0
            boolean r10 = r8.containsKey(r5)
            if (r10 == 0) goto L_0x029d
            java.lang.Object r10 = r8.get(r5)
            java.lang.Integer r10 = (java.lang.Integer) r10
            int r9 = r10.intValue()
        L_0x029d:
            java.util.HashMap<java.lang.String, androidx.constraintlayout.core.motion.utils.TimeCycleSplineSet> r10 = r0.mTimeCycleAttributesMap
            java.lang.Object r10 = r10.get(r5)
            androidx.constraintlayout.core.motion.utils.TimeCycleSplineSet r10 = (androidx.constraintlayout.core.motion.utils.TimeCycleSplineSet) r10
            r10.setup(r9)
            goto L_0x0280
        L_0x02a9:
            r18 = r5
        L_0x02ab:
            java.util.ArrayList<androidx.constraintlayout.core.motion.MotionPaths> r4 = r0.mMotionPaths
            int r4 = r4.size()
            r5 = 2
            int r4 = r4 + r5
            androidx.constraintlayout.core.motion.MotionPaths[] r4 = new androidx.constraintlayout.core.motion.MotionPaths[r4]
            r9 = 1
            androidx.constraintlayout.core.motion.MotionPaths r10 = r0.mStartMotionPath
            r11 = 0
            r4[r11] = r10
            int r10 = r4.length
            r11 = 1
            int r10 = r10 - r11
            androidx.constraintlayout.core.motion.MotionPaths r11 = r0.mEndMotionPath
            r4[r10] = r11
            java.util.ArrayList<androidx.constraintlayout.core.motion.MotionPaths> r10 = r0.mMotionPaths
            int r10 = r10.size()
            if (r10 <= 0) goto L_0x02d3
            int r10 = r0.mCurveFitType
            int r11 = androidx.constraintlayout.core.motion.key.MotionKey.UNSET
            if (r10 != r11) goto L_0x02d3
            r10 = 0
            r0.mCurveFitType = r10
        L_0x02d3:
            java.util.ArrayList<androidx.constraintlayout.core.motion.MotionPaths> r10 = r0.mMotionPaths
            java.util.Iterator r10 = r10.iterator()
        L_0x02d9:
            boolean r11 = r10.hasNext()
            if (r11 == 0) goto L_0x02eb
            java.lang.Object r11 = r10.next()
            androidx.constraintlayout.core.motion.MotionPaths r11 = (androidx.constraintlayout.core.motion.MotionPaths) r11
            int r13 = r9 + 1
            r4[r9] = r11
            r9 = r13
            goto L_0x02d9
        L_0x02eb:
            r10 = 18
            java.util.HashSet r11 = new java.util.HashSet
            r11.<init>()
            androidx.constraintlayout.core.motion.MotionPaths r13 = r0.mEndMotionPath
            java.util.HashMap<java.lang.String, androidx.constraintlayout.core.motion.CustomVariable> r13 = r13.customAttributes
            java.util.Set r13 = r13.keySet()
            java.util.Iterator r13 = r13.iterator()
        L_0x02fe:
            boolean r14 = r13.hasNext()
            if (r14 == 0) goto L_0x032d
            java.lang.Object r14 = r13.next()
            java.lang.String r14 = (java.lang.String) r14
            androidx.constraintlayout.core.motion.MotionPaths r15 = r0.mStartMotionPath
            java.util.HashMap<java.lang.String, androidx.constraintlayout.core.motion.CustomVariable> r15 = r15.customAttributes
            boolean r15 = r15.containsKey(r14)
            if (r15 == 0) goto L_0x032c
            java.lang.StringBuilder r15 = new java.lang.StringBuilder
            r15.<init>()
            r15.append(r12)
            r15.append(r14)
            java.lang.String r15 = r15.toString()
            boolean r15 = r6.contains(r15)
            if (r15 != 0) goto L_0x032c
            r11.add(r14)
        L_0x032c:
            goto L_0x02fe
        L_0x032d:
            r12 = 0
            java.lang.String[] r13 = new java.lang.String[r12]
            java.lang.Object[] r12 = r11.toArray(r13)
            java.lang.String[] r12 = (java.lang.String[]) r12
            r0.mAttributeNames = r12
            int r12 = r12.length
            int[] r12 = new int[r12]
            r0.mAttributeInterpolatorCount = r12
            r12 = 0
        L_0x033e:
            java.lang.String[] r13 = r0.mAttributeNames
            int r14 = r13.length
            if (r12 >= r14) goto L_0x0379
            r13 = r13[r12]
            int[] r14 = r0.mAttributeInterpolatorCount
            r15 = 0
            r14[r12] = r15
            r14 = 0
        L_0x034b:
            int r15 = r4.length
            if (r14 >= r15) goto L_0x0375
            r15 = r4[r14]
            java.util.HashMap<java.lang.String, androidx.constraintlayout.core.motion.CustomVariable> r15 = r15.customAttributes
            boolean r15 = r15.containsKey(r13)
            if (r15 == 0) goto L_0x0371
            r15 = r4[r14]
            java.util.HashMap<java.lang.String, androidx.constraintlayout.core.motion.CustomVariable> r15 = r15.customAttributes
            java.lang.Object r15 = r15.get(r13)
            androidx.constraintlayout.core.motion.CustomVariable r15 = (androidx.constraintlayout.core.motion.CustomVariable) r15
            if (r15 == 0) goto L_0x0371
            int[] r5 = r0.mAttributeInterpolatorCount
            r22 = r5[r12]
            int r23 = r15.numberOfInterpolatedValues()
            int r22 = r22 + r23
            r5[r12] = r22
            goto L_0x0375
        L_0x0371:
            int r14 = r14 + 1
            r5 = 2
            goto L_0x034b
        L_0x0375:
            int r12 = r12 + 1
            r5 = 2
            goto L_0x033e
        L_0x0379:
            r5 = 0
            r12 = r4[r5]
            int r5 = r12.mPathMotionArc
            r12 = -1
            if (r5 == r12) goto L_0x0383
            r5 = 1
            goto L_0x0384
        L_0x0383:
            r5 = 0
        L_0x0384:
            java.lang.String[] r12 = r0.mAttributeNames
            int r12 = r12.length
            int r12 = r12 + r10
            boolean[] r12 = new boolean[r12]
            r13 = 1
        L_0x038b:
            int r14 = r4.length
            if (r13 >= r14) goto L_0x039e
            r14 = r4[r13]
            int r15 = r13 + -1
            r15 = r4[r15]
            java.lang.String[] r1 = r0.mAttributeNames
            r14.different(r15, r12, r1, r5)
            int r13 = r13 + 1
            r1 = r34
            goto L_0x038b
        L_0x039e:
            r1 = 0
            r2 = 1
        L_0x03a0:
            int r9 = r12.length
            if (r2 >= r9) goto L_0x03ac
            boolean r9 = r12[r2]
            if (r9 == 0) goto L_0x03a9
            int r1 = r1 + 1
        L_0x03a9:
            int r2 = r2 + 1
            goto L_0x03a0
        L_0x03ac:
            int[] r2 = new int[r1]
            r0.mInterpolateVariables = r2
            r2 = 2
            int r9 = java.lang.Math.max(r2, r1)
            double[] r2 = new double[r9]
            r0.mInterpolateData = r2
            double[] r2 = new double[r9]
            r0.mInterpolateVelocity = r2
            r1 = 0
            r2 = 1
        L_0x03bf:
            int r13 = r12.length
            if (r2 >= r13) goto L_0x03d0
            boolean r13 = r12[r2]
            if (r13 == 0) goto L_0x03cd
            int[] r13 = r0.mInterpolateVariables
            int r14 = r1 + 1
            r13[r1] = r2
            r1 = r14
        L_0x03cd:
            int r2 = r2 + 1
            goto L_0x03bf
        L_0x03d0:
            int r2 = r4.length
            int[] r13 = r0.mInterpolateVariables
            int r13 = r13.length
            r14 = 2
            int[] r15 = new int[r14]
            r14 = 1
            r15[r14] = r13
            r13 = 0
            r15[r13] = r2
            java.lang.Object r2 = java.lang.reflect.Array.newInstance(r3, r15)
            double[][] r2 = (double[][]) r2
            int r13 = r4.length
            double[] r13 = new double[r13]
            r14 = 0
        L_0x03e7:
            int r15 = r4.length
            if (r14 >= r15) goto L_0x0407
            r15 = r4[r14]
            r22 = r1
            r1 = r2[r14]
            r23 = r5
            int[] r5 = r0.mInterpolateVariables
            r15.fillStandard(r1, r5)
            r1 = r4[r14]
            float r1 = r1.time
            r15 = r6
            double r5 = (double) r1
            r13[r14] = r5
            int r14 = r14 + 1
            r6 = r15
            r1 = r22
            r5 = r23
            goto L_0x03e7
        L_0x0407:
            r22 = r1
            r23 = r5
            r15 = r6
            r1 = 0
        L_0x040d:
            int[] r5 = r0.mInterpolateVariables
            int r6 = r5.length
            if (r1 >= r6) goto L_0x0468
            r5 = r5[r1]
            java.lang.String[] r6 = androidx.constraintlayout.core.motion.MotionPaths.names
            int r6 = r6.length
            if (r5 >= r6) goto L_0x045b
            java.lang.StringBuilder r6 = new java.lang.StringBuilder
            r6.<init>()
            java.lang.String[] r14 = androidx.constraintlayout.core.motion.MotionPaths.names
            r24 = r5
            int[] r5 = r0.mInterpolateVariables
            r5 = r5[r1]
            r5 = r14[r5]
            r6.append(r5)
            java.lang.String r5 = " ["
            r6.append(r5)
            java.lang.String r5 = r6.toString()
            r6 = 0
        L_0x0435:
            int r14 = r4.length
            if (r6 >= r14) goto L_0x0456
            java.lang.StringBuilder r14 = new java.lang.StringBuilder
            r14.<init>()
            r14.append(r5)
            r25 = r2[r6]
            r26 = r8
            r27 = r9
            r8 = r25[r1]
            r14.append(r8)
            java.lang.String r5 = r14.toString()
            int r6 = r6 + 1
            r8 = r26
            r9 = r27
            goto L_0x0435
        L_0x0456:
            r26 = r8
            r27 = r9
            goto L_0x0461
        L_0x045b:
            r24 = r5
            r26 = r8
            r27 = r9
        L_0x0461:
            int r1 = r1 + 1
            r8 = r26
            r9 = r27
            goto L_0x040d
        L_0x0468:
            r26 = r8
            r27 = r9
            java.lang.String[] r1 = r0.mAttributeNames
            int r1 = r1.length
            r5 = 1
            int r1 = r1 + r5
            androidx.constraintlayout.core.motion.utils.CurveFit[] r1 = new androidx.constraintlayout.core.motion.utils.CurveFit[r1]
            r0.mSpline = r1
            r1 = 0
        L_0x0476:
            java.lang.String[] r5 = r0.mAttributeNames
            int r6 = r5.length
            if (r1 >= r6) goto L_0x04fd
            r6 = 0
            r8 = 0
            double[][] r8 = (double[][]) r8
            r9 = 0
            r5 = r5[r1]
            r14 = 0
        L_0x0483:
            r24 = r10
            int r10 = r4.length
            if (r14 >= r10) goto L_0x04d8
            r10 = r4[r14]
            boolean r10 = r10.hasCustomData(r5)
            if (r10 == 0) goto L_0x04cb
            if (r8 != 0) goto L_0x04b5
            int r10 = r4.length
            double[] r9 = new double[r10]
            int r10 = r4.length
            r25 = r9
            r9 = r4[r14]
            int r9 = r9.getCustomDataCount(r5)
            r28 = r11
            r29 = r12
            r11 = 2
            int[] r12 = new int[r11]
            r11 = 1
            r12[r11] = r9
            r9 = 0
            r12[r9] = r10
            java.lang.Object r9 = java.lang.reflect.Array.newInstance(r3, r12)
            r8 = r9
            double[][] r8 = (double[][]) r8
            r9 = r25
            goto L_0x04b9
        L_0x04b5:
            r28 = r11
            r29 = r12
        L_0x04b9:
            r10 = r4[r14]
            float r10 = r10.time
            double r10 = (double) r10
            r9[r6] = r10
            r10 = r4[r14]
            r11 = r8[r6]
            r12 = 0
            r10.getCustomData(r5, r11, r12)
            int r6 = r6 + 1
            goto L_0x04cf
        L_0x04cb:
            r28 = r11
            r29 = r12
        L_0x04cf:
            int r14 = r14 + 1
            r10 = r24
            r11 = r28
            r12 = r29
            goto L_0x0483
        L_0x04d8:
            r28 = r11
            r29 = r12
            double[] r9 = java.util.Arrays.copyOf(r9, r6)
            java.lang.Object[] r10 = java.util.Arrays.copyOf(r8, r6)
            r8 = r10
            double[][] r8 = (double[][]) r8
            androidx.constraintlayout.core.motion.utils.CurveFit[] r10 = r0.mSpline
            int r11 = r1 + 1
            int r12 = r0.mCurveFitType
            androidx.constraintlayout.core.motion.utils.CurveFit r12 = androidx.constraintlayout.core.motion.utils.CurveFit.get(r12, r9, r8)
            r10[r11] = r12
            int r1 = r1 + 1
            r10 = r24
            r11 = r28
            r12 = r29
            goto L_0x0476
        L_0x04fd:
            r24 = r10
            r28 = r11
            r29 = r12
            androidx.constraintlayout.core.motion.utils.CurveFit[] r1 = r0.mSpline
            int r5 = r0.mCurveFitType
            androidx.constraintlayout.core.motion.utils.CurveFit r5 = androidx.constraintlayout.core.motion.utils.CurveFit.get(r5, r13, r2)
            r6 = 0
            r1[r6] = r5
            r1 = r4[r6]
            int r1 = r1.mPathMotionArc
            r5 = -1
            if (r1 == r5) goto L_0x0556
            int r1 = r4.length
            int[] r5 = new int[r1]
            double[] r6 = new double[r1]
            r8 = 2
            int[] r9 = new int[r8]
            r10 = 1
            r9[r10] = r8
            r8 = 0
            r9[r8] = r1
            java.lang.Object r3 = java.lang.reflect.Array.newInstance(r3, r9)
            double[][] r3 = (double[][]) r3
            r8 = 0
        L_0x052a:
            if (r8 >= r1) goto L_0x0550
            r9 = r4[r8]
            int r9 = r9.mPathMotionArc
            r5[r8] = r9
            r9 = r4[r8]
            float r9 = r9.time
            double r9 = (double) r9
            r6[r8] = r9
            r9 = r3[r8]
            r10 = r4[r8]
            float r10 = r10.f73x
            double r10 = (double) r10
            r12 = 0
            r9[r12] = r10
            r9 = r3[r8]
            r10 = r4[r8]
            float r10 = r10.f74y
            double r10 = (double) r10
            r14 = 1
            r9[r14] = r10
            int r8 = r8 + 1
            goto L_0x052a
        L_0x0550:
            androidx.constraintlayout.core.motion.utils.CurveFit r8 = androidx.constraintlayout.core.motion.utils.CurveFit.getArc(r5, r6, r3)
            r0.mArcSpline = r8
        L_0x0556:
            r1 = 2143289344(0x7fc00000, float:NaN)
            java.util.HashMap r3 = new java.util.HashMap
            r3.<init>()
            r0.mCycleMap = r3
            java.util.ArrayList<androidx.constraintlayout.core.motion.key.MotionKey> r3 = r0.mKeyList
            if (r3 == 0) goto L_0x05cc
            java.util.Iterator r3 = r7.iterator()
        L_0x0567:
            boolean r5 = r3.hasNext()
            if (r5 == 0) goto L_0x0593
            java.lang.Object r5 = r3.next()
            java.lang.String r5 = (java.lang.String) r5
            androidx.constraintlayout.core.motion.utils.KeyCycleOscillator r6 = androidx.constraintlayout.core.motion.utils.KeyCycleOscillator.makeWidgetCycle(r5)
            if (r6 != 0) goto L_0x057a
            goto L_0x0567
        L_0x057a:
            boolean r8 = r6.variesByPath()
            if (r8 == 0) goto L_0x058a
            boolean r8 = java.lang.Float.isNaN(r1)
            if (r8 == 0) goto L_0x058a
            float r1 = r30.getPreCycleDistance()
        L_0x058a:
            r6.setType(r5)
            java.util.HashMap<java.lang.String, androidx.constraintlayout.core.motion.utils.KeyCycleOscillator> r8 = r0.mCycleMap
            r8.put(r5, r6)
            goto L_0x0567
        L_0x0593:
            java.util.ArrayList<androidx.constraintlayout.core.motion.key.MotionKey> r3 = r0.mKeyList
            java.util.Iterator r3 = r3.iterator()
        L_0x0599:
            boolean r5 = r3.hasNext()
            if (r5 == 0) goto L_0x05b2
            java.lang.Object r5 = r3.next()
            androidx.constraintlayout.core.motion.key.MotionKey r5 = (androidx.constraintlayout.core.motion.key.MotionKey) r5
            boolean r6 = r5 instanceof androidx.constraintlayout.core.motion.key.MotionKeyCycle
            if (r6 == 0) goto L_0x05b1
            r6 = r5
            androidx.constraintlayout.core.motion.key.MotionKeyCycle r6 = (androidx.constraintlayout.core.motion.key.MotionKeyCycle) r6
            java.util.HashMap<java.lang.String, androidx.constraintlayout.core.motion.utils.KeyCycleOscillator> r8 = r0.mCycleMap
            r6.addCycleValues(r8)
        L_0x05b1:
            goto L_0x0599
        L_0x05b2:
            java.util.HashMap<java.lang.String, androidx.constraintlayout.core.motion.utils.KeyCycleOscillator> r3 = r0.mCycleMap
            java.util.Collection r3 = r3.values()
            java.util.Iterator r3 = r3.iterator()
        L_0x05bc:
            boolean r5 = r3.hasNext()
            if (r5 == 0) goto L_0x05cc
            java.lang.Object r5 = r3.next()
            androidx.constraintlayout.core.motion.utils.KeyCycleOscillator r5 = (androidx.constraintlayout.core.motion.utils.KeyCycleOscillator) r5
            r5.setup(r1)
            goto L_0x05bc
        L_0x05cc:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.motion.Motion.setup(int, int, float, long):void");
    }

    public String toString() {
        return " start: x: " + this.mStartMotionPath.f73x + " y: " + this.mStartMotionPath.f74y + " end: x: " + this.mEndMotionPath.f73x + " y: " + this.mEndMotionPath.f74y;
    }

    private void readView(MotionPaths motionPaths) {
        motionPaths.setBounds((float) this.mView.getX(), (float) this.mView.getY(), (float) this.mView.getWidth(), (float) this.mView.getHeight());
    }

    public void setView(MotionWidget view) {
        this.mView = view;
    }

    public MotionWidget getView() {
        return this.mView;
    }

    public void setStart(MotionWidget mw) {
        this.mStartMotionPath.time = 0.0f;
        this.mStartMotionPath.position = 0.0f;
        this.mStartMotionPath.setBounds((float) mw.getX(), (float) mw.getY(), (float) mw.getWidth(), (float) mw.getHeight());
        this.mStartMotionPath.applyParameters(mw);
        this.mStartPoint.setState(mw);
    }

    public void setEnd(MotionWidget mw) {
        this.mEndMotionPath.time = 1.0f;
        this.mEndMotionPath.position = 1.0f;
        readView(this.mEndMotionPath);
        this.mEndMotionPath.setBounds((float) mw.getLeft(), (float) mw.getTop(), (float) mw.getWidth(), (float) mw.getHeight());
        this.mEndMotionPath.applyParameters(mw);
        this.mEndPoint.setState(mw);
    }

    public void setStartState(ViewState rect, MotionWidget v, int rotation, int preWidth, int preHeight) {
        this.mStartMotionPath.time = 0.0f;
        this.mStartMotionPath.position = 0.0f;
        Rect r = new Rect();
        switch (rotation) {
            case 1:
                int cx = rect.left + rect.right;
                r.left = ((rect.top + rect.bottom) - rect.width()) / 2;
                r.top = preWidth - ((rect.height() + cx) / 2);
                r.right = r.left + rect.width();
                r.bottom = r.top + rect.height();
                break;
            case 2:
                int cx2 = rect.left + rect.right;
                r.left = preHeight - ((rect.width() + (rect.top + rect.bottom)) / 2);
                r.top = (cx2 - rect.height()) / 2;
                r.right = r.left + rect.width();
                r.bottom = r.top + rect.height();
                break;
        }
        this.mStartMotionPath.setBounds((float) r.left, (float) r.top, (float) r.width(), (float) r.height());
        this.mStartPoint.setState(r, v, rotation, rect.rotation);
    }

    /* access modifiers changed from: package-private */
    public void rotate(Rect rect, Rect out, int rotation, int preHeight, int preWidth) {
        switch (rotation) {
            case 1:
                int cx = rect.left + rect.right;
                out.left = ((rect.top + rect.bottom) - rect.width()) / 2;
                out.top = preWidth - ((rect.height() + cx) / 2);
                out.right = out.left + rect.width();
                out.bottom = out.top + rect.height();
                return;
            case 2:
                int cx2 = rect.left + rect.right;
                out.left = preHeight - ((rect.width() + (rect.top + rect.bottom)) / 2);
                out.top = (cx2 - rect.height()) / 2;
                out.right = out.left + rect.width();
                out.bottom = out.top + rect.height();
                return;
            case 3:
                int cx3 = rect.left + rect.right;
                int i = rect.top + rect.bottom;
                out.left = ((rect.height() / 2) + rect.top) - (cx3 / 2);
                out.top = preWidth - ((rect.height() + cx3) / 2);
                out.right = out.left + rect.width();
                out.bottom = out.top + rect.height();
                return;
            case 4:
                int cx4 = rect.left + rect.right;
                out.left = preHeight - ((rect.width() + (rect.bottom + rect.top)) / 2);
                out.top = (cx4 - rect.height()) / 2;
                out.right = out.left + rect.width();
                out.bottom = out.top + rect.height();
                return;
            default:
                return;
        }
    }

    private static DifferentialInterpolator getInterpolator(int type, String interpolatorString, int id) {
        switch (type) {
            case -1:
                final Easing easing = Easing.getInterpolator(interpolatorString);
                return new DifferentialInterpolator() {

                    /* renamed from: mX */
                    float f70mX;

                    public float getInterpolation(float x) {
                        this.f70mX = x;
                        return (float) easing.get((double) x);
                    }

                    public float getVelocity() {
                        return (float) easing.getDiff((double) this.f70mX);
                    }
                };
            default:
                return null;
        }
    }

    /* access modifiers changed from: package-private */
    public void setBothStates(MotionWidget v) {
        this.mStartMotionPath.time = 0.0f;
        this.mStartMotionPath.position = 0.0f;
        this.mNoMovement = true;
        this.mStartMotionPath.setBounds((float) v.getX(), (float) v.getY(), (float) v.getWidth(), (float) v.getHeight());
        this.mEndMotionPath.setBounds((float) v.getX(), (float) v.getY(), (float) v.getWidth(), (float) v.getHeight());
        this.mStartPoint.setState(v);
        this.mEndPoint.setState(v);
    }

    private float getAdjustedPosition(float position, float[] velocity) {
        if (velocity != null) {
            velocity[0] = 1.0f;
        } else {
            float f = this.mStaggerScale;
            if (((double) f) != 1.0d) {
                float f2 = this.mStaggerOffset;
                if (position < f2) {
                    position = 0.0f;
                }
                if (position > f2 && ((double) position) < 1.0d) {
                    position = Math.min((position - f2) * f, 1.0f);
                }
            }
        }
        float adjusted = position;
        Easing easing = this.mStartMotionPath.mKeyFrameEasing;
        float start = 0.0f;
        float end = Float.NaN;
        Iterator<MotionPaths> it = this.mMotionPaths.iterator();
        while (it.hasNext()) {
            MotionPaths frame = it.next();
            if (frame.mKeyFrameEasing != null) {
                if (frame.time < position) {
                    easing = frame.mKeyFrameEasing;
                    start = frame.time;
                } else if (Float.isNaN(end)) {
                    end = frame.time;
                }
            }
        }
        if (easing != null) {
            if (Float.isNaN(end)) {
                end = 1.0f;
            }
            float offset = (position - start) / (end - start);
            adjusted = ((end - start) * ((float) easing.get((double) offset))) + start;
            if (velocity != null) {
                velocity[0] = (float) easing.getDiff((double) offset);
            }
        }
        return adjusted;
    }

    /* access modifiers changed from: package-private */
    public void endTrigger(boolean start) {
    }

    public boolean interpolate(MotionWidget child, float global_position, long time, KeyCache keyCache) {
        float position;
        float section;
        MotionWidget motionWidget = child;
        float position2 = getAdjustedPosition(global_position, (float[]) null);
        int i = this.mQuantizeMotionSteps;
        if (i != -1) {
            float f = position2;
            float steps = 1.0f / ((float) i);
            float jump = ((float) Math.floor((double) (position2 / steps))) * steps;
            float section2 = (position2 % steps) / steps;
            if (!Float.isNaN(this.mQuantizeMotionPhase)) {
                section2 = (this.mQuantizeMotionPhase + section2) % 1.0f;
            }
            DifferentialInterpolator differentialInterpolator = this.mQuantizeMotionInterpolator;
            if (differentialInterpolator != null) {
                section = differentialInterpolator.getInterpolation(section2);
            } else {
                section = ((double) section2) > 0.5d ? 1.0f : 0.0f;
            }
            position = (section * steps) + jump;
        } else {
            position = position2;
        }
        HashMap<String, SplineSet> hashMap = this.mAttributesMap;
        if (hashMap != null) {
            for (SplineSet aSpline : hashMap.values()) {
                aSpline.setProperty(motionWidget, position);
            }
        }
        CurveFit[] curveFitArr = this.mSpline;
        if (curveFitArr != null) {
            curveFitArr[0].getPos((double) position, this.mInterpolateData);
            this.mSpline[0].getSlope((double) position, this.mInterpolateVelocity);
            CurveFit curveFit = this.mArcSpline;
            if (curveFit != null) {
                double[] dArr = this.mInterpolateData;
                if (dArr.length > 0) {
                    curveFit.getPos((double) position, dArr);
                    this.mArcSpline.getSlope((double) position, this.mInterpolateVelocity);
                }
            }
            if (!this.mNoMovement) {
                this.mStartMotionPath.setView(position, child, this.mInterpolateVariables, this.mInterpolateData, this.mInterpolateVelocity, (double[]) null);
            }
            if (this.mTransformPivotTarget != -1) {
                if (this.mTransformPivotView == null) {
                    this.mTransformPivotView = child.getParent().findViewById(this.mTransformPivotTarget);
                }
                MotionWidget layout = this.mTransformPivotView;
                if (layout != null) {
                    float cy = ((float) (layout.getTop() + this.mTransformPivotView.getBottom())) / 2.0f;
                    float cx = ((float) (this.mTransformPivotView.getLeft() + this.mTransformPivotView.getRight())) / 2.0f;
                    if (child.getRight() - child.getLeft() > 0 && child.getBottom() - child.getTop() > 0) {
                        motionWidget.setPivotX(cx - ((float) child.getLeft()));
                        motionWidget.setPivotY(cy - ((float) child.getTop()));
                    }
                }
            }
            int i2 = 1;
            while (true) {
                CurveFit[] curveFitArr2 = this.mSpline;
                if (i2 >= curveFitArr2.length) {
                    break;
                }
                curveFitArr2[i2].getPos((double) position, this.mValuesBuff);
                this.mStartMotionPath.customAttributes.get(this.mAttributeNames[i2 - 1]).setInterpolatedValue(motionWidget, this.mValuesBuff);
                i2++;
            }
            if (this.mStartPoint.mVisibilityMode == 0) {
                if (position <= 0.0f) {
                    motionWidget.setVisibility(this.mStartPoint.visibility);
                } else if (position >= 1.0f) {
                    motionWidget.setVisibility(this.mEndPoint.visibility);
                } else if (this.mEndPoint.visibility != this.mStartPoint.visibility) {
                    motionWidget.setVisibility(4);
                }
            }
            if (this.mKeyTriggers != null) {
                int i3 = 0;
                while (true) {
                    MotionKeyTrigger[] motionKeyTriggerArr = this.mKeyTriggers;
                    if (i3 >= motionKeyTriggerArr.length) {
                        break;
                    }
                    motionKeyTriggerArr[i3].conditionallyFire(position, motionWidget);
                    i3++;
                }
            }
        } else {
            float float_l = this.mStartMotionPath.f73x + ((this.mEndMotionPath.f73x - this.mStartMotionPath.f73x) * position);
            float float_t = this.mStartMotionPath.f74y + ((this.mEndMotionPath.f74y - this.mStartMotionPath.f74y) * position);
            int l = (int) (float_l + 0.5f);
            int t = (int) (float_t + 0.5f);
            int r = (int) (float_l + 0.5f + this.mStartMotionPath.width + ((this.mEndMotionPath.width - this.mStartMotionPath.width) * position));
            int b = (int) (0.5f + float_t + this.mStartMotionPath.height + ((this.mEndMotionPath.height - this.mStartMotionPath.height) * position));
            int i4 = r - l;
            int i5 = b - t;
            motionWidget.layout(l, t, r, b);
        }
        HashMap<String, KeyCycleOscillator> hashMap2 = this.mCycleMap;
        if (hashMap2 != null) {
            for (KeyCycleOscillator osc : hashMap2.values()) {
                if (osc instanceof KeyCycleOscillator.PathRotateSet) {
                    double[] dArr2 = this.mInterpolateVelocity;
                    ((KeyCycleOscillator.PathRotateSet) osc).setPathRotate(child, position, dArr2[0], dArr2[1]);
                } else {
                    osc.setProperty(motionWidget, position);
                }
            }
        }
        return false;
    }

    /* access modifiers changed from: package-private */
    public void getDpDt(float position, float locationX, float locationY, float[] mAnchorDpDt) {
        double[] dArr;
        float f = position;
        float position2 = getAdjustedPosition(position, this.mVelocity);
        CurveFit[] curveFitArr = this.mSpline;
        if (curveFitArr != null) {
            curveFitArr[0].getSlope((double) position2, this.mInterpolateVelocity);
            this.mSpline[0].getPos((double) position2, this.mInterpolateData);
            float v = this.mVelocity[0];
            int i = 0;
            while (true) {
                dArr = this.mInterpolateVelocity;
                if (i >= dArr.length) {
                    break;
                }
                dArr[i] = dArr[i] * ((double) v);
                i++;
            }
            CurveFit curveFit = this.mArcSpline;
            if (curveFit != null) {
                double[] dArr2 = this.mInterpolateData;
                if (dArr2.length > 0) {
                    curveFit.getPos((double) position2, dArr2);
                    this.mArcSpline.getSlope((double) position2, this.mInterpolateVelocity);
                    this.mStartMotionPath.setDpDt(locationX, locationY, mAnchorDpDt, this.mInterpolateVariables, this.mInterpolateVelocity, this.mInterpolateData);
                    return;
                }
                return;
            }
            this.mStartMotionPath.setDpDt(locationX, locationY, mAnchorDpDt, this.mInterpolateVariables, dArr, this.mInterpolateData);
            return;
        }
        float dleft = this.mEndMotionPath.f73x - this.mStartMotionPath.f73x;
        float dTop = this.mEndMotionPath.f74y - this.mStartMotionPath.f74y;
        float dWidth = this.mEndMotionPath.width - this.mStartMotionPath.width;
        float dHeight = this.mEndMotionPath.height - this.mStartMotionPath.height;
        mAnchorDpDt[0] = ((1.0f - locationX) * dleft) + ((dleft + dWidth) * locationX);
        mAnchorDpDt[1] = ((1.0f - locationY) * dTop) + ((dTop + dHeight) * locationY);
    }

    /* access modifiers changed from: package-private */
    public void getPostLayoutDvDp(float position, int width, int height, float locationX, float locationY, float[] mAnchorDpDt) {
        VelocityMatrix vmat;
        float position2 = getAdjustedPosition(position, this.mVelocity);
        HashMap<String, SplineSet> hashMap = this.mAttributesMap;
        KeyCycleOscillator keyCycleOscillator = null;
        SplineSet trans_x = hashMap == null ? null : hashMap.get("translationX");
        HashMap<String, SplineSet> hashMap2 = this.mAttributesMap;
        SplineSet trans_y = hashMap2 == null ? null : hashMap2.get("translationY");
        HashMap<String, SplineSet> hashMap3 = this.mAttributesMap;
        SplineSet rotation = hashMap3 == null ? null : hashMap3.get("rotationZ");
        HashMap<String, SplineSet> hashMap4 = this.mAttributesMap;
        SplineSet scale_x = hashMap4 == null ? null : hashMap4.get("scaleX");
        HashMap<String, SplineSet> hashMap5 = this.mAttributesMap;
        SplineSet scale_y = hashMap5 == null ? null : hashMap5.get("scaleY");
        HashMap<String, KeyCycleOscillator> hashMap6 = this.mCycleMap;
        KeyCycleOscillator osc_x = hashMap6 == null ? null : hashMap6.get("translationX");
        HashMap<String, KeyCycleOscillator> hashMap7 = this.mCycleMap;
        KeyCycleOscillator osc_y = hashMap7 == null ? null : hashMap7.get("translationY");
        HashMap<String, KeyCycleOscillator> hashMap8 = this.mCycleMap;
        KeyCycleOscillator osc_r = hashMap8 == null ? null : hashMap8.get("rotationZ");
        HashMap<String, KeyCycleOscillator> hashMap9 = this.mCycleMap;
        KeyCycleOscillator osc_sx = hashMap9 == null ? null : hashMap9.get("scaleX");
        HashMap<String, KeyCycleOscillator> hashMap10 = this.mCycleMap;
        if (hashMap10 != null) {
            keyCycleOscillator = hashMap10.get("scaleY");
        }
        KeyCycleOscillator osc_sy = keyCycleOscillator;
        VelocityMatrix vmat2 = new VelocityMatrix();
        vmat2.clear();
        vmat2.setRotationVelocity(rotation, position2);
        vmat2.setTranslationVelocity(trans_x, trans_y, position2);
        vmat2.setScaleVelocity(scale_x, scale_y, position2);
        vmat2.setRotationVelocity(osc_r, position2);
        vmat2.setTranslationVelocity(osc_x, osc_y, position2);
        vmat2.setScaleVelocity(osc_sx, osc_sy, position2);
        CurveFit curveFit = this.mArcSpline;
        if (curveFit != null) {
            double[] dArr = this.mInterpolateData;
            if (dArr.length > 0) {
                curveFit.getPos((double) position2, dArr);
                this.mArcSpline.getSlope((double) position2, this.mInterpolateVelocity);
                vmat = vmat2;
                KeyCycleOscillator keyCycleOscillator2 = osc_x;
                KeyCycleOscillator osc_x2 = osc_r;
                KeyCycleOscillator keyCycleOscillator3 = osc_sx;
                KeyCycleOscillator keyCycleOscillator4 = osc_sy;
                this.mStartMotionPath.setDpDt(locationX, locationY, mAnchorDpDt, this.mInterpolateVariables, this.mInterpolateVelocity, this.mInterpolateData);
            } else {
                vmat = vmat2;
                KeyCycleOscillator keyCycleOscillator5 = osc_sx;
                KeyCycleOscillator keyCycleOscillator6 = osc_sy;
                KeyCycleOscillator keyCycleOscillator7 = osc_x;
                KeyCycleOscillator osc_x3 = osc_r;
            }
            vmat.applyTransform(locationX, locationY, width, height, mAnchorDpDt);
            return;
        }
        VelocityMatrix vmat3 = vmat2;
        KeyCycleOscillator osc_sx2 = osc_sx;
        KeyCycleOscillator osc_sy2 = osc_sy;
        KeyCycleOscillator osc_x4 = osc_x;
        KeyCycleOscillator osc_x5 = osc_r;
        if (this.mSpline != null) {
            float position3 = getAdjustedPosition(position2, this.mVelocity);
            this.mSpline[0].getSlope((double) position3, this.mInterpolateVelocity);
            this.mSpline[0].getPos((double) position3, this.mInterpolateData);
            float v = this.mVelocity[0];
            int i = 0;
            while (true) {
                double[] dArr2 = this.mInterpolateVelocity;
                if (i < dArr2.length) {
                    dArr2[i] = dArr2[i] * ((double) v);
                    i++;
                } else {
                    float f = locationX;
                    float f2 = locationY;
                    float f3 = v;
                    this.mStartMotionPath.setDpDt(f, f2, mAnchorDpDt, this.mInterpolateVariables, dArr2, this.mInterpolateData);
                    vmat3.applyTransform(f, f2, width, height, mAnchorDpDt);
                    return;
                }
            }
        } else {
            float dleft = this.mEndMotionPath.f73x - this.mStartMotionPath.f73x;
            float dTop = this.mEndMotionPath.f74y - this.mStartMotionPath.f74y;
            mAnchorDpDt[0] = ((1.0f - locationX) * dleft) + ((dleft + (this.mEndMotionPath.width - this.mStartMotionPath.width)) * locationX);
            mAnchorDpDt[1] = ((1.0f - locationY) * dTop) + ((dTop + (this.mEndMotionPath.height - this.mStartMotionPath.height)) * locationY);
            vmat3.clear();
            VelocityMatrix vmat4 = vmat3;
            vmat4.setRotationVelocity(rotation, position2);
            vmat4.setTranslationVelocity(trans_x, trans_y, position2);
            vmat4.setScaleVelocity(scale_x, scale_y, position2);
            vmat4.setRotationVelocity(osc_x5, position2);
            KeyCycleOscillator osc_x6 = osc_x4;
            vmat4.setTranslationVelocity(osc_x6, osc_y, position2);
            KeyCycleOscillator osc_sy3 = osc_sy2;
            vmat4.setScaleVelocity(osc_sx2, osc_sy3, position2);
            KeyCycleOscillator keyCycleOscillator8 = osc_sy3;
            KeyCycleOscillator keyCycleOscillator9 = osc_x6;
            VelocityMatrix velocityMatrix = vmat4;
            vmat4.applyTransform(locationX, locationY, width, height, mAnchorDpDt);
        }
    }

    public int getDrawPath() {
        int mode = this.mStartMotionPath.mDrawPath;
        Iterator<MotionPaths> it = this.mMotionPaths.iterator();
        while (it.hasNext()) {
            mode = Math.max(mode, it.next().mDrawPath);
        }
        return Math.max(mode, this.mEndMotionPath.mDrawPath);
    }

    public void setDrawPath(int debugMode) {
        this.mStartMotionPath.mDrawPath = debugMode;
    }

    /* access modifiers changed from: package-private */
    public String name() {
        return this.mView.getName();
    }

    /* access modifiers changed from: package-private */
    public void positionKeyframe(MotionWidget view, MotionKeyPosition key, float x, float y, String[] attribute, float[] value) {
        FloatRect start = new FloatRect();
        start.left = this.mStartMotionPath.f73x;
        start.top = this.mStartMotionPath.f74y;
        start.right = start.left + this.mStartMotionPath.width;
        start.bottom = start.top + this.mStartMotionPath.height;
        FloatRect end = new FloatRect();
        end.left = this.mEndMotionPath.f73x;
        end.top = this.mEndMotionPath.f74y;
        end.right = end.left + this.mEndMotionPath.width;
        end.bottom = end.top + this.mEndMotionPath.height;
        key.positionAttributes(view, start, end, x, y, attribute, value);
    }

    public int getKeyFramePositions(int[] type, float[] pos) {
        int i = 0;
        int count = 0;
        Iterator<MotionKey> it = this.mKeyList.iterator();
        while (it.hasNext()) {
            MotionKey key = it.next();
            int i2 = i + 1;
            type[i] = key.mFramePosition + (key.mType * 1000);
            float time = ((float) key.mFramePosition) / 100.0f;
            this.mSpline[0].getPos((double) time, this.mInterpolateData);
            this.mStartMotionPath.getCenter((double) time, this.mInterpolateVariables, this.mInterpolateData, pos, count);
            count += 2;
            i = i2;
        }
        return i;
    }

    public int getKeyFrameInfo(int type, int[] info) {
        int i = type;
        int count = 0;
        int cursor = 0;
        float[] pos = new float[2];
        Iterator<MotionKey> it = this.mKeyList.iterator();
        while (it.hasNext()) {
            MotionKey key = it.next();
            if (key.mType == i || i != -1) {
                int len = cursor;
                info[cursor] = 0;
                int cursor2 = cursor + 1;
                info[cursor2] = key.mType;
                int cursor3 = cursor2 + 1;
                info[cursor3] = key.mFramePosition;
                float time = ((float) key.mFramePosition) / 100.0f;
                this.mSpline[0].getPos((double) time, this.mInterpolateData);
                float f = time;
                this.mStartMotionPath.getCenter((double) time, this.mInterpolateVariables, this.mInterpolateData, pos, 0);
                int cursor4 = cursor3 + 1;
                info[cursor4] = Float.floatToIntBits(pos[0]);
                int cursor5 = cursor4 + 1;
                info[cursor5] = Float.floatToIntBits(pos[1]);
                if (key instanceof MotionKeyPosition) {
                    MotionKeyPosition kp = (MotionKeyPosition) key;
                    int cursor6 = cursor5 + 1;
                    info[cursor6] = kp.mPositionType;
                    int cursor7 = cursor6 + 1;
                    info[cursor7] = Float.floatToIntBits(kp.mPercentX);
                    cursor5 = cursor7 + 1;
                    info[cursor5] = Float.floatToIntBits(kp.mPercentY);
                }
                cursor = cursor5 + 1;
                info[len] = cursor - len;
                count++;
            }
        }
        return count;
    }

    public boolean setValue(int id, int value) {
        switch (id) {
            case 509:
                setPathMotionArc(value);
                return true;
            case TypedValues.TransitionType.TYPE_AUTO_TRANSITION /*704*/:
                return true;
            default:
                return false;
        }
    }

    public boolean setValue(int id, float value) {
        return false;
    }

    public boolean setValue(int id, String value) {
        if (705 == id) {
            PrintStream printStream = System.out;
            printStream.println("TYPE_INTERPOLATOR  " + value);
            this.mQuantizeMotionInterpolator = getInterpolator(-1, value, 0);
        }
        return false;
    }

    public boolean setValue(int id, boolean value) {
        return false;
    }

    public int getId(String name) {
        return 0;
    }
}
