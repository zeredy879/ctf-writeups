package androidx.constraintlayout.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.Log;
import android.util.SparseArray;
import android.util.Xml;
import java.util.ArrayList;
import org.xmlpull.v1.XmlPullParser;

public class ConstraintLayoutStates {
    private static final boolean DEBUG = false;
    public static final String TAG = "ConstraintLayoutStates";
    private final ConstraintLayout mConstraintLayout;
    private SparseArray<ConstraintSet> mConstraintSetMap = new SparseArray<>();
    private ConstraintsChangedListener mConstraintsChangedListener = null;
    int mCurrentConstraintNumber = -1;
    int mCurrentStateId = -1;
    ConstraintSet mDefaultConstraintSet;
    private SparseArray<State> mStateList = new SparseArray<>();

    ConstraintLayoutStates(Context context, ConstraintLayout layout, int resourceID) {
        this.mConstraintLayout = layout;
        load(context, resourceID);
    }

    public boolean needsToChange(int id, float width, float height) {
        int i = this.mCurrentStateId;
        if (i != id) {
            return true;
        }
        State state = (State) (id == -1 ? this.mStateList.valueAt(0) : this.mStateList.get(i));
        if ((this.mCurrentConstraintNumber == -1 || !state.mVariants.get(this.mCurrentConstraintNumber).match(width, height)) && this.mCurrentConstraintNumber != state.findMatch(width, height)) {
            return true;
        }
        return false;
    }

    public void updateConstraints(int id, float width, float height) {
        ConstraintSet constraintSet;
        int cid;
        State state;
        int match;
        ConstraintSet constraintSet2;
        int cid2;
        int i = this.mCurrentStateId;
        if (i == id) {
            if (id == -1) {
                state = this.mStateList.valueAt(0);
            } else {
                state = this.mStateList.get(i);
            }
            if ((this.mCurrentConstraintNumber == -1 || !state.mVariants.get(this.mCurrentConstraintNumber).match(width, height)) && this.mCurrentConstraintNumber != (match = state.findMatch(width, height))) {
                if (match == -1) {
                    constraintSet2 = this.mDefaultConstraintSet;
                } else {
                    constraintSet2 = state.mVariants.get(match).mConstraintSet;
                }
                if (match == -1) {
                    cid2 = state.mConstraintID;
                } else {
                    cid2 = state.mVariants.get(match).mConstraintID;
                }
                if (constraintSet2 != null) {
                    this.mCurrentConstraintNumber = match;
                    ConstraintsChangedListener constraintsChangedListener = this.mConstraintsChangedListener;
                    if (constraintsChangedListener != null) {
                        constraintsChangedListener.preLayoutChange(-1, cid2);
                    }
                    constraintSet2.applyTo(this.mConstraintLayout);
                    ConstraintsChangedListener constraintsChangedListener2 = this.mConstraintsChangedListener;
                    if (constraintsChangedListener2 != null) {
                        constraintsChangedListener2.postLayoutChange(-1, cid2);
                        return;
                    }
                    return;
                }
                return;
            }
            return;
        }
        this.mCurrentStateId = id;
        State state2 = this.mStateList.get(id);
        int match2 = state2.findMatch(width, height);
        if (match2 == -1) {
            constraintSet = state2.mConstraintSet;
        } else {
            constraintSet = state2.mVariants.get(match2).mConstraintSet;
        }
        if (match2 == -1) {
            cid = state2.mConstraintID;
        } else {
            cid = state2.mVariants.get(match2).mConstraintID;
        }
        if (constraintSet == null) {
            Log.v("ConstraintLayoutStates", "NO Constraint set found ! id=" + id + ", dim =" + width + ", " + height);
            return;
        }
        this.mCurrentConstraintNumber = match2;
        ConstraintsChangedListener constraintsChangedListener3 = this.mConstraintsChangedListener;
        if (constraintsChangedListener3 != null) {
            constraintsChangedListener3.preLayoutChange(id, cid);
        }
        constraintSet.applyTo(this.mConstraintLayout);
        ConstraintsChangedListener constraintsChangedListener4 = this.mConstraintsChangedListener;
        if (constraintsChangedListener4 != null) {
            constraintsChangedListener4.postLayoutChange(id, cid);
        }
    }

    public void setOnConstraintsChanged(ConstraintsChangedListener constraintsChangedListener) {
        this.mConstraintsChangedListener = constraintsChangedListener;
    }

    static class State {
        int mConstraintID = -1;
        ConstraintSet mConstraintSet;
        int mId;
        ArrayList<Variant> mVariants = new ArrayList<>();

        public State(Context context, XmlPullParser parser) {
            TypedArray a = context.obtainStyledAttributes(Xml.asAttributeSet(parser), C0015R.styleable.State);
            int N = a.getIndexCount();
            for (int i = 0; i < N; i++) {
                int attr = a.getIndex(i);
                if (attr == C0015R.styleable.State_android_id) {
                    this.mId = a.getResourceId(attr, this.mId);
                } else if (attr == C0015R.styleable.State_constraints) {
                    this.mConstraintID = a.getResourceId(attr, this.mConstraintID);
                    String type = context.getResources().getResourceTypeName(this.mConstraintID);
                    String resourceName = context.getResources().getResourceName(this.mConstraintID);
                    if ("layout".equals(type)) {
                        ConstraintSet constraintSet = new ConstraintSet();
                        this.mConstraintSet = constraintSet;
                        constraintSet.clone(context, this.mConstraintID);
                    }
                }
            }
            a.recycle();
        }

        /* access modifiers changed from: package-private */
        public void add(Variant size) {
            this.mVariants.add(size);
        }

        public int findMatch(float width, float height) {
            for (int i = 0; i < this.mVariants.size(); i++) {
                if (this.mVariants.get(i).match(width, height)) {
                    return i;
                }
            }
            return -1;
        }
    }

    static class Variant {
        int mConstraintID = -1;
        ConstraintSet mConstraintSet;
        int mId;
        float mMaxHeight = Float.NaN;
        float mMaxWidth = Float.NaN;
        float mMinHeight = Float.NaN;
        float mMinWidth = Float.NaN;

        public Variant(Context context, XmlPullParser parser) {
            TypedArray a = context.obtainStyledAttributes(Xml.asAttributeSet(parser), C0015R.styleable.Variant);
            int N = a.getIndexCount();
            for (int i = 0; i < N; i++) {
                int attr = a.getIndex(i);
                if (attr == C0015R.styleable.Variant_constraints) {
                    this.mConstraintID = a.getResourceId(attr, this.mConstraintID);
                    String type = context.getResources().getResourceTypeName(this.mConstraintID);
                    String resourceName = context.getResources().getResourceName(this.mConstraintID);
                    if ("layout".equals(type)) {
                        ConstraintSet constraintSet = new ConstraintSet();
                        this.mConstraintSet = constraintSet;
                        constraintSet.clone(context, this.mConstraintID);
                    }
                } else if (attr == C0015R.styleable.Variant_region_heightLessThan) {
                    this.mMaxHeight = a.getDimension(attr, this.mMaxHeight);
                } else if (attr == C0015R.styleable.Variant_region_heightMoreThan) {
                    this.mMinHeight = a.getDimension(attr, this.mMinHeight);
                } else if (attr == C0015R.styleable.Variant_region_widthLessThan) {
                    this.mMaxWidth = a.getDimension(attr, this.mMaxWidth);
                } else if (attr == C0015R.styleable.Variant_region_widthMoreThan) {
                    this.mMinWidth = a.getDimension(attr, this.mMinWidth);
                } else {
                    Log.v("ConstraintLayoutStates", "Unknown tag");
                }
            }
            a.recycle();
        }

        /* access modifiers changed from: package-private */
        public boolean match(float widthDp, float heightDp) {
            if (!Float.isNaN(this.mMinWidth) && widthDp < this.mMinWidth) {
                return false;
            }
            if (!Float.isNaN(this.mMinHeight) && heightDp < this.mMinHeight) {
                return false;
            }
            if (!Float.isNaN(this.mMaxWidth) && widthDp > this.mMaxWidth) {
                return false;
            }
            if (Float.isNaN(this.mMaxHeight) || heightDp <= this.mMaxHeight) {
                return true;
            }
            return false;
        }
    }

    /* JADX WARNING: Can't fix incorrect switch cases order */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    private void load(android.content.Context r10, int r11) {
        /*
            r9 = this;
            android.content.res.Resources r0 = r10.getResources()
            android.content.res.XmlResourceParser r1 = r0.getXml(r11)
            r2 = 0
            r3 = 0
            r4 = 0
            int r5 = r1.getEventType()     // Catch:{ XmlPullParserException -> 0x0090, IOException -> 0x008b }
        L_0x000f:
            r6 = 1
            if (r5 == r6) goto L_0x008a
            switch(r5) {
                case 0: goto L_0x007e;
                case 1: goto L_0x0015;
                case 2: goto L_0x001a;
                case 3: goto L_0x0017;
                default: goto L_0x0015;
            }     // Catch:{ XmlPullParserException -> 0x0090, IOException -> 0x008b }
        L_0x0015:
            goto L_0x0084
        L_0x0017:
            r3 = 0
            goto L_0x0084
        L_0x001a:
            java.lang.String r7 = r1.getName()     // Catch:{ XmlPullParserException -> 0x0090, IOException -> 0x008b }
            r3 = r7
            r7 = -1
            int r8 = r3.hashCode()     // Catch:{ XmlPullParserException -> 0x0090, IOException -> 0x008b }
            switch(r8) {
                case -1349929691: goto L_0x004f;
                case 80204913: goto L_0x0045;
                case 1382829617: goto L_0x003c;
                case 1657696882: goto L_0x0032;
                case 1901439077: goto L_0x0028;
                default: goto L_0x0027;
            }     // Catch:{ XmlPullParserException -> 0x0090, IOException -> 0x008b }
        L_0x0027:
            goto L_0x0059
        L_0x0028:
            java.lang.String r6 = "Variant"
            boolean r6 = r3.equals(r6)     // Catch:{ XmlPullParserException -> 0x0090, IOException -> 0x008b }
            if (r6 == 0) goto L_0x0027
            r6 = 3
            goto L_0x005a
        L_0x0032:
            java.lang.String r6 = "layoutDescription"
            boolean r6 = r3.equals(r6)     // Catch:{ XmlPullParserException -> 0x0090, IOException -> 0x008b }
            if (r6 == 0) goto L_0x0027
            r6 = 0
            goto L_0x005a
        L_0x003c:
            java.lang.String r8 = "StateSet"
            boolean r8 = r3.equals(r8)     // Catch:{ XmlPullParserException -> 0x0090, IOException -> 0x008b }
            if (r8 == 0) goto L_0x0027
            goto L_0x005a
        L_0x0045:
            java.lang.String r6 = "State"
            boolean r6 = r3.equals(r6)     // Catch:{ XmlPullParserException -> 0x0090, IOException -> 0x008b }
            if (r6 == 0) goto L_0x0027
            r6 = 2
            goto L_0x005a
        L_0x004f:
            java.lang.String r6 = "ConstraintSet"
            boolean r6 = r3.equals(r6)     // Catch:{ XmlPullParserException -> 0x0090, IOException -> 0x008b }
            if (r6 == 0) goto L_0x0027
            r6 = 4
            goto L_0x005a
        L_0x0059:
            r6 = -1
        L_0x005a:
            switch(r6) {
                case 0: goto L_0x007c;
                case 1: goto L_0x007b;
                case 2: goto L_0x006d;
                case 3: goto L_0x0062;
                case 4: goto L_0x005e;
                default: goto L_0x005d;
            }     // Catch:{ XmlPullParserException -> 0x0090, IOException -> 0x008b }
        L_0x005d:
            goto L_0x007d
        L_0x005e:
            r9.parseConstraintSet(r10, r1)     // Catch:{ XmlPullParserException -> 0x0090, IOException -> 0x008b }
            goto L_0x007d
        L_0x0062:
            androidx.constraintlayout.widget.ConstraintLayoutStates$Variant r6 = new androidx.constraintlayout.widget.ConstraintLayoutStates$Variant     // Catch:{ XmlPullParserException -> 0x0090, IOException -> 0x008b }
            r6.<init>(r10, r1)     // Catch:{ XmlPullParserException -> 0x0090, IOException -> 0x008b }
            if (r4 == 0) goto L_0x007d
            r4.add(r6)     // Catch:{ XmlPullParserException -> 0x0090, IOException -> 0x008b }
            goto L_0x007d
        L_0x006d:
            androidx.constraintlayout.widget.ConstraintLayoutStates$State r6 = new androidx.constraintlayout.widget.ConstraintLayoutStates$State     // Catch:{ XmlPullParserException -> 0x0090, IOException -> 0x008b }
            r6.<init>(r10, r1)     // Catch:{ XmlPullParserException -> 0x0090, IOException -> 0x008b }
            r4 = r6
            android.util.SparseArray<androidx.constraintlayout.widget.ConstraintLayoutStates$State> r6 = r9.mStateList     // Catch:{ XmlPullParserException -> 0x0090, IOException -> 0x008b }
            int r7 = r4.mId     // Catch:{ XmlPullParserException -> 0x0090, IOException -> 0x008b }
            r6.put(r7, r4)     // Catch:{ XmlPullParserException -> 0x0090, IOException -> 0x008b }
            goto L_0x007d
        L_0x007b:
            goto L_0x007d
        L_0x007c:
        L_0x007d:
            goto L_0x0084
        L_0x007e:
            java.lang.String r6 = r1.getName()     // Catch:{ XmlPullParserException -> 0x0090, IOException -> 0x008b }
            r2 = r6
        L_0x0084:
            int r6 = r1.next()     // Catch:{ XmlPullParserException -> 0x0090, IOException -> 0x008b }
            r5 = r6
            goto L_0x000f
        L_0x008a:
            goto L_0x0094
        L_0x008b:
            r4 = move-exception
            r4.printStackTrace()
            goto L_0x0095
        L_0x0090:
            r4 = move-exception
            r4.printStackTrace()
        L_0x0094:
        L_0x0095:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.widget.ConstraintLayoutStates.load(android.content.Context, int):void");
    }

    private void parseConstraintSet(Context context, XmlPullParser parser) {
        ConstraintSet set = new ConstraintSet();
        int count = parser.getAttributeCount();
        int i = 0;
        while (i < count) {
            String name = parser.getAttributeName(i);
            String s = parser.getAttributeValue(i);
            if (name == null || s == null || !"id".equals(name)) {
                i++;
            } else {
                int id = -1;
                if (s.contains("/")) {
                    id = context.getResources().getIdentifier(s.substring(s.indexOf(47) + 1), "id", context.getPackageName());
                }
                if (id == -1) {
                    if (s.length() > 1) {
                        id = Integer.parseInt(s.substring(1));
                    } else {
                        Log.e("ConstraintLayoutStates", "error in parsing id");
                    }
                }
                set.load(context, parser);
                this.mConstraintSetMap.put(id, set);
                return;
            }
        }
    }
}
