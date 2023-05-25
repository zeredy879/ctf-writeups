package androidx.lifecycle;

import android.os.Binder;
import android.os.Build;
import android.os.Bundle;
import android.os.Parcelable;
import android.util.Size;
import android.util.SizeF;
import android.util.SparseArray;
import androidx.savedstate.SavedStateRegistry;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public final class SavedStateHandle {
    private static final Class[] ACCEPTABLE_CLASSES;
    private static final String KEYS = "keys";
    private static final String VALUES = "values";
    private final Map<String, SavingStateLiveData<?>> mLiveDatas;
    final Map<String, Object> mRegular;
    private final SavedStateRegistry.SavedStateProvider mSavedStateProvider;
    final Map<String, SavedStateRegistry.SavedStateProvider> mSavedStateProviders;

    public SavedStateHandle(Map<String, Object> initialState) {
        this.mSavedStateProviders = new HashMap();
        this.mLiveDatas = new HashMap();
        this.mSavedStateProvider = new SavedStateRegistry.SavedStateProvider() {
            public Bundle saveState() {
                for (Map.Entry<String, SavedStateRegistry.SavedStateProvider> entry : new HashMap<>(SavedStateHandle.this.mSavedStateProviders).entrySet()) {
                    SavedStateHandle.this.set(entry.getKey(), entry.getValue().saveState());
                }
                Set<String> keySet = SavedStateHandle.this.mRegular.keySet();
                ArrayList keys = new ArrayList(keySet.size());
                ArrayList value = new ArrayList(keys.size());
                for (String key : keySet) {
                    keys.add(key);
                    value.add(SavedStateHandle.this.mRegular.get(key));
                }
                Bundle res = new Bundle();
                res.putParcelableArrayList(SavedStateHandle.KEYS, keys);
                res.putParcelableArrayList(SavedStateHandle.VALUES, value);
                return res;
            }
        };
        this.mRegular = new HashMap(initialState);
    }

    public SavedStateHandle() {
        this.mSavedStateProviders = new HashMap();
        this.mLiveDatas = new HashMap();
        this.mSavedStateProvider = new SavedStateRegistry.SavedStateProvider() {
            public Bundle saveState() {
                for (Map.Entry<String, SavedStateRegistry.SavedStateProvider> entry : new HashMap<>(SavedStateHandle.this.mSavedStateProviders).entrySet()) {
                    SavedStateHandle.this.set(entry.getKey(), entry.getValue().saveState());
                }
                Set<String> keySet = SavedStateHandle.this.mRegular.keySet();
                ArrayList keys = new ArrayList(keySet.size());
                ArrayList value = new ArrayList(keys.size());
                for (String key : keySet) {
                    keys.add(key);
                    value.add(SavedStateHandle.this.mRegular.get(key));
                }
                Bundle res = new Bundle();
                res.putParcelableArrayList(SavedStateHandle.KEYS, keys);
                res.putParcelableArrayList(SavedStateHandle.VALUES, value);
                return res;
            }
        };
        this.mRegular = new HashMap();
    }

    static SavedStateHandle createHandle(Bundle restoredState, Bundle defaultState) {
        if (restoredState == null && defaultState == null) {
            return new SavedStateHandle();
        }
        Map<String, Object> state = new HashMap<>();
        if (defaultState != null) {
            for (String key : defaultState.keySet()) {
                state.put(key, defaultState.get(key));
            }
        }
        if (restoredState == null) {
            return new SavedStateHandle(state);
        }
        ArrayList keys = restoredState.getParcelableArrayList(KEYS);
        ArrayList values = restoredState.getParcelableArrayList(VALUES);
        if (keys == null || values == null || keys.size() != values.size()) {
            throw new IllegalStateException("Invalid bundle passed as restored state");
        }
        for (int i = 0; i < keys.size(); i++) {
            state.put((String) keys.get(i), values.get(i));
        }
        return new SavedStateHandle(state);
    }

    /* access modifiers changed from: package-private */
    public SavedStateRegistry.SavedStateProvider savedStateProvider() {
        return this.mSavedStateProvider;
    }

    public boolean contains(String key) {
        return this.mRegular.containsKey(key);
    }

    public <T> MutableLiveData<T> getLiveData(String key) {
        return getLiveDataInternal(key, false, (Object) null);
    }

    public <T> MutableLiveData<T> getLiveData(String key, T initialValue) {
        return getLiveDataInternal(key, true, initialValue);
    }

    private <T> MutableLiveData<T> getLiveDataInternal(String key, boolean hasInitialValue, T initialValue) {
        SavingStateLiveData<T> mutableLd;
        MutableLiveData<T> liveData = this.mLiveDatas.get(key);
        if (liveData != null) {
            return liveData;
        }
        if (this.mRegular.containsKey(key)) {
            mutableLd = new SavingStateLiveData<>(this, key, this.mRegular.get(key));
        } else if (hasInitialValue) {
            mutableLd = new SavingStateLiveData<>(this, key, initialValue);
        } else {
            mutableLd = new SavingStateLiveData<>(this, key);
        }
        this.mLiveDatas.put(key, mutableLd);
        return mutableLd;
    }

    public Set<String> keys() {
        HashSet<String> allKeys = new HashSet<>(this.mRegular.keySet());
        allKeys.addAll(this.mSavedStateProviders.keySet());
        allKeys.addAll(this.mLiveDatas.keySet());
        return allKeys;
    }

    public <T> T get(String key) {
        return this.mRegular.get(key);
    }

    public <T> void set(String key, T value) {
        validateValue(value);
        MutableLiveData<T> mutableLiveData = this.mLiveDatas.get(key);
        if (mutableLiveData != null) {
            mutableLiveData.setValue(value);
        } else {
            this.mRegular.put(key, value);
        }
    }

    private static void validateValue(Object value) {
        if (value != null) {
            Class<?>[] clsArr = ACCEPTABLE_CLASSES;
            int length = clsArr.length;
            int i = 0;
            while (i < length) {
                if (!clsArr[i].isInstance(value)) {
                    i++;
                } else {
                    return;
                }
            }
            throw new IllegalArgumentException("Can't put value with type " + value.getClass() + " into saved state");
        }
    }

    public <T> T remove(String key) {
        T latestValue = this.mRegular.remove(key);
        SavingStateLiveData<?> liveData = this.mLiveDatas.remove(key);
        if (liveData != null) {
            liveData.detach();
        }
        return latestValue;
    }

    public void setSavedStateProvider(String key, SavedStateRegistry.SavedStateProvider provider) {
        this.mSavedStateProviders.put(key, provider);
    }

    public void clearSavedStateProvider(String key) {
        this.mSavedStateProviders.remove(key);
    }

    static class SavingStateLiveData<T> extends MutableLiveData<T> {
        private SavedStateHandle mHandle;
        private String mKey;

        SavingStateLiveData(SavedStateHandle handle, String key, T value) {
            super(value);
            this.mKey = key;
            this.mHandle = handle;
        }

        SavingStateLiveData(SavedStateHandle handle, String key) {
            this.mKey = key;
            this.mHandle = handle;
        }

        public void setValue(T value) {
            SavedStateHandle savedStateHandle = this.mHandle;
            if (savedStateHandle != null) {
                savedStateHandle.mRegular.put(this.mKey, value);
            }
            super.setValue(value);
        }

        /* access modifiers changed from: package-private */
        public void detach() {
            this.mHandle = null;
        }
    }

    static {
        Class[] clsArr = new Class[29];
        clsArr[0] = Boolean.TYPE;
        clsArr[1] = boolean[].class;
        clsArr[2] = Double.TYPE;
        clsArr[3] = double[].class;
        clsArr[4] = Integer.TYPE;
        clsArr[5] = int[].class;
        clsArr[6] = Long.TYPE;
        clsArr[7] = long[].class;
        clsArr[8] = String.class;
        clsArr[9] = String[].class;
        clsArr[10] = Binder.class;
        clsArr[11] = Bundle.class;
        clsArr[12] = Byte.TYPE;
        clsArr[13] = byte[].class;
        clsArr[14] = Character.TYPE;
        clsArr[15] = char[].class;
        clsArr[16] = CharSequence.class;
        clsArr[17] = CharSequence[].class;
        clsArr[18] = ArrayList.class;
        clsArr[19] = Float.TYPE;
        clsArr[20] = float[].class;
        clsArr[21] = Parcelable.class;
        clsArr[22] = Parcelable[].class;
        clsArr[23] = Serializable.class;
        clsArr[24] = Short.TYPE;
        clsArr[25] = short[].class;
        clsArr[26] = SparseArray.class;
        clsArr[27] = Build.VERSION.SDK_INT >= 21 ? Size.class : Integer.TYPE;
        clsArr[28] = Build.VERSION.SDK_INT >= 21 ? SizeF.class : Integer.TYPE;
        ACCEPTABLE_CLASSES = clsArr;
    }
}
