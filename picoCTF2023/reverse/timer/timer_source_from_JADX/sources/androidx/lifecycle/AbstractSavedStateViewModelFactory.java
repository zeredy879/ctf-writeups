package androidx.lifecycle;

import android.os.Bundle;
import androidx.lifecycle.ViewModelProvider;
import androidx.savedstate.SavedStateRegistry;
import androidx.savedstate.SavedStateRegistryOwner;

public abstract class AbstractSavedStateViewModelFactory extends ViewModelProvider.KeyedFactory {
    static final String TAG_SAVED_STATE_HANDLE_CONTROLLER = "androidx.lifecycle.savedstate.vm.tag";
    private final Bundle mDefaultArgs;
    private final Lifecycle mLifecycle;
    private final SavedStateRegistry mSavedStateRegistry;

    /* access modifiers changed from: protected */
    public abstract <T extends ViewModel> T create(String str, Class<T> cls, SavedStateHandle savedStateHandle);

    public AbstractSavedStateViewModelFactory(SavedStateRegistryOwner owner, Bundle defaultArgs) {
        this.mSavedStateRegistry = owner.getSavedStateRegistry();
        this.mLifecycle = owner.getLifecycle();
        this.mDefaultArgs = defaultArgs;
    }

    public final <T extends ViewModel> T create(String key, Class<T> modelClass) {
        SavedStateHandleController controller = SavedStateHandleController.create(this.mSavedStateRegistry, this.mLifecycle, key, this.mDefaultArgs);
        T viewmodel = create(key, modelClass, controller.getHandle());
        viewmodel.setTagIfAbsent(TAG_SAVED_STATE_HANDLE_CONTROLLER, controller);
        return viewmodel;
    }

    public final <T extends ViewModel> T create(Class<T> modelClass) {
        String canonicalName = modelClass.getCanonicalName();
        if (canonicalName != null) {
            return create(canonicalName, modelClass);
        }
        throw new IllegalArgumentException("Local and anonymous classes can not be ViewModels");
    }

    /* access modifiers changed from: package-private */
    public void onRequery(ViewModel viewModel) {
        SavedStateHandleController.attachHandleIfNeeded(viewModel, this.mSavedStateRegistry, this.mLifecycle);
    }
}
