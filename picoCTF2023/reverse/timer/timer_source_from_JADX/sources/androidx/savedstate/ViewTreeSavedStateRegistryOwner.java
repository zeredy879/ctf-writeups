package androidx.savedstate;

import android.view.View;

public final class ViewTreeSavedStateRegistryOwner {
    private ViewTreeSavedStateRegistryOwner() {
    }

    public static void set(View view, SavedStateRegistryOwner owner) {
        view.setTag(C0074R.C0075id.view_tree_saved_state_registry_owner, owner);
    }

    /* JADX DEBUG: Multi-variable search result rejected for TypeSearchVarInfo{r3v1, resolved type: java.lang.Object} */
    /* JADX DEBUG: Multi-variable search result rejected for TypeSearchVarInfo{r0v4, resolved type: androidx.savedstate.SavedStateRegistryOwner} */
    /* JADX WARNING: Multi-variable type inference failed */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public static androidx.savedstate.SavedStateRegistryOwner get(android.view.View r4) {
        /*
            int r0 = androidx.savedstate.C0074R.C0075id.view_tree_saved_state_registry_owner
            java.lang.Object r0 = r4.getTag(r0)
            androidx.savedstate.SavedStateRegistryOwner r0 = (androidx.savedstate.SavedStateRegistryOwner) r0
            if (r0 == 0) goto L_0x000b
            return r0
        L_0x000b:
            android.view.ViewParent r1 = r4.getParent()
        L_0x000f:
            if (r0 != 0) goto L_0x0026
            boolean r2 = r1 instanceof android.view.View
            if (r2 == 0) goto L_0x0026
            r2 = r1
            android.view.View r2 = (android.view.View) r2
            int r3 = androidx.savedstate.C0074R.C0075id.view_tree_saved_state_registry_owner
            java.lang.Object r3 = r2.getTag(r3)
            r0 = r3
            androidx.savedstate.SavedStateRegistryOwner r0 = (androidx.savedstate.SavedStateRegistryOwner) r0
            android.view.ViewParent r1 = r2.getParent()
            goto L_0x000f
        L_0x0026:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.savedstate.ViewTreeSavedStateRegistryOwner.get(android.view.View):androidx.savedstate.SavedStateRegistryOwner");
    }
}
