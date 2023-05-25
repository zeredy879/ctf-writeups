package androidx.core.view;

import android.os.Build;
import android.view.View;
import android.view.Window;
import android.view.WindowInsetsController;

public final class WindowCompat {
    public static final int FEATURE_ACTION_BAR = 8;
    public static final int FEATURE_ACTION_BAR_OVERLAY = 9;
    public static final int FEATURE_ACTION_MODE_OVERLAY = 10;

    private WindowCompat() {
    }

    public static <T extends View> T requireViewById(Window window, int id) {
        if (Build.VERSION.SDK_INT >= 28) {
            return window.requireViewById(id);
        }
        T view = window.findViewById(id);
        if (view != null) {
            return view;
        }
        throw new IllegalArgumentException("ID does not reference a View inside this Window");
    }

    public static void setDecorFitsSystemWindows(Window window, boolean decorFitsSystemWindows) {
        if (Build.VERSION.SDK_INT >= 30) {
            Impl30.setDecorFitsSystemWindows(window, decorFitsSystemWindows);
        } else if (Build.VERSION.SDK_INT >= 16) {
            Impl16.setDecorFitsSystemWindows(window, decorFitsSystemWindows);
        }
    }

    public static WindowInsetsControllerCompat getInsetsController(Window window, View view) {
        if (Build.VERSION.SDK_INT >= 30) {
            return Impl30.getInsetsController(window);
        }
        return new WindowInsetsControllerCompat(window, view);
    }

    private static class Impl16 {
        private Impl16() {
        }

        static void setDecorFitsSystemWindows(Window window, boolean decorFitsSystemWindows) {
            int i;
            View decorView = window.getDecorView();
            int sysUiVis = decorView.getSystemUiVisibility();
            if (decorFitsSystemWindows) {
                i = sysUiVis & -1793;
            } else {
                i = sysUiVis | 1792;
            }
            decorView.setSystemUiVisibility(i);
        }
    }

    private static class Impl30 {
        private Impl30() {
        }

        static void setDecorFitsSystemWindows(Window window, boolean decorFitsSystemWindows) {
            window.setDecorFitsSystemWindows(decorFitsSystemWindows);
        }

        static WindowInsetsControllerCompat getInsetsController(Window window) {
            WindowInsetsController insetsController = window.getInsetsController();
            if (insetsController != null) {
                return WindowInsetsControllerCompat.toWindowInsetsControllerCompat(insetsController);
            }
            return null;
        }
    }
}
