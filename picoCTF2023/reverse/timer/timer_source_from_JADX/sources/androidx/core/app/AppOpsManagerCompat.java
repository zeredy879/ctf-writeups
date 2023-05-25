package androidx.core.app;

import android.app.AppOpsManager;
import android.content.Context;
import android.os.Binder;
import android.os.Build;

public final class AppOpsManagerCompat {
    public static final int MODE_ALLOWED = 0;
    public static final int MODE_DEFAULT = 3;
    public static final int MODE_ERRORED = 2;
    public static final int MODE_IGNORED = 1;

    private AppOpsManagerCompat() {
    }

    public static String permissionToOp(String permission) {
        if (Build.VERSION.SDK_INT >= 23) {
            return AppOpsManager.permissionToOp(permission);
        }
        return null;
    }

    public static int noteOp(Context context, String op, int uid, String packageName) {
        if (Build.VERSION.SDK_INT >= 19) {
            return ((AppOpsManager) context.getSystemService("appops")).noteOp(op, uid, packageName);
        }
        return 1;
    }

    public static int noteOpNoThrow(Context context, String op, int uid, String packageName) {
        if (Build.VERSION.SDK_INT >= 19) {
            return ((AppOpsManager) context.getSystemService("appops")).noteOpNoThrow(op, uid, packageName);
        }
        return 1;
    }

    public static int noteProxyOp(Context context, String op, String proxiedPackageName) {
        if (Build.VERSION.SDK_INT >= 23) {
            return ((AppOpsManager) context.getSystemService(AppOpsManager.class)).noteProxyOp(op, proxiedPackageName);
        }
        return 1;
    }

    public static int noteProxyOpNoThrow(Context context, String op, String proxiedPackageName) {
        if (Build.VERSION.SDK_INT >= 23) {
            return ((AppOpsManager) context.getSystemService(AppOpsManager.class)).noteProxyOpNoThrow(op, proxiedPackageName);
        }
        return 1;
    }

    public static int checkOrNoteProxyOp(Context context, int proxyUid, String op, String proxiedPackageName) {
        if (Build.VERSION.SDK_INT < 29) {
            return noteProxyOpNoThrow(context, op, proxiedPackageName);
        }
        AppOpsManager appOpsManager = Api29Impl.getSystemService(context);
        int checkProxiedOpResult = Api29Impl.checkOpNoThrow(appOpsManager, op, Binder.getCallingUid(), proxiedPackageName);
        if (checkProxiedOpResult != 0) {
            return checkProxiedOpResult;
        }
        return Api29Impl.checkOpNoThrow(appOpsManager, op, proxyUid, Api29Impl.getOpPackageName(context));
    }

    static class Api29Impl {
        private Api29Impl() {
        }

        static AppOpsManager getSystemService(Context context) {
            return (AppOpsManager) context.getSystemService(AppOpsManager.class);
        }

        static int checkOpNoThrow(AppOpsManager appOpsManager, String op, int uid, String packageName) {
            if (appOpsManager == null) {
                return 1;
            }
            return appOpsManager.checkOpNoThrow(op, uid, packageName);
        }

        static String getOpPackageName(Context context) {
            return context.getOpPackageName();
        }
    }
}
