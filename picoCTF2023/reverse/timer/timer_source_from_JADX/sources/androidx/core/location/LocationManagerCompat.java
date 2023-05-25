package androidx.core.location;

import android.content.Context;
import android.location.GnssStatus;
import android.location.GpsStatus;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.location.LocationRequest;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.provider.Settings;
import android.text.TextUtils;
import androidx.collection.SimpleArrayMap;
import androidx.core.location.GnssStatusCompat;
import androidx.core.p003os.CancellationSignal;
import androidx.core.p003os.ExecutorCompat;
import androidx.core.util.Consumer;
import androidx.core.util.ObjectsCompat;
import androidx.core.util.Preconditions;
import java.lang.ref.WeakReference;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.WeakHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;

public final class LocationManagerCompat {
    private static final long GET_CURRENT_LOCATION_TIMEOUT_MS = 30000;
    private static final long MAX_CURRENT_LOCATION_AGE_MS = 10000;
    private static final long PRE_N_LOOPER_TIMEOUT_S = 5;
    private static Field sContextField;
    static final WeakHashMap<LocationListener, List<WeakReference<LocationListenerTransport>>> sLocationListeners = new WeakHashMap<>();
    private static Method sRequestLocationUpdatesExecutorMethod;
    private static Method sRequestLocationUpdatesLooperMethod;

    public static boolean isLocationEnabled(LocationManager locationManager) {
        if (Build.VERSION.SDK_INT >= 28) {
            return Api28Impl.isLocationEnabled(locationManager);
        }
        if (Build.VERSION.SDK_INT <= 19) {
            try {
                if (sContextField == null) {
                    Field declaredField = LocationManager.class.getDeclaredField("mContext");
                    sContextField = declaredField;
                    declaredField.setAccessible(true);
                }
                Context context = (Context) sContextField.get(locationManager);
                if (context != null) {
                    if (Build.VERSION.SDK_INT != 19) {
                        return !TextUtils.isEmpty(Settings.Secure.getString(context.getContentResolver(), "location_providers_allowed"));
                    }
                    if (Settings.Secure.getInt(context.getContentResolver(), "location_mode", 0) != 0) {
                        return true;
                    }
                    return false;
                }
            } catch (ClassCastException | IllegalAccessException | NoSuchFieldException | SecurityException e) {
            }
        }
        if (locationManager.isProviderEnabled("network") || locationManager.isProviderEnabled("gps")) {
            return true;
        }
        return false;
    }

    public static boolean hasProvider(LocationManager locationManager, String provider) {
        if (Build.VERSION.SDK_INT >= 31) {
            return Api31Impl.hasProvider(locationManager, provider);
        }
        if (locationManager.getAllProviders().contains(provider)) {
            return true;
        }
        try {
            if (locationManager.getProvider(provider) != null) {
                return true;
            }
            return false;
        } catch (SecurityException e) {
            return false;
        }
    }

    public static void getCurrentLocation(LocationManager locationManager, String provider, CancellationSignal cancellationSignal, Executor executor, Consumer<Location> consumer) {
        if (Build.VERSION.SDK_INT >= 30) {
            Api30Impl.getCurrentLocation(locationManager, provider, cancellationSignal, executor, consumer);
            return;
        }
        if (cancellationSignal != null) {
            cancellationSignal.throwIfCanceled();
        }
        Location location = locationManager.getLastKnownLocation(provider);
        if (location == null || SystemClock.elapsedRealtime() - LocationCompat.getElapsedRealtimeMillis(location) >= MAX_CURRENT_LOCATION_AGE_MS) {
            final CancellableLocationListener listener = new CancellableLocationListener(locationManager, executor, consumer);
            locationManager.requestLocationUpdates(provider, 0, 0.0f, listener, Looper.getMainLooper());
            if (cancellationSignal != null) {
                cancellationSignal.setOnCancelListener(new CancellationSignal.OnCancelListener() {
                    public void onCancel() {
                        CancellableLocationListener.this.cancel();
                    }
                });
            }
            listener.startTimeout(GET_CURRENT_LOCATION_TIMEOUT_MS);
            return;
        }
        executor.execute(new LocationManagerCompat$$ExternalSyntheticLambda0(consumer, location));
    }

    public static void requestLocationUpdates(LocationManager locationManager, String provider, LocationRequestCompat locationRequest, Executor executor, LocationListenerCompat listener) {
        LocationManager locationManager2 = locationManager;
        String str = provider;
        LocationRequestCompat locationRequestCompat = locationRequest;
        Executor executor2 = executor;
        LocationListenerCompat locationListenerCompat = listener;
        if (Build.VERSION.SDK_INT >= 31) {
            Api31Impl.requestLocationUpdates(locationManager, str, locationRequest.toLocationRequest(), executor2, locationListenerCompat);
            return;
        }
        if (Build.VERSION.SDK_INT >= 30) {
            try {
                if (sRequestLocationUpdatesExecutorMethod == null) {
                    Method declaredMethod = LocationManager.class.getDeclaredMethod("requestLocationUpdates", new Class[]{LocationRequest.class, Executor.class, LocationListener.class});
                    sRequestLocationUpdatesExecutorMethod = declaredMethod;
                    declaredMethod.setAccessible(true);
                }
                LocationRequest request = locationRequestCompat.toLocationRequest(str);
                if (request != null) {
                    sRequestLocationUpdatesExecutorMethod.invoke(locationManager, new Object[]{request, executor2, locationListenerCompat});
                    return;
                }
            } catch (IllegalAccessException | NoSuchMethodException | UnsupportedOperationException | InvocationTargetException e) {
            }
        }
        LocationListenerTransport transport = new LocationListenerTransport(locationListenerCompat, executor2);
        if (Build.VERSION.SDK_INT >= 19) {
            try {
                if (sRequestLocationUpdatesLooperMethod == null) {
                    Method declaredMethod2 = LocationManager.class.getDeclaredMethod("requestLocationUpdates", new Class[]{LocationRequest.class, LocationListener.class, Looper.class});
                    sRequestLocationUpdatesLooperMethod = declaredMethod2;
                    declaredMethod2.setAccessible(true);
                }
                LocationRequest request2 = locationRequestCompat.toLocationRequest(str);
                if (request2 != null) {
                    synchronized (sLocationListeners) {
                        sRequestLocationUpdatesLooperMethod.invoke(locationManager, new Object[]{request2, transport, Looper.getMainLooper()});
                        transport.register();
                    }
                    return;
                }
            } catch (IllegalAccessException | NoSuchMethodException | UnsupportedOperationException | InvocationTargetException e2) {
            }
        }
        synchronized (sLocationListeners) {
            locationManager.requestLocationUpdates(provider, locationRequest.getIntervalMillis(), locationRequest.getMinUpdateDistanceMeters(), transport, Looper.getMainLooper());
            transport.register();
        }
    }

    public static void requestLocationUpdates(LocationManager locationManager, String provider, LocationRequestCompat locationRequest, LocationListenerCompat listener, Looper looper) {
        if (Build.VERSION.SDK_INT >= 31) {
            Api31Impl.requestLocationUpdates(locationManager, provider, locationRequest.toLocationRequest(), ExecutorCompat.create(new Handler(looper)), listener);
            return;
        }
        if (Build.VERSION.SDK_INT >= 19) {
            try {
                if (sRequestLocationUpdatesLooperMethod == null) {
                    Method declaredMethod = LocationManager.class.getDeclaredMethod("requestLocationUpdates", new Class[]{LocationRequest.class, LocationListener.class, Looper.class});
                    sRequestLocationUpdatesLooperMethod = declaredMethod;
                    declaredMethod.setAccessible(true);
                }
                LocationRequest request = locationRequest.toLocationRequest(provider);
                if (request != null) {
                    sRequestLocationUpdatesLooperMethod.invoke(locationManager, new Object[]{request, listener, looper});
                    return;
                }
            } catch (IllegalAccessException | NoSuchMethodException | UnsupportedOperationException | InvocationTargetException e) {
            }
        }
        locationManager.requestLocationUpdates(provider, locationRequest.getIntervalMillis(), locationRequest.getMinUpdateDistanceMeters(), listener, looper);
    }

    public static void removeUpdates(LocationManager locationManager, LocationListenerCompat listener) {
        WeakHashMap<LocationListener, List<WeakReference<LocationListenerTransport>>> weakHashMap = sLocationListeners;
        synchronized (weakHashMap) {
            List<WeakReference<LocationListenerTransport>> transports = weakHashMap.remove(listener);
            if (transports != null) {
                for (WeakReference<LocationListenerTransport> reference : transports) {
                    LocationListenerTransport transport = (LocationListenerTransport) reference.get();
                    if (transport != null && transport.unregister()) {
                        locationManager.removeUpdates(transport);
                    }
                }
            }
        }
        locationManager.removeUpdates(listener);
    }

    public static String getGnssHardwareModelName(LocationManager locationManager) {
        if (Build.VERSION.SDK_INT >= 28) {
            return Api28Impl.getGnssHardwareModelName(locationManager);
        }
        return null;
    }

    public static int getGnssYearOfHardware(LocationManager locationManager) {
        if (Build.VERSION.SDK_INT >= 28) {
            return Api28Impl.getGnssYearOfHardware(locationManager);
        }
        return 0;
    }

    private static class GnssLazyLoader {
        static final SimpleArrayMap<Object, Object> sGnssStatusListeners = new SimpleArrayMap<>();

        private GnssLazyLoader() {
        }
    }

    public static boolean registerGnssStatusCallback(LocationManager locationManager, GnssStatusCompat.Callback callback, Handler handler) {
        if (Build.VERSION.SDK_INT >= 30) {
            return registerGnssStatusCallback(locationManager, ExecutorCompat.create(handler), callback);
        }
        return registerGnssStatusCallback(locationManager, (Executor) new InlineHandlerExecutor(handler), callback);
    }

    public static boolean registerGnssStatusCallback(LocationManager locationManager, Executor executor, GnssStatusCompat.Callback callback) {
        if (Build.VERSION.SDK_INT >= 30) {
            return registerGnssStatusCallback(locationManager, (Handler) null, executor, callback);
        }
        Looper looper = Looper.myLooper();
        if (looper == null) {
            looper = Looper.getMainLooper();
        }
        return registerGnssStatusCallback(locationManager, new Handler(looper), executor, callback);
    }

    /* JADX WARNING: Code restructure failed: missing block: B:67:0x00de, code lost:
        return true;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:71:0x00ea, code lost:
        return false;
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    private static boolean registerGnssStatusCallback(android.location.LocationManager r18, android.os.Handler r19, java.util.concurrent.Executor r20, androidx.core.location.GnssStatusCompat.Callback r21) {
        /*
            r1 = r18
            r2 = r19
            r3 = r20
            r4 = r21
            int r0 = android.os.Build.VERSION.SDK_INT
            r5 = 1
            r6 = 0
            r7 = 30
            if (r0 < r7) goto L_0x0035
            androidx.collection.SimpleArrayMap<java.lang.Object, java.lang.Object> r7 = androidx.core.location.LocationManagerCompat.GnssLazyLoader.sGnssStatusListeners
            monitor-enter(r7)
            androidx.collection.SimpleArrayMap<java.lang.Object, java.lang.Object> r0 = androidx.core.location.LocationManagerCompat.GnssLazyLoader.sGnssStatusListeners     // Catch:{ all -> 0x0032 }
            java.lang.Object r0 = r0.get(r4)     // Catch:{ all -> 0x0032 }
            androidx.core.location.LocationManagerCompat$GnssStatusTransport r0 = (androidx.core.location.LocationManagerCompat.GnssStatusTransport) r0     // Catch:{ all -> 0x0032 }
            if (r0 != 0) goto L_0x0023
            androidx.core.location.LocationManagerCompat$GnssStatusTransport r8 = new androidx.core.location.LocationManagerCompat$GnssStatusTransport     // Catch:{ all -> 0x0032 }
            r8.<init>(r4)     // Catch:{ all -> 0x0032 }
            r0 = r8
        L_0x0023:
            boolean r8 = r1.registerGnssStatusCallback(r3, r0)     // Catch:{ all -> 0x0032 }
            if (r8 == 0) goto L_0x0030
            androidx.collection.SimpleArrayMap<java.lang.Object, java.lang.Object> r6 = androidx.core.location.LocationManagerCompat.GnssLazyLoader.sGnssStatusListeners     // Catch:{ all -> 0x0032 }
            r6.put(r4, r0)     // Catch:{ all -> 0x0032 }
            monitor-exit(r7)     // Catch:{ all -> 0x0032 }
            return r5
        L_0x0030:
            monitor-exit(r7)     // Catch:{ all -> 0x0032 }
            return r6
        L_0x0032:
            r0 = move-exception
            monitor-exit(r7)     // Catch:{ all -> 0x0032 }
            throw r0
        L_0x0035:
            int r0 = android.os.Build.VERSION.SDK_INT
            r7 = 24
            if (r0 < r7) goto L_0x006f
            if (r2 == 0) goto L_0x003f
            r0 = 1
            goto L_0x0040
        L_0x003f:
            r0 = 0
        L_0x0040:
            androidx.core.util.Preconditions.checkArgument(r0)
            androidx.collection.SimpleArrayMap<java.lang.Object, java.lang.Object> r7 = androidx.core.location.LocationManagerCompat.GnssLazyLoader.sGnssStatusListeners
            monitor-enter(r7)
            androidx.collection.SimpleArrayMap<java.lang.Object, java.lang.Object> r0 = androidx.core.location.LocationManagerCompat.GnssLazyLoader.sGnssStatusListeners     // Catch:{ all -> 0x006c }
            java.lang.Object r0 = r0.get(r4)     // Catch:{ all -> 0x006c }
            androidx.core.location.LocationManagerCompat$PreRGnssStatusTransport r0 = (androidx.core.location.LocationManagerCompat.PreRGnssStatusTransport) r0     // Catch:{ all -> 0x006c }
            if (r0 != 0) goto L_0x0057
            androidx.core.location.LocationManagerCompat$PreRGnssStatusTransport r8 = new androidx.core.location.LocationManagerCompat$PreRGnssStatusTransport     // Catch:{ all -> 0x006c }
            r8.<init>(r4)     // Catch:{ all -> 0x006c }
            r0 = r8
            goto L_0x005a
        L_0x0057:
            r0.unregister()     // Catch:{ all -> 0x006c }
        L_0x005a:
            r0.register(r3)     // Catch:{ all -> 0x006c }
            boolean r8 = r1.registerGnssStatusCallback(r0, r2)     // Catch:{ all -> 0x006c }
            if (r8 == 0) goto L_0x006a
            androidx.collection.SimpleArrayMap<java.lang.Object, java.lang.Object> r6 = androidx.core.location.LocationManagerCompat.GnssLazyLoader.sGnssStatusListeners     // Catch:{ all -> 0x006c }
            r6.put(r4, r0)     // Catch:{ all -> 0x006c }
            monitor-exit(r7)     // Catch:{ all -> 0x006c }
            return r5
        L_0x006a:
            monitor-exit(r7)     // Catch:{ all -> 0x006c }
            return r6
        L_0x006c:
            r0 = move-exception
            monitor-exit(r7)     // Catch:{ all -> 0x006c }
            throw r0
        L_0x006f:
            if (r2 == 0) goto L_0x0073
            r0 = 1
            goto L_0x0074
        L_0x0073:
            r0 = 0
        L_0x0074:
            androidx.core.util.Preconditions.checkArgument(r0)
            androidx.collection.SimpleArrayMap<java.lang.Object, java.lang.Object> r7 = androidx.core.location.LocationManagerCompat.GnssLazyLoader.sGnssStatusListeners
            monitor-enter(r7)
            androidx.collection.SimpleArrayMap<java.lang.Object, java.lang.Object> r0 = androidx.core.location.LocationManagerCompat.GnssLazyLoader.sGnssStatusListeners     // Catch:{ all -> 0x0155 }
            java.lang.Object r0 = r0.get(r4)     // Catch:{ all -> 0x0155 }
            androidx.core.location.LocationManagerCompat$GpsStatusTransport r0 = (androidx.core.location.LocationManagerCompat.GpsStatusTransport) r0     // Catch:{ all -> 0x0155 }
            if (r0 != 0) goto L_0x008b
            androidx.core.location.LocationManagerCompat$GpsStatusTransport r8 = new androidx.core.location.LocationManagerCompat$GpsStatusTransport     // Catch:{ all -> 0x0155 }
            r8.<init>(r1, r4)     // Catch:{ all -> 0x0155 }
            r0 = r8
            goto L_0x008f
        L_0x008b:
            r0.unregister()     // Catch:{ all -> 0x0155 }
            r8 = r0
        L_0x008f:
            r8.register(r3)     // Catch:{ all -> 0x0155 }
            r9 = r8
            java.util.concurrent.FutureTask r0 = new java.util.concurrent.FutureTask     // Catch:{ all -> 0x0155 }
            androidx.core.location.LocationManagerCompat$$ExternalSyntheticLambda1 r10 = new androidx.core.location.LocationManagerCompat$$ExternalSyntheticLambda1     // Catch:{ all -> 0x0155 }
            r10.<init>(r1, r9)     // Catch:{ all -> 0x0155 }
            r0.<init>(r10)     // Catch:{ all -> 0x0155 }
            r10 = r0
            android.os.Looper r0 = android.os.Looper.myLooper()     // Catch:{ all -> 0x0155 }
            android.os.Looper r11 = r19.getLooper()     // Catch:{ all -> 0x0155 }
            if (r0 != r11) goto L_0x00ac
            r10.run()     // Catch:{ all -> 0x0155 }
            goto L_0x00b2
        L_0x00ac:
            boolean r0 = r2.post(r10)     // Catch:{ all -> 0x0155 }
            if (r0 == 0) goto L_0x013e
        L_0x00b2:
            r11 = 0
            java.util.concurrent.TimeUnit r0 = java.util.concurrent.TimeUnit.SECONDS     // Catch:{ ExecutionException -> 0x010e, TimeoutException -> 0x00f6 }
            r12 = 5
            long r12 = r0.toNanos(r12)     // Catch:{ ExecutionException -> 0x010e, TimeoutException -> 0x00f6 }
            long r14 = java.lang.System.nanoTime()     // Catch:{ ExecutionException -> 0x010e, TimeoutException -> 0x00f6 }
            long r14 = r14 + r12
        L_0x00c0:
            java.util.concurrent.TimeUnit r0 = java.util.concurrent.TimeUnit.NANOSECONDS     // Catch:{ InterruptedException -> 0x00eb }
            java.lang.Object r0 = r10.get(r12, r0)     // Catch:{ InterruptedException -> 0x00eb }
            java.lang.Boolean r0 = (java.lang.Boolean) r0     // Catch:{ InterruptedException -> 0x00eb }
            boolean r0 = r0.booleanValue()     // Catch:{ InterruptedException -> 0x00eb }
            if (r0 == 0) goto L_0x00df
            androidx.collection.SimpleArrayMap<java.lang.Object, java.lang.Object> r0 = androidx.core.location.LocationManagerCompat.GnssLazyLoader.sGnssStatusListeners     // Catch:{ InterruptedException -> 0x00eb }
            r0.put(r4, r9)     // Catch:{ InterruptedException -> 0x00eb }
            if (r11 == 0) goto L_0x00dd
            java.lang.Thread r0 = java.lang.Thread.currentThread()     // Catch:{ all -> 0x0155 }
            r0.interrupt()     // Catch:{ all -> 0x0155 }
        L_0x00dd:
            monitor-exit(r7)     // Catch:{ all -> 0x0155 }
            return r5
        L_0x00df:
            if (r11 == 0) goto L_0x00e9
            java.lang.Thread r0 = java.lang.Thread.currentThread()     // Catch:{ all -> 0x0155 }
            r0.interrupt()     // Catch:{ all -> 0x0155 }
        L_0x00e9:
            monitor-exit(r7)     // Catch:{ all -> 0x0155 }
            return r6
        L_0x00eb:
            r0 = move-exception
            r11 = 1
            long r16 = java.lang.System.nanoTime()     // Catch:{ ExecutionException -> 0x010e, TimeoutException -> 0x00f6 }
            long r12 = r14 - r16
            goto L_0x00c0
        L_0x00f4:
            r0 = move-exception
            goto L_0x0133
        L_0x00f6:
            r0 = move-exception
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException     // Catch:{ all -> 0x00f4 }
            java.lang.StringBuilder r6 = new java.lang.StringBuilder     // Catch:{ all -> 0x00f4 }
            r6.<init>()     // Catch:{ all -> 0x00f4 }
            r6.append(r2)     // Catch:{ all -> 0x00f4 }
            java.lang.String r12 = " appears to be blocked, please run registerGnssStatusCallback() directly on a Looper thread or ensure the main Looper is not blocked by this thread"
            r6.append(r12)     // Catch:{ all -> 0x00f4 }
            java.lang.String r6 = r6.toString()     // Catch:{ all -> 0x00f4 }
            r5.<init>(r6, r0)     // Catch:{ all -> 0x00f4 }
            throw r5     // Catch:{ all -> 0x00f4 }
        L_0x010e:
            r0 = move-exception
            java.lang.Throwable r5 = r0.getCause()     // Catch:{ all -> 0x00f4 }
            boolean r5 = r5 instanceof java.lang.RuntimeException     // Catch:{ all -> 0x00f4 }
            if (r5 != 0) goto L_0x012c
            java.lang.Throwable r5 = r0.getCause()     // Catch:{ all -> 0x00f4 }
            boolean r5 = r5 instanceof java.lang.Error     // Catch:{ all -> 0x00f4 }
            if (r5 == 0) goto L_0x0126
            java.lang.Throwable r5 = r0.getCause()     // Catch:{ all -> 0x00f4 }
            java.lang.Error r5 = (java.lang.Error) r5     // Catch:{ all -> 0x00f4 }
            throw r5     // Catch:{ all -> 0x00f4 }
        L_0x0126:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException     // Catch:{ all -> 0x00f4 }
            r5.<init>(r0)     // Catch:{ all -> 0x00f4 }
            throw r5     // Catch:{ all -> 0x00f4 }
        L_0x012c:
            java.lang.Throwable r5 = r0.getCause()     // Catch:{ all -> 0x00f4 }
            java.lang.RuntimeException r5 = (java.lang.RuntimeException) r5     // Catch:{ all -> 0x00f4 }
            throw r5     // Catch:{ all -> 0x00f4 }
        L_0x0133:
            if (r11 == 0) goto L_0x013c
            java.lang.Thread r5 = java.lang.Thread.currentThread()     // Catch:{ all -> 0x0155 }
            r5.interrupt()     // Catch:{ all -> 0x0155 }
        L_0x013c:
            throw r0     // Catch:{ all -> 0x0155 }
        L_0x013e:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException     // Catch:{ all -> 0x0155 }
            java.lang.StringBuilder r5 = new java.lang.StringBuilder     // Catch:{ all -> 0x0155 }
            r5.<init>()     // Catch:{ all -> 0x0155 }
            r5.append(r2)     // Catch:{ all -> 0x0155 }
            java.lang.String r6 = " is shutting down"
            r5.append(r6)     // Catch:{ all -> 0x0155 }
            java.lang.String r5 = r5.toString()     // Catch:{ all -> 0x0155 }
            r0.<init>(r5)     // Catch:{ all -> 0x0155 }
            throw r0     // Catch:{ all -> 0x0155 }
        L_0x0155:
            r0 = move-exception
            monitor-exit(r7)     // Catch:{ all -> 0x0155 }
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.core.location.LocationManagerCompat.registerGnssStatusCallback(android.location.LocationManager, android.os.Handler, java.util.concurrent.Executor, androidx.core.location.GnssStatusCompat$Callback):boolean");
    }

    public static void unregisterGnssStatusCallback(LocationManager locationManager, GnssStatusCompat.Callback callback) {
        if (Build.VERSION.SDK_INT >= 30) {
            synchronized (GnssLazyLoader.sGnssStatusListeners) {
                GnssStatusTransport transport = (GnssStatusTransport) GnssLazyLoader.sGnssStatusListeners.remove(callback);
                if (transport != null) {
                    locationManager.unregisterGnssStatusCallback(transport);
                }
            }
        } else if (Build.VERSION.SDK_INT >= 24) {
            synchronized (GnssLazyLoader.sGnssStatusListeners) {
                PreRGnssStatusTransport transport2 = (PreRGnssStatusTransport) GnssLazyLoader.sGnssStatusListeners.remove(callback);
                if (transport2 != null) {
                    transport2.unregister();
                    locationManager.unregisterGnssStatusCallback(transport2);
                }
            }
        } else {
            synchronized (GnssLazyLoader.sGnssStatusListeners) {
                GpsStatusTransport transport3 = (GpsStatusTransport) GnssLazyLoader.sGnssStatusListeners.remove(callback);
                if (transport3 != null) {
                    transport3.unregister();
                    locationManager.removeGpsStatusListener(transport3);
                }
            }
        }
    }

    private LocationManagerCompat() {
    }

    private static class LocationListenerTransport implements LocationListener {
        final Executor mExecutor;
        volatile LocationListenerCompat mListener;

        LocationListenerTransport(LocationListenerCompat listener, Executor executor) {
            this.mListener = (LocationListenerCompat) ObjectsCompat.requireNonNull(listener, "invalid null listener");
            this.mExecutor = executor;
        }

        public void register() {
            List<WeakReference<LocationListenerTransport>> transports = LocationManagerCompat.sLocationListeners.get(this.mListener);
            if (transports == null) {
                transports = new ArrayList<>(1);
                LocationManagerCompat.sLocationListeners.put(this.mListener, transports);
            } else if (Build.VERSION.SDK_INT >= 24) {
                transports.removeIf(C0305xa0af9a6b.INSTANCE);
            } else {
                Iterator<WeakReference<LocationListenerTransport>> it = transports.iterator();
                while (it.hasNext()) {
                    if (it.next().get() == null) {
                        it.remove();
                    }
                }
            }
            transports.add(new WeakReference(this));
        }

        static /* synthetic */ boolean lambda$register$0(WeakReference reference) {
            return reference.get() == null;
        }

        public boolean unregister() {
            LocationListenerCompat listener = this.mListener;
            if (listener == null) {
                return false;
            }
            this.mListener = null;
            List<WeakReference<LocationListenerTransport>> transports = LocationManagerCompat.sLocationListeners.get(listener);
            if (transports == null) {
                return true;
            }
            if (Build.VERSION.SDK_INT >= 24) {
                transports.removeIf(C0306xa0af9a6c.INSTANCE);
            } else {
                Iterator<WeakReference<LocationListenerTransport>> it = transports.iterator();
                while (it.hasNext()) {
                    if (it.next().get() == null) {
                        it.remove();
                    }
                }
            }
            if (!transports.isEmpty()) {
                return true;
            }
            LocationManagerCompat.sLocationListeners.remove(listener);
            return true;
        }

        static /* synthetic */ boolean lambda$unregister$1(WeakReference reference) {
            return reference.get() == null;
        }

        public void onLocationChanged(Location location) {
            LocationListenerCompat listener = this.mListener;
            if (listener != null) {
                this.mExecutor.execute(new C0300xa0af9a66(this, listener, location));
            }
        }

        /* access modifiers changed from: package-private */
        /* renamed from: lambda$onLocationChanged$2$androidx-core-location-LocationManagerCompat$LocationListenerTransport */
        public /* synthetic */ void mo6177xad6a74fb(LocationListenerCompat listener, Location location) {
            if (this.mListener == listener) {
                listener.onLocationChanged(location);
            }
        }

        public void onLocationChanged(List<Location> locations) {
            LocationListenerCompat listener = this.mListener;
            if (listener != null) {
                this.mExecutor.execute(new C0304xa0af9a6a(this, listener, locations));
            }
        }

        /* access modifiers changed from: package-private */
        /* renamed from: lambda$onLocationChanged$3$androidx-core-location-LocationManagerCompat$LocationListenerTransport */
        public /* synthetic */ void mo6178x2fb529da(LocationListenerCompat listener, List locations) {
            if (this.mListener == listener) {
                listener.onLocationChanged(locations);
            }
        }

        public void onFlushComplete(int requestCode) {
            LocationListenerCompat listener = this.mListener;
            if (listener != null) {
                this.mExecutor.execute(new C0299xa0af9a65(this, listener, requestCode));
            }
        }

        /* access modifiers changed from: package-private */
        /* renamed from: lambda$onFlushComplete$4$androidx-core-location-LocationManagerCompat$LocationListenerTransport */
        public /* synthetic */ void mo6176xf4e2685b(LocationListenerCompat listener, int requestCode) {
            if (this.mListener == listener) {
                listener.onFlushComplete(requestCode);
            }
        }

        public void onStatusChanged(String provider, int status, Bundle extras) {
            LocationListenerCompat listener = this.mListener;
            if (listener != null) {
                this.mExecutor.execute(new C0303xa0af9a69(this, listener, provider, status, extras));
            }
        }

        /* access modifiers changed from: package-private */
        /* renamed from: lambda$onStatusChanged$5$androidx-core-location-LocationManagerCompat$LocationListenerTransport */
        public /* synthetic */ void mo6181xe07c10d5(LocationListenerCompat listener, String provider, int status, Bundle extras) {
            if (this.mListener == listener) {
                listener.onStatusChanged(provider, status, extras);
            }
        }

        public void onProviderEnabled(String provider) {
            LocationListenerCompat listener = this.mListener;
            if (listener != null) {
                this.mExecutor.execute(new C0302xa0af9a68(this, listener, provider));
            }
        }

        /* access modifiers changed from: package-private */
        /* renamed from: lambda$onProviderEnabled$6$androidx-core-location-LocationManagerCompat$LocationListenerTransport */
        public /* synthetic */ void mo6180x5ebfe4c6(LocationListenerCompat listener, String provider) {
            if (this.mListener == listener) {
                listener.onProviderEnabled(provider);
            }
        }

        public void onProviderDisabled(String provider) {
            LocationListenerCompat listener = this.mListener;
            if (listener != null) {
                this.mExecutor.execute(new C0301xa0af9a67(this, listener, provider));
            }
        }

        /* access modifiers changed from: package-private */
        /* renamed from: lambda$onProviderDisabled$7$androidx-core-location-LocationManagerCompat$LocationListenerTransport */
        public /* synthetic */ void mo6179x48c02650(LocationListenerCompat listener, String provider) {
            if (this.mListener == listener) {
                listener.onProviderDisabled(provider);
            }
        }
    }

    private static class GnssStatusTransport extends GnssStatus.Callback {
        final GnssStatusCompat.Callback mCallback;

        GnssStatusTransport(GnssStatusCompat.Callback callback) {
            Preconditions.checkArgument(callback != null, "invalid null callback");
            this.mCallback = callback;
        }

        public void onStarted() {
            this.mCallback.onStarted();
        }

        public void onStopped() {
            this.mCallback.onStopped();
        }

        public void onFirstFix(int ttffMillis) {
            this.mCallback.onFirstFix(ttffMillis);
        }

        public void onSatelliteStatusChanged(GnssStatus status) {
            this.mCallback.onSatelliteStatusChanged(GnssStatusCompat.wrap(status));
        }
    }

    private static class PreRGnssStatusTransport extends GnssStatus.Callback {
        final GnssStatusCompat.Callback mCallback;
        volatile Executor mExecutor;

        PreRGnssStatusTransport(GnssStatusCompat.Callback callback) {
            Preconditions.checkArgument(callback != null, "invalid null callback");
            this.mCallback = callback;
        }

        public void register(Executor executor) {
            boolean z = true;
            Preconditions.checkArgument(executor != null, "invalid null executor");
            if (this.mExecutor != null) {
                z = false;
            }
            Preconditions.checkState(z);
            this.mExecutor = executor;
        }

        public void unregister() {
            this.mExecutor = null;
        }

        public void onStarted() {
            Executor executor = this.mExecutor;
            if (executor != null) {
                executor.execute(new C0307xcc169346(this, executor));
            }
        }

        /* access modifiers changed from: package-private */
        /* renamed from: lambda$onStarted$0$androidx-core-location-LocationManagerCompat$PreRGnssStatusTransport */
        public /* synthetic */ void mo6192x7ba12b9c(Executor executor) {
            if (this.mExecutor == executor) {
                this.mCallback.onStarted();
            }
        }

        public void onStopped() {
            Executor executor = this.mExecutor;
            if (executor != null) {
                executor.execute(new C0308xcc169347(this, executor));
            }
        }

        /* access modifiers changed from: package-private */
        /* renamed from: lambda$onStopped$1$androidx-core-location-LocationManagerCompat$PreRGnssStatusTransport */
        public /* synthetic */ void mo6193x80a5cd6f(Executor executor) {
            if (this.mExecutor == executor) {
                this.mCallback.onStopped();
            }
        }

        public void onFirstFix(int ttffMillis) {
            Executor executor = this.mExecutor;
            if (executor != null) {
                executor.execute(new C0309xcc169348(this, executor, ttffMillis));
            }
        }

        /* access modifiers changed from: package-private */
        /* renamed from: lambda$onFirstFix$2$androidx-core-location-LocationManagerCompat$PreRGnssStatusTransport */
        public /* synthetic */ void mo6190x4191f1e(Executor executor, int ttffMillis) {
            if (this.mExecutor == executor) {
                this.mCallback.onFirstFix(ttffMillis);
            }
        }

        public void onSatelliteStatusChanged(GnssStatus status) {
            Executor executor = this.mExecutor;
            if (executor != null) {
                executor.execute(new C0310xcc169349(this, executor, status));
            }
        }

        /* access modifiers changed from: package-private */
        /* renamed from: lambda$onSatelliteStatusChanged$3$androidx-core-location-LocationManagerCompat$PreRGnssStatusTransport */
        public /* synthetic */ void mo6191xdecf6cdb(Executor executor, GnssStatus status) {
            if (this.mExecutor == executor) {
                this.mCallback.onSatelliteStatusChanged(GnssStatusCompat.wrap(status));
            }
        }
    }

    private static class GpsStatusTransport implements GpsStatus.Listener {
        final GnssStatusCompat.Callback mCallback;
        volatile Executor mExecutor;
        private final LocationManager mLocationManager;

        GpsStatusTransport(LocationManager locationManager, GnssStatusCompat.Callback callback) {
            Preconditions.checkArgument(callback != null, "invalid null callback");
            this.mLocationManager = locationManager;
            this.mCallback = callback;
        }

        public void register(Executor executor) {
            Preconditions.checkState(this.mExecutor == null);
            this.mExecutor = executor;
        }

        public void unregister() {
            this.mExecutor = null;
        }

        public void onGpsStatusChanged(int event) {
            Executor executor = this.mExecutor;
            if (executor != null) {
                switch (event) {
                    case 1:
                        executor.execute(new C0295x7b1274a6(this, executor));
                        return;
                    case 2:
                        executor.execute(new C0296x7b1274a7(this, executor));
                        return;
                    case 3:
                        GpsStatus gpsStatus = this.mLocationManager.getGpsStatus((GpsStatus) null);
                        if (gpsStatus != null) {
                            executor.execute(new C0297x7b1274a8(this, executor, gpsStatus.getTimeToFirstFix()));
                            return;
                        }
                        return;
                    case 4:
                        GpsStatus gpsStatus2 = this.mLocationManager.getGpsStatus((GpsStatus) null);
                        if (gpsStatus2 != null) {
                            executor.execute(new C0298x7b1274a9(this, executor, GnssStatusCompat.wrap(gpsStatus2)));
                            return;
                        }
                        return;
                    default:
                        return;
                }
            }
        }

        /* access modifiers changed from: package-private */
        /* renamed from: lambda$onGpsStatusChanged$0$androidx-core-location-LocationManagerCompat$GpsStatusTransport */
        public /* synthetic */ void mo6168x75e92221(Executor executor) {
            if (this.mExecutor == executor) {
                this.mCallback.onStarted();
            }
        }

        /* access modifiers changed from: package-private */
        /* renamed from: lambda$onGpsStatusChanged$1$androidx-core-location-LocationManagerCompat$GpsStatusTransport */
        public /* synthetic */ void mo6169xc3a89a22(Executor executor) {
            if (this.mExecutor == executor) {
                this.mCallback.onStopped();
            }
        }

        /* access modifiers changed from: package-private */
        /* renamed from: lambda$onGpsStatusChanged$2$androidx-core-location-LocationManagerCompat$GpsStatusTransport */
        public /* synthetic */ void mo6170x11681223(Executor executor, int ttff) {
            if (this.mExecutor == executor) {
                this.mCallback.onFirstFix(ttff);
            }
        }

        /* access modifiers changed from: package-private */
        /* renamed from: lambda$onGpsStatusChanged$3$androidx-core-location-LocationManagerCompat$GpsStatusTransport */
        public /* synthetic */ void mo6171x5f278a24(Executor executor, GnssStatusCompat gnssStatus) {
            if (this.mExecutor == executor) {
                this.mCallback.onSatelliteStatusChanged(gnssStatus);
            }
        }
    }

    private static class Api31Impl {
        private Api31Impl() {
        }

        static boolean hasProvider(LocationManager locationManager, String provider) {
            return locationManager.hasProvider(provider);
        }

        static void requestLocationUpdates(LocationManager locationManager, String provider, LocationRequest locationRequest, Executor executor, LocationListener listener) {
            locationManager.requestLocationUpdates(provider, locationRequest, executor, listener);
        }
    }

    private static class Api30Impl {
        private Api30Impl() {
        }

        static void getCurrentLocation(LocationManager locationManager, String provider, CancellationSignal cancellationSignal, Executor executor, Consumer<Location> consumer) {
            android.os.CancellationSignal cancellationSignal2;
            if (cancellationSignal != null) {
                cancellationSignal2 = (android.os.CancellationSignal) cancellationSignal.getCancellationSignalObject();
            } else {
                cancellationSignal2 = null;
            }
            Objects.requireNonNull(consumer);
            locationManager.getCurrentLocation(provider, cancellationSignal2, executor, new LocationManagerCompat$Api30Impl$$ExternalSyntheticLambda0(consumer));
        }
    }

    private static class Api28Impl {
        private Api28Impl() {
        }

        static boolean isLocationEnabled(LocationManager locationManager) {
            return locationManager.isLocationEnabled();
        }

        static String getGnssHardwareModelName(LocationManager locationManager) {
            return locationManager.getGnssHardwareModelName();
        }

        static int getGnssYearOfHardware(LocationManager locationManager) {
            return locationManager.getGnssYearOfHardware();
        }
    }

    private static final class CancellableLocationListener implements LocationListener {
        private Consumer<Location> mConsumer;
        private final Executor mExecutor;
        private final LocationManager mLocationManager;
        private final Handler mTimeoutHandler = new Handler(Looper.getMainLooper());
        Runnable mTimeoutRunnable;
        private boolean mTriggered;

        CancellableLocationListener(LocationManager locationManager, Executor executor, Consumer<Location> consumer) {
            this.mLocationManager = locationManager;
            this.mExecutor = executor;
            this.mConsumer = consumer;
        }

        public void cancel() {
            synchronized (this) {
                if (!this.mTriggered) {
                    this.mTriggered = true;
                    cleanup();
                }
            }
        }

        public void startTimeout(long timeoutMs) {
            synchronized (this) {
                if (!this.mTriggered) {
                    C02931 r0 = new Runnable() {
                        public void run() {
                            CancellableLocationListener.this.mTimeoutRunnable = null;
                            Location location = null;
                            CancellableLocationListener.this.onLocationChanged((Location) null);
                        }
                    };
                    this.mTimeoutRunnable = r0;
                    this.mTimeoutHandler.postDelayed(r0, timeoutMs);
                }
            }
        }

        public void onStatusChanged(String provider, int status, Bundle extras) {
        }

        public void onProviderEnabled(String provider) {
        }

        public void onProviderDisabled(String p) {
            Location location = null;
            onLocationChanged((Location) null);
        }

        public void onLocationChanged(Location location) {
            synchronized (this) {
                if (!this.mTriggered) {
                    this.mTriggered = true;
                    this.mExecutor.execute(new C0294x27d5f43a(this.mConsumer, location));
                    cleanup();
                }
            }
        }

        private void cleanup() {
            this.mConsumer = null;
            this.mLocationManager.removeUpdates(this);
            Runnable runnable = this.mTimeoutRunnable;
            if (runnable != null) {
                this.mTimeoutHandler.removeCallbacks(runnable);
                this.mTimeoutRunnable = null;
            }
        }
    }

    private static final class InlineHandlerExecutor implements Executor {
        private final Handler mHandler;

        InlineHandlerExecutor(Handler handler) {
            this.mHandler = (Handler) Preconditions.checkNotNull(handler);
        }

        public void execute(Runnable command) {
            if (Looper.myLooper() == this.mHandler.getLooper()) {
                command.run();
            } else if (!this.mHandler.post((Runnable) Preconditions.checkNotNull(command))) {
                throw new RejectedExecutionException(this.mHandler + " is shutting down");
            }
        }
    }
}
