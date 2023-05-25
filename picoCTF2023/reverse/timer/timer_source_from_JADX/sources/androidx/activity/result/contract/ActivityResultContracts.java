package androidx.activity.result.contract;

import android.content.ClipData;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Build;
import androidx.activity.result.ActivityResult;
import androidx.activity.result.IntentSenderRequest;
import androidx.activity.result.contract.ActivityResultContract;
import androidx.collection.ArrayMap;
import androidx.core.content.ContextCompat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

public final class ActivityResultContracts {
    private ActivityResultContracts() {
    }

    public static final class StartActivityForResult extends ActivityResultContract<Intent, ActivityResult> {
        public static final String EXTRA_ACTIVITY_OPTIONS_BUNDLE = "androidx.activity.result.contract.extra.ACTIVITY_OPTIONS_BUNDLE";

        public Intent createIntent(Context context, Intent input) {
            return input;
        }

        public ActivityResult parseResult(int resultCode, Intent intent) {
            return new ActivityResult(resultCode, intent);
        }
    }

    public static final class StartIntentSenderForResult extends ActivityResultContract<IntentSenderRequest, ActivityResult> {
        public static final String ACTION_INTENT_SENDER_REQUEST = "androidx.activity.result.contract.action.INTENT_SENDER_REQUEST";
        public static final String EXTRA_INTENT_SENDER_REQUEST = "androidx.activity.result.contract.extra.INTENT_SENDER_REQUEST";
        public static final String EXTRA_SEND_INTENT_EXCEPTION = "androidx.activity.result.contract.extra.SEND_INTENT_EXCEPTION";

        public Intent createIntent(Context context, IntentSenderRequest input) {
            return new Intent(ACTION_INTENT_SENDER_REQUEST).putExtra(EXTRA_INTENT_SENDER_REQUEST, input);
        }

        public ActivityResult parseResult(int resultCode, Intent intent) {
            return new ActivityResult(resultCode, intent);
        }
    }

    public static final class RequestMultiplePermissions extends ActivityResultContract<String[], Map<String, Boolean>> {
        public static final String ACTION_REQUEST_PERMISSIONS = "androidx.activity.result.contract.action.REQUEST_PERMISSIONS";
        public static final String EXTRA_PERMISSIONS = "androidx.activity.result.contract.extra.PERMISSIONS";
        public static final String EXTRA_PERMISSION_GRANT_RESULTS = "androidx.activity.result.contract.extra.PERMISSION_GRANT_RESULTS";

        public Intent createIntent(Context context, String[] input) {
            return createIntent(input);
        }

        public ActivityResultContract.SynchronousResult<Map<String, Boolean>> getSynchronousResult(Context context, String[] input) {
            if (input == null || input.length == 0) {
                return new ActivityResultContract.SynchronousResult<>(Collections.emptyMap());
            }
            Map<String, Boolean> grantState = new ArrayMap<>();
            boolean allGranted = true;
            for (String permission : input) {
                boolean granted = ContextCompat.checkSelfPermission(context, permission) == 0;
                grantState.put(permission, Boolean.valueOf(granted));
                if (!granted) {
                    allGranted = false;
                }
            }
            if (allGranted) {
                return new ActivityResultContract.SynchronousResult<>(grantState);
            }
            return null;
        }

        public Map<String, Boolean> parseResult(int resultCode, Intent intent) {
            if (resultCode != -1) {
                return Collections.emptyMap();
            }
            if (intent == null) {
                return Collections.emptyMap();
            }
            String[] permissions = intent.getStringArrayExtra(EXTRA_PERMISSIONS);
            int[] grantResults = intent.getIntArrayExtra(EXTRA_PERMISSION_GRANT_RESULTS);
            if (grantResults == null || permissions == null) {
                return Collections.emptyMap();
            }
            Map<String, Boolean> result = new HashMap<>();
            int size = permissions.length;
            for (int i = 0; i < size; i++) {
                result.put(permissions[i], Boolean.valueOf(grantResults[i] == 0));
            }
            return result;
        }

        static Intent createIntent(String[] input) {
            return new Intent(ACTION_REQUEST_PERMISSIONS).putExtra(EXTRA_PERMISSIONS, input);
        }
    }

    public static final class RequestPermission extends ActivityResultContract<String, Boolean> {
        public Intent createIntent(Context context, String input) {
            return RequestMultiplePermissions.createIntent(new String[]{input});
        }

        public Boolean parseResult(int resultCode, Intent intent) {
            int[] grantResults;
            boolean z = false;
            if (intent == null || resultCode != -1 || (grantResults = intent.getIntArrayExtra(RequestMultiplePermissions.EXTRA_PERMISSION_GRANT_RESULTS)) == null || grantResults.length == 0) {
                return false;
            }
            if (grantResults[0] == 0) {
                z = true;
            }
            return Boolean.valueOf(z);
        }

        public ActivityResultContract.SynchronousResult<Boolean> getSynchronousResult(Context context, String input) {
            if (input == null) {
                return new ActivityResultContract.SynchronousResult<>(false);
            }
            if (ContextCompat.checkSelfPermission(context, input) == 0) {
                return new ActivityResultContract.SynchronousResult<>(true);
            }
            return null;
        }
    }

    public static class TakePicturePreview extends ActivityResultContract<Void, Bitmap> {
        public Intent createIntent(Context context, Void input) {
            return new Intent("android.media.action.IMAGE_CAPTURE");
        }

        public final ActivityResultContract.SynchronousResult<Bitmap> getSynchronousResult(Context context, Void input) {
            return null;
        }

        public final Bitmap parseResult(int resultCode, Intent intent) {
            if (intent == null || resultCode != -1) {
                return null;
            }
            return (Bitmap) intent.getParcelableExtra("data");
        }
    }

    public static class TakePicture extends ActivityResultContract<Uri, Boolean> {
        public Intent createIntent(Context context, Uri input) {
            return new Intent("android.media.action.IMAGE_CAPTURE").putExtra("output", input);
        }

        public final ActivityResultContract.SynchronousResult<Boolean> getSynchronousResult(Context context, Uri input) {
            return null;
        }

        public final Boolean parseResult(int resultCode, Intent intent) {
            return Boolean.valueOf(resultCode == -1);
        }
    }

    public static class TakeVideo extends ActivityResultContract<Uri, Bitmap> {
        public Intent createIntent(Context context, Uri input) {
            return new Intent("android.media.action.VIDEO_CAPTURE").putExtra("output", input);
        }

        public final ActivityResultContract.SynchronousResult<Bitmap> getSynchronousResult(Context context, Uri input) {
            return null;
        }

        public final Bitmap parseResult(int resultCode, Intent intent) {
            if (intent == null || resultCode != -1) {
                return null;
            }
            return (Bitmap) intent.getParcelableExtra("data");
        }
    }

    public static final class PickContact extends ActivityResultContract<Void, Uri> {
        public Intent createIntent(Context context, Void input) {
            return new Intent("android.intent.action.PICK").setType("vnd.android.cursor.dir/contact");
        }

        public Uri parseResult(int resultCode, Intent intent) {
            if (intent == null || resultCode != -1) {
                return null;
            }
            return intent.getData();
        }
    }

    public static class GetContent extends ActivityResultContract<String, Uri> {
        public Intent createIntent(Context context, String input) {
            return new Intent("android.intent.action.GET_CONTENT").addCategory("android.intent.category.OPENABLE").setType(input);
        }

        public final ActivityResultContract.SynchronousResult<Uri> getSynchronousResult(Context context, String input) {
            return null;
        }

        public final Uri parseResult(int resultCode, Intent intent) {
            if (intent == null || resultCode != -1) {
                return null;
            }
            return intent.getData();
        }
    }

    public static class GetMultipleContents extends ActivityResultContract<String, List<Uri>> {
        public Intent createIntent(Context context, String input) {
            return new Intent("android.intent.action.GET_CONTENT").addCategory("android.intent.category.OPENABLE").setType(input).putExtra("android.intent.extra.ALLOW_MULTIPLE", true);
        }

        public final ActivityResultContract.SynchronousResult<List<Uri>> getSynchronousResult(Context context, String input) {
            return null;
        }

        public final List<Uri> parseResult(int resultCode, Intent intent) {
            if (intent == null || resultCode != -1) {
                return Collections.emptyList();
            }
            return getClipDataUris(intent);
        }

        static List<Uri> getClipDataUris(Intent intent) {
            LinkedHashSet<Uri> resultSet = new LinkedHashSet<>();
            if (intent.getData() != null) {
                resultSet.add(intent.getData());
            }
            ClipData clipData = intent.getClipData();
            if (clipData == null && resultSet.isEmpty()) {
                return Collections.emptyList();
            }
            if (clipData != null) {
                for (int i = 0; i < clipData.getItemCount(); i++) {
                    Uri uri = clipData.getItemAt(i).getUri();
                    if (uri != null) {
                        resultSet.add(uri);
                    }
                }
            }
            return new ArrayList(resultSet);
        }
    }

    public static class OpenDocument extends ActivityResultContract<String[], Uri> {
        public Intent createIntent(Context context, String[] input) {
            return new Intent("android.intent.action.OPEN_DOCUMENT").putExtra("android.intent.extra.MIME_TYPES", input).setType("*/*");
        }

        public final ActivityResultContract.SynchronousResult<Uri> getSynchronousResult(Context context, String[] input) {
            return null;
        }

        public final Uri parseResult(int resultCode, Intent intent) {
            if (intent == null || resultCode != -1) {
                return null;
            }
            return intent.getData();
        }
    }

    public static class OpenMultipleDocuments extends ActivityResultContract<String[], List<Uri>> {
        public Intent createIntent(Context context, String[] input) {
            return new Intent("android.intent.action.OPEN_DOCUMENT").putExtra("android.intent.extra.MIME_TYPES", input).putExtra("android.intent.extra.ALLOW_MULTIPLE", true).setType("*/*");
        }

        public final ActivityResultContract.SynchronousResult<List<Uri>> getSynchronousResult(Context context, String[] input) {
            return null;
        }

        public final List<Uri> parseResult(int resultCode, Intent intent) {
            if (resultCode != -1 || intent == null) {
                return Collections.emptyList();
            }
            return GetMultipleContents.getClipDataUris(intent);
        }
    }

    public static class OpenDocumentTree extends ActivityResultContract<Uri, Uri> {
        public Intent createIntent(Context context, Uri input) {
            Intent intent = new Intent("android.intent.action.OPEN_DOCUMENT_TREE");
            if (Build.VERSION.SDK_INT >= 26 && input != null) {
                intent.putExtra("android.provider.extra.INITIAL_URI", input);
            }
            return intent;
        }

        public final ActivityResultContract.SynchronousResult<Uri> getSynchronousResult(Context context, Uri input) {
            return null;
        }

        public final Uri parseResult(int resultCode, Intent intent) {
            if (intent == null || resultCode != -1) {
                return null;
            }
            return intent.getData();
        }
    }

    public static class CreateDocument extends ActivityResultContract<String, Uri> {
        public Intent createIntent(Context context, String input) {
            return new Intent("android.intent.action.CREATE_DOCUMENT").setType("*/*").putExtra("android.intent.extra.TITLE", input);
        }

        public final ActivityResultContract.SynchronousResult<Uri> getSynchronousResult(Context context, String input) {
            return null;
        }

        public final Uri parseResult(int resultCode, Intent intent) {
            if (intent == null || resultCode != -1) {
                return null;
            }
            return intent.getData();
        }
    }
}
