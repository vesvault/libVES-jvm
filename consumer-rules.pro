# JNI fields and constructors accessed reflectively from C must be kept.
-keepclassmembers class com.vesvault.libves.** {
    long nativeHandle;
    long parentHandle;
}

-keep class com.vesvault.libves.VESException {
    <init>(...);
    *;
}

-keep enum com.vesvault.libves.ErrorCode {
    *;
}
