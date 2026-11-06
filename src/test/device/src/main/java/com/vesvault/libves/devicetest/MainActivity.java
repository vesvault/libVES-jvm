/***************************************************************************
 * libVES-jvm:   Java bindings for libVES.c
 * (c) 2026 VESvault Corp     SPDX-License-Identifier: Apache-2.0
 ***************************************************************************/
package com.vesvault.libves.devicetest;

import android.app.Activity;
import android.content.res.AssetManager;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.WindowManager;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

/** Runs DeviceTest on launch and shows each line; logcat has them too, tag libves-test. */
public class MainActivity extends Activity {
    private TextView view;
    private ScrollView scroll;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        // Over the lock screen, screen on. Behind a locked screen the app is "top sleeping",
        // and Android 15 blocks its network a few seconds later (blocked=APP_BACKGROUND,
        // network_blocked_for_top_sleeping_and_above), which would read as a libcurl failure.
        if (Build.VERSION.SDK_INT >= 27) {
            setShowWhenLocked(true);
            setTurnScreenOn(true);
        }
        view = new TextView(this);
        view.setTypeface(Typeface.MONOSPACE);
        view.setTextSize(11);
        view.setPadding(24, 24, 24, 24);
        view.setTextIsSelectable(true);
        scroll = new ScrollView(this);
        scroll.addView(view);
        setContentView(scroll);
        new Thread(this::runTests, "libves-test").start();
    }

    private void runTests() {
        line("libVES-jvm device test");
        line(Build.MANUFACTURER + " " + Build.MODEL + ", Android " + Build.VERSION.RELEASE
            + " (API " + Build.VERSION.SDK_INT + "), " + Build.SUPPORTED_ABIS[0]);
        try {
            File dir = new File(getCacheDir(), "fixtures");
            copyAssets(dir);
            new DeviceTest(dir, this::line, true, getApplicationInfo().nativeLibraryDir).run();
        } catch (Throwable e) {
            line("FAIL  the test could not start: " + e);
        }
    }

    private void copyAssets(File dir) throws IOException {
        dir.mkdirs();
        AssetManager am = getAssets();
        byte[] buf = new byte[65536];
        for (String name : am.list("fixtures")) {
            try (InputStream in = am.open("fixtures/" + name);
                 FileOutputStream out = new FileOutputStream(new File(dir, name))) {
                for (int n; (n = in.read(buf)) > 0;) out.write(buf, 0, n);
            }
        }
    }

    private void line(String s) {
        Log.i("libves-test", s);
        runOnUiThread(() -> {
            view.append(s + "\n");
            scroll.post(() -> scroll.fullScroll(View.FOCUS_DOWN));
        });
    }
}
