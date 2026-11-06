/***************************************************************************
 * libVES-jvm:   Java bindings for libVES.c
 * (c) 2026 VESvault Corp     SPDX-License-Identifier: Apache-2.0
 ***************************************************************************/
package com.vesvault.libves.devicetest;

import java.io.File;

/** DeviceTest from a JVM on the build host (host-test.sh). args: fixturesDir */
public class HostMain {
    public static void main(String[] args) {
        System.exit(new DeviceTest(new File(args[0]), System.out::println, false, null).run() == 0 ? 0 : 1);
    }
}
