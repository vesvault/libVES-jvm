// A small app that runs DeviceTest on a phone. It takes the release .aar as a
// file, not the project, so what runs is what the SBOM describes, and keeps the
// native libraries unstripped-again and unpacked, so the test can hash them.
// build-apk.sh builds it; this project is not part of the library's build.
plugins {
    id("com.android.application") version "8.7.3"
}

android {
    namespace = "com.vesvault.libves.devicetest"
    compileSdk = 34
    buildToolsVersion = "34.0.0"

    defaultConfig {
        applicationId = "com.vesvault.libves.devicetest"
        minSdk = 21
        targetSdk = 34
        versionCode = 1
        versionName = "1"
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
            keepDebugSymbols += "**/*.so"
        }
    }
}

dependencies {
    implementation(files("../../../build/outputs/aar/libves-jvm-release.aar"))
    compileOnly("org.jetbrains:annotations:24.1.0")
}
