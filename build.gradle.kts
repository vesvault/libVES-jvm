plugins {
    id("com.android.library") version "8.7.3"
}

group = "com.vesvault"
version = "0.1.0"

android {
    namespace = "com.vesvault.libves"
    compileSdk = 34
    buildToolsVersion = "34.0.0"
    ndkVersion = "27.3.13750724"

    defaultConfig {
        minSdk = 21
        consumerProguardFiles("consumer-rules.pro")
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
        externalNativeBuild {
            ndkBuild { }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    externalNativeBuild {
        ndkBuild {
            path = file("src/main/cpp/Android.mk")
        }
    }
}

dependencies {
    compileOnly("org.jetbrains:annotations:24.1.0")
}
