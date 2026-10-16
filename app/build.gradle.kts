plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.example.sshtunnel"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.example.sshtunnel"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"

        // ABI yang dibangun untuk library native tun2socks.
        // Hapus ABI yang tidak diperlukan supaya build lebih cepat dan APK lebih kecil.
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
        externalNativeBuild {
            ndkBuild {
                // Alignment 16 KB (wajib untuk perangkat Android 15+ dengan page size 16 KB).
                arguments += listOf("APP_SUPPORT_FLEXIBLE_PAGE_SIZES=true")
            }
        }
    }
    signingConfigs {
        create("aospTest") {
            storeFile = file("testkey.keystore")
            storePassword = "android"
            keyAlias = "testkey"
            keyPassword = "android"
            enableV1Signing = true
            enableV2Signing = true
            enableV3Signing = true
        }
    }

    externalNativeBuild {
        ndkBuild {
            path = file("src/main/jni/Android.mk")
        }
    }
    
    buildTypes {
        // debug juga ditandatangani kunci yang sama, karena workflow GitHub Actions membangun debug
        debug {
        isMinifyEnabled = false
        proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            signingConfig = signingConfigs.getByName("aospTest")
        }
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("aospTest")
        }
    }

   

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += setOf(
                "/META-INF/{AL2.0,LGPL2.1}",
                "META-INF/DEPENDENCIES",
                "META-INF/INDEX.LIST",
                "META-INF/LICENSE*",
                "META-INF/NOTICE*",
                "META-INF/versions/9/OSGI-INF/MANIFEST.MF",
            )
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    val composeBom = platform("androidx.compose:compose-bom:2024.10.01")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-core")
    debugImplementation("androidx.compose.ui:ui-tooling")

    // Klien SSH. Versi bisa dinaikkan ke rilis terbaru (cek di Maven Central).
    implementation("com.hierynomus:sshj:0.39.0")
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")
    // sshj memakai SLF4J; NOP supaya tidak ada warning "no binding".
    implementation("org.slf4j:slf4j-nop:2.0.16")
}
