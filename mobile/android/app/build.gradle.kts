plugins { id("com.android.application") }

android {
    namespace = "com.tallowbrook.driver"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.tallowbrook.driver"
        minSdk = 26
        targetSdk = 36
        versionCode = 412
        versionName = "4.12.0"
    }

    signingConfigs {
        create("upload") {
            storeFile = rootProject.file("../../pki/keystores/android-upload.jks")
            storePassword = System.getenv("UPLOAD_STORE_PASSWORD")
            keyAlias = "upload"
            keyPassword = System.getenv("UPLOAD_KEY_PASSWORD")
            enableV1Signing = true
            enableV2Signing = true
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
            signingConfig = signingConfigs.getByName("upload")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation("androidx.security:security-crypto:1.1.0")
    implementation("com.google.crypto.tink:tink-android:1.23.0")
    implementation("org.conscrypt:conscrypt-android:2.7.0")
    implementation("com.squareup.okhttp3:okhttp:5.5.0")
}
