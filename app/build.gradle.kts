plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "com.example.passvault"
    compileSdk {
        version = release(36) {
            minorApiLevel = 1
        }
    }

    defaultConfig {
        applicationId = "com.example.passvault"
        minSdk = 26
        targetSdk = 36
        versionCode = 4
        versionName = "3.1"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    buildFeatures {
        // Нужен BuildConfig.VERSION_NAME: раньше версия была захардкожена
        // строкой в окне «О программе» и разъезжалась с versionName.
        buildConfig = true
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    testOptions {
        unitTests {
            // Ядро (Core.kt) не трогает android.*, поэтому проверяется обычными
            // JVM-тестами — без эмулятора и подключённого телефона.
            isIncludeAndroidResources = false
            isReturnDefaultValues = true

            all {
                // Argon2id с настоящими параметрами просит 256 МиБ на попытку.
                // Стандартной кучи тестовой JVM на это не хватает, и тест падал
                // бы по нехватке памяти, а не по существу.
                it.maxHeapSize = "2g"
            }
        }
    }
}

dependencies {
    // Argon2id (формат PMVAULT2) чистой Java. Нативная библиотека не нужна,
    // поэтому это работает и на устройстве, и в обычных JVM-тестах.
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    implementation(libs.androidx.activity.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.androidx.core.ktx)
    implementation(libs.material)
    testImplementation(libs.junit)
    // В android.jar классы org.json — заглушки, бросающие исключения.
    // Для JVM-тестов подкладываем настоящую реализацию.
    testImplementation("org.json:json:20240303")
}