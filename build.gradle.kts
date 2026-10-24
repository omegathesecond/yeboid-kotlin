plugins {
    id("com.android.library") version "8.9.1"
    id("org.jetbrains.kotlin.android") version "2.2.20"
    id("maven-publish")
}
group = "com.yeboid"
version = "0.1.1"
android {
    namespace = "com.yeboid"
    compileSdk = 35
    defaultConfig { minSdk = 23; manifestPlaceholders["appAuthRedirectScheme"] = "yeboid-sdk-unconfigured" }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    testOptions { unitTests.isIncludeAndroidResources = true }
    publishing { singleVariant("release") { withSourcesJar() } }
}
kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
dependencies {
    api("net.openid:appauth:0.11.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.14.1")
}
afterEvaluate {
    publishing { publications { create<MavenPublication>("release") { from(components["release"]); artifactId = "yeboid-android" } } }
}
