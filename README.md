# YeboID for Kotlin / Android

An Android library using [AppAuth](https://github.com/openid/AppAuth-Android) Custom Tabs, S256 PKCE, persisted one-use callback transactions and Android Keystore AES-GCM storage. Android API 23+, Java 17. This produces an AAR library, not an APK. Read [AGENTS.md](AGENTS.md).

## Install from source

```sh
git clone --branch v0.1.0 https://github.com/omegathesecond/yeboid-kotlin.git
```

In your Android app's `settings.gradle.kts`, include the adjacent checkout:

```kotlin
includeBuild("../yeboid-kotlin")
```

In your app module:

```kotlin
dependencies {
    implementation("com.yeboid:yeboid-android:0.1.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
}
android.defaultConfig.manifestPlaceholders["appAuthRedirectScheme"] = "com.yourcompany.yourapp"
```

The composite build supplies the dependency locally; no Maven Central publication is claimed. Alternatively run `./gradlew publishToMavenLocal` in the SDK and add `mavenLocal()` to your app's repositories. Use an exact source tag for reproducibility.

Register `com.yourcompany.yourapp://oauth/callback` exactly in [Developer Apps](https://yeboid.com/developer/apps). Configure AppAuth's redirect receiver for that scheme. The app module must supply its registered scheme; inspect the host app's merged manifest before release. Never register the SDK test placeholder scheme.

## Activity sign-in

```kotlin
import android.net.Uri
import androidx.activity.result.contract.ActivityResultContracts
import androidx.lifecycle.lifecycleScope
import com.yeboid.YeboID
import kotlinx.coroutines.launch

// Fields of your Activity. Keep this client for the session; close it onDestroy.
private val identity by lazy {
    YeboID(this, "YOUR_PUBLIC_CLIENT_ID", Uri.parse("com.yourcompany.yourapp://oauth/callback"))
}
private val login = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
    lifecycleScope.launch {
        try {
            val data = result.data
            if (data == null) { identity.cancelSignIn(); showAuthCancelled() }
            else {
                identity.completeSignIn(data)
                val sub = identity.userInfo().getString("sub")
                onSignedIn(sub)
            }
        } catch (error: Exception) { showAuthError(error) }
    }
}
// In your button handler:
lifecycleScope.launch {
    try { login.launch(identity.signInIntent()) }
    catch (error: Exception) { identity.cancelSignIn(); showAuthError(error) }
}
```

The `showAuthCancelled`, `showAuthError` and `onSignedIn` handlers belong to your app. Connect them to the existing UI. Do not swallow exceptions. For coroutine cancellation, rethrow `CancellationException` after any required cleanup.

Defaults request `openid profile offline_access`. Pass `scopes = listOf(...)` only for permissions explicitly registered and consented. Discovery validates supported scopes, while YeboID enforces the client's registration. The granted token scope is available from `tokens().grantedScopes`. Store only `sub` as `yeboid_user_id` in your product database. Your backend must authenticate access tokens and authorize resources itself.

## Refresh and logout

```kotlin
val tokens = identity.refresh() // serialized; persists rotation before returning
// Send tokens.accessToken to your product API as Bearer.
identity.signOut()             // revoke before deleting local storage
identity.close()               // release AppAuth resources when the client is no longer used
```

Use one client instance per issuer/client. Calls serialize behind a mutex; never share refresh storage across independent clients/processes without external locking. No automatic refresh retries: if network/storage state after rotation is uncertain, require a new login. Revocation errors preserve the app session and propagate. Sign-out does not erase the browser's SSO cookie.

The default `AndroidKeyStore` encrypts both tokens and pending PKCE state. **Exclude its preferences from cloud and device-to-device backup** (or disable backup for the host app); Android Keystore keys do not transfer with restored preferences. The store exposes `preferencesName` for backup exclusions. Custom `SecureStore` implementations must encrypt and throw on failures. Never use plaintext SharedPreferences.

```sh
./gradlew testDebugUnitTest assembleRelease
```

CI builds the AAR and runs Robolectric protocol/storage-error tests. Actual device callbacks, browser availability and Keystore behavior still need a host-app test.
