package com.yeboid

import android.content.Context
import android.content.Intent
import android.net.Uri
import kotlinx.coroutines.runBlocking
import net.openid.appauth.AuthorizationRequest
import net.openid.appauth.AuthorizationResponse
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class YeboIDTest {
    private class Memory : SecureStore {
        val values = mutableMapOf<String, String>()
        var fail = false
        override fun get(key: String) = values[key]
        override fun put(key: String, value: String) { if (fail) error("storage"); values[key] = value }
        override fun remove(key: String) { values.remove(key) }
    }
    private fun metadata() = JSONObject("""{"issuer":"https://api.yeboid.com","authorization_endpoint":"https://yeboid.com/oauth/authorize","token_endpoint":"https://api.yeboid.com/oauth/token","userinfo_endpoint":"https://api.yeboid.com/oauth/userinfo","revocation_endpoint":"https://api.yeboid.com/oauth/revoke","jwks_uri":"https://api.yeboid.com/.well-known/jwks.json","response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"scopes_supported":["openid","profile","offline_access"],"code_challenge_methods_supported":["S256"]}""")
    private fun registration() = JSONObject("""{"client_id":"app","redirect_uris":["com.example://callback"],"scopes":["openid","profile","offline_access"]}""")
    @Test fun pendingPKCEIsEncryptedByStoreAndWrongStateFailsBeforeExchange() = runBlocking {
        val memory = Memory()
        val client = YeboID(RuntimeEnvironment.getApplication(), "app", Uri.parse("com.example://callback"), store = memory,
            http = { url, _, _ -> if (url.endsWith("/configuration")) registration() else metadata() })
        // Robolectric has no installed browser. The real error must remain visible;
        // inspect the durable transaction created before the browser launch failed.
        try { client.signInIntent() } catch (_: android.content.ActivityNotFoundException) { }
        val pending = JSONObject(memory.values["pending"]!!)
        val request = AuthorizationRequest.jsonDeserialize(pending.getJSONObject("request"))
        assertEquals("S256", request.codeVerifierChallengeMethod)
        assertNotNull(request.codeVerifier)
        assertEquals("https://yeboid.com/oauth/authorize", request.configuration.authorizationEndpoint.toString())
        val response = AuthorizationResponse.Builder(request).setState("wrong").setAuthorizationCode("code").build()
        try { client.completeSignIn(response.toIntent()); fail("wrong state must fail") } catch (e: YeboIDException) { assertEquals("state_mismatch", e.code) }
        assertNull(memory.values["pending"])
        client.close()
    }
    @Test fun outagesAndStorageFailuresAreVisible() = runBlocking {
        val memory = Memory()
        val context = RuntimeEnvironment.getApplication()
        val client = YeboID(context, "app", Uri.parse("com.example://callback"), store = memory, http = { _, _, _ -> throw YeboIDException("offline") })
        try { client.signInIntent(); fail("offline must throw") } catch (e: YeboIDException) { assertEquals("offline", e.code) }
        assertNull(memory.values["pending"])
        client.close()
        val other = YeboID(context, "app", Uri.parse("com.example://callback"), store = memory,
            http = { url, _, _ -> if (url.endsWith("/configuration")) registration() else metadata() })
        memory.fail = true
        try { other.signInIntent(); fail("storage must throw") } catch (e: IllegalStateException) { assertEquals("storage", e.message) }
        other.close()
    }
    @Test fun failedRevocationPreservesTheSession() = runBlocking {
        val memory = Memory()
        memory.put("tokens", Tokens("access", "refresh", System.currentTimeMillis() + 900000, "openid").json())
        val client = YeboID(RuntimeEnvironment.getApplication(), "app", Uri.parse("com.example://callback"), store = memory,
            http = { url, _, _ -> if (url.endsWith("openid-configuration")) metadata() else throw YeboIDException("offline") })
        try { client.signOut(); fail("outage must throw") } catch (e: YeboIDException) { assertEquals("offline", e.code) }
        assertNotNull(memory.values["tokens"])
        client.close()
    }
}
